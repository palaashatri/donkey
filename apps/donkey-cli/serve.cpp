// `donkey-cli serve`: JSON-RPC 2.0 over stdin and stdout (G11-T1). Framing is one request per
// line and one response per line. Requests are read one at a time, so a slow analysis delays the
// responses behind it but never corrupts them. The protocol, its methods and its error codes are in
// docs/RPC.md. Only read methods are implemented; write methods are refused and say why.

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "commands.h"
#include "donkey/analysis/analysis.h"
#include "donkey/binary/debug_info.h"
#include "donkey/binary/image.h"
#include "donkey/core/json.h"
#include "donkey/core/status.h"
#include "donkey/core/version.h"
#include "donkey/decode/decode.h"
#include "donkey/ir/debug_names.h"
#include "donkey/ir/ir.h"
#include "donkey/ir/lift.h"
#include "donkey/project/project.h"
#include "donkey/project/string_literals.h"
#include "json.h"
#include "serve.h"

namespace donkey::cli {
namespace {

constexpr int kExitOk = 0;
constexpr int kExitFailure = 1;
constexpr std::size_t kMaxMessageBytes = 16U * 1024U * 1024U;
constexpr std::uint64_t kMaxListLimit = 100000;
constexpr std::uint64_t kDefaultListLimit = 1000;
constexpr std::uint64_t kMaxInstructions = 4096;
constexpr std::uint64_t kDefaultInstructions = 64;

// JSON-RPC 2.0 defines the first five codes; the rest are application codes.
constexpr int kParseError = -32700;
constexpr int kInvalidRequest = -32600;
constexpr int kMethodNotFound = -32601;
constexpr int kInvalidParams = -32602;
constexpr int kOpenFailed = -32000;
constexpr int kNoImage = -32001;
constexpr int kUnknownFunction = -32004;
constexpr int kNoProject = -32008;
constexpr int kProjectFailed = -32009;
constexpr int kImageNotInProject = -32010;
constexpr int kWriteDisabled = -32003;
constexpr int kAnalysisFailed = -32005;
constexpr int kNotFound = -32006;

struct RpcError {
  int code = 0;
  std::string donkey_code;
  std::string message;
};

// A method's outcome: the raw JSON text of its result, or an error.
struct Reply {
  bool ok = true;
  std::string result;
  RpcError error;
};

Reply success(std::string result) {
  Reply reply;
  reply.result = std::move(result);
  return reply;
}

Reply failure(int code, std::string donkey_code, std::string message) {
  Reply reply;
  reply.ok = false;
  reply.error = RpcError{code, std::move(donkey_code), std::move(message)};
  return reply;
}

struct Session {
  bool open = false;
  LoadedBinary loaded;
  std::optional<AnalysisResult> analysis;
  // G11: the project that `annotations.list` reads and, when writes are allowed, that the write
  // methods change. Without `--project` there is no project.
  std::string project_path;
  std::optional<Project> project;
  bool allow_write = false;
};

// Quotes a string as JSON. Names taken from a binary can hold any bytes, so bytes that are not
// valid UTF-8 are written as U+FFFD; every response is valid UTF-8 JSON.
std::string quote_utf8(std::string_view text) {
  std::string out = "\"";
  std::size_t i = 0;
  while (i < text.size()) {
    const auto c = static_cast<unsigned char>(text[i]);
    if (c < 0x80U) {
      switch (c) {
        case '"':
          out += "\\\"";
          break;
        case '\\':
          out += "\\\\";
          break;
        case '\n':
          out += "\\n";
          break;
        case '\r':
          out += "\\r";
          break;
        case '\t':
          out += "\\t";
          break;
        default:
          if (c < 0x20U) {
            char escaped[8];
            std::snprintf(escaped, sizeof(escaped), "\\u%04x", static_cast<unsigned>(c));
            out += escaped;
          } else {
            out.push_back(static_cast<char>(c));
          }
      }
      ++i;
      continue;
    }
    std::size_t length = 0;
    std::uint32_t code_point = 0;
    std::uint32_t minimum = 0;
    if ((c & 0xe0U) == 0xc0U) {
      length = 2;
      code_point = c & 0x1fU;
      minimum = 0x80U;
    } else if ((c & 0xf0U) == 0xe0U) {
      length = 3;
      code_point = c & 0x0fU;
      minimum = 0x800U;
    } else if ((c & 0xf8U) == 0xf0U) {
      length = 4;
      code_point = c & 0x07U;
      minimum = 0x10000U;
    } else {
      out += "\\ufffd";
      ++i;
      continue;
    }
    bool valid = i + length <= text.size();
    for (std::size_t k = 1; valid && k < length; ++k) {
      const auto continuation = static_cast<unsigned char>(text[i + k]);
      if ((continuation & 0xc0U) != 0x80U) {
        valid = false;
      } else {
        code_point = (code_point << 6U) | (continuation & 0x3fU);
      }
    }
    if (valid && (code_point < minimum || code_point > 0x10ffffU ||
                  (code_point >= 0xd800U && code_point <= 0xdfffU))) {
      valid = false;
    }
    if (!valid) {
      out += "\\ufffd";
      ++i;
      continue;
    }
    out.append(text.substr(i, length));
    i += length;
  }
  out += "\"";
  return out;
}

std::string join(const std::vector<std::string>& items, std::string_view open,
                 std::string_view close) {
  std::string out{open};
  for (std::size_t i = 0; i < items.size(); ++i) {
    if (i != 0) {
      out += ", ";
    }
    out += items[i];
  }
  out += close;
  return out;
}

std::string bytes_hex(const Instruction& instruction) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  for (std::size_t i = 0; i < instruction.length && i < instruction.bytes.size(); ++i) {
    out.push_back(kDigits[instruction.bytes[i] >> 4U]);
    out.push_back(kDigits[instruction.bytes[i] & 0x0fU]);
  }
  return out;
}

// Parses "0x..." (hex) or decimal digits into a 64-bit value; false on any other text or overflow.
bool parse_address_text(std::string_view text, std::uint64_t& out) {
  unsigned base = 10;
  std::size_t start = 0;
  if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
    base = 16;
    start = 2;
  }
  if (start >= text.size()) {
    return false;
  }
  std::uint64_t value = 0;
  for (const char c : text.substr(start)) {
    unsigned digit = 0;
    if (c >= '0' && c <= '9') {
      digit = static_cast<unsigned>(c - '0');
    } else if (base == 16 && c >= 'a' && c <= 'f') {
      digit = static_cast<unsigned>(c - 'a') + 10U;
    } else if (base == 16 && c >= 'A' && c <= 'F') {
      digit = static_cast<unsigned>(c - 'A') + 10U;
    } else {
      return false;
    }
    if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / base) {
      return false;
    }
    value = value * base + digit;
  }
  out = value;
  return true;
}

// An address given as a JSON number, or as a string ("0x401000" or decimal).
bool read_address(const JsonValue& value, std::uint64_t& out) {
  if (value.is_number()) {
    constexpr double kExactLimit = 9007199254740992.0;  // 2^53: every smaller integer is exact
    if (value.number < 0.0 || value.number > kExactLimit ||
        std::floor(value.number) != value.number) {
      return false;
    }
    out = static_cast<std::uint64_t>(value.number);
    return true;
  }
  if (value.is_string()) {
    return parse_address_text(value.text, out);
  }
  return false;
}

// An optional integer parameter in [1, maximum]. A missing parameter yields `fallback`.
std::optional<RpcError> bounded_param(const JsonValue& params, std::string_view key,
                                      std::uint64_t fallback, std::uint64_t maximum,
                                      std::uint64_t& out) {
  out = fallback;
  const JsonValue* value = params.find(key);
  if (value == nullptr) {
    return std::nullopt;
  }
  std::uint64_t parsed = 0;
  if (!read_address(*value, parsed) || parsed == 0 || parsed > maximum) {
    return RpcError{kInvalidParams, "rpc.invalid_params",
                    std::string(key) + " must be an integer from 1 to " + std::to_string(maximum)};
  }
  out = parsed;
  return std::nullopt;
}

std::string diagnostics_json(const std::vector<Diagnostic>& diagnostics) {
  std::vector<std::string> items;
  items.reserve(diagnostics.size());
  for (const Diagnostic& diagnostic : diagnostics) {
    items.push_back("{\"status\": " + quote(status_name(diagnostic.status)) +
                    ", \"code\": " + quote_utf8(diagnostic.code) +
                    ", \"message\": " + quote_utf8(diagnostic.message) + "}");
  }
  return join(items, "[", "]");
}

std::optional<RpcError> require_image(const Session& session) {
  if (!session.open) {
    return RpcError{kNoImage, "rpc.no_image", "no binary is open; call open first"};
  }
  return std::nullopt;
}

// Runs the default analysis once per opened binary and keeps it for the following requests.
std::optional<RpcError> ensure_analysis(Session& session) {
  if (session.analysis.has_value()) {
    return std::nullopt;
  }
  auto result = analyze(session.loaded.image, session.loaded.data, AnalysisOptions{});
  if (!result) {
    return RpcError{kAnalysisFailed, "rpc.analysis_failed",
                    result.diagnostic().code + ": " + result.diagnostic().message};
  }
  session.analysis = std::move(result.value());
  return std::nullopt;
}

Reply hello_method(const Session& session) {
  const bool writes = session.project.has_value() && session.allow_write;
  return success(
      "{\"protocol\": \"donkey.rpc.v1\", \"tool\": \"donkey-cli\", \"tool_version\": " +
      quote(version()) +
      ", \"methods\": [\"hello\", \"open\", \"info\", \"functions\", \"strings\", \"xrefs\", "
      "\"disasm\", \"callgraph\", \"decompile\", \"annotations.list\", \"rename\", \"comment\", "
      "\"type.apply\"], \"not_implemented\": [], \"writes\": " +
      std::string(writes ? "\"enabled\"" : "\"disabled\"") + "}");
}

Reply open_method(const JsonValue& params, Session& session) {
  const JsonValue* path = params.find("path");
  if (path == nullptr || !path->is_string() || path->text.empty()) {
    return failure(kInvalidParams, "rpc.invalid_params", "path must be a non-empty string");
  }
  auto loaded = load_binary(path->text);
  if (!loaded) {
    return failure(kOpenFailed, "rpc.open_failed",
                   loaded.diagnostic().code + ": " + loaded.diagnostic().message);
  }
  session.loaded = std::move(loaded.value());
  session.analysis.reset();
  session.open = true;
  const BinaryImage& image = session.loaded.image;
  return success("{\"path\": " + quote_utf8(image.path) +
                 ", \"format\": " + quote(format_name(image.format)) +
                 ", \"architecture\": " + quote(architecture_name(image.architecture)) +
                 ", \"bits\": " + std::to_string(image.bits) +
                 ", \"endian\": " + quote(endian_name(image.endian)) + ", \"file_size\": " +
                 std::to_string(image.file_size) + ", \"sha256\": " + quote(image.sha256) +
                 ", \"sections\": " + std::to_string(image.sections.size()) +
                 ", \"symbols\": " + std::to_string(image.symbols.size()) +
                 ", \"partial\": " + (image.partial ? "true" : "false") + "}");
}

Reply info_method(const JsonValue& params, Session& session) {
  if (auto error = require_image(session)) {
    return failure(error->code, error->donkey_code, error->message);
  }
  std::uint64_t limit = 0;
  if (auto error = bounded_param(params, "limit", kDefaultListLimit, kMaxListLimit, limit)) {
    return failure(error->code, error->donkey_code, error->message);
  }
  const BinaryImage& image = session.loaded.image;
  std::vector<std::string> sections;
  for (const Section& section : image.sections) {
    sections.push_back("{\"name\": " + quote_utf8(section.name) + ", \"type\": " +
                       quote_utf8(section.type) + ", \"address\": " + quote(hex(section.address)) +
                       ", \"file_offset\": " + std::to_string(section.file_offset) +
                       ", \"file_size\": " + std::to_string(section.file_size) +
                       ", \"virtual_size\": " + std::to_string(section.virtual_size) +
                       ", \"readable\": " + (section.readable ? "true" : "false") +
                       ", \"writable\": " + (section.writable ? "true" : "false") +
                       ", \"executable\": " + (section.executable ? "true" : "false") + "}");
  }
  std::vector<std::string> symbols;
  for (const Symbol& symbol : image.symbols) {
    if (symbols.size() >= limit) {
      break;
    }
    symbols.push_back("{\"name\": " + quote_utf8(symbol.name) + ", \"address\": " +
                      quote(hex(symbol.address)) + ", \"size\": " + std::to_string(symbol.size) +
                      ", \"kind\": " + quote(symbol_kind_name(symbol.kind)) +
                      ", \"binding\": " + quote(symbol_binding_name(symbol.binding)) +
                      ", \"imported\": " + (symbol.imported ? "true" : "false") +
                      ", \"exported\": " + (symbol.exported ? "true" : "false") + "}");
  }
  return success("{\"format\": " + quote(format_name(image.format)) +
                 ", \"architecture\": " + quote(architecture_name(image.architecture)) +
                 ", \"bits\": " + std::to_string(image.bits) +
                 ", \"endian\": " + quote(endian_name(image.endian)) +
                 ", \"image_base\": " + quote(hex(image.image_base)) + ", \"entry_point\": " +
                 (image.has_entry_point() ? quote(hex(image.entry_point)) : std::string("null")) +
                 ", \"sha256\": " + quote(image.sha256) +
                 ", \"partial\": " + (image.partial ? "true" : "false") +
                 ", \"sections\": " + join(sections, "[", "]") +
                 ", \"symbols_total\": " + std::to_string(image.symbols.size()) +
                 ", \"symbols\": " + join(symbols, "[", "]") +
                 ", \"diagnostics\": " + diagnostics_json(image.diagnostics) + "}");
}

Reply functions_method(const JsonValue& params, Session& session) {
  if (auto error = require_image(session)) {
    return failure(error->code, error->donkey_code, error->message);
  }
  std::uint64_t limit = 0;
  if (auto error = bounded_param(params, "limit", kDefaultListLimit, kMaxListLimit, limit)) {
    return failure(error->code, error->donkey_code, error->message);
  }
  if (auto error = ensure_analysis(session)) {
    return failure(error->code, error->donkey_code, error->message);
  }
  const AnalysisResult& analysis = *session.analysis;
  std::vector<std::string> items;
  for (const Function& function : analysis.functions) {
    if (items.size() >= limit) {
      break;
    }
    items.push_back(
        "{\"name\": " + quote_utf8(function.name.empty() ? "<unnamed>" : function.name) +
        ", \"address\": " + quote(hex(function.address)) + ", \"end_address\": " +
        (function.has_extent ? quote(hex(function.end_address)) : std::string("null")) +
        ", \"blocks\": " + std::to_string(function.block_count) +
        ", \"estimated\": " + (function.estimated ? "true" : "false") +
        ", \"exported\": " + (function.exported ? "true" : "false") + "}");
  }
  return success("{\"status\": " + quote(analysis.partial ? "Partial" : "Complete") +
                 ", \"count\": " + std::to_string(analysis.functions.size()) +
                 ", \"functions\": " + join(items, "[", "]") +
                 ", \"diagnostics\": " + diagnostics_json(analysis.diagnostics) + "}");
}

Reply strings_method(const JsonValue& params, Session& session) {
  if (auto error = require_image(session)) {
    return failure(error->code, error->donkey_code, error->message);
  }
  std::uint64_t limit = 0;
  if (auto error = bounded_param(params, "limit", kDefaultListLimit, kMaxListLimit, limit)) {
    return failure(error->code, error->donkey_code, error->message);
  }
  if (auto error = ensure_analysis(session)) {
    return failure(error->code, error->donkey_code, error->message);
  }
  const AnalysisResult& analysis = *session.analysis;
  std::vector<std::string> items;
  for (const StringLiteral& literal : analysis.strings) {
    if (items.size() >= limit) {
      break;
    }
    items.push_back("{\"address\": " + quote(hex(literal.address)) +
                    ", \"file_offset\": " + std::to_string(literal.file_offset) +
                    ", \"mapped\": " + (literal.mapped ? "true" : "false") + ", \"encoding\": " +
                    quote(literal.encoding) + ", \"text\": " + quote_utf8(literal.text) + "}");
  }
  return success("{\"count\": " + std::to_string(analysis.strings.size()) +
                 ", \"strings\": " + join(items, "[", "]") + "}");
}

Reply xrefs_method(const JsonValue& params, Session& session) {
  if (auto error = require_image(session)) {
    return failure(error->code, error->donkey_code, error->message);
  }
  std::uint64_t limit = 0;
  if (auto error = bounded_param(params, "limit", kDefaultListLimit, kMaxListLimit, limit)) {
    return failure(error->code, error->donkey_code, error->message);
  }
  std::optional<std::uint64_t> target;
  if (const JsonValue* address = params.find("address")) {
    std::uint64_t parsed = 0;
    if (!read_address(*address, parsed)) {
      return failure(kInvalidParams, "rpc.invalid_params", "address must be a number or a string");
    }
    target = parsed;
  }
  if (auto error = ensure_analysis(session)) {
    return failure(error->code, error->donkey_code, error->message);
  }
  std::vector<std::string> items;
  std::size_t matching = 0;
  for (const Xref& xref : session.analysis->xrefs) {
    if (target.has_value() && xref.to != *target) {
      continue;
    }
    ++matching;
    if (items.size() >= limit) {
      continue;
    }
    items.push_back("{\"from\": " + quote(hex(xref.from)) + ", \"to\": " + quote(hex(xref.to)) +
                    ", \"kind\": " + quote(xref_kind_name(xref.kind)) + "}");
  }
  return success("{\"count\": " + std::to_string(matching) +
                 ", \"xrefs\": " + join(items, "[", "]") + "}");
}

Reply disasm_method(const JsonValue& params, Session& session) {
  if (auto error = require_image(session)) {
    return failure(error->code, error->donkey_code, error->message);
  }
  const JsonValue* address_member = params.find("address");
  std::uint64_t address = 0;
  if (address_member == nullptr || !read_address(*address_member, address)) {
    return failure(kInvalidParams, "rpc.invalid_params",
                   "address is required and must be a number or a string");
  }
  std::uint64_t count = 0;
  if (auto error = bounded_param(params, "count", kDefaultInstructions, kMaxInstructions, count)) {
    return failure(error->code, error->donkey_code, error->message);
  }
  if (auto error = ensure_analysis(session)) {
    return failure(error->code, error->donkey_code, error->message);
  }
  const std::vector<Instruction>& instructions = session.analysis->instructions;
  const auto first = std::find_if(
      instructions.begin(), instructions.end(),
      [address](const Instruction& instruction) { return instruction.address == address; });
  if (first == instructions.end()) {
    return failure(kNotFound, "rpc.not_found", "no decoded instruction starts at " + hex(address));
  }
  std::vector<std::string> items;
  for (auto it = first; it != instructions.end() && items.size() < count; ++it) {
    items.push_back(
        "{\"address\": " + quote(hex(it->address)) + ", \"bytes\": " + quote(bytes_hex(*it)) +
        ", \"length\": " + std::to_string(it->length) + ", \"mnemonic\": " +
        quote_utf8(it->mnemonic) + ", \"operands\": " + quote_utf8(it->operands) +
        ", \"class\": " + quote(instruction_class_name(it->classification)) + ", \"target\": " +
        (it->direct_target.has_value() ? quote(hex(*it->direct_target)) : std::string("null")) +
        "}");
  }
  return success("{\"address\": " + quote(hex(address)) +
                 ", \"instructions\": " + join(items, "[", "]") + "}");
}

Reply callgraph_method(const JsonValue& params, Session& session) {
  if (auto error = require_image(session)) {
    return failure(error->code, error->donkey_code, error->message);
  }
  std::uint64_t limit = 0;
  if (auto error = bounded_param(params, "limit", kDefaultListLimit, kMaxListLimit, limit)) {
    return failure(error->code, error->donkey_code, error->message);
  }
  if (auto error = ensure_analysis(session)) {
    return failure(error->code, error->donkey_code, error->message);
  }
  const CallGraph& graph = session.analysis->call_graph;
  std::vector<std::string> items;
  for (const CallGraphEdge& edge : graph.edges) {
    if (items.size() >= limit) {
      break;
    }
    items.push_back("{\"caller\": " + quote(hex(edge.caller)) + ", \"callee\": " +
                    quote(hex(edge.callee)) + ", \"site\": " + quote(hex(edge.site)) + "}");
  }
  return success("{\"edge_count\": " + std::to_string(graph.edges.size()) +
                 ", \"edges\": " + join(items, "[", "]") +
                 ", \"unresolved\": " + std::to_string(graph.unresolved.size()) +
                 ", \"orphan_sites\": " + std::to_string(graph.orphan_sites) + "}");
}

// The project image that holds the open binary, matched by SHA-256. The project must have saved
// this binary (`donkey-cli project save`) before its annotations can be read or changed.
std::optional<RpcError> project_image(Session& session, std::int64_t& image_id) {
  if (!session.project.has_value()) {
    return RpcError{kNoProject, "rpc.no_project",
                    "this method needs a project: start serve with --project <database>"};
  }
  if (auto error = require_image(session)) {
    return error;
  }
  auto images = session.project->images();
  if (!images) {
    return RpcError{kProjectFailed, "rpc.project_failed",
                    images.diagnostic().code + ": " + images.diagnostic().message};
  }
  for (const ProjectImage& image : images.value()) {
    if (image.sha256 == session.loaded.image.sha256) {
      image_id = image.id;
      return std::nullopt;
    }
  }
  return RpcError{kImageNotInProject, "rpc.image_not_in_project",
                  "the open binary is not in the project; save it with donkey-cli project save"};
}

// G11: one function's pseudocode, lifted and named the way `donkey-cli decompile` names it.
Reply decompile_method(const JsonValue& params, Session& session) {
  if (auto error = require_image(session)) {
    return failure(error->code, error->donkey_code, error->message);
  }
  const JsonValue* address_member = params.find("address");
  std::uint64_t address = 0;
  if (address_member == nullptr || !read_address(*address_member, address)) {
    return failure(kInvalidParams, "rpc.invalid_params",
                   "address is required and must be a number or a string");
  }
  if (auto error = ensure_analysis(session)) {
    return failure(error->code, error->donkey_code, error->message);
  }
  const Function* function = nullptr;
  for (const Function& candidate : session.analysis->functions) {
    if (candidate.address == address) {
      function = &candidate;
      break;
    }
  }
  if (function == nullptr) {
    return failure(kUnknownFunction, "rpc.unknown_function",
                   "no function starts at " + hex(address));
  }
  auto lifted = lift_function(session.loaded.image, *session.analysis, *function);
  if (!lifted) {
    return failure(kAnalysisFailed, "rpc.lift_failed",
                   lifted.diagnostic().code + ": " + lifted.diagnostic().message);
  }
  if (auto read = read_debug_info(session.loaded.image, session.loaded.data); read.has_value()) {
    if (const DebugFunction* named = read.value().function_at(function->address)) {
      (void)apply_debug_parameter_names(lifted.value(), *named, read.value());
      (void)apply_debug_stack_names(lifted.value(), *named, read.value());
    }
  }
  // The strings the project defines for this binary print as literals (G12-T2). Without a project
  // that holds this binary there are none.
  PseudocodeOptions pseudo_options;
  std::int64_t image_id = 0;
  if (!project_image(session, image_id).has_value()) {
    if (auto rows = session.project->annotations(image_id); rows.has_value()) {
      pseudo_options.string_literals =
          string_literals(rows.value(), session.loaded.image, session.loaded.data);
    }
  }
  auto text = format_pseudocode(lifted.value(), pseudo_options);
  if (!text) {
    return failure(kAnalysisFailed, "rpc.format_failed",
                   text.diagnostic().code + ": " + text.diagnostic().message);
  }
  std::vector<std::string> notes;
  for (const std::string& note : lifted.value().notes) {
    notes.push_back(quote_utf8(note));
  }
  return success("{\"address\": " + quote(hex(function->address)) +
                 ", \"name\": " + quote_utf8(function->name) +
                 ", \"partial\": " + (lifted.value().partial ? "true" : "false") + ", \"notes\": " +
                 join(notes, "[", "]") + ", \"pseudocode\": " + quote_utf8(text.value()) + "}");
}

// G11: the annotations the project holds for the open binary.
Reply annotations_list_method(const JsonValue&, Session& session) {
  std::int64_t image_id = 0;
  if (auto error = project_image(session, image_id)) {
    return failure(error->code, error->donkey_code, error->message);
  }
  auto rows = session.project->annotations(image_id);
  if (!rows) {
    return failure(kProjectFailed, "rpc.project_failed",
                   rows.diagnostic().code + ": " + rows.diagnostic().message);
  }
  std::vector<std::string> items;
  for (const Annotation& row : rows.value()) {
    items.push_back("{\"kind\": " + quote(annotation_kind_name(row.kind)) + ", \"address\": " +
                    quote(hex(row.address)) + ", \"text\": " + quote_utf8(row.text) + "}");
  }
  return success("{\"count\": " + std::to_string(items.size()) +
                 ", \"annotations\": " + join(items, "[", "]") + "}");
}

// A write method is refused unless the server was started with a project and --allow-write.
Reply write_refused(std::string_view method, const Session& session) {
  const std::string reason = !session.project.has_value()
                                 ? "no project: start serve with --project <database> --allow-write"
                                 : "--allow-write was not given";
  return failure(kWriteDisabled, "rpc.write_disabled",
                 std::string(method) + " is a write method; writes are disabled (" + reason + ")");
}

// G11: rename, comment. An empty text clears the annotation, as in the project API.
Reply annotation_write_method(const JsonValue& params, Session& session, AnnotationKind kind,
                              std::string_view method) {
  if (!session.allow_write || !session.project.has_value()) {
    return write_refused(method, session);
  }
  std::int64_t image_id = 0;
  if (auto error = project_image(session, image_id)) {
    return failure(error->code, error->donkey_code, error->message);
  }
  const JsonValue* address_member = params.find("address");
  std::uint64_t address = 0;
  if (address_member == nullptr || !read_address(*address_member, address)) {
    return failure(kInvalidParams, "rpc.invalid_params",
                   "address is required and must be a number or a string");
  }
  const JsonValue* text = params.find("text");
  if (text == nullptr || !text->is_string()) {
    return failure(kInvalidParams, "rpc.invalid_params", "text must be a string");
  }
  auto written = session.project->set_annotation(image_id, kind, address, text->text);
  if (!written) {
    return failure(kProjectFailed, "rpc.project_failed",
                   written.diagnostic().code + ": " + written.diagnostic().message);
  }
  return success("{\"method\": " + quote(method) + ", \"address\": " + quote(hex(address)) +
                 ", \"text\": " + quote_utf8(text->text) + "}");
}

// G11: applies a stored type to an address as a function prototype or as a data slot.
Reply type_apply_method(const JsonValue& params, Session& session) {
  if (!session.allow_write || !session.project.has_value()) {
    return write_refused("type.apply", session);
  }
  std::int64_t image_id = 0;
  if (auto error = project_image(session, image_id)) {
    return failure(error->code, error->donkey_code, error->message);
  }
  const JsonValue* address_member = params.find("address");
  std::uint64_t address = 0;
  if (address_member == nullptr || !read_address(*address_member, address)) {
    return failure(kInvalidParams, "rpc.invalid_params",
                   "address is required and must be a number or a string");
  }
  const JsonValue* type_member = params.find("type_id");
  if (type_member == nullptr || !type_member->is_number() || type_member->number < 0 ||
      type_member->number != static_cast<double>(static_cast<std::uint64_t>(type_member->number))) {
    return failure(kInvalidParams, "rpc.invalid_params", "type_id must be a whole number");
  }
  TypeApplicationKind kind = TypeApplicationKind::FunctionPrototype;
  if (const JsonValue* kind_member = params.find("kind"); kind_member != nullptr) {
    if (!kind_member->is_string()) {
      return failure(kInvalidParams, "rpc.invalid_params", "kind must be prototype or data");
    }
    if (kind_member->text == "data") {
      kind = TypeApplicationKind::DataSlot;
    } else if (kind_member->text != "prototype") {
      return failure(kInvalidParams, "rpc.invalid_params", "kind must be prototype or data");
    }
  }
  const auto type_id = static_cast<std::uint64_t>(type_member->number);
  auto applied = session.project->set_type_application(image_id, kind, address, TypeId(type_id));
  if (!applied) {
    return failure(kProjectFailed, "rpc.project_failed",
                   applied.diagnostic().code + ": " + applied.diagnostic().message);
  }
  return success("{\"method\": \"type.apply\", \"address\": " + quote(hex(address)) +
                 ", \"type_id\": " + std::to_string(type_id) + ", \"kind\": " +
                 quote(kind == TypeApplicationKind::DataSlot ? "data" : "prototype") + "}");
}

Reply dispatch(std::string_view method, const JsonValue& params, Session& session) {
  if (method == "hello") {
    return hello_method(session);
  }
  if (method == "open") {
    return open_method(params, session);
  }
  if (method == "info") {
    return info_method(params, session);
  }
  if (method == "functions") {
    return functions_method(params, session);
  }
  if (method == "strings") {
    return strings_method(params, session);
  }
  if (method == "xrefs") {
    return xrefs_method(params, session);
  }
  if (method == "disasm") {
    return disasm_method(params, session);
  }
  if (method == "callgraph") {
    return callgraph_method(params, session);
  }
  if (method == "decompile") {
    return decompile_method(params, session);
  }
  if (method == "annotations.list") {
    return annotations_list_method(params, session);
  }
  if (method == "rename") {
    return annotation_write_method(params, session, AnnotationKind::Rename, method);
  }
  if (method == "comment") {
    return annotation_write_method(params, session, AnnotationKind::Comment, method);
  }
  if (method == "type.apply") {
    return type_apply_method(params, session);
  }
  return failure(kMethodNotFound, "rpc.method_not_found", "unknown method " + quote_utf8(method));
}

// The id as it is echoed back: null when absent, a string, or the number's exact spelling.
std::string id_json(const JsonValue* id) {
  if (id == nullptr || id->is_null()) {
    return "null";
  }
  if (id->is_string()) {
    return quote_utf8(id->text);
  }
  return id->text;
}

std::string error_line(const std::string& id, const RpcError& error) {
  return "{\"jsonrpc\": \"2.0\", \"id\": " + id +
         ", \"error\": {\"code\": " + std::to_string(error.code) +
         ", \"message\": " + quote_utf8(error.message) +
         ", \"data\": {\"donkey_code\": " + quote(error.donkey_code) + "}}}";
}

std::optional<std::string> handle_request(const JsonValue& request, Session& session);

// One request line in, at most one response line out. Notifications (no id) get no response.
std::optional<std::string> handle_line(std::string_view line, Session& session) {
  JsonLimits limits;
  limits.max_bytes = kMaxMessageBytes;
  auto parsed = parse_json(line, limits);
  if (!parsed) {
    return error_line("null",
                      RpcError{kParseError, "rpc.parse",
                               parsed.diagnostic().code + ": " + parsed.diagnostic().message});
  }
  return handle_request(parsed.value(), session);
}

// One parsed request in, at most one response out. Shared by `serve` and `batch`.
std::optional<std::string> handle_request(const JsonValue& request, Session& session) {
  if (!request.is_object()) {
    return error_line(
        "null", RpcError{kInvalidRequest, "rpc.invalid_request", "a request is a JSON object"});
  }
  const JsonValue* id = request.find("id");
  const std::string id_text = id_json(id);
  const bool notification = id == nullptr;
  const JsonValue* version_member = request.find("jsonrpc");
  if (version_member == nullptr || !version_member->is_string() || version_member->text != "2.0") {
    return error_line(id_text, RpcError{kInvalidRequest, "rpc.invalid_request",
                                        "jsonrpc must be the string \"2.0\""});
  }
  const JsonValue* method = request.find("method");
  if (method == nullptr || !method->is_string()) {
    return error_line(id_text,
                      RpcError{kInvalidRequest, "rpc.invalid_request", "method must be a string"});
  }
  if (id != nullptr && !id->is_string() && !id->is_number() && !id->is_null()) {
    return error_line("null", RpcError{kInvalidRequest, "rpc.invalid_request",
                                       "id must be a string, a number or null"});
  }
  JsonValue no_params;
  no_params.kind = JsonValue::Kind::Object;
  const JsonValue* params_member = request.find("params");
  const JsonValue& params = params_member != nullptr ? *params_member : no_params;
  if (!params.is_object()) {
    if (notification) {
      return std::nullopt;
    }
    return error_line(id_text,
                      RpcError{kInvalidParams, "rpc.invalid_params", "params must be an object"});
  }

  Reply reply = dispatch(method->text, params, session);
  if (notification) {
    return std::nullopt;
  }
  if (!reply.ok) {
    return error_line(id_text, reply.error);
  }
  return "{\"jsonrpc\": \"2.0\", \"id\": " + id_text + ", \"result\": " + reply.result + "}";
}

enum class ReadStatus { Line, TooLarge, End };

// Reads one line from stdin without holding more than the message limit. A line over the limit
// is consumed to its end and reported, so the next request still parses.
ReadStatus read_line(std::string& line) {
  line.clear();
  bool too_large = false;
  bool any = false;
  int ch = 0;
  while ((ch = std::getc(stdin)) != EOF) {
    any = true;
    if (ch == '\n') {
      break;
    }
    if (too_large) {
      continue;
    }
    if (line.size() >= kMaxMessageBytes) {
      too_large = true;
      line.clear();
      continue;
    }
    line.push_back(static_cast<char>(ch));
  }
  if (too_large) {
    return ReadStatus::TooLarge;
  }
  if (ch == EOF && !any) {
    return ReadStatus::End;
  }
  if (!line.empty() && line.back() == '\r') {
    line.pop_back();
  }
  return ReadStatus::Line;
}

void write_line(const std::string& text) {
  std::fwrite(text.data(), 1, text.size(), stdout);
  std::fputc('\n', stdout);
  std::fflush(stdout);
}

}  // namespace

int command_serve(const std::vector<std::string_view>& arguments) {
  Session session;
  for (std::size_t i = 0; i < arguments.size(); ++i) {
    const std::string_view argument = arguments[i];
    if (argument == "--project") {
      if (i + 1 >= arguments.size()) {
        std::fprintf(stderr, "donkey-cli serve: --project needs a database path\n");
        return 2;
      }
      session.project_path = std::string(arguments[++i]);
    } else if (argument == "--allow-write") {
      session.allow_write = true;
    } else {
      std::fprintf(stderr,
                   "donkey-cli serve: unknown argument %s; requests are read from stdin, and "
                   "the options are --project <database> and --allow-write\n",
                   std::string(argument).c_str());
      return 2;
    }
  }
  if (session.allow_write && session.project_path.empty()) {
    std::fprintf(stderr, "donkey-cli serve: --allow-write needs --project <database>\n");
    return 2;
  }
  if (!session.project_path.empty()) {
    auto project = Project::open(session.project_path);
    if (!project) {
      std::fprintf(stderr, "donkey-cli serve: cannot open project %s: %s\n",
                   session.project_path.c_str(), project.diagnostic().message.c_str());
      return kExitFailure;
    }
    session.project.emplace(std::move(project.value()));
  }
  std::string line;
  while (true) {
    const ReadStatus status = read_line(line);
    if (status == ReadStatus::End) {
      break;
    }
    if (status == ReadStatus::TooLarge) {
      write_line(error_line("null", RpcError{kInvalidRequest, "rpc.too_large",
                                             "a request is larger than the 16 MiB limit"}));
      continue;
    }
    if (line.empty()) {
      continue;
    }
    if (auto response = handle_line(line, session)) {
      write_line(*response);
    }
  }
  return kExitOk;
}

int command_batch(const std::vector<std::string_view>& arguments) {
  if (arguments.size() != 1) {
    std::fprintf(stderr,
                 "donkey-cli batch: expected one script file: donkey-cli batch <script.json>\n");
    return 2;
  }
  const std::string path(arguments[0]);
  std::FILE* file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) {
    std::fprintf(stderr, "donkey-cli batch: cannot open %s\n", path.c_str());
    return kExitFailure;
  }
  std::string text;
  char buffer[65536];
  std::size_t count = 0;
  while ((count = std::fread(buffer, 1, sizeof(buffer), file)) > 0) {
    if (text.size() + count > kMaxMessageBytes) {
      std::fclose(file);
      std::fprintf(stderr, "donkey-cli batch: %s is larger than the 16 MiB limit\n", path.c_str());
      return kExitFailure;
    }
    text.append(buffer, count);
  }
  std::fclose(file);

  JsonLimits limits;
  limits.max_bytes = kMaxMessageBytes;
  auto parsed = parse_json(text, limits);
  if (!parsed) {
    std::fprintf(stderr, "donkey-cli batch: %s: %s: %s\n", path.c_str(),
                 parsed.diagnostic().code.c_str(), parsed.diagnostic().message.c_str());
    return kExitFailure;
  }
  if (!parsed.value().is_array()) {
    std::fprintf(stderr, "donkey-cli batch: %s must hold a JSON array of requests\n", path.c_str());
    return kExitFailure;
  }

  // One session for the whole script, so an `open` early in it serves the requests after it. The
  // responses are printed as one JSON array, in request order; notifications have none.
  Session session;
  std::string out = "[";
  bool first = true;
  for (const JsonValue& request : parsed.value().items) {
    auto response = handle_request(request, session);
    if (!response.has_value()) {
      continue;
    }
    out += first ? "\n  " : ",\n  ";
    out += *response;
    first = false;
  }
  out += first ? "]\n" : "\n]\n";
  std::fwrite(out.data(), 1, out.size(), stdout);
  std::fflush(stdout);
  return kExitOk;
}

}  // namespace donkey::cli

namespace donkey::cli {

std::string serve_text(std::string_view input) {
  Session session;
  std::string output;
  std::size_t begin = 0;
  while (true) {
    std::size_t end = input.find('\n', begin);
    if (end == std::string_view::npos) {
      end = input.size();
    }
    std::string_view line = input.substr(begin, end - begin);
    if (!line.empty() && line.back() == '\r') {
      line.remove_suffix(1);
    }
    if (line.size() > kMaxMessageBytes) {
      output += error_line("null", RpcError{kInvalidRequest, "rpc.too_large",
                                            "a request is larger than the 16 MiB limit"});
      output += '\n';
    } else if (!line.empty()) {
      if (auto response = handle_line(line, session)) {
        output += *response;
        output += '\n';
      }
    }
    if (end == input.size()) {
      break;
    }
    begin = end + 1;
  }
  return output;
}

}  // namespace donkey::cli
