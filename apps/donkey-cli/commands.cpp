#include "commands.h"

#include <algorithm>
#include <charconv>
#include <cinttypes>
#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/analysis/link_calls.h"
#include "donkey/analysis/signature_gen.h"
#include "donkey/analysis/signatures.h"
#include "donkey/binary/archive.h"
#include "donkey/binary/core.h"
#include "donkey/binary/debug_info.h"
#include "donkey/binary/demangle.h"
#include "donkey/binary/image.h"
#include "donkey/binary/link.h"
#include "donkey/binary/minidump.h"
#include "donkey/binary/separate_debug.h"
#include "donkey/core/checked.h"
#include "donkey/core/status.h"
#include "donkey/core/version.h"
#include "donkey/debug/condition.h"
#include "donkey/debug/debug.h"
#include "donkey/decode/decode.h"
#include "donkey/ir/debug_names.h"
#include "donkey/ir/lift.h"
#include "donkey/ir/local_names.h"
#include "donkey/patch/patch.h"
#include "donkey/plugin/plugin.h"
#include "donkey/project/cdecl.h"
#include "donkey/project/project.h"
#include "donkey/project/string_literals.h"
#include "donkey/project/types.h"
#include "json.h"

namespace donkey::cli {
namespace {

constexpr int kExitOk = 0;
constexpr int kExitFailure = 1;
constexpr int kExitUsage = 2;
constexpr std::size_t kMaxDisassemblyCount = 100000;

bool parse_u64(std::string_view text, std::uint64_t& out) {
  int base = 10;
  if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
    base = 16;
    text.remove_prefix(2);
  }
  if (text.empty()) {
    return false;
  }
  const auto* begin = text.data();
  const auto* end = text.data() + text.size();
  const auto result = std::from_chars(begin, end, out, base);
  return result.ec == std::errc() && result.ptr == end;
}

int fail(const Diagnostic& diagnostic) {
  std::fprintf(stderr, "error [%s]: %s", diagnostic.code.c_str(), diagnostic.message.c_str());
  if (diagnostic.offset.has_value()) {
    std::fprintf(stderr, " (at file offset 0x%" PRIx64 ")", *diagnostic.offset);
  }
  std::fprintf(stderr, "\n");
  return kExitFailure;
}

int usage_error(const char* message) {
  std::fprintf(stderr, "donkey-cli: %s\n", message);
  return kExitUsage;
}

bool take_value(const std::vector<std::string_view>& arguments, std::size_t& index,
                std::string_view& value) {
  if (index + 1 >= arguments.size()) {
    return false;
  }
  value = arguments[++index];
  return true;
}

std::string permissions(bool readable, bool writable, bool executable) {
  std::string out = "---";
  out[0] = readable ? 'r' : '-';
  out[1] = writable ? 'w' : '-';
  out[2] = executable ? 'x' : '-';
  return out;
}

std::string display_name(const std::string& name) {
  return name.empty() ? "<unnamed>" : name;
}

struct InfoOptions {
  std::string path;
  bool json = false;
  std::size_t max_symbols = 10000;
  LoadOptions load_options;
};

struct DisasmOptions {
  std::string path;
  std::string section;
  bool json = false;
  std::optional<std::uint64_t> address;
  std::size_t count = 64;
  LoadOptions load_options;
};

/// The default cap of `decompile` without --function (see --max-functions).
constexpr std::size_t kDefaultMaxDecompiledFunctions = 1000;

struct AnalysisRequest {
  std::string path;
  bool json = false;
  std::optional<std::uint64_t> address;
  std::size_t max_instructions = 1000000;
  std::size_t max_strings = 100000;
  std::size_t min_string_length = 4;
  std::size_t max_items = 1000;
  /// Whole-binary decompile output is capped at this many functions; --max-functions raises it.
  std::size_t max_functions = kDefaultMaxDecompiledFunctions;
  std::vector<std::uint64_t> function_starts;
  /// A project whose saved local names are applied to the decompiled output (G12-T3).
  std::string project_path;
  LoadOptions load_options;
};

bool try_parse_load_flag(const std::vector<std::string_view>& arguments, std::size_t& index,
                         LoadOptions& options, const char*& error_message) {
  const std::string_view argument = arguments[index];
  if (argument == "--isolate") {
    options.isolate = true;
    return true;
  }
  if (argument == "--raw") {
    options.force_raw = true;
    return true;
  }
  if (argument == "--arch") {
    std::string_view value;
    if (!take_value(arguments, index, value)) {
      error_message = "--arch needs an architecture name (x86, x86_64, arm, aarch64, riscv64)";
      return true;
    }
    const auto arch = parse_architecture(value);
    if (!arch.has_value()) {
      error_message = "invalid --arch value";
      return true;
    }
    options.preferred_architecture = arch.value();
    return true;
  }
  if (argument == "--base") {
    std::string_view value;
    if (!take_value(arguments, index, value)) {
      error_message = "--base needs an address";
      return true;
    }
    std::uint64_t parsed = 0;
    if (!parse_u64(value, parsed)) {
      error_message = "invalid --base address";
      return true;
    }
    options.raw_base_address = parsed;
    return true;
  }
  if (argument == "--entry") {
    std::string_view value;
    if (!take_value(arguments, index, value)) {
      error_message = "--entry needs an address";
      return true;
    }
    std::uint64_t parsed = 0;
    if (!parse_u64(value, parsed)) {
      error_message = "invalid --entry address";
      return true;
    }
    options.raw_entry_point = parsed;
    options.has_raw_entry_point = true;
    return true;
  }
  if (argument == "--bits") {
    std::string_view value;
    if (!take_value(arguments, index, value)) {
      error_message = "--bits needs 32 or 64";
      return true;
    }
    std::uint64_t parsed = 0;
    if (!parse_u64(value, parsed) || (parsed != 32 && parsed != 64)) {
      error_message = "invalid --bits value (expected 32 or 64)";
      return true;
    }
    options.raw_bits = static_cast<unsigned>(parsed);
    return true;
  }
  if (argument == "--endian") {
    std::string_view value;
    if (!take_value(arguments, index, value)) {
      error_message = "--endian needs little or big";
      return true;
    }
    if (value == "little") {
      options.raw_endian = Endian::Little;
    } else if (value == "big") {
      options.raw_endian = Endian::Big;
    } else {
      error_message = "invalid --endian value (expected little or big)";
    }
    return true;
  }
  return false;
}

/// The demangling of `name` (Itanium `_Z` or MSVC `?`), or an empty string when `name` is not a
/// mangled name or the demangler does not read it. The raw name is always printed too.
std::string demangled_name(const std::string& name) {
  if (is_msvc_name(name)) {
    const auto demangled = demangle_msvc(name);
    return demangled.has_value() ? demangled.value() : std::string();
  }
  if (!is_itanium_name(name)) {
    return {};
  }
  const auto demangled = demangle_itanium(name);
  return demangled.has_value() ? demangled.value() : std::string();
}

void print_human_info(const BinaryImage& image, std::size_t max_symbols) {
  std::printf("File:      %s\n", image.path.c_str());
  std::printf("Size:      %" PRIu64 " bytes\n", image.file_size);
  std::printf("SHA-256:   %s\n", image.sha256.c_str());
  std::printf("Format:    %s (%s), %s-endian, %u-bit\n", format_name(image.format),
              image.format_detail.c_str(), endian_name(image.endian), image.bits);
  std::printf("Arch:      %s\n", architecture_name(image.architecture));
  if (!image.fat_architectures.empty()) {
    std::printf("Slices:    ");
    for (std::size_t i = 0; i < image.fat_architectures.size(); ++i) {
      std::printf("%s%s", i == 0 ? "" : ", ", architecture_name(image.fat_architectures[i]));
    }
    std::printf("\n");
  }
  std::printf("Base:      %s\n", hex(image.image_base).c_str());
  if (image.has_entry_point()) {
    std::printf("Entry:     %s\n", hex(image.entry_point).c_str());
  } else {
    std::printf("Entry:     unavailable\n");
  }
  std::printf("Status:    %s\n", image.partial ? "Partial" : "Complete");

  std::printf("\nSegments (%zu):\n", image.segments.size());
  for (const auto& segment : image.segments) {
    std::printf("  [%u] %-16s va %s size 0x%" PRIx64 " (file 0x%" PRIx64 " size 0x%" PRIx64 ")\n",
                segment.index, segment.name.c_str(), hex(segment.virtual_address).c_str(),
                segment.virtual_size, segment.file_offset, segment.file_size);
  }

  std::printf("\nSections (%zu):\n", image.sections.size());
  for (const auto& section : image.sections) {
    std::printf("  [%2u] %-28s va %-18s file 0x%-8" PRIx64 " size 0x%-8" PRIx64 " %s\n",
                static_cast<unsigned>(section.id.value()), section.name.c_str(),
                hex(section.address).c_str(), section.file_offset, section.virtual_size,
                permissions(section.readable, section.writable, section.executable).c_str());
  }

  std::size_t imports = 0;
  std::size_t exports = 0;
  for (const auto& symbol : image.symbols) {
    imports += symbol.imported ? 1U : 0U;
    exports += symbol.exported ? 1U : 0U;
  }
  std::printf("\nSymbols: %zu total, %zu imports, %zu exports\n", image.symbols.size(), imports,
              exports);
  std::size_t shown = 0;
  for (const auto& symbol : image.symbols) {
    if (!symbol.imported && !symbol.exported) {
      continue;
    }
    if (shown++ >= max_symbols) {
      std::printf("  ... truncated\n");
      break;
    }
    std::printf("  %-8s %-40s %s", symbol.imported ? "import" : "export", symbol.name.c_str(),
                hex(symbol.address).c_str());
    if (!symbol.module.empty()) {
      std::printf(" (%s)", symbol.module.c_str());
    }
    if (const std::string demangled = demangled_name(symbol.name); !demangled.empty()) {
      std::printf("  [%s]", demangled.c_str());
    }
    std::printf("\n");
  }

  if (!image.diagnostics.empty()) {
    std::printf("\nDiagnostics:\n");
    for (const auto& diagnostic : image.diagnostics) {
      std::printf("  [%s] %s: %s\n", status_name(diagnostic.status), diagnostic.code.c_str(),
                  diagnostic.message.c_str());
    }
  }
}

std::string json_info(const BinaryImage& image, std::size_t max_symbols) {
  std::string out;
  out.reserve(4096);
  out += "{\n";
  out += "  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
  out += "  \"tool\": \"donkey-cli\",\n";
  out += "  \"tool_version\": " + quote(version()) + ",\n";
  out += "  \"status\": " + quote(image.partial ? "Partial" : "Complete") + ",\n";
  out += "  \"file\": {\n";
  out += "    \"path\": " + quote(image.path) + ",\n";
  out += "    \"size\": " + std::to_string(image.file_size) + ",\n";
  out += "    \"sha256\": " + quote(image.sha256) + "\n";
  out += "  },\n";
  out += "  \"image\": {\n";
  out += "    \"format\": " + quote(format_name(image.format)) + ",\n";
  out += "    \"format_detail\": " + quote(image.format_detail) + ",\n";
  out += "    \"bits\": " + std::to_string(image.bits) + ",\n";
  out += "    \"endian\": " + quote(endian_name(image.endian)) + ",\n";
  out += "    \"architecture\": " + quote(architecture_name(image.architecture)) + ",\n";
  if (!image.fat_architectures.empty()) {
    out += "    \"fat_architectures\": [";
    for (std::size_t i = 0; i < image.fat_architectures.size(); ++i) {
      out += (i == 0 ? "" : ", ") + quote(architecture_name(image.fat_architectures[i]));
    }
    out += "],\n";
  }
  out += "    \"image_base\": " + quote(hex(image.image_base)) + ",\n";
  out += "    \"entry_point\": " +
         (image.has_entry_point() ? quote(hex(image.entry_point)) : std::string("null")) + "\n";
  out += "  },\n";

  out += "  \"segments\": [";
  for (std::size_t i = 0; i < image.segments.size(); ++i) {
    const auto& segment = image.segments[i];
    out += i == 0 ? "\n" : ",\n";
    out += "    {\"index\": " + std::to_string(segment.index) +
           ", \"name\": " + quote(segment.name) +
           ", \"virtual_address\": " + quote(hex(segment.virtual_address)) +
           ", \"virtual_size\": " + std::to_string(segment.virtual_size) +
           ", \"file_offset\": " + quote(hex(segment.file_offset)) +
           ", \"file_size\": " + std::to_string(segment.file_size) + ", \"permissions\": " +
           quote(permissions(segment.readable, segment.writable, segment.executable)) + "}";
  }
  out += image.segments.empty() ? "],\n" : "\n  ],\n";

  out += "  \"sections\": [";
  for (std::size_t i = 0; i < image.sections.size(); ++i) {
    const auto& section = image.sections[i];
    out += i == 0 ? "\n" : ",\n";
    out += "    {\"id\": " + std::to_string(section.id.value()) +
           ", \"name\": " + quote(section.name) + ", \"address\": " + quote(hex(section.address)) +
           ", \"virtual_size\": " + std::to_string(section.virtual_size) +
           ", \"file_offset\": " + quote(hex(section.file_offset)) +
           ", \"file_size\": " + std::to_string(section.file_size) + ", \"permissions\": " +
           quote(permissions(section.readable, section.writable, section.executable)) + "}";
  }
  out += image.sections.empty() ? "],\n" : "\n  ],\n";

  std::size_t imports = 0;
  std::size_t exports = 0;
  for (const auto& symbol : image.symbols) {
    imports += symbol.imported ? 1U : 0U;
    exports += symbol.exported ? 1U : 0U;
  }
  out += "  \"symbols\": {\"total\": " + std::to_string(image.symbols.size()) +
         ", \"imports\": " + std::to_string(imports) + ", \"exports\": " + std::to_string(exports) +
         ", \"items\": [";
  std::size_t written = 0;
  for (const auto& symbol : image.symbols) {
    if (!symbol.imported && !symbol.exported) {
      continue;
    }
    if (written >= max_symbols) {
      break;
    }
    out += written == 0 ? "\n" : ",\n";
    out += "    {\"kind\": " + quote(symbol.imported ? "import" : "export") +
           ", \"name\": " + quote(symbol.name) +
           ", \"demangled\": " + quote(demangled_name(symbol.name)) +
           ", \"module\": " + quote(symbol.module) +
           ", \"address\": " + quote(hex(symbol.address)) +
           ", \"size\": " + std::to_string(symbol.size) +
           ", \"binding\": " + quote(symbol_binding_name(symbol.binding)) + "}";
    ++written;
  }
  if (written == 0) {
    out += "], \"truncated\": false},\n";
  } else {
    out += "\n  ], \"truncated\": ";
    out += written < imports + exports ? "true" : "false";
    out += "},\n";
  }

  out += "  \"diagnostics\": [";
  for (std::size_t i = 0; i < image.diagnostics.size(); ++i) {
    const auto& diagnostic = image.diagnostics[i];
    out += i == 0 ? "\n" : ",\n";
    out += "    {\"status\": " + quote(status_name(diagnostic.status)) +
           ", \"code\": " + quote(diagnostic.code) + ", \"message\": " + quote(diagnostic.message) +
           "}";
  }
  out += image.diagnostics.empty() ? "]\n" : "\n  ]\n";
  out += "}\n";
  return out;
}

bool load(const std::string& path, LoadedBinary& loaded, const LoadOptions& options = {}) {
  auto result = load_binary(path, options);
  if (!result) {
    fail(result.diagnostic());
    return false;
  }
  loaded = std::move(result.value());
  return true;
}

std::string instruction_json(const Instruction& instruction) {
  std::string out =
      "{\"address\": " + quote(hex(instruction.address)) +
      ", \"bytes\": " + quote(instruction_bytes_hex(instruction)) +
      ", \"length\": " + std::to_string(instruction.length) +
      ", \"mnemonic\": " + quote(instruction.mnemonic) +
      ", \"operands\": " + quote(instruction.operands) +
      ", \"class\": " + quote(instruction_class_name(instruction.classification)) +
      ", \"target\": " +
      (instruction.direct_target.has_value() ? quote(hex(instruction.direct_target.value()))
                                             : std::string("null")) +
      "}";
  return out;
}

int command_disasm_run(const DisasmOptions& options) {
  LoadedBinary loaded;
  if (!load(options.path, loaded, options.load_options)) {
    return kExitFailure;
  }
  const BinaryImage& image = loaded.image;

  std::span<const std::byte> bytes;
  std::uint64_t start = 0;
  if (!options.section.empty()) {
    const Section* section = nullptr;
    for (const auto& candidate : image.sections) {
      if (candidate.name == options.section) {
        section = &candidate;
        break;
      }
    }
    if (section == nullptr) {
      std::fprintf(stderr, "donkey-cli: section '%s' not found\n", options.section.c_str());
      return kExitFailure;
    }
    if (!section->has_file_data) {
      std::fprintf(stderr, "donkey-cli: section '%s' has no file data\n", options.section.c_str());
      return kExitFailure;
    }
    start = options.address.value_or(section->address);
    if (!checked::in_range(section->file_offset, section->file_size, loaded.data.size())) {
      return usage_error("section is not backed by the file");
    }
    bytes = std::span<const std::byte>(loaded.data.data() + section->file_offset,
                                       static_cast<std::size_t>(section->file_size));
  } else {
    start = options.address.value_or(
        image.has_entry_point() ? image.entry_point
                                : (image.sections.empty() ? 0 : image.sections[0].address));
    if (start == 0 && !image.has_entry_point()) {
      return usage_error("no disassembly address available; pass --address");
    }
    auto offset = image.va_to_file_offset(start);
    if (!offset) {
      return fail(offset.diagnostic());
    }
    std::uint64_t available = loaded.data.size() - static_cast<std::size_t>(offset.value());
    // Stop at the end of the section that contains the start address so the
    // listing does not run into unrelated data after the code.
    if (const Section* section = image.section_for_va(start); section != nullptr) {
      if (section->has_file_data && section->file_size != 0 && start >= section->address &&
          start - section->address < section->file_size) {
        available = section->file_size - (start - section->address);
      }
    }
    bytes = std::span<const std::byte>(loaded.data.data() + offset.value(),
                                       static_cast<std::size_t>(available));
  }

  auto decoder = Decoder::create(image.architecture, image.endian);
  if (!decoder) {
    return fail(decoder.diagnostic());
  }
  auto stream = decoder.value().decode(bytes, start, options.count);
  if (!stream) {
    return fail(stream.diagnostic());
  }

  if (options.json) {
    std::string out;
    out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
    out += "  \"tool\": \"donkey-cli\",\n";
    out += "  \"tool_version\": " + quote(version()) + ",\n";
    out += "  \"architecture\": " + quote(architecture_name(image.architecture)) + ",\n";
    out += "  \"start\": " + quote(hex(start)) + ",\n";
    out += "  \"instruction_count\": " + std::to_string(stream.value().instructions.size()) + ",\n";
    out += "  \"truncated\": ";
    out += stream.value().truncated ? "true" : "false";
    out += ",\n  \"stop_reason\": " + quote(stream.value().stop_reason) + ",\n";
    out += "  \"instructions\": [";
    for (std::size_t i = 0; i < stream.value().instructions.size(); ++i) {
      out += i == 0 ? "\n" : ",\n";
      out += "    " + instruction_json(stream.value().instructions[i]);
    }
    out += stream.value().instructions.empty() ? "]\n" : "\n  ]\n";
    out += "}\n";
    std::fwrite(out.data(), 1, out.size(), stdout);
  } else {
    for (const auto& instruction : stream.value().instructions) {
      std::printf("  %-18s  %-32s  %s", hex(instruction.address).c_str(),
                  instruction_bytes_hex(instruction).c_str(), instruction.mnemonic.c_str());
      if (!instruction.operands.empty()) {
        std::printf(" %s", instruction.operands.c_str());
      }
      if (instruction.direct_target.has_value()) {
        std::printf("   ; -> %s", hex(instruction.direct_target.value()).c_str());
      }
      std::printf("\n");
    }
    if (stream.value().truncated) {
      std::printf("... stopped: %s\n", stream.value().stop_reason.c_str());
    }
  }
  return kExitOk;
}

int command_analysis(const AnalysisRequest& request, const std::string& mode) {
  LoadedBinary loaded;
  if (!load(request.path, loaded, request.load_options)) {
    return kExitFailure;
  }
  AnalysisOptions options;
  options.max_instructions = request.max_instructions;
  options.max_strings = request.max_strings;
  options.min_string_length = request.min_string_length;
  options.user_function_starts = request.function_starts;
  auto result = analyze(loaded.image, loaded.data, options);
  if (!result) {
    return fail(result.diagnostic());
  }
  const AnalysisResult& analysis = result.value();

  if (mode == "strings") {
    if (request.json) {
      std::string out;
      out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
      out += "  \"tool\": \"donkey-cli\",\n";
      out += "  \"tool_version\": " + quote(version()) + ",\n";
      out += "  \"count\": " + std::to_string(analysis.strings.size()) + ",\n";
      out += "  \"strings\": [";
      std::size_t written = 0;
      for (const auto& literal : analysis.strings) {
        if (written >= request.max_items) {
          break;
        }
        out += written == 0 ? "\n" : ",\n";
        out += "    {\"address\": " +
               (literal.mapped ? quote(hex(literal.address)) : std::string("null")) +
               ", \"file_offset\": " + quote(hex(literal.file_offset)) +
               ", \"encoding\": " + quote(literal.encoding) + ", \"text\": " + quote(literal.text) +
               "}";
        ++written;
      }
      out += written == 0 ? "]\n" : "\n  ]\n";
      out += "}\n";
      std::fwrite(out.data(), 1, out.size(), stdout);
    } else {
      for (const auto& literal : analysis.strings) {
        std::printf("%-18s %-10s %s\n",
                    literal.mapped ? hex(literal.address).c_str() : "<unmapped>",
                    literal.encoding.c_str(), literal.text.c_str());
      }
      std::printf("(%zu strings)\n", analysis.strings.size());
    }
    return kExitOk;
  }

  if (mode == "callgraph") {
    auto name_of = [&](std::uint64_t address) {
      for (const Function& function : analysis.functions) {
        if (function.address == address) {
          return function.name;
        }
      }
      return std::string();
    };
    const CallGraph& graph = analysis.call_graph;
    if (request.json) {
      std::string out;
      out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
      out += "  \"tool\": \"donkey-cli\",\n";
      out += "  \"tool_version\": " + quote(version()) + ",\n";
      out += "  \"partial\": " + std::string(analysis.cfg.partial ? "true" : "false") + ",\n";
      out += "  \"edges\": [";
      for (std::size_t i = 0; i < graph.edges.size(); ++i) {
        const CallGraphEdge& edge = graph.edges[i];
        out += i == 0 ? "\n" : ",\n";
        out += "    {\"caller\": " + quote(hex(edge.caller)) +
               ", \"caller_name\": " + quote(name_of(edge.caller)) +
               ", \"callee\": " + quote(hex(edge.callee)) +
               ", \"callee_name\": " + quote(name_of(edge.callee)) +
               ", \"site\": " + quote(hex(edge.site)) + "}";
      }
      out += graph.edges.empty() ? "],\n" : "\n  ],\n";
      out += "  \"unresolved\": [";
      for (std::size_t i = 0; i < graph.unresolved.size(); ++i) {
        out += i == 0 ? "\n" : ",\n";
        out += "    {\"caller\": " + quote(hex(graph.unresolved[i].caller)) +
               ", \"site\": " + quote(hex(graph.unresolved[i].site)) + "}";
      }
      out += graph.unresolved.empty() ? "],\n" : "\n  ],\n";
      out += "  \"orphan_sites\": " + std::to_string(graph.orphan_sites) + "\n}\n";
      std::fwrite(out.data(), 1, out.size(), stdout);
    } else {
      for (const CallGraphEdge& edge : graph.edges) {
        std::printf("%-18s %-28s -> %-18s %s (at %s)\n", hex(edge.caller).c_str(),
                    name_of(edge.caller).c_str(), hex(edge.callee).c_str(),
                    name_of(edge.callee).c_str(), hex(edge.site).c_str());
      }
      for (const auto& unresolved : graph.unresolved) {
        std::printf("%-18s %-28s -> <indirect>         (at %s)\n", hex(unresolved.caller).c_str(),
                    name_of(unresolved.caller).c_str(), hex(unresolved.site).c_str());
      }
      std::printf("(%zu direct calls, %zu indirect, %zu outside known functions)\n",
                  graph.edges.size(), graph.unresolved.size(), graph.orphan_sites);
    }
    return kExitOk;
  }

  if (mode == "functions") {
    if (request.json) {
      std::string out;
      out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
      out += "  \"tool\": \"donkey-cli\",\n";
      out += "  \"tool_version\": " + quote(version()) + ",\n";
      out += "  \"count\": " + std::to_string(analysis.functions.size()) + ",\n";
      out += "  \"functions\": [";
      for (std::size_t i = 0; i < analysis.functions.size(); ++i) {
        const auto& function = analysis.functions[i];
        out += i == 0 ? "\n" : ",\n";
        out += "    {\"id\": " + std::to_string(function.id.value()) +
               ", \"name\": " + quote(display_name(function.name)) +
               ", \"address\": " + quote(hex(function.address)) + ", \"end_address\": " +
               (function.has_extent ? quote(hex(function.end_address)) : std::string("null")) +
               ", \"size\": " +
               (function.has_extent ? std::to_string(function.end_address - function.address)
                                    : std::string("null")) +
               ", \"blocks\": " + std::to_string(function.block_count) +
               ", \"estimated\": " + (function.estimated ? "true" : "false") +
               ", \"exported\": " + (function.exported ? "true" : "false") +
               ", \"from_symbol\": " + (function.from_symbol ? "true" : "false") +
               ", \"from_unwind\": " + (function.from_unwind ? "true" : "false") + "}";
      }
      out += analysis.functions.empty() ? "]\n" : "\n  ]\n";
      out += "}\n";
      std::fwrite(out.data(), 1, out.size(), stdout);
    } else {
      for (const auto& function : analysis.functions) {
        const std::string size =
            function.has_extent ? std::to_string(function.end_address - function.address) + " B"
                                : std::string("? B");
        std::printf("%-18s %-10s %3u blocks  %s%s%s\n", hex(function.address).c_str(), size.c_str(),
                    function.block_count, display_name(function.name).c_str(),
                    function.exported ? " [export]" : "", function.estimated ? " [estimated]" : "");
      }
      std::printf("(%zu functions)\n", analysis.functions.size());
    }
    return kExitOk;
  }

  if (mode == "xrefs") {
    std::vector<const Xref*> selected;
    for (const auto& xref : analysis.xrefs) {
      if (!request.address.has_value() || xref.to == request.address.value() ||
          xref.from == request.address.value()) {
        selected.push_back(&xref);
      }
    }
    if (request.json) {
      std::string out;
      out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
      out += "  \"tool\": \"donkey-cli\",\n";
      out += "  \"tool_version\": " + quote(version()) + ",\n";
      out += "  \"count\": " + std::to_string(selected.size()) + ",\n";
      out += "  \"xrefs\": [";
      std::size_t written = 0;
      for (const Xref* xref : selected) {
        if (written >= request.max_items) {
          break;
        }
        out += written == 0 ? "\n" : ",\n";
        out += "    {\"from\": " + quote(hex(xref->from)) + ", \"to\": " + quote(hex(xref->to)) +
               ", \"kind\": " + quote(xref_kind_name(xref->kind)) + "}";
        ++written;
      }
      out += written == 0 ? "]\n" : "\n  ]\n";
      out += "}\n";
      std::fwrite(out.data(), 1, out.size(), stdout);
    } else {
      for (const Xref* xref : selected) {
        std::printf("%-18s -> %-18s %s\n", hex(xref->from).c_str(), hex(xref->to).c_str(),
                    xref_kind_name(xref->kind));
      }
      std::printf("(%zu xrefs)\n", selected.size());
    }
    return kExitOk;
  }

  // analyze: summary of the whole deterministic pass.
  if (request.json) {
    std::string out;
    out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
    out += "  \"tool\": \"donkey-cli\",\n";
    out += "  \"tool_version\": " + quote(version()) + ",\n";
    out += "  \"status\": " + quote(analysis.partial ? "Partial" : "Complete") + ",\n";
    out += "  \"architecture\": " + quote(architecture_name(analysis.architecture)) + ",\n";
    out += "  \"counts\": {\"instructions\": " + std::to_string(analysis.instructions.size()) +
           ", \"functions\": " + std::to_string(analysis.functions.size()) +
           ", \"xrefs\": " + std::to_string(analysis.xrefs.size()) +
           ", \"strings\": " + std::to_string(analysis.strings.size()) +
           ", \"blocks\": " + std::to_string(analysis.cfg.blocks.size()) +
           ", \"edges\": " + std::to_string(analysis.cfg.edges.size()) + "},\n";
    out += "  \"functions\": [";
    for (std::size_t i = 0; i < analysis.functions.size(); ++i) {
      const auto& function = analysis.functions[i];
      out += i == 0 ? "\n" : ",\n";
      out += "    {\"name\": " + quote(display_name(function.name)) +
             ", \"address\": " + quote(hex(function.address)) + ", \"end_address\": " +
             (function.has_extent ? quote(hex(function.end_address)) : std::string("null")) +
             ", \"blocks\": " + std::to_string(function.block_count) +
             ", \"estimated\": " + (function.estimated ? "true" : "false") +
             ", \"exported\": " + (function.exported ? "true" : "false") + "}";
    }
    out += analysis.functions.empty() ? "],\n" : "\n  ],\n";
    out += "  \"diagnostics\": [";
    for (std::size_t i = 0; i < analysis.diagnostics.size(); ++i) {
      const auto& diagnostic = analysis.diagnostics[i];
      out += i == 0 ? "\n" : ",\n";
      out += "    {\"status\": " + quote(status_name(diagnostic.status)) +
             ", \"code\": " + quote(diagnostic.code) +
             ", \"message\": " + quote(diagnostic.message) + "}";
    }
    out += analysis.diagnostics.empty() ? "]\n" : "\n  ]\n";
    out += "}\n";
    std::fwrite(out.data(), 1, out.size(), stdout);
  } else {
    std::printf("Status:       %s\n", analysis.partial ? "Partial" : "Complete");
    std::printf("Architecture: %s\n", architecture_name(analysis.architecture));
    std::printf("Instructions: %zu\n", analysis.instructions.size());
    std::printf("Functions:    %zu\n", analysis.functions.size());
    std::printf("Blocks:       %zu\n", analysis.cfg.blocks.size());
    std::printf("CFG edges:    %zu\n", analysis.cfg.edges.size());
    std::printf("Xrefs:        %zu\n", analysis.xrefs.size());
    std::printf("Strings:      %zu\n", analysis.strings.size());
    for (const auto& function : analysis.functions) {
      std::printf("  %-18s %s\n", hex(function.address).c_str(),
                  display_name(function.name).c_str());
    }
    if (!analysis.diagnostics.empty()) {
      std::printf("Diagnostics:\n");
      for (const auto& diagnostic : analysis.diagnostics) {
        std::printf("  [%s] %s\n", status_name(diagnostic.status), diagnostic.code.c_str());
      }
    }
  }
  return kExitOk;
}

}  // namespace

void print_usage(std::FILE* out) {
  std::fprintf(
      out,
      "donkey-cli %s - headless binary analysis\n"
      "\n"
      "Usage:\n"
      "  donkey-cli --version\n"
      "  donkey-cli --help\n"
      "  donkey-cli info <binary> [--json] [--max-symbols N]\n"
      "  donkey-cli disasm <binary> [--json] [--address A] [--count N]"
      " [--section NAME]\n"
      "  donkey-cli strings <binary> [--json] [--min-length N]"
      " [--max-strings N]\n"
      "  donkey-cli functions <binary> [--json] [--max-instructions N] [--function A]...\n"
      "  donkey-cli callgraph <binary> [--json] [--max-instructions N] [--function A]...\n"
      "  donkey-cli core <file> [--json]\n"
      "  donkey-cli debuginfo <binary> [--json] [--max-items N] [--debug-file PATH]\n"
      "  donkey-cli cfg <binary> [--json] [--function A] [--max-instructions N]\n"
      "  donkey-cli decompile <binary> [--json] [--function A] [--max-instructions N] "
      "[--max-functions N] [--project DB]\n"
      "  donkey-cli xrefs <binary> [--json] [--address A]\n"
      "  donkey-cli sig make <object.o|archive.a> --lib NAME --version V --license L --out FILE"
      " [--json]\n"
      "  donkey-cli link <executable> <library>... [--json]\n"
      "  donkey-cli project link <database> [--json]\n"
      "  donkey-cli project string <database> <image-id> <address> [--json]\n"
      "  donkey-cli analyze <binary> [--json] [--max-instructions N]\n"
      "  donkey-cli project save <database> <binary> [--json]\n"
      "  donkey-cli project info <database> [--json]\n"
      "  donkey-cli project rename <database> <image-id> <address> <text>|--clear\n"
      "  donkey-cli project comment <database> <image-id> <address> <text>|--clear\n"
      "  donkey-cli project bookmark <database> <image-id> <address> [<text>]|--clear\n"
      "  donkey-cli project annotations <database> <image-id> [--json]\n"
      "  donkey-cli project local-name <database> <image-id> <function> <variable> <name>|--clear\n"
      "  donkey-cli project local-names <database> <image-id> [--json]\n"
      "  donkey-cli project backup <database> <backup> [--force] [--json]\n"
      "  donkey-cli project restore <database> <backup> [--json]\n"
      "  donkey-cli debug launch <binary> [--arg A]... [--break SYMBOL|ADDR]... [--break-if "
      "SYMBOL|ADDR CONDITION]... [--watch "
      "SYMBOL|ADDR[:LEN][:rw]]... [--watch-if SYMBOL|ADDR[:LEN][:rw] CONDITION]... [--run]"
      " [--mock] [--json]\n"
      "  donkey-cli patch apply <binary> --offset <hex> --replacement <hex> [--original "
      "<hex>] --output <out> [--force] [--json]\n"
      "  donkey-cli plugin info <plugin-lib> [--json]\n"
      "  donkey-cli plugin run <plugin-lib> [--input <json>] [--isolate] [--caps "
      "<mask|name>] [--json]\n"
      "  donkey-cli serve [--project <db>] [--allow-write]\n"
      "                                   JSON-RPC 2.0 on stdin/stdout (see docs/RPC.md)\n"
      "  donkey-cli batch <script.json>   run a JSON array of RPC requests, print the responses\n"
      "\n"
      "Every command except `debug launch` only reads files and never executes them.\n"
      "`debug launch` runs the program under the native debugger (it stops at the\n"
      "entry point; --run continues through breakpoints and terminates the target\n"
      "when done).\n",
      std::string(version()).c_str());
}

int command_info(const std::vector<std::string_view>& arguments) {
  InfoOptions options;
  for (std::size_t i = 0; i < arguments.size(); ++i) {
    const std::string_view argument = arguments[i];
    const char* flag_error = nullptr;
    if (argument == "--json") {
      options.json = true;
    } else if (argument == "--max-symbols") {
      std::string_view value;
      if (!take_value(arguments, i, value)) {
        return usage_error("--max-symbols needs a value");
      }
      std::uint64_t parsed = 0;
      if (!parse_u64(value, parsed)) {
        return usage_error("invalid --max-symbols value");
      }
      options.max_symbols = static_cast<std::size_t>(parsed);
    } else if (try_parse_load_flag(arguments, i, options.load_options, flag_error)) {
      if (flag_error != nullptr) {
        return usage_error(flag_error);
      }
    } else if (!argument.empty() && argument.front() == '-') {
      return usage_error("unknown option for info");
    } else if (options.path.empty()) {
      options.path = std::string(argument);
    } else {
      return usage_error("info accepts exactly one file");
    }
  }
  if (options.path.empty()) {
    return usage_error("info needs a file path");
  }
  LoadedBinary loaded;
  if (!load(options.path, loaded, options.load_options)) {
    return kExitFailure;
  }
  if (options.json) {
    const std::string output = json_info(loaded.image, options.max_symbols);
    std::fwrite(output.data(), 1, output.size(), stdout);
  } else {
    print_human_info(loaded.image, options.max_symbols);
  }
  return kExitOk;
}

int command_disasm(const std::vector<std::string_view>& arguments) {
  DisasmOptions options;
  for (std::size_t i = 0; i < arguments.size(); ++i) {
    const std::string_view argument = arguments[i];
    const char* flag_error = nullptr;
    if (argument == "--json") {
      options.json = true;
    } else if (argument == "--address") {
      std::string_view value;
      if (!take_value(arguments, i, value)) {
        return usage_error("--address needs a value");
      }
      std::uint64_t parsed = 0;
      if (!parse_u64(value, parsed)) {
        return usage_error("invalid --address value");
      }
      options.address = parsed;
    } else if (argument == "--count") {
      std::string_view value;
      if (!take_value(arguments, i, value)) {
        return usage_error("--count needs a value");
      }
      std::uint64_t parsed = 0;
      if (!parse_u64(value, parsed) || parsed == 0 || parsed > kMaxDisassemblyCount) {
        return usage_error("invalid --count value");
      }
      options.count = static_cast<std::size_t>(parsed);
    } else if (argument == "--section") {
      std::string_view value;
      if (!take_value(arguments, i, value)) {
        return usage_error("--section needs a value");
      }
      options.section = std::string(value);
    } else if (try_parse_load_flag(arguments, i, options.load_options, flag_error)) {
      if (flag_error != nullptr) {
        return usage_error(flag_error);
      }
    } else if (!argument.empty() && argument.front() == '-') {
      return usage_error("unknown option for disasm");
    } else if (options.path.empty()) {
      options.path = std::string(argument);
    } else {
      return usage_error("disasm accepts exactly one file");
    }
  }
  if (options.path.empty()) {
    return usage_error("disasm needs a file path");
  }
  return command_disasm_run(options);
}

int command_strings(const std::vector<std::string_view>& arguments) {
  AnalysisRequest request;
  for (std::size_t i = 0; i < arguments.size(); ++i) {
    const std::string_view argument = arguments[i];
    const char* flag_error = nullptr;
    if (argument == "--json") {
      request.json = true;
    } else if (argument == "--min-length") {
      std::string_view value;
      if (!take_value(arguments, i, value)) {
        return usage_error("--min-length needs a value");
      }
      std::uint64_t parsed = 0;
      if (!parse_u64(value, parsed) || parsed == 0) {
        return usage_error("invalid --min-length value");
      }
      request.min_string_length = static_cast<std::size_t>(parsed);
    } else if (argument == "--max-strings") {
      std::string_view value;
      if (!take_value(arguments, i, value)) {
        return usage_error("--max-strings needs a value");
      }
      std::uint64_t parsed = 0;
      if (!parse_u64(value, parsed) || parsed == 0) {
        return usage_error("invalid --max-strings value");
      }
      request.max_strings = static_cast<std::size_t>(parsed);
    } else if (argument == "--max-instructions") {
      std::string_view value;
      if (!take_value(arguments, i, value)) {
        return usage_error("--max-instructions needs a value");
      }
      std::uint64_t parsed = 0;
      if (!parse_u64(value, parsed) || parsed == 0) {
        return usage_error("invalid --max-instructions value");
      }
      request.max_instructions = static_cast<std::size_t>(parsed);
    } else if (try_parse_load_flag(arguments, i, request.load_options, flag_error)) {
      if (flag_error != nullptr) {
        return usage_error(flag_error);
      }
    } else if (!argument.empty() && argument.front() == '-') {
      return usage_error("unknown option for strings");
    } else if (request.path.empty()) {
      request.path = std::string(argument);
    } else {
      return usage_error("strings accepts exactly one file");
    }
  }
  if (request.path.empty()) {
    return usage_error("strings needs a file path");
  }
  return command_analysis(request, "strings");
}

int command_functions(const std::vector<std::string_view>& arguments) {
  AnalysisRequest request;
  for (std::size_t i = 0; i < arguments.size(); ++i) {
    const std::string_view argument = arguments[i];
    const char* flag_error = nullptr;
    if (argument == "--json") {
      request.json = true;
    } else if (argument == "--max-instructions") {
      std::string_view value;
      if (!take_value(arguments, i, value)) {
        return usage_error("--max-instructions needs a value");
      }
      std::uint64_t parsed = 0;
      if (!parse_u64(value, parsed) || parsed == 0) {
        return usage_error("invalid --max-instructions value");
      }
      request.max_instructions = static_cast<std::size_t>(parsed);
    } else if (argument == "--function") {
      std::string_view value;
      std::uint64_t parsed = 0;
      if (!take_value(arguments, i, value) || !parse_u64(value, parsed)) {
        return usage_error("--function needs an address");
      }
      request.function_starts.push_back(parsed);
    } else if (try_parse_load_flag(arguments, i, request.load_options, flag_error)) {
      if (flag_error != nullptr) {
        return usage_error(flag_error);
      }
    } else if (!argument.empty() && argument.front() == '-') {
      return usage_error("unknown option for functions");
    } else if (request.path.empty()) {
      request.path = std::string(argument);
    } else {
      return usage_error("functions accepts exactly one file");
    }
  }
  if (request.path.empty()) {
    return usage_error("functions needs a file path");
  }
  return command_analysis(request, "functions");
}

int command_callgraph(const std::vector<std::string_view>& arguments) {
  AnalysisRequest request;
  for (std::size_t i = 0; i < arguments.size(); ++i) {
    const std::string_view argument = arguments[i];
    const char* flag_error = nullptr;
    if (argument == "--json") {
      request.json = true;
    } else if (argument == "--max-instructions") {
      std::string_view value;
      if (!take_value(arguments, i, value)) {
        return usage_error("--max-instructions needs a value");
      }
      std::uint64_t parsed = 0;
      if (!parse_u64(value, parsed) || parsed == 0) {
        return usage_error("invalid --max-instructions value");
      }
      request.max_instructions = static_cast<std::size_t>(parsed);
    } else if (argument == "--function") {
      std::string_view value;
      std::uint64_t parsed = 0;
      if (!take_value(arguments, i, value) || !parse_u64(value, parsed)) {
        return usage_error("--function needs an address");
      }
      request.function_starts.push_back(parsed);
    } else if (try_parse_load_flag(arguments, i, request.load_options, flag_error)) {
      if (flag_error != nullptr) {
        return usage_error(flag_error);
      }
    } else if (!argument.empty() && argument.front() == '-') {
      return usage_error("unknown option for callgraph");
    } else if (request.path.empty()) {
      request.path = std::string(argument);
    } else {
      return usage_error("callgraph accepts exactly one file");
    }
  }
  if (request.path.empty()) {
    return usage_error("callgraph needs a file path");
  }
  return command_analysis(request, "callgraph");
}

/// A Windows minidump (G15-T3): its architecture, exception, threads, modules and memory ranges.
int print_minidump(const LoadedBinary& loaded, bool json) {
  auto result = read_minidump(loaded.data.span());
  if (!result) {
    return fail(result.diagnostic());
  }
  const MinidumpInfo& dump = result.value();
  if (json) {
    std::string out = "{\n  \"format\": \"minidump\",\n";
    out += "  \"architecture\": " + quote(dump.architecture_name()) + ",\n";
    out += "  \"partial\": " + std::string(dump.partial ? "true" : "false") + ",\n";
    out += "  \"exception\": " +
           std::string(dump.has_exception
                           ? "{\"thread\": " + std::to_string(dump.exception.thread_id) +
                                 ", \"code\": " + quote(hex(dump.exception.code)) +
                                 ", \"address\": " + quote(hex(dump.exception.address)) + "}"
                           : "null") +
           ",\n";
    out += "  \"threads\": [";
    for (std::size_t i = 0; i < dump.threads.size(); ++i) {
      const MinidumpThread& thread = dump.threads[i];
      out += i == 0 ? "\n" : ",\n";
      out += "    {\"id\": " + std::to_string(thread.id) + ", \"pc\": " + quote(hex(thread.pc)) +
             ", \"sp\": " + quote(hex(thread.sp)) + "}";
    }
    out += "\n  ],\n  \"modules\": [";
    for (std::size_t i = 0; i < dump.modules.size(); ++i) {
      const MinidumpModule& module = dump.modules[i];
      out += i == 0 ? "\n" : ",\n";
      out += "    {\"base\": " + quote(hex(module.base)) +
             ", \"size\": " + std::to_string(module.size) + ", \"name\": " + quote(module.name) +
             "}";
    }
    out += "\n  ],\n  \"memory_ranges\": " + std::to_string(dump.memory.size()) + "\n}\n";
    std::fputs(out.c_str(), stdout);
    return kExitOk;
  }
  std::printf("minidump: %s, Windows %u.%u build %u%s\n", dump.architecture_name().c_str(),
              static_cast<unsigned>(dump.major_version), static_cast<unsigned>(dump.minor_version),
              static_cast<unsigned>(dump.build_number), dump.partial ? " (partial)" : "");
  if (dump.has_exception) {
    std::printf("exception %s in thread %u at %s\n", hex(dump.exception.code).c_str(),
                static_cast<unsigned>(dump.exception.thread_id),
                hex(dump.exception.address).c_str());
  }
  for (const MinidumpThread& thread : dump.threads) {
    std::printf("thread %u  pc %s  sp %s\n", static_cast<unsigned>(thread.id),
                hex(thread.pc).c_str(), hex(thread.sp).c_str());
  }
  for (const MinidumpModule& module : dump.modules) {
    std::printf("module %s %s %s\n", hex(module.base).c_str(), hex(module.size).c_str(),
                module.name.c_str());
  }
  std::printf("memory ranges: %zu\n", dump.memory.size());
  for (const Diagnostic& diagnostic : dump.diagnostics) {
    std::printf("note [%s]: %s\n", diagnostic.code.c_str(), diagnostic.message.c_str());
  }
  return kExitOk;
}

int command_core(const std::vector<std::string_view>& arguments) {
  std::string path;
  bool json = false;
  LoadOptions load_options;
  for (std::size_t i = 0; i < arguments.size(); ++i) {
    const std::string_view argument = arguments[i];
    const char* flag_error = nullptr;
    if (argument == "--json") {
      json = true;
    } else if (try_parse_load_flag(arguments, i, load_options, flag_error)) {
      if (flag_error != nullptr) {
        return usage_error(flag_error);
      }
    } else if (!argument.empty() && argument.front() == '-') {
      return usage_error("unknown option for core");
    } else if (path.empty()) {
      path = std::string(argument);
    } else {
      return usage_error("core accepts exactly one file");
    }
  }
  if (path.empty()) {
    return usage_error("core needs a file path");
  }
  LoadedBinary loaded;
  if (!load(path, loaded, load_options)) {
    return kExitFailure;
  }
  if (is_minidump(loaded.data.span())) {
    return print_minidump(loaded, json);
  }
  auto result = read_elf_core(loaded.image, loaded.data);
  if (!result) {
    return fail(result.diagnostic());
  }
  const CoreInfo& info = result.value();
  if (json) {
    std::string out = "{\n  \"process\": " + quote(info.process_name) + ",\n";
    out += "  \"partial\": " + std::string(info.partial ? "true" : "false") + ",\n";
    out += "  \"threads\": [";
    for (std::size_t i = 0; i < info.threads.size(); ++i) {
      const CoreThread& thread = info.threads[i];
      out += i == 0 ? "\n" : ",\n";
      out += "    {\"pid\": " + std::to_string(thread.pid) +
             ", \"signal\": " + std::to_string(thread.signal) +
             ", \"pc\": " + quote(hex(thread.pc)) + ", \"sp\": " + quote(hex(thread.sp)) + "}";
    }
    out += "\n  ],\n  \"mappings\": [";
    for (std::size_t i = 0; i < info.mappings.size(); ++i) {
      const CoreMapping& mapping = info.mappings[i];
      out += i == 0 ? "\n" : ",\n";
      out += "    {\"start\": " + quote(hex(mapping.start)) +
             ", \"end\": " + quote(hex(mapping.end)) +
             ", \"file_offset\": " + quote(hex(mapping.file_offset)) +
             ", \"path\": " + quote(mapping.path) + "}";
    }
    out += "\n  ]\n}\n";
    std::fputs(out.c_str(), stdout);
    return kExitOk;
  }
  std::printf("core of %s: %zu thread%s, %zu mapping%s%s\n", info.process_name.c_str(),
              info.threads.size(), info.threads.size() == 1 ? "" : "s", info.mappings.size(),
              info.mappings.size() == 1 ? "" : "s", info.partial ? " (partial)" : "");
  for (const CoreThread& thread : info.threads) {
    std::printf("thread %u  signal %d  pc %s  sp %s\n", static_cast<unsigned>(thread.pid),
                static_cast<int>(thread.signal), hex(thread.pc).c_str(), hex(thread.sp).c_str());
  }
  for (const CoreMapping& mapping : info.mappings) {
    std::printf("%s-%s  offset %s  %s\n", hex(mapping.start).c_str(), hex(mapping.end).c_str(),
                hex(mapping.file_offset).c_str(), mapping.path.c_str());
  }
  return kExitOk;
}

int command_debuginfo(const std::vector<std::string_view>& arguments) {
  std::string path;
  std::string debug_file;
  bool json = false;
  std::size_t max_items = 1000;
  LoadOptions load_options;
  for (std::size_t i = 0; i < arguments.size(); ++i) {
    const std::string_view argument = arguments[i];
    const char* flag_error = nullptr;
    if (argument == "--json") {
      json = true;
    } else if (argument == "--max-items") {
      std::string_view value;
      std::uint64_t parsed = 0;
      if (!take_value(arguments, i, value) || !parse_u64(value, parsed) || parsed == 0) {
        return usage_error("--max-items needs a positive value");
      }
      max_items = static_cast<std::size_t>(parsed);
    } else if (argument == "--debug-file") {
      std::string_view value;
      if (!take_value(arguments, i, value)) {
        return usage_error("--debug-file needs a path");
      }
      debug_file = std::string(value);
    } else if (try_parse_load_flag(arguments, i, load_options, flag_error)) {
      if (flag_error != nullptr) {
        return usage_error(flag_error);
      }
    } else if (!argument.empty() && argument.front() == '-') {
      return usage_error("unknown option for debuginfo");
    } else if (path.empty()) {
      path = std::string(argument);
    } else {
      return usage_error("debuginfo accepts exactly one file");
    }
  }
  if (path.empty()) {
    return usage_error("debuginfo needs a file path");
  }
  LoadedBinary loaded;
  if (!load(path, loaded, load_options)) {
    return kExitFailure;
  }
  auto result = read_debug_info(loaded.image, loaded.data);
  // A stripped binary keeps its debug information in a separate file, found by its build-id or
  // its debuglink (G07). That file is read in place of the binary's own sections.
  std::optional<LoadedBinary> separate;
  std::string separate_path;
  if (!debug_file.empty()) {
    // A file the user names is checked against the binary, and a mismatch is an error: it is
    // never used silently in place of the binary's own debug information.
    auto checked = check_separate_debug_file(loaded.image, loaded.data, debug_file);
    if (!checked) {
      return fail(checked.diagnostic());
    }
    auto opened = donkey::load_binary(checked.value());
    if (!opened) {
      return fail(opened.diagnostic());
    }
    separate_path = checked.value();
    separate = std::move(opened.value());
    result = read_debug_info(separate->image, separate->data);
  } else if (!result && result.diagnostic().code == "dwarf.not_present") {
    if (auto found = find_separate_debug_file(loaded.image, loaded.data, path)) {
      if (auto opened = donkey::load_binary(found.value())) {
        separate_path = found.value();
        separate = std::move(opened.value());
        result = read_debug_info(separate->image, separate->data);
      }
    }
  }
  if (!result) {
    return fail(result.diagnostic());
  }
  const DebugInfo& info = result.value();
  if (!separate_path.empty() && !json) {
    std::printf("separate debug file: %s\n", separate_path.c_str());
  }
  if (!json) {
    std::printf("DWARF %u-%u, %zu compile units, %zu functions, %zu variables, %zu types%s\n",
                static_cast<unsigned>(info.min_version), static_cast<unsigned>(info.max_version),
                info.compile_units, info.functions.size(), info.variables.size(), info.types.size(),
                info.partial ? " (partial)" : "");
    for (const std::string& producer : info.producers) {
      std::printf("producer: %s\n", producer.c_str());
    }
    std::size_t shown = 0;
    for (const DebugFunction& f : info.functions) {
      if (shown++ >= max_items) {
        break;
      }
      std::printf("%-18s %6llu B  %s", hex(f.address).c_str(),
                  static_cast<unsigned long long>(f.size), info.prototype(f).c_str());
      if (!f.file.empty()) {
        std::printf("  [%s:%u]", f.file.c_str(), f.line);
      }
      std::printf("  {%s}\n", f.provenance.label().c_str());
    }
    for (const DebugVariable& v : info.variables) {
      if (shown++ >= max_items) {
        break;
      }
      std::printf("%-18s var      %s %s  {%s}\n", hex(v.address).c_str(),
                  info.type_name(v.type).c_str(), v.name.c_str(), v.provenance.label().c_str());
    }
    for (const Diagnostic& d : info.diagnostics) {
      std::printf("diagnostic %s: %s\n", d.code.c_str(), d.message.c_str());
    }
    return kExitOk;
  }
  std::string out;
  out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
  out += "  \"tool\": \"donkey-cli\",\n";
  out += "  \"tool_version\": " + quote(version()) + ",\n";
  out += "  \"status\": " + quote(info.partial ? "Partial" : "Complete") + ",\n";
  out += "  \"format\": " + quote(info.format) + ",\n";
  out += "  \"versions\": [" + std::to_string(info.min_version) + ", " +
         std::to_string(info.max_version) + "],\n";
  out += "  \"compile_units\": " + std::to_string(info.compile_units) + ",\n";
  out += "  \"producers\": [";
  for (std::size_t i = 0; i < info.producers.size(); ++i) {
    out += (i == 0 ? "" : ", ") + quote(info.producers[i]);
  }
  out += "],\n  \"functions\": [";
  std::size_t written = 0;
  for (const DebugFunction& f : info.functions) {
    if (written >= max_items) {
      break;
    }
    out += written == 0 ? "\n" : ",\n";
    out += "    {\"address\": " + quote(hex(f.address)) + ", \"size\": " + std::to_string(f.size) +
           ", \"name\": " + quote(f.name) + ", \"prototype\": " + quote(info.prototype(f)) +
           ", \"return_type\": " + quote(info.type_name(f.return_type)) + ", \"parameters\": [";
    for (std::size_t p = 0; p < f.parameters.size(); ++p) {
      out += (p == 0 ? "" : ", ") + std::string("{\"name\": ") + quote(f.parameters[p].name) +
             ", \"type\": " + quote(info.type_name(f.parameters[p].type)) + "}";
    }
    out += "], \"file\": " + quote(f.file) + ", \"line\": " + std::to_string(f.line) +
           ", \"provenance\": " + quote(f.provenance.label()) + "}";
    ++written;
  }
  out += written == 0 ? "],\n" : "\n  ],\n";
  out += "  \"variables\": [";
  written = 0;
  for (const DebugVariable& v : info.variables) {
    if (written >= max_items) {
      break;
    }
    out += written == 0 ? "\n" : ",\n";
    out += "    {\"address\": " + quote(hex(v.address)) + ", \"name\": " + quote(v.name) +
           ", \"type\": " + quote(info.type_name(v.type)) +
           ", \"provenance\": " + quote(v.provenance.label()) + "}";
    ++written;
  }
  out += written == 0 ? "],\n" : "\n  ],\n";
  out += "  \"counts\": {\"functions\": " + std::to_string(info.functions.size()) +
         ", \"variables\": " + std::to_string(info.variables.size()) +
         ", \"types\": " + std::to_string(info.types.size()) + "},\n";
  out += "  \"diagnostics\": [";
  for (std::size_t i = 0; i < info.diagnostics.size(); ++i) {
    out += (i == 0 ? "" : ", ") + std::string("{\"code\": ") + quote(info.diagnostics[i].code) +
           ", \"message\": " + quote(info.diagnostics[i].message) + "}";
  }
  out += "]\n}\n";
  std::fwrite(out.data(), 1, out.size(), stdout);
  return kExitOk;
}

int command_xrefs(const std::vector<std::string_view>& arguments) {
  AnalysisRequest request;
  for (std::size_t i = 0; i < arguments.size(); ++i) {
    const std::string_view argument = arguments[i];
    const char* flag_error = nullptr;
    if (argument == "--json") {
      request.json = true;
    } else if (argument == "--address") {
      std::string_view value;
      if (!take_value(arguments, i, value)) {
        return usage_error("--address needs a value");
      }
      std::uint64_t parsed = 0;
      if (!parse_u64(value, parsed)) {
        return usage_error("invalid --address value");
      }
      request.address = parsed;
    } else if (argument == "--max-instructions") {
      std::string_view value;
      if (!take_value(arguments, i, value)) {
        return usage_error("--max-instructions needs a value");
      }
      std::uint64_t parsed = 0;
      if (!parse_u64(value, parsed) || parsed == 0) {
        return usage_error("invalid --max-instructions value");
      }
      request.max_instructions = static_cast<std::size_t>(parsed);
    } else if (try_parse_load_flag(arguments, i, request.load_options, flag_error)) {
      if (flag_error != nullptr) {
        return usage_error(flag_error);
      }
    } else if (!argument.empty() && argument.front() == '-') {
      return usage_error("unknown option for xrefs");
    } else if (request.path.empty()) {
      request.path = std::string(argument);
    } else {
      return usage_error("xrefs accepts exactly one file");
    }
  }
  if (request.path.empty()) {
    return usage_error("xrefs needs a file path");
  }
  return command_analysis(request, "xrefs");
}

int command_analyze(const std::vector<std::string_view>& arguments) {
  AnalysisRequest request;
  for (std::size_t i = 0; i < arguments.size(); ++i) {
    const std::string_view argument = arguments[i];
    const char* flag_error = nullptr;
    if (argument == "--json") {
      request.json = true;
    } else if (argument == "--max-instructions") {
      std::string_view value;
      if (!take_value(arguments, i, value)) {
        return usage_error("--max-instructions needs a value");
      }
      std::uint64_t parsed = 0;
      if (!parse_u64(value, parsed) || parsed == 0) {
        return usage_error("invalid --max-instructions value");
      }
      request.max_instructions = static_cast<std::size_t>(parsed);
    } else if (try_parse_load_flag(arguments, i, request.load_options, flag_error)) {
      if (flag_error != nullptr) {
        return usage_error(flag_error);
      }
    } else if (!argument.empty() && argument.front() == '-') {
      return usage_error("unknown option for analyze");
    } else if (request.path.empty()) {
      request.path = std::string(argument);
    } else {
      return usage_error("analyze accepts exactly one file");
    }
  }
  if (request.path.empty()) {
    return usage_error("analyze needs a file path");
  }
  return command_analysis(request, "analyze");
}

int command_cfg(const std::vector<std::string_view>& arguments) {
  AnalysisRequest request;
  for (std::size_t i = 0; i < arguments.size(); ++i) {
    const std::string_view argument = arguments[i];
    const char* flag_error = nullptr;
    if (argument == "--json") {
      request.json = true;
    } else if (argument == "--function") {
      std::string_view value;
      if (!take_value(arguments, i, value)) {
        return usage_error("--function needs an address");
      }
      std::uint64_t parsed = 0;
      if (!parse_u64(value, parsed)) {
        return usage_error("invalid --function address");
      }
      request.address = parsed;
    } else if (argument == "--max-instructions") {
      std::string_view value;
      if (!take_value(arguments, i, value)) {
        return usage_error("--max-instructions needs a value");
      }
      std::uint64_t parsed = 0;
      if (!parse_u64(value, parsed) || parsed == 0) {
        return usage_error("invalid --max-instructions value");
      }
      request.max_instructions = static_cast<std::size_t>(parsed);
    } else if (try_parse_load_flag(arguments, i, request.load_options, flag_error)) {
      if (flag_error != nullptr) {
        return usage_error(flag_error);
      }
    } else if (!argument.empty() && argument.front() == '-') {
      return usage_error("unknown option for cfg");
    } else if (request.path.empty()) {
      request.path = std::string(argument);
    } else {
      return usage_error("cfg accepts exactly one file");
    }
  }
  if (request.path.empty()) {
    return usage_error("cfg needs a file path");
  }

  LoadedBinary loaded;
  if (!load(request.path, loaded, request.load_options)) {
    return kExitFailure;
  }
  AnalysisOptions options;
  options.max_instructions = request.max_instructions;
  auto result = analyze(loaded.image, loaded.data, options);
  if (!result) {
    return fail(result.diagnostic());
  }
  const AnalysisResult& analysis = result.value();

  const Function* function = nullptr;
  if (request.address.has_value()) {
    for (const Function& candidate : analysis.functions) {
      if (candidate.address == request.address.value()) {
        function = &candidate;
        break;
      }
    }
    if (function == nullptr) {
      return fail(Diagnostic::make(Status::InvalidInput, "cli.unknown_function",
                                   "no function starts at the requested address",
                                   request.address.value()));
    }
  }

  auto function_of_block = [&](const BasicBlock& block) -> const Function* {
    for (const Function& candidate : analysis.functions) {
      if (candidate.id == block.function) {
        return &candidate;
      }
    }
    return nullptr;
  };

  if (request.json) {
    std::string out;
    out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
    out += "  \"tool\": \"donkey-cli\",\n";
    out += "  \"tool_version\": " + quote(version()) + ",\n";
    out += "  \"status\": " + quote(analysis.cfg.partial ? "Partial" : "Complete") + ",\n";
    out += "  \"blocks\": [";
    std::size_t written = 0;
    for (const BasicBlock& block : analysis.cfg.blocks) {
      if (function != nullptr && block.function != function->id) {
        continue;
      }
      const Function* owner = function_of_block(block);
      out += written == 0 ? "\n" : ",\n";
      out += "    {\"address\": " + quote(hex(block.address)) +
             ", \"end_address\": " + quote(hex(block.end_address)) +
             ", \"function\": " + quote(hex(owner != nullptr ? owner->address : 0)) +
             ", \"instructions\": " + std::to_string(block.instruction_count) + "}";
      ++written;
    }
    out += written == 0 ? "],\n" : "\n  ],\n";
    out += "  \"edges\": [";
    written = 0;
    for (const CfgEdge& edge : analysis.cfg.edges) {
      if (function != nullptr) {
        const BasicBlock* owner = nullptr;
        for (const BasicBlock& block : analysis.cfg.blocks) {
          if (edge.from >= block.address && edge.from < block.end_address) {
            owner = &block;
            break;
          }
        }
        if (owner == nullptr || owner->function != function->id) {
          continue;
        }
      }
      out += written == 0 ? "\n" : ",\n";
      out += "    {\"from\": " + quote(hex(edge.from)) +
             ", \"to\": " + (edge.to == 0 ? std::string("null") : quote(hex(edge.to))) +
             ", \"kind\": " + quote(cfg_edge_kind_name(edge.kind)) + "}";
      ++written;
    }
    out += written == 0 ? "]\n" : "\n  ]\n";
    out += "}\n";
    std::fwrite(out.data(), 1, out.size(), stdout);
    return kExitOk;
  }

  for (const Function& candidate : analysis.functions) {
    if (function != nullptr && candidate.id != function->id) {
      continue;
    }
    std::printf("%s  %s  blocks=%u  %s\n", hex(candidate.address).c_str(),
                display_name(candidate.name).c_str(), candidate.block_count,
                candidate.estimated ? "[estimated]" : "[complete]");
    for (const BasicBlock& block : analysis.cfg.blocks) {
      if (block.function != candidate.id) {
        continue;
      }
      std::printf("  block %s..%s (%u instructions)\n", hex(block.address).c_str(),
                  hex(block.end_address).c_str(), block.instruction_count);
    }
    for (const CfgEdge& edge : analysis.cfg.edges) {
      bool owned = false;
      for (const BasicBlock& block : analysis.cfg.blocks) {
        if (block.function == candidate.id && edge.from >= block.address &&
            edge.from < block.end_address) {
          owned = true;
          break;
        }
      }
      if (!owned) {
        continue;
      }
      std::printf("  %s -> %s  %s\n", hex(edge.from).c_str(),
                  edge.to == 0 ? "<indirect>" : hex(edge.to).c_str(),
                  cfg_edge_kind_name(edge.kind));
    }
  }
  return kExitOk;
}

int command_decompile(const std::vector<std::string_view>& arguments) {
  AnalysisRequest request;
  for (std::size_t i = 0; i < arguments.size(); ++i) {
    const std::string_view argument = arguments[i];
    const char* flag_error = nullptr;
    if (argument == "--json") {
      request.json = true;
    } else if (argument == "--function") {
      std::string_view value;
      if (!take_value(arguments, i, value)) {
        return usage_error("--function needs an address");
      }
      std::uint64_t parsed = 0;
      if (!parse_u64(value, parsed)) {
        return usage_error("invalid --function address");
      }
      request.address = parsed;
    } else if (argument == "--max-instructions") {
      std::string_view value;
      if (!take_value(arguments, i, value)) {
        return usage_error("--max-instructions needs a value");
      }
      std::uint64_t parsed = 0;
      if (!parse_u64(value, parsed) || parsed == 0) {
        return usage_error("invalid --max-instructions value");
      }
      request.max_instructions = static_cast<std::size_t>(parsed);
    } else if (argument == "--max-functions") {
      std::string_view value;
      std::uint64_t parsed = 0;
      if (!take_value(arguments, i, value) || !parse_u64(value, parsed) || parsed == 0) {
        return usage_error("--max-functions needs a positive value");
      }
      request.max_functions = static_cast<std::size_t>(parsed);
    } else if (argument == "--project") {
      std::string_view value;
      if (!take_value(arguments, i, value)) {
        return usage_error("--project needs a database path");
      }
      request.project_path = std::string(value);
    } else if (try_parse_load_flag(arguments, i, request.load_options, flag_error)) {
      if (flag_error != nullptr) {
        return usage_error(flag_error);
      }
    } else if (!argument.empty() && argument.front() == '-') {
      return usage_error("unknown option for decompile");
    } else if (request.path.empty()) {
      request.path = std::string(argument);
    } else {
      return usage_error("decompile accepts exactly one file");
    }
  }
  if (request.path.empty()) {
    return usage_error("decompile needs a file path");
  }

  LoadedBinary loaded;
  if (!load(request.path, loaded, request.load_options)) {
    return kExitFailure;
  }
  AnalysisOptions options;
  options.max_instructions = request.max_instructions;
  auto analysis = analyze(loaded.image, loaded.data, options);
  if (!analysis) {
    return fail(analysis.diagnostic());
  }

  std::vector<const Function*> selected;
  if (request.address.has_value()) {
    for (const Function& function : analysis.value().functions) {
      if (function.address == request.address.value()) {
        selected.push_back(&function);
        break;
      }
    }
    if (selected.empty()) {
      return fail(Diagnostic::make(Status::InvalidInput, "cli.unknown_function",
                                   "no function starts at the requested address",
                                   request.address.value()));
    }
  } else {
    for (const Function& function : analysis.value().functions) {
      selected.push_back(&function);
    }
  }

  // The local names the project saved for this binary (G12-T3). They are applied after the debug
  // names, so a user name wins.
  std::map<std::uint64_t, std::vector<UserLocalName>> user_names;
  // The strings the project defines, as the literals the pseudocode prints (G12-T2).
  PseudocodeOptions pseudo_options;
  if (!request.project_path.empty()) {
    auto project = Project::open(request.project_path);
    if (!project) {
      return fail(project.diagnostic());
    }
    auto images = project.value().images();
    if (!images) {
      return fail(images.diagnostic());
    }
    std::optional<std::int64_t> image_id;
    for (const ProjectImage& image : images.value()) {
      if (image.sha256 == loaded.image.sha256) {
        image_id = image.id;
        break;
      }
    }
    if (!image_id) {
      return fail(Diagnostic::make(
          Status::InvalidInput, "cli.project_image_missing",
          "the project has no image of this binary; save it with project save first"));
    }
    auto names = project.value().local_names(*image_id);
    if (!names) {
      return fail(names.diagnostic());
    }
    for (const LocalName& entry : names.value()) {
      user_names[entry.function_address].push_back(UserLocalName{entry.variable, entry.name});
    }
    auto rows = project.value().annotations(*image_id);
    if (!rows) {
      return fail(rows.diagnostic());
    }
    pseudo_options.string_literals = string_literals(rows.value(), loaded.image, loaded.data);
  }

  // The DWARF of the binary, when it has any, names the parameters and the frame slots of
  // each function (G04-T4). Naming is display-only and changes no statement.
  std::optional<DebugInfo> debug;
  if (auto read = read_debug_info(loaded.image, loaded.data); read.has_value()) {
    debug = std::move(read.value());
  }
  auto lift_named = [&](const Function& function) {
    auto lifted = lift_function(loaded.image, analysis.value(), function);
    if (lifted && debug) {
      if (const DebugFunction* named = debug->function_at(function.address)) {
        (void)apply_debug_parameter_names(lifted.value(), *named, *debug);
        (void)apply_debug_stack_names(lifted.value(), *named, *debug);
      }
    }
    if (lifted) {
      if (const auto found = user_names.find(function.address); found != user_names.end()) {
        auto applied = apply_user_local_names(lifted.value(), found->second);
        if (!applied) {
          return make_error<IrFunction>(applied.diagnostic().status, applied.diagnostic().code,
                                        applied.diagnostic().message);
        }
      }
    }
    return lifted;
  };
  // A name the decompiler refuses fails the command before any output, instead of showing up as
  // an unsupported function.
  for (const Function* function : selected) {
    if (user_names.count(function->address) == 0) {
      continue;
    }
    auto checked = lift_named(*function);
    if (!checked && checked.diagnostic().code.rfind("ir.local_", 0) == 0) {
      return fail(checked.diagnostic());
    }
  }
  if (request.json) {
    std::string out;
    out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
    out += "  \"tool\": \"donkey-cli\",\n";
    out += "  \"tool_version\": " + quote(version()) + ",\n";
    // The cap is stated, never silent: total_functions counts every function of the binary that
    // this run selected, shown_functions the ones printed below.
    const std::size_t shown = std::min(selected.size(), request.max_functions);
    out += "  \"total_functions\": " + std::to_string(selected.size()) + ",\n";
    out += "  \"shown_functions\": " + std::to_string(shown) + ",\n";
    out += "  \"max_functions\": " + std::to_string(request.max_functions) + ",\n";
    out += std::string("  \"truncated\": ") + (shown < selected.size() ? "true" : "false") + ",\n";
    out += "  \"functions\": [";
    std::size_t written = 0;
    for (const Function* function : selected) {
      if (written >= request.max_functions) {
        break;
      }
      auto lifted = lift_named(*function);
      out += written == 0 ? "\n" : ",\n";
      if (!lifted) {
        out += "    {\"address\": " + quote(hex(function->address)) +
               ", \"name\": " + quote(display_name(function->name)) +
               ", \"status\": \"Unsupported\", \"code\": " + quote(lifted.diagnostic().code) +
               ", \"pseudocode\": null}";
        ++written;
        continue;
      }
      auto pseudo_res = format_pseudocode_lines(lifted.value(), pseudo_options);
      if (!pseudo_res) {
        out += "    {\"address\": " + quote(hex(function->address)) +
               ", \"name\": " + quote(display_name(function->name)) +
               ", \"status\": \"InvalidIR\", \"code\": " + quote(pseudo_res.diagnostic().code) +
               ", \"pseudocode\": null}";
        ++written;
        continue;
      }
      const Pseudocode& pc = pseudo_res.value();
      out += "    {\"address\": " + quote(hex(function->address)) +
             ", \"name\": " + quote(display_name(function->name)) +
             ", \"status\": " + quote(lifted.value().partial ? "Partial" : "Complete") +
             ", \"blocks\": " + std::to_string(lifted.value().blocks.size()) +
             ", \"pseudocode\": " + quote(pc.full_text) + ", \"source_map\": [";
      for (std::size_t li = 0; li < pc.lines.size(); ++li) {
        out += li == 0 ? "\n" : ",\n";
        out +=
            "        {\"line\": " + std::to_string(li + 1) +
            ", \"text\": " + quote(pc.lines[li].text) + ", \"source_address\": " +
            (pc.lines[li].source_address != 0 ? quote(hex(pc.lines[li].source_address)) : "null") +
            "}";
      }
      out += pc.lines.empty() ? "]}" : "\n      ]}";
      ++written;
    }
    out += written == 0 ? "]\n" : "\n  ]\n";
    out += "}\n";
    std::fwrite(out.data(), 1, out.size(), stdout);
    return kExitOk;
  }

  const std::size_t text_shown = std::min(selected.size(), request.max_functions);
  bool first = true;
  for (std::size_t index = 0; index < text_shown; ++index) {
    const Function* function = selected[index];
    if (!first) {
      std::printf("\n");
    }
    first = false;
    auto lifted = lift_named(*function);
    if (!lifted) {
      std::printf("// %s: unsupported (%s)\n", display_name(function->name).c_str(),
                  lifted.diagnostic().code.c_str());
      continue;
    }
    auto text = format_pseudocode(lifted.value(), pseudo_options);
    if (!text) {
      std::printf("// %s: rejected IR (%s: %s)\n", display_name(function->name).c_str(),
                  text.diagnostic().code.c_str(), text.diagnostic().message.c_str());
      continue;
    }
    std::fwrite(text.value().data(), 1, text.value().size(), stdout);
  }
  if (text_shown < selected.size()) {
    std::printf(
        "\n// truncated: showing %zu of %zu functions; raise the limit with "
        "--max-functions N\n",
        text_shown, selected.size());
  }
  return kExitOk;
}

namespace {

/// `project type add|list|apply`: the C types a project holds, and which address each
/// applies to (G05-T4). The declarations are read from a C header of the supported subset.
int command_project_type(const std::vector<std::string_view>& positional, bool json) {
  if (positional.empty()) {
    return usage_error("project type needs a subcommand: add, list or apply");
  }
  const std::string_view action = positional[0];
  const std::vector<std::string_view> rest(positional.begin() + 1, positional.end());

  if (action == "add") {
    if (rest.size() != 2) {
      return usage_error("project type add needs a database and a C declarations file");
    }
    const std::string database(rest[0]);
    const std::string path(rest[1]);
    std::ifstream file(path, std::ios::binary);
    if (!file) {
      return usage_error("cannot open the declarations file");
    }
    // Read at most one byte past the limit, so an oversized file is reported as such.
    std::string text;
    char buffer[4096];
    while (file && text.size() <= donkey::kMaxCDeclarationBytes) {
      file.read(buffer, sizeof(buffer));
      text.append(buffer, static_cast<std::size_t>(file.gcount()));
    }
    auto project = Project::open(database);
    if (!project) {
      return fail(project.diagnostic());
    }
    auto known = project.value().types();
    if (!known) {
      return fail(known.diagnostic());
    }
    auto declared = donkey::parse_c_declarations(text, known.value());
    if (!declared) {
      return fail(declared.diagnostic());
    }
    donkey::TypeTable table = known.value();
    for (const donkey::TypeDefinition& definition : declared.value()) {
      table.put(definition);
    }
    auto saved = project.value().replace_types(table);
    if (!saved) {
      return fail(saved.diagnostic());
    }
    if (json) {
      std::string out;
      out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
      out += "  \"tool\": \"donkey-cli\",\n";
      out += "  \"tool_version\": " + quote(version()) + ",\n";
      out += "  \"database\": " + quote(database) + ",\n";
      out += "  \"declarations\": " + quote(path) + ",\n";
      out += "  \"added\": " + std::to_string(declared.value().size()) + "\n}\n";
      std::fwrite(out.data(), 1, out.size(), stdout);
    } else {
      std::printf("Added %zu types from %s\n", declared.value().size(), path.c_str());
    }
    return kExitOk;
  }

  if (action == "list") {
    if (rest.size() != 1) {
      return usage_error("project type list needs a database");
    }
    const std::string database(rest[0]);
    auto project = Project::open(database);
    if (!project) {
      return fail(project.diagnostic());
    }
    auto table = project.value().types();
    if (!table) {
      return fail(table.diagnostic());
    }
    const std::vector<donkey::TypeDefinition> types = table.value().list();
    if (json) {
      std::string out;
      out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
      out += "  \"tool\": \"donkey-cli\",\n";
      out += "  \"tool_version\": " + quote(version()) + ",\n";
      out += "  \"database\": " + quote(database) + ",\n";
      out += "  \"types\": [";
      for (std::size_t i = 0; i < types.size(); ++i) {
        const donkey::TypeDefinition& type = types[i];
        out += i == 0 ? "\n" : ",\n";
        out += "    {\"id\": " + std::to_string(type.id.value()) +
               ", \"kind\": " + quote(donkey::type_kind_name(type.kind)) +
               ", \"name\": " + quote(type.name) + ", \"size\": " + std::to_string(type.size) +
               ", \"provenance\": " + quote(donkey::type_provenance_name(type.provenance)) + "}";
      }
      out += types.empty() ? "]\n" : "\n  ]\n";
      out += "}\n";
      std::fwrite(out.data(), 1, out.size(), stdout);
    } else {
      std::printf("%zu types\n", types.size());
      for (const donkey::TypeDefinition& type : types) {
        std::printf("  #%-5llu %-9s %-20s %llu bytes\n",
                    static_cast<unsigned long long>(type.id.value()),
                    donkey::type_kind_name(type.kind), type.name.c_str(),
                    static_cast<unsigned long long>(type.size));
      }
    }
    return kExitOk;
  }

  if (action == "apply") {
    if (rest.size() != 4) {
      return usage_error(
          "project type apply needs a database, an image id, an address and a type name");
    }
    const std::string database(rest[0]);
    std::uint64_t image_id = 0;
    if (!parse_u64(rest[1], image_id) || image_id == 0 ||
        image_id > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
      return usage_error("invalid image id");
    }
    std::uint64_t address = 0;
    if (!parse_u64(rest[2], address)) {
      return usage_error("invalid address");
    }
    const std::string name(rest[3]);
    auto project = Project::open(database);
    if (!project) {
      return fail(project.diagnostic());
    }
    auto table = project.value().types();
    if (!table) {
      return fail(table.diagnostic());
    }
    // The first type with that name. A function type applies as a prototype; any other
    // type applies to a data slot.
    const std::vector<donkey::TypeDefinition> types = table.value().list();
    const donkey::TypeDefinition* chosen = nullptr;
    for (const donkey::TypeDefinition& type : types) {
      if (type.name == name) {
        chosen = &type;
        break;
      }
    }
    if (chosen == nullptr) {
      return usage_error("no type with that name in the project");
    }
    const donkey::TypeApplicationKind kind = chosen->kind == donkey::TypeKind::Function
                                                 ? donkey::TypeApplicationKind::FunctionPrototype
                                                 : donkey::TypeApplicationKind::DataSlot;
    auto applied = project.value().set_type_application(static_cast<std::int64_t>(image_id), kind,
                                                        address, chosen->id);
    if (!applied) {
      return fail(applied.diagnostic());
    }
    if (json) {
      std::string out;
      out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
      out += "  \"tool\": \"donkey-cli\",\n";
      out += "  \"tool_version\": " + quote(version()) + ",\n";
      out += "  \"database\": " + quote(database) + ",\n";
      out += "  \"image_id\": " + std::to_string(image_id) + ",\n";
      out += "  \"address\": " + quote(hex(address)) + ",\n";
      out += "  \"type\": " + quote(name) + ",\n";
      out += "  \"applied_as\": " +
             quote(kind == donkey::TypeApplicationKind::FunctionPrototype ? "prototype" : "data") +
             "\n}\n";
      std::fwrite(out.data(), 1, out.size(), stdout);
    } else {
      std::printf("Applied %s to %s in image %llu\n", name.c_str(), hex(address).c_str(),
                  static_cast<unsigned long long>(image_id));
    }
    return kExitOk;
  }

  return usage_error("project type needs a subcommand: add, list or apply");
}

}  // namespace

namespace {

/// A member mode in the octal form that `ar tv` and `ls` use, such as "644".
std::string octal_mode(std::uint32_t mode) {
  char buffer[16];
  std::snprintf(buffer, sizeof(buffer), "%o", static_cast<unsigned>(mode));
  return buffer;
}

}  // namespace

int command_sig(const std::vector<std::string_view>& arguments) {
  if (arguments.empty() || arguments[0] != "make") {
    return usage_error("sig needs a subcommand: make");
  }
  std::string path;
  std::string out;
  donkey::SignatureGenOptions options;
  bool json = false;
  for (std::size_t i = 1; i < arguments.size(); ++i) {
    const std::string_view arg = arguments[i];
    if (arg == "--json") {
      json = true;
    } else if (arg == "--lib" || arg == "--version" || arg == "--license" || arg == "--out") {
      std::string_view value;
      if (!take_value(arguments, i, value)) {
        return usage_error("sig make: each of --lib, --version, --license and --out needs a value");
      }
      if (arg == "--lib") {
        options.library = std::string(value);
      } else if (arg == "--version") {
        options.version = std::string(value);
      } else if (arg == "--license") {
        options.license = std::string(value);
      } else {
        out = std::string(value);
      }
    } else if (!arg.empty() && arg.front() == '-') {
      return usage_error("unknown option for sig make");
    } else if (path.empty()) {
      path = std::string(arg);
    } else {
      return usage_error("sig make takes one object or archive file");
    }
  }
  if (path.empty() || out.empty()) {
    return usage_error("sig make needs an object or archive file and --out FILE");
  }
  // Objects and archives are read whole; the limit keeps a huge file from exhausting memory.
  constexpr std::uintmax_t kMaxInputBytes = std::uintmax_t{1} << 30;
  std::error_code size_error;
  const std::uintmax_t size = std::filesystem::file_size(path, size_error);
  if (size_error) {
    return usage_error("cannot open the object or archive file");
  }
  if (size > kMaxInputBytes) {
    return usage_error("the object or archive file is larger than 1 GiB");
  }
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    return usage_error("cannot open the object or archive file");
  }
  std::vector<std::byte> bytes;
  bytes.reserve(static_cast<std::size_t>(size));
  std::vector<char> buffer(1 << 20);
  while (file) {
    file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    const auto count = static_cast<std::size_t>(file.gcount());
    for (std::size_t i = 0; i < count; ++i) {
      bytes.push_back(static_cast<std::byte>(buffer[i]));
    }
  }

  auto generated = donkey::generate_signatures(bytes, options);
  if (!generated) {
    return fail(generated.diagnostic());
  }
  const donkey::SignatureGenResult& result = generated.value();
  std::ofstream written(out, std::ios::binary | std::ios::trunc);
  if (!written) {
    return fail(Diagnostic{Status::InvalidInput, "sig.write", "cannot write the signature file",
                           std::nullopt});
  }
  written << donkey::write_signature_set(result.set) << '\n';
  if (!written) {
    return fail(Diagnostic{Status::InvalidInput, "sig.write", "cannot write the signature file",
                           std::nullopt});
  }
  if (json) {
    std::string text = "{\n";
    text += "  \"library\": " + quote(result.set.library) + ",\n";
    text += "  \"version\": " + quote(result.set.version) + ",\n";
    text += "  \"signatures\": " + std::to_string(result.set.signatures.size()) + ",\n";
    text += "  \"functions\": " + std::to_string(result.functions) + ",\n";
    text += "  \"skipped\": " + std::to_string(result.skipped) + ",\n";
    text += std::string("  \"partial\": ") + (result.partial ? "true" : "false") + ",\n";
    text += "  \"out\": " + quote(out) + "\n}\n";
    std::fwrite(text.data(), 1, text.size(), stdout);
    return kExitOk;
  }
  std::printf("wrote %zu signatures for %s %s to %s (%zu functions, %zu skipped)\n",
              result.set.signatures.size(), result.set.library.c_str(), result.set.version.c_str(),
              out.c_str(), result.functions, result.skipped);
  for (const std::string& note : result.notes) {
    std::printf("  note: %s\n", note.c_str());
  }
  if (result.partial) {
    std::printf("  note: reading stopped early, so the set may be incomplete\n");
  }
  return kExitOk;
}

int command_archive(const std::vector<std::string_view>& arguments) {
  if (arguments.empty()) {
    return usage_error("archive needs a subcommand: list");
  }
  if (arguments[0] != "list") {
    return usage_error("unknown archive subcommand (expected list)");
  }
  bool json = false;
  std::vector<std::string_view> positional;
  for (std::size_t i = 1; i < arguments.size(); ++i) {
    if (arguments[i] == "--json") {
      json = true;
    } else if (!arguments[i].empty() && arguments[i].front() == '-') {
      return usage_error("unknown option for archive list");
    } else {
      positional.push_back(arguments[i]);
    }
  }
  if (positional.size() != 1) {
    return usage_error("archive list needs one archive file");
  }
  const std::string path(positional[0]);
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    return usage_error("cannot open the archive file");
  }
  // Archives are read whole here; the limit keeps a huge file from exhausting memory.
  constexpr std::uintmax_t kMaxArchiveFileBytes = std::uintmax_t{1} << 30;
  std::vector<std::byte> bytes;
  std::vector<char> buffer(1 << 20);
  while (file) {
    file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    const auto count = static_cast<std::size_t>(file.gcount());
    bytes.insert(bytes.end(), reinterpret_cast<const std::byte*>(buffer.data()),
                 reinterpret_cast<const std::byte*>(buffer.data()) + count);
    if (bytes.size() > kMaxArchiveFileBytes) {
      std::fprintf(stderr, "error [archive.too_large]: the file is larger than 1 GiB\n");
      return kExitFailure;
    }
  }
  auto index = donkey::read_archive(bytes);
  if (!index) {
    return fail(index.diagnostic());
  }
  const std::vector<donkey::ArchiveMember>& members = index.value().members;
  if (json) {
    std::string out;
    out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
    out += "  \"tool\": \"donkey-cli\",\n";
    out += "  \"tool_version\": " + quote(version()) + ",\n";
    out += "  \"file\": " + quote(path) + ",\n";
    out += "  \"partial\": " + std::string(index.value().partial ? "true" : "false") + ",\n";
    out += "  \"note\": " + quote(index.value().note) + ",\n";
    out += "  \"members\": [";
    for (std::size_t i = 0; i < members.size(); ++i) {
      const donkey::ArchiveMember& member = members[i];
      out += i == 0 ? "\n" : ",\n";
      out += "    {\"name\": " + quote(member.name) +
             ", \"kind\": " + quote(donkey::archive_member_kind_name(member.kind)) +
             ", \"offset\": " + quote(hex(member.offset)) +
             ", \"size\": " + std::to_string(member.size) +
             ", \"modified\": " + std::to_string(member.modified) +
             ", \"mode\": " + quote(octal_mode(member.mode)) + "}";
    }
    out += members.empty() ? "]\n" : "\n  ]\n";
    out += "}\n";
    std::fwrite(out.data(), 1, out.size(), stdout);
  } else {
    std::printf("%zu members%s\n", members.size(),
                index.value().partial ? (" (partial: " + index.value().note + ")").c_str() : "");
    for (const donkey::ArchiveMember& member : members) {
      std::printf("  %-18s %10llu  %-12s %s\n", hex(member.offset).c_str(),
                  static_cast<unsigned long long>(member.size),
                  donkey::archive_member_kind_name(member.kind), member.name.c_str());
    }
  }
  return kExitOk;
}

namespace {

/// The link report of `loaded` images in link order, each labelled by `labels`. Imports are bound
/// by name and library. Each image is analysed, so a call through a PLT stub is bound to the export
/// the link chose for that import (G15-T2).
int report_link(const std::vector<std::string>& labels,
                const std::vector<donkey::LoadedBinary>& loaded, bool json) {
  std::vector<donkey::LinkInput> inputs;
  inputs.reserve(loaded.size());
  for (const donkey::LoadedBinary& item : loaded) {
    inputs.push_back({&item.image, item.data});
  }
  const donkey::LinkResult result = donkey::resolve_imports(inputs);
  // Each image is analysed for its call sites, so a call through a PLT stub can be bound to the
  // export the link chose for that import.
  std::vector<donkey::AnalysisResult> analyses;
  analyses.reserve(loaded.size());
  bool partial = false;
  for (const donkey::LoadedBinary& item : loaded) {
    auto analysis = donkey::analyze(item.image, item.data);
    if (!analysis) {
      return fail(analysis.diagnostic());
    }
    partial = partial || analysis.value().partial;
    analyses.push_back(std::move(analysis.value()));
  }
  auto resolved = donkey::resolve_import_calls(inputs, result, analyses);
  if (!resolved) {
    return fail(resolved.diagnostic());
  }
  const std::vector<donkey::ImportCall>& calls = resolved.value();
  std::size_t unbound_calls = 0;
  for (const donkey::ImportCall& call : calls) {
    if (call.provider == donkey::kUnboundImport) {
      ++unbound_calls;
    }
  }
  if (json) {
    std::string out;
    out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
    out += "  \"tool\": \"donkey-cli\",\n";
    out += "  \"tool_version\": " + quote(version()) + ",\n";
    out += "  \"inputs\": [";
    for (std::size_t i = 0; i < labels.size(); ++i) {
      out += (i == 0 ? "" : ", ") + quote(std::string(labels[i]));
    }
    out += "],\n";
    out += "  \"unbound\": " + std::to_string(result.unbound) + ",\n";
    out += "  \"bindings\": [";
    for (std::size_t i = 0; i < result.bindings.size(); ++i) {
      const donkey::ImportBinding& binding = result.bindings[i];
      const bool bound = binding.provider != donkey::kUnboundImport;
      out += i == 0 ? "\n" : ",\n";
      out += "    {\"importer\": " + quote(labels[binding.importer]) +
             ", \"name\": " + quote(binding.name) +
             ", \"provider\": " + (bound ? quote(labels[binding.provider]) : std::string("null")) +
             ", \"library\": " + quote(binding.library) +
             ", \"address\": " + (bound ? quote(hex(binding.address)) : std::string("null")) + "}";
    }
    out += result.bindings.empty() ? "],\n" : "\n  ],\n";
    out += "  \"partial\": " + std::string(partial ? "true" : "false") + ",\n";
    out += "  \"unbound_calls\": " + std::to_string(unbound_calls) + ",\n";
    out += "  \"calls\": [";
    for (std::size_t i = 0; i < calls.size(); ++i) {
      const donkey::ImportCall& call = calls[i];
      const bool bound = call.provider != donkey::kUnboundImport;
      out += i == 0 ? "\n" : ",\n";
      out += "    {\"importer\": " + quote(labels[call.importer]) +
             ", \"from\": " + quote(hex(call.from)) +
             ", \"kind\": " + quote(donkey::xref_kind_name(call.kind)) +
             ", \"stub\": " + quote(hex(call.stub)) + ", \"name\": " + quote(call.name) +
             ", \"provider\": " + (bound ? quote(labels[call.provider]) : std::string("null")) +
             ", \"to\": " + (bound ? quote(hex(call.to)) : std::string("null")) + "}";
    }
    out += calls.empty() ? "]\n" : "\n  ]\n";
    out += "}\n";
    std::fwrite(out.data(), 1, out.size(), stdout);
  } else {
    std::printf("%zu imports, %zu unbound\n", result.bindings.size(), result.unbound);
    for (const donkey::ImportBinding& binding : result.bindings) {
      const std::string& importer = labels[binding.importer];
      if (binding.provider == donkey::kUnboundImport) {
        std::printf("  %s: %s is not exported by any input\n", importer.c_str(),
                    binding.name.c_str());
      } else {
        std::printf("  %s: %s from %s at %s\n", importer.c_str(), binding.name.c_str(),
                    binding.library.c_str(), hex(binding.address).c_str());
      }
    }
    std::printf("%zu calls through PLT stubs or GOT slots, %zu to imports no input exports\n",
                calls.size(), unbound_calls);
    for (const donkey::ImportCall& call : calls) {
      const std::string& importer = labels[call.importer];
      if (call.provider == donkey::kUnboundImport) {
        std::printf("  %s: %s %s calls %s, which no input exports\n", importer.c_str(),
                    donkey::xref_kind_name(call.kind), hex(call.from).c_str(), call.name.c_str());
      } else {
        std::printf("  %s: %s %s calls %s in %s at %s\n", importer.c_str(),
                    donkey::xref_kind_name(call.kind), hex(call.from).c_str(), call.name.c_str(),
                    labels[call.provider].c_str(), hex(call.to).c_str());
      }
    }
    if (partial) {
      std::printf("note: an image was only partly analysed, so some call sites may be missing\n");
    }
  }
  return kExitOk;
}

}  // namespace

int command_link(const std::vector<std::string_view>& arguments) {
  bool json = false;
  std::vector<std::string_view> positional;
  for (const std::string_view argument : arguments) {
    if (argument == "--json") {
      json = true;
    } else if (!argument.empty() && argument.front() == '-') {
      return usage_error("unknown option for link");
    } else {
      positional.push_back(argument);
    }
  }
  if (positional.size() < 2) {
    return usage_error("link needs the executable and at least one library, in link order");
  }
  // The link inputs point into these buffers, so they are all loaded before any input is built.
  std::vector<std::string> labels;
  std::vector<donkey::LoadedBinary> loaded;
  labels.reserve(positional.size());
  loaded.reserve(positional.size());
  for (const std::string_view path : positional) {
    auto result = donkey::load_binary(std::string(path));
    if (!result) {
      return fail(result.diagnostic());
    }
    labels.emplace_back(path);
    loaded.push_back(std::move(result.value()));
  }
  return report_link(labels, loaded, json);
}

int command_project(const std::vector<std::string_view>& arguments) {
  if (arguments.empty()) {
    return usage_error("project needs a subcommand: save, info, link, string or type");
  }
  const std::string_view subcommand = arguments[0];
  bool json = false;
  bool clear = false;
  bool force = false;
  LoadOptions load_options;
  std::vector<std::string_view> positional;
  for (std::size_t i = 1; i < arguments.size(); ++i) {
    const std::string_view argument = arguments[i];
    const char* flag_error = nullptr;
    if (argument == "--json") {
      json = true;
    } else if (argument == "--clear") {
      clear = true;
    } else if (argument == "--force") {
      force = true;
    } else if (try_parse_load_flag(arguments, i, load_options, flag_error)) {
      if (flag_error != nullptr) {
        return usage_error(flag_error);
      }
    } else if (!argument.empty() && argument.front() == '-') {
      return usage_error("unknown option for project");
    } else {
      positional.push_back(argument);
    }
  }

  if (subcommand == "type") {
    return command_project_type(positional, json);
  }

  if (subcommand == "save") {
    if (positional.size() != 2) {
      return usage_error("project save needs a database path and a binary path");
    }
    const std::string database(positional[0]);
    const std::string binary(positional[1]);
    LoadedBinary loaded;
    if (!load(binary, loaded, load_options)) {
      return kExitFailure;
    }
    auto analysis = analyze(loaded.image, loaded.data);
    if (!analysis) {
      return fail(analysis.diagnostic());
    }
    auto project = Project::create(database);
    if (!project) {
      return fail(project.diagnostic());
    }
    auto image_id = project.value().import(loaded, analysis.value());
    if (!image_id) {
      return fail(image_id.diagnostic());
    }
    auto integrity = project.value().check_integrity();
    if (!integrity) {
      return fail(integrity.diagnostic());
    }
    if (json) {
      std::string out;
      out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
      out += "  \"tool\": \"donkey-cli\",\n";
      out += "  \"tool_version\": " + quote(version()) + ",\n";
      out += "  \"database\": " + quote(database) + ",\n";
      out += "  \"schema\": " + std::to_string(project.value().schema_version()) + ",\n";
      out += "  \"image_id\": " + std::to_string(image_id.value()) + ",\n";
      out += "  \"integrity\": " + std::string(integrity.value() ? "true" : "false") + ",\n";
      out += "  \"sha256\": " + quote(loaded.image.sha256) + "\n";
      out += "}\n";
      std::fwrite(out.data(), 1, out.size(), stdout);
    } else {
      std::printf("Database:  %s\n", database.c_str());
      std::printf("Schema:    %d\n", project.value().schema_version());
      std::printf("Image ID:  %lld\n", static_cast<long long>(image_id.value()));
      std::printf("Integrity: %s\n", integrity.value() ? "ok" : "failed");
      std::printf("SHA-256:   %s\n", loaded.image.sha256.c_str());
    }
    return kExitOk;
  }

  if (subcommand == "link") {
    if (positional.size() != 1) {
      return usage_error("project link needs a database path");
    }
    const std::string database(positional[0]);
    auto project = Project::open(database);
    if (!project) {
      return fail(project.diagnostic());
    }
    auto images = project.value().images();
    if (!images) {
      return fail(images.diagnostic());
    }
    if (images.value().size() < 2) {
      return usage_error("project link needs at least two images in the project");
    }
    // The project lists its images in the order they were saved, which is the link order: the
    // first image saved is the executable. Each file must still match the hash the project
    // recorded.
    std::vector<std::string> labels;
    std::vector<donkey::LoadedBinary> loaded;
    for (const ProjectImage& image : images.value()) {
      auto result = donkey::load_binary(image.path);
      if (!result) {
        return fail(result.diagnostic());
      }
      if (result.value().image.sha256 != image.sha256) {
        std::fprintf(stderr,
                     "error [project.image_changed]: %s no longer matches the hash the project "
                     "recorded\n",
                     image.path.c_str());
        return kExitFailure;
      }
      labels.push_back(image.path);
      loaded.push_back(std::move(result.value()));
    }
    return report_link(labels, loaded, json);
  }

  if (subcommand == "info") {
    if (positional.size() != 1) {
      return usage_error("project info needs a database path");
    }
    const std::string database(positional[0]);
    auto project = Project::open(database);
    if (!project) {
      return fail(project.diagnostic());
    }
    auto images = project.value().images();
    if (!images) {
      return fail(images.diagnostic());
    }
    auto integrity = project.value().check_integrity();
    if (!integrity) {
      return fail(integrity.diagnostic());
    }
    if (json) {
      std::string out;
      out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
      out += "  \"tool\": \"donkey-cli\",\n";
      out += "  \"tool_version\": " + quote(version()) + ",\n";
      out += "  \"database\": " + quote(database) + ",\n";
      out += "  \"project_schema\": " + std::to_string(project.value().schema_version()) + ",\n";
      out += "  \"integrity\": " + std::string(integrity.value() ? "true" : "false") + ",\n";
      out += "  \"images\": [";
      for (std::size_t i = 0; i < images.value().size(); ++i) {
        const ProjectImage& image = images.value()[i];
        out += i == 0 ? "\n" : ",\n";
        out += "    {\"id\": " + std::to_string(image.id) + ", \"path\": " + quote(image.path) +
               ", \"sha256\": " + quote(image.sha256) + ", \"format\": " + quote(image.format) +
               ", \"architecture\": " + quote(image.architecture) +
               ", \"bits\": " + std::to_string(image.bits) +
               ", \"entry_point\": " + quote(hex(image.entry_point)) +
               ", \"file_size\": " + std::to_string(image.file_size) +
               ", \"sections\": " + std::to_string(image.sections) +
               ", \"functions\": " + std::to_string(image.functions) +
               ", \"annotations\": " + std::to_string(image.annotations) +
               ", \"partial\": " + (image.analysis_partial ? "true" : "false") + "}";
      }
      out += images.value().empty() ? "]\n" : "\n  ]\n";
      out += "}\n";
      std::fwrite(out.data(), 1, out.size(), stdout);
    } else {
      std::printf("Database:  %s\n", database.c_str());
      std::printf("Schema:    %d\n", project.value().schema_version());
      std::printf("Integrity: %s\n", integrity.value() ? "ok" : "failed");
      std::printf("Images:    %zu\n", images.value().size());
      for (const ProjectImage& image : images.value()) {
        std::printf("  [%lld] %s %s-%u entry %s, %zu sections, %zu functions%s\n",
                    static_cast<long long>(image.id), image.format.c_str(),
                    image.architecture.c_str(), image.bits, hex(image.entry_point).c_str(),
                    image.sections, image.functions, image.analysis_partial ? " (partial)" : "");
      }
    }
    return kExitOk;
  }

  if (subcommand == "string") {
    // project string <db> <image-id> <address>: the NUL-terminated string at that address becomes a
    // string range of the project (G12-T2). The bytes come from the saved binary, and only when its
    // SHA-256 still matches the project's record.
    if (positional.size() != 3) {
      return usage_error("project string needs a database, image id and address");
    }
    const std::string database(positional[0]);
    std::uint64_t parsed_id = 0;
    if (!parse_u64(positional[1], parsed_id) || parsed_id == 0 ||
        parsed_id > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
      return usage_error("invalid image id");
    }
    std::uint64_t address = 0;
    if (!parse_u64(positional[2], address)) {
      return usage_error("invalid address");
    }
    auto project = Project::open(database);
    if (!project) {
      return fail(project.diagnostic());
    }
    auto images = project.value().images();
    if (!images) {
      return fail(images.diagnostic());
    }
    const ProjectImage* found = nullptr;
    for (const ProjectImage& image : images.value()) {
      if (image.id == static_cast<std::int64_t>(parsed_id)) {
        found = &image;
        break;
      }
    }
    if (found == nullptr) {
      return usage_error("no image with that id in the project");
    }
    auto loaded = donkey::load_binary(found->path);
    if (!loaded) {
      return fail(loaded.diagnostic());
    }
    if (loaded.value().image.sha256 != found->sha256) {
      std::fprintf(stderr,
                   "error [project.image_changed]: %s no longer matches the hash the project "
                   "recorded\n",
                   found->path.c_str());
      return kExitFailure;
    }
    auto offset = loaded.value().image.va_to_file_offset(address);
    if (!offset) {
      return fail(Diagnostic::make(
          Status::InvalidInput, "cli.unmapped_address",
          "the address " + hex(address) + " is not in a section of the image", std::nullopt));
    }
    const std::span<const std::byte> file = loaded.value().data;
    const std::uint64_t available =
        file.size() - std::min<std::uint64_t>(file.size(), offset.value());
    const std::uint64_t limit = std::min<std::uint64_t>(available, donkey::kMaxDataRangeBytes);
    std::uint64_t length = 0;
    while (length < limit &&
           file[static_cast<std::size_t>(offset.value() + length)] != std::byte{0}) {
      ++length;
    }
    if (length == limit) {
      return fail(Diagnostic::make(Status::InvalidInput, "cli.no_terminator",
                                   "no NUL terminator within the range the image holds at that "
                                   "address",
                                   address));
    }
    const std::string text = donkey::format_string_range_text(length + 1);
    auto written = project.value().set_annotation(static_cast<std::int64_t>(parsed_id),
                                                  AnnotationKind::DataRange, address, text);
    if (!written) {
      return fail(written.diagnostic());
    }
    if (json) {
      std::string out;
      out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
      out += "  \"tool\": \"donkey-cli\",\n";
      out += "  \"tool_version\": " + quote(version()) + ",\n";
      out += "  \"database\": " + quote(database) + ",\n";
      out += "  \"image_id\": " + std::to_string(parsed_id) + ",\n";
      out += "  \"address\": " + quote(hex(address)) + ",\n";
      out += "  \"text\": " + quote(text) + ",\n";
      out += "  \"bytes\": " + std::to_string(length + 1) + "\n";
      out += "}\n";
      std::fwrite(out.data(), 1, out.size(), stdout);
    } else {
      std::printf("Set string at %s in image %llu: %llu bytes with the terminator\n",
                  hex(address).c_str(), static_cast<unsigned long long>(parsed_id),
                  static_cast<unsigned long long>(length + 1));
    }
    return kExitOk;
  }

  if (subcommand == "rename" || subcommand == "comment" || subcommand == "bookmark") {
    const bool is_bookmark = subcommand == "bookmark";
    const std::string sub_str(subcommand);
    if (clear) {
      if (positional.size() != 3) {
        return usage_error(
            ("project " + sub_str + " --clear needs a database, image id and address").c_str());
      }
    } else if (positional.size() != 4 && !(is_bookmark && positional.size() == 3)) {
      return usage_error(("project " + sub_str + " needs a database, image id and address" +
                          (is_bookmark ? " (and optional text)" : " and text"))
                             .c_str());
    }
    const std::string database(positional[0]);
    std::uint64_t parsed_id = 0;
    if (!parse_u64(positional[1], parsed_id) || parsed_id == 0 ||
        parsed_id > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
      return usage_error("invalid image id");
    }
    std::uint64_t address = 0;
    if (!parse_u64(positional[2], address)) {
      return usage_error("invalid address");
    }
    auto project = Project::open(database);
    if (!project) {
      return fail(project.diagnostic());
    }
    AnnotationKind kind = AnnotationKind::Rename;
    if (subcommand == "comment") {
      kind = AnnotationKind::Comment;
    } else if (subcommand == "bookmark") {
      kind = AnnotationKind::Bookmark;
    }
    const std::string text = positional.size() >= 4 ? std::string(positional[3])
                             : is_bookmark          ? "bookmark"
                                                    : "";
    Result<void> written = clear ? project.value().clear_annotation(
                                       static_cast<std::int64_t>(parsed_id), kind, address)
                                 : project.value().set_annotation(
                                       static_cast<std::int64_t>(parsed_id), kind, address, text);
    if (!written) {
      return fail(written.diagnostic());
    }
    if (json) {
      std::string out;
      out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
      out += "  \"tool\": \"donkey-cli\",\n";
      out += "  \"tool_version\": " + quote(version()) + ",\n";
      out += "  \"database\": " + quote(database) + ",\n";
      out += "  \"image_id\": " + std::to_string(parsed_id) + ",\n";
      out += "  \"kind\": " + quote(annotation_kind_name(kind)) + ",\n";
      out += "  \"address\": " + quote(hex(address)) + ",\n";
      out += "  \"cleared\": " + std::string(clear ? "true" : "false") + ",\n";
      out += "  \"text\": " + quote(clear ? std::string() : std::string(positional[3])) + "\n";
      out += "}\n";
      std::fwrite(out.data(), 1, out.size(), stdout);
    } else if (clear) {
      std::printf("Cleared %s at %s in image %llu\n", annotation_kind_name(kind),
                  hex(address).c_str(), static_cast<unsigned long long>(parsed_id));
    } else {
      std::printf("Set %s at %s in image %llu: %s\n", annotation_kind_name(kind),
                  hex(address).c_str(), static_cast<unsigned long long>(parsed_id),
                  std::string(positional[3]).c_str());
    }
    return kExitOk;
  }

  if (subcommand == "local-name") {
    // project local-name <db> <image-id> <function> <variable> <name>, or ... --clear without name.
    if (clear ? positional.size() != 4 : positional.size() != 5) {
      return usage_error(
          "project local-name needs a database, image id, function address, variable key and "
          "name (or --clear without the name)");
    }
    const std::string database(positional[0]);
    std::uint64_t parsed_id = 0;
    if (!parse_u64(positional[1], parsed_id) || parsed_id == 0 ||
        parsed_id > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
      return usage_error("invalid image id");
    }
    std::uint64_t function_address = 0;
    if (!parse_u64(positional[2], function_address)) {
      return usage_error("invalid function address");
    }
    const std::string variable(positional[3]);
    const std::string name = clear ? std::string() : std::string(positional[4]);
    auto project = Project::open(database);
    if (!project) {
      return fail(project.diagnostic());
    }
    auto written = project.value().set_local_name(static_cast<std::int64_t>(parsed_id),
                                                  function_address, variable, name);
    if (!written) {
      return fail(written.diagnostic());
    }
    if (json) {
      std::string out;
      out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
      out += "  \"tool\": \"donkey-cli\",\n";
      out += "  \"tool_version\": " + quote(version()) + ",\n";
      out += "  \"database\": " + quote(database) + ",\n";
      out += "  \"image_id\": " + std::to_string(parsed_id) + ",\n";
      out += "  \"function\": " + quote(hex(function_address)) + ",\n";
      out += "  \"variable\": " + quote(variable) + ",\n";
      out += "  \"name\": " + (clear ? std::string("null") : quote(name)) + "\n";
      out += "}\n";
      std::fwrite(out.data(), 1, out.size(), stdout);
    } else if (clear) {
      std::printf("Cleared the local name of %s in %s\n", variable.c_str(),
                  hex(function_address).c_str());
    } else {
      std::printf("Named %s in %s as %s\n", variable.c_str(), hex(function_address).c_str(),
                  name.c_str());
    }
    return kExitOk;
  }

  if (subcommand == "local-names") {
    if (positional.size() != 2) {
      return usage_error("project local-names needs a database and an image id");
    }
    const std::string database(positional[0]);
    std::uint64_t parsed_id = 0;
    if (!parse_u64(positional[1], parsed_id) || parsed_id == 0 ||
        parsed_id > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
      return usage_error("invalid image id");
    }
    auto project = Project::open(database);
    if (!project) {
      return fail(project.diagnostic());
    }
    auto found = project.value().local_names(static_cast<std::int64_t>(parsed_id));
    if (!found) {
      return fail(found.diagnostic());
    }
    if (json) {
      std::string out;
      out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
      out += "  \"tool\": \"donkey-cli\",\n";
      out += "  \"tool_version\": " + quote(version()) + ",\n";
      out += "  \"database\": " + quote(database) + ",\n";
      out += "  \"image_id\": " + std::to_string(parsed_id) + ",\n";
      out += "  \"local_names\": [";
      for (std::size_t i = 0; i < found.value().size(); ++i) {
        const LocalName& entry = found.value()[i];
        out += i == 0 ? "\n" : ",\n";
        out += "    {\"function\": " + quote(hex(entry.function_address)) +
               ", \"variable\": " + quote(entry.variable) + ", \"name\": " + quote(entry.name) +
               "}";
      }
      out += found.value().empty() ? "]\n" : "\n  ]\n";
      out += "}\n";
      std::fwrite(out.data(), 1, out.size(), stdout);
    } else {
      std::printf("Image %llu: %zu local names\n", static_cast<unsigned long long>(parsed_id),
                  found.value().size());
      for (const LocalName& entry : found.value()) {
        std::printf("  %-18s %-24s %s\n", hex(entry.function_address).c_str(),
                    entry.variable.c_str(), entry.name.c_str());
      }
    }
    return kExitOk;
  }

  if (subcommand == "annotations") {
    if (positional.size() != 2) {
      return usage_error("project annotations needs a database and an image id");
    }
    const std::string database(positional[0]);
    std::uint64_t parsed_id = 0;
    if (!parse_u64(positional[1], parsed_id) || parsed_id == 0 ||
        parsed_id > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
      return usage_error("invalid image id");
    }
    auto project = Project::open(database);
    if (!project) {
      return fail(project.diagnostic());
    }
    auto found = project.value().annotations(static_cast<std::int64_t>(parsed_id));
    if (!found) {
      return fail(found.diagnostic());
    }
    if (json) {
      std::string out;
      out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
      out += "  \"tool\": \"donkey-cli\",\n";
      out += "  \"tool_version\": " + quote(version()) + ",\n";
      out += "  \"database\": " + quote(database) + ",\n";
      out += "  \"image_id\": " + std::to_string(parsed_id) + ",\n";
      out += "  \"annotations\": [";
      for (std::size_t i = 0; i < found.value().size(); ++i) {
        const Annotation& annotation = found.value()[i];
        out += i == 0 ? "\n" : ",\n";
        out += "    {\"kind\": " + quote(annotation_kind_name(annotation.kind)) +
               ", \"address\": " + quote(hex(annotation.address)) +
               ", \"text\": " + quote(annotation.text) + "}";
      }
      out += found.value().empty() ? "]\n" : "\n  ]\n";
      out += "}\n";
      std::fwrite(out.data(), 1, out.size(), stdout);
    } else {
      std::printf("Image %llu: %zu annotations\n", static_cast<unsigned long long>(parsed_id),
                  found.value().size());
      for (const Annotation& annotation : found.value()) {
        std::printf("  %-18s %-7s %s\n", hex(annotation.address).c_str(),
                    annotation_kind_name(annotation.kind), annotation.text.c_str());
      }
    }
    return kExitOk;
  }

  if (subcommand == "backup") {
    if (positional.size() != 2) {
      return usage_error("project backup needs a database path and a backup path");
    }
    const std::string database(positional[0]);
    const std::string backup(positional[1]);
    auto project = Project::open(database);
    if (!project) {
      return fail(project.diagnostic());
    }
    auto written = project.value().backup(backup, force);
    if (!written) {
      return fail(written.diagnostic());
    }
    auto restore_check = Project::open(backup);
    if (!restore_check) {
      return fail(restore_check.diagnostic());
    }
    auto integrity = restore_check.value().check_integrity();
    if (!integrity) {
      return fail(integrity.diagnostic());
    }
    if (json) {
      std::string out;
      out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
      out += "  \"tool\": \"donkey-cli\",\n";
      out += "  \"tool_version\": " + quote(version()) + ",\n";
      out += "  \"database\": " + quote(database) + ",\n";
      out += "  \"backup\": " + quote(backup) + ",\n";
      out +=
          "  \"project_schema\": " + std::to_string(restore_check.value().schema_version()) + ",\n";
      out += "  \"integrity\": " + std::string(integrity.value() ? "true" : "false") + "\n";
      out += "}\n";
      std::fwrite(out.data(), 1, out.size(), stdout);
    } else {
      std::printf("Database:  %s\n", database.c_str());
      std::printf("Backup:    %s\n", backup.c_str());
      std::printf("Schema:    %d\n", restore_check.value().schema_version());
      std::printf("Integrity: %s\n", integrity.value() ? "ok" : "failed");
    }
    return kExitOk;
  }

  if (subcommand == "restore") {
    if (positional.size() != 2) {
      return usage_error("project restore needs a database path and a backup path");
    }
    const std::string database(positional[0]);
    const std::string backup(positional[1]);
    auto written = Project::restore(database, backup);
    if (!written) {
      return fail(written.diagnostic());
    }
    auto restored = Project::open(database);
    if (!restored) {
      return fail(restored.diagnostic());
    }
    auto integrity = restored.value().check_integrity();
    if (!integrity) {
      return fail(integrity.diagnostic());
    }
    auto images = restored.value().images();
    if (!images) {
      return fail(images.diagnostic());
    }
    if (json) {
      std::string out;
      out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
      out += "  \"tool\": \"donkey-cli\",\n";
      out += "  \"tool_version\": " + quote(version()) + ",\n";
      out += "  \"database\": " + quote(database) + ",\n";
      out += "  \"backup\": " + quote(backup) + ",\n";
      out += "  \"project_schema\": " + std::to_string(restored.value().schema_version()) + ",\n";
      out += "  \"integrity\": " + std::string(integrity.value() ? "true" : "false") + ",\n";
      out += "  \"images\": " + std::to_string(images.value().size()) + "\n";
      out += "}\n";
      std::fwrite(out.data(), 1, out.size(), stdout);
    } else {
      std::printf("Database:  %s\n", database.c_str());
      std::printf("Restored:  %s\n", backup.c_str());
      std::printf("Schema:    %d\n", restored.value().schema_version());
      std::printf("Integrity: %s\n", integrity.value() ? "ok" : "failed");
      std::printf("Images:    %zu\n", images.value().size());
    }
    return kExitOk;
  }

  return usage_error(
      "unknown project subcommand (expected save, info, rename, comment, bookmark, annotations, "
      "local-name, local-names, backup, restore or type)");
}

namespace {

/// One stop observed while running under `debug launch --run`.
struct DebugStopRecord {
  debug::StopInfo info;
  std::uint64_t static_address = 0;
  std::string function;
};

std::string json_stop(const DebugStopRecord& stop) {
  return "{\"reason\": " + quote(debug::stop_reason_name(stop.info.reason)) +
         ", \"address\": " + quote(hex(stop.info.address)) +
         ", \"static_address\": " + quote(hex(stop.static_address)) +
         ", \"function\": " + quote(stop.function) +
         ", \"description\": " + quote(stop.info.description) + "}";
}

/// Resolve a breakpoint spec: a hex/decimal static address or a symbol name.
bool resolve_breakpoint(const BinaryImage* image, std::string_view spec, std::uint64_t& out);

/// A condition with each `*SYMBOL` operand replaced by the symbol's static address, so a condition
/// can name a data symbol the way --break names a function. Other text is left as it is.
Result<std::string> resolve_condition_symbols(const BinaryImage* image, std::string_view text) {
  std::string out;
  std::size_t i = 0;
  while (i < text.size()) {
    if (text[i] != '*') {
      out.push_back(text[i]);
      ++i;
      continue;
    }
    std::size_t start = i + 1;
    while (start < text.size() && std::isspace(static_cast<unsigned char>(text[start])) != 0) {
      ++start;
    }
    const bool identifier =
        start < text.size() &&
        (std::isalpha(static_cast<unsigned char>(text[start])) != 0 || text[start] == '_');
    if (!identifier) {
      out.push_back('*');
      ++i;
      continue;
    }
    std::size_t end = start;
    while (end < text.size() &&
           (std::isalnum(static_cast<unsigned char>(text[end])) != 0 || text[end] == '_')) {
      ++end;
    }
    const std::string_view name = text.substr(start, end - start);
    std::uint64_t address = 0;
    if (!resolve_breakpoint(image, name, address)) {
      return make_error<std::string>(
          Status::InvalidInput, "debug.unknown_symbol",
          "no symbol named `" + std::string(name) + "` for a condition operand");
    }
    out += "*" + hex(address);
    i = end;
  }
  return out;
}

/// A condition as the adapter takes it: the operand, the operator and the value. A memory operand
/// is written at `memory_address`, the runtime address.
std::string condition_text(const debug::BreakCondition& condition, std::uint64_t memory_address) {
  const std::string operand =
      condition.memory ? "*" + hex(memory_address) : condition.register_name;
  return operand + " " + debug::condition_op_text(condition.op) + " " + hex(condition.value);
}

/// A watch as the command line gives it: TARGET[:LENGTH][:rw]. The target's address is the part
/// before the first colon, its size in bytes is 1, 2, 4 or 8 (default 4), and the access is write
/// (default), or read-or-write with `rw`. Returns the problem, or an empty string when the spec is
/// well formed.
std::string split_watch_spec(std::string_view spec, std::string& target, std::uint64_t& length,
                             debug::WatchKind& kind) {
  const std::string text(spec);
  const auto first = text.find(':');
  target = text.substr(0, first);
  length = 4;
  kind = debug::WatchKind::Write;
  if (first == std::string::npos) {
    return {};
  }
  const std::string rest = text.substr(first + 1);
  const auto second = rest.find(':');
  std::uint64_t parsed = 0;
  if (!parse_u64(rest.substr(0, second), parsed) ||
      (parsed != 1 && parsed != 2 && parsed != 4 && parsed != 8)) {
    return "a watch's length must be 1, 2, 4 or 8 bytes";
  }
  length = parsed;
  if (second != std::string::npos) {
    if (rest.substr(second + 1) != "rw") {
      return "a watch's access must be rw (the default is write)";
    }
    kind = debug::WatchKind::ReadWrite;
  }
  return {};
}

bool resolve_breakpoint(const BinaryImage* image, std::string_view spec, std::uint64_t& out) {
  if (parse_u64(spec, out)) {
    return true;
  }
  if (image == nullptr) {
    return false;
  }
  for (const Symbol& symbol : image->symbols) {
    if (!symbol.imported && symbol.address != 0 &&
        (symbol.name == spec || symbol.name == "_" + std::string(spec))) {
      out = symbol.address;
      return true;
    }
  }
  return false;
}

}  // namespace

int command_debug(const std::vector<std::string_view>& arguments) {
  if (arguments.empty()) {
    return usage_error("debug needs a subcommand: launch");
  }
  const std::string_view subcommand = arguments[0];
  if (subcommand != "launch") {
    return usage_error("unknown debug subcommand; supported: launch");
  }

  bool json = false;
  bool mock = false;
  bool run = false;
  std::string binary_path;
  std::vector<std::string> args;
  std::vector<std::string> break_specs;
  std::vector<std::string> watch_specs;
  std::vector<std::pair<std::string, std::string>> conditional_specs;        // location, condition
  std::vector<std::pair<std::string, std::string>> conditional_watch_specs;  // watch, condition

  for (std::size_t i = 1; i < arguments.size(); ++i) {
    const std::string_view arg = arguments[i];
    if (arg == "--json") {
      json = true;
    } else if (arg == "--mock") {
      mock = true;
    } else if (arg == "--run") {
      run = true;
    } else if (arg == "--break-if") {
      std::string_view spec;
      std::string_view condition;
      if (!take_value(arguments, i, spec) || !take_value(arguments, i, condition)) {
        return usage_error("--break-if needs a location and a condition");
      }
      conditional_specs.emplace_back(std::string(spec), std::string(condition));
    } else if (arg == "--watch-if") {
      std::string_view spec;
      std::string_view condition;
      if (!take_value(arguments, i, spec) || !take_value(arguments, i, condition)) {
        return usage_error("--watch-if needs a watch and a condition");
      }
      conditional_watch_specs.emplace_back(std::string(spec), std::string(condition));
    } else if (arg == "--arg" || arg == "--break" || arg == "--watch") {
      std::string_view val;
      if (!take_value(arguments, i, val)) {
        return usage_error(arg == "--arg"     ? "--arg needs a value"
                           : arg == "--watch" ? "--watch needs a value"
                                              : "--break needs a value");
      }
      if (arg == "--watch") {
        watch_specs.emplace_back(val);
      } else {
        (arg == "--arg" ? args : break_specs).emplace_back(val);
      }
    } else if (!arg.empty() && arg.front() == '-') {
      return usage_error("unknown option for debug launch");
    } else if (binary_path.empty()) {
      binary_path = std::string(arg);
    } else {
      return usage_error("debug launch accepts exactly one binary file");
    }
  }

  if (binary_path.empty()) {
    return usage_error("debug launch needs a binary file path");
  }

  auto adapter = debug::create_debug_adapter(mock);
  if (!mock && !adapter->capabilities().can_launch) {
    return fail(Diagnostic{Status::Unsupported, "debug.unsupported_platform",
                           "native debugging is not implemented on this host; use --mock for "
                           "the simulation adapter",
                           std::nullopt});
  }
  auto static_image = load_binary_file(binary_path);
  const BinaryImage* image = static_image ? &static_image.value() : nullptr;

  std::vector<std::uint64_t> static_breaks;
  for (const std::string& spec : break_specs) {
    std::uint64_t address = 0;
    if (!resolve_breakpoint(image, spec, address)) {
      return fail(Diagnostic{Status::InvalidInput, "debug.unknown_breakpoint",
                             "no symbol or address '" + spec + "' in " + binary_path,
                             std::nullopt});
    }
    static_breaks.push_back(address);
  }

  // A conditional breakpoint's condition is checked here, before anything runs, so a malformed one
  // or an unknown symbol is refused before the target is started.
  struct PendingCondition {
    std::uint64_t static_address = 0;
    debug::BreakCondition condition;
  };
  std::vector<PendingCondition> pending_conditions;
  for (const auto& [spec, text] : conditional_specs) {
    std::uint64_t address = 0;
    if (!resolve_breakpoint(image, spec, address)) {
      return fail(Diagnostic{Status::InvalidInput, "debug.unknown_breakpoint",
                             "no symbol or address '" + spec + "' in " + binary_path,
                             std::nullopt});
    }
    auto resolved = resolve_condition_symbols(image, text);
    if (!resolved) {
      return fail(resolved.diagnostic());
    }
    auto parsed = debug::parse_break_condition(resolved.value());
    if (!parsed) {
      return fail(parsed.diagnostic());
    }
    pending_conditions.push_back(PendingCondition{address, parsed.value()});
  }
  // A conditional watch is checked here, before the launch, like a conditional breakpoint.
  struct PendingWatchCondition {
    std::uint64_t static_address = 0;
    std::uint64_t length = 4;
    debug::WatchKind kind = debug::WatchKind::Write;
    debug::BreakCondition condition;
  };
  std::vector<PendingWatchCondition> pending_watch_conditions;
  for (const auto& [spec, text] : conditional_watch_specs) {
    std::string target;
    std::uint64_t length = 4;
    auto kind = debug::WatchKind::Write;
    const std::string problem = split_watch_spec(spec, target, length, kind);
    if (!problem.empty()) {
      return usage_error(problem.c_str());
    }
    std::uint64_t address = 0;
    if (!resolve_breakpoint(image, target, address)) {
      return fail(Diagnostic{Status::InvalidInput, "debug.unknown_watch",
                             "no symbol or address '" + target + "' in " + binary_path,
                             std::nullopt});
    }
    auto resolved = resolve_condition_symbols(image, text);
    if (!resolved) {
      return fail(resolved.diagnostic());
    }
    auto parsed = debug::parse_break_condition(resolved.value());
    if (!parsed) {
      return fail(parsed.diagnostic());
    }
    pending_watch_conditions.push_back(
        PendingWatchCondition{address, length, kind, parsed.value()});
  }

  debug::LaunchConfig config;
  config.binary_path = binary_path;
  config.arguments = args;
  config.stop_at_entry = true;
  auto res = adapter->launch(config);
  if (!res) {
    return fail(res.diagnostic());
  }

  const auto& translator = adapter->address_translator();
  auto function_at = [&](std::uint64_t static_address) {
    if (image == nullptr) {
      return std::string();
    }
    const Symbol* symbol = image->symbol_at(static_address);
    return symbol != nullptr ? symbol->name : std::string();
  };
  auto record = [&](const debug::StopInfo& info) {
    DebugStopRecord stop;
    stop.info = info;
    stop.static_address = info.address != 0 ? translator.runtime_to_static(info.address) : 0;
    stop.function = function_at(stop.static_address);
    return stop;
  };

  auto entry_event = adapter->poll_events();
  const DebugStopRecord entry =
      record(entry_event.has_value() ? entry_event.value() : debug::StopInfo{});
  auto frames = adapter->call_stack();
  auto threads = adapter->threads();
  auto registers = adapter->read_registers();

  for (std::uint64_t address : static_breaks) {
    auto bp = adapter->set_breakpoint(translator.static_to_runtime(address));
    if (!bp) {
      (void)adapter->terminate();
      return fail(bp.diagnostic());
    }
  }
  for (const PendingCondition& pending : pending_conditions) {
    // A memory operand's address is a file address in the condition, and the target sees it at
    // its runtime address.
    const std::uint64_t memory =
        pending.condition.memory ? translator.static_to_runtime(pending.condition.address) : 0;
    auto bp =
        adapter->set_conditional_breakpoint(translator.static_to_runtime(pending.static_address),
                                            condition_text(pending.condition, memory));
    if (!bp) {
      (void)adapter->terminate();
      return fail(bp.diagnostic());
    }
  }
  // A watch is TARGET[:LENGTH][:rw]: the target's address, its size in bytes (default 4), and the
  // access (default write; rw traps on reads and writes too). The debug registers take it only
  // while the target is stopped, which it is here.
  for (const std::string& spec : watch_specs) {
    std::string target;
    std::uint64_t length = 4;
    auto kind = debug::WatchKind::Write;
    const std::string problem = split_watch_spec(spec, target, length, kind);
    if (!problem.empty()) {
      (void)adapter->terminate();
      return usage_error(problem.c_str());
    }
    std::uint64_t address = 0;
    if (!resolve_breakpoint(image, target, address)) {
      (void)adapter->terminate();
      return fail(Diagnostic{Status::InvalidInput, "debug.unknown_watch",
                             "no symbol or address '" + target + "' in " + binary_path,
                             std::nullopt});
    }
    auto watch = adapter->set_watchpoint(translator.static_to_runtime(address),
                                         static_cast<std::uint8_t>(length), kind);
    if (!watch) {
      (void)adapter->terminate();
      return fail(watch.diagnostic());
    }
  }
  // A conditional watch was checked before the launch and is set now that the target is stopped.
  // A memory operand's address is a file address in the condition, and the target sees it at its
  // runtime address.
  for (const PendingWatchCondition& pending : pending_watch_conditions) {
    const std::uint64_t memory =
        pending.condition.memory ? translator.static_to_runtime(pending.condition.address) : 0;
    auto watch =
        adapter->set_conditional_watchpoint(translator.static_to_runtime(pending.static_address),
                                            static_cast<std::uint8_t>(pending.length), pending.kind,
                                            condition_text(pending.condition, memory));
    if (!watch) {
      (void)adapter->terminate();
      return fail(watch.diagnostic());
    }
  }

  // Run to completion, recording each stop. Bounded so a breakpoint in a hot
  // loop cannot make the command run forever.
  constexpr std::size_t kMaxStops = 1000;
  std::vector<DebugStopRecord> stops;
  std::optional<int> exit_code;
  if (run) {
    while (stops.size() < kMaxStops) {
      if (!adapter->resume()) {
        break;
      }
      auto event = adapter->wait_for_event(30000);
      if (!event || event.value().reason == debug::StopReason::None) {
        break;  // timed out: still running
      }
      if (event.value().reason == debug::StopReason::Exited) {
        exit_code = event.value().exit_code;
        break;
      }
      stops.push_back(record(event.value()));
    }
  }
  const std::string final_state = debug::session_state_name(adapter->state());
  if (adapter->state() != debug::SessionState::Exited) {
    (void)adapter->terminate();
  }

  if (json) {
    std::string out;
    out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
    out += "  \"tool\": \"donkey-cli\",\n";
    out += "  \"tool_version\": " + quote(version()) + ",\n";
    out += "  \"adapter\": " + quote(mock ? "mock" : "native") + ",\n";
    out += "  \"state\": " + quote(final_state) + ",\n";
    out += "  \"stop_reason\": " + quote(debug::stop_reason_name(entry.info.reason)) + ",\n";
    out += "  \"entry_address\": " + quote(hex(entry.info.address)) + ",\n";
    out += "  \"entry_static_address\": " + quote(hex(entry.static_address)) + ",\n";
    out += "  \"runtime_base\": " + quote(hex(translator.runtime_base)) + ",\n";
    out += "  \"static_base\": " + quote(hex(translator.static_base)) + ",\n";
    out += "  \"registers\": [";
    if (registers.has_value()) {
      for (std::size_t i = 0; i < registers.value().size(); ++i) {
        out += i == 0 ? "\n" : ",\n";
        out += "    {\"name\": " + quote(registers.value()[i].name) +
               ", \"value\": " + quote(hex(registers.value()[i].value)) + "}";
      }
    }
    out += (registers.has_value() && !registers.value().empty()) ? "\n  ],\n" : "],\n";
    out += "  \"threads\": [";
    if (threads.has_value()) {
      for (std::size_t i = 0; i < threads.value().size(); ++i) {
        out += i == 0 ? "\n" : ",\n";
        out += "    {\"id\": " + std::to_string(threads.value()[i].id) +
               ", \"name\": " + quote(threads.value()[i].name) +
               ", \"current\": " + (threads.value()[i].is_current ? "true" : "false") + "}";
      }
    }
    out += (threads.has_value() && !threads.value().empty()) ? "\n  ],\n" : "],\n";
    out += "  \"frames\": [";
    if (frames.has_value()) {
      for (std::size_t i = 0; i < frames.value().size(); ++i) {
        out += i == 0 ? "\n" : ",\n";
        out += "    {\"index\": " + std::to_string(frames.value()[i].index) +
               ", \"ip\": " + quote(hex(frames.value()[i].instruction_pointer)) +
               ", \"sp\": " + quote(hex(frames.value()[i].stack_pointer)) +
               ", \"function\": " + quote(frames.value()[i].function_name) +
               ", \"static_address\": " + quote(hex(frames.value()[i].static_address)) + "}";
      }
    }
    out += (frames.has_value() && !frames.value().empty()) ? "\n  ],\n" : "],\n";
    out += "  \"stops\": [";
    for (std::size_t i = 0; i < stops.size(); ++i) {
      out += (i == 0 ? "\n    " : ",\n    ") + json_stop(stops[i]);
    }
    out += stops.empty() ? "],\n" : "\n  ],\n";
    out += "  \"exit_code\": " + (exit_code ? std::to_string(*exit_code) : std::string("null")) +
           "\n}\n";
    std::fwrite(out.data(), 1, out.size(), stdout);
    return kExitOk;
  }

  std::printf("Debugger (%s adapter): stopped at %s %s (static %s%s%s)\n", mock ? "mock" : "native",
              debug::stop_reason_name(entry.info.reason), hex(entry.info.address).c_str(),
              hex(entry.static_address).c_str(), entry.function.empty() ? "" : ", ",
              entry.function.c_str());
  if (registers.has_value()) {
    std::printf("Registers:\n");
    for (const auto& reg : registers.value()) {
      std::printf("  %-8s %s\n", reg.name.c_str(), hex(reg.value).c_str());
    }
  }
  if (frames.has_value()) {
    std::printf("Call stack:\n");
    for (const auto& f : frames.value()) {
      std::printf("  #%u  %s  %s (static %s)\n", f.index, hex(f.instruction_pointer).c_str(),
                  f.function_name.c_str(), hex(f.static_address).c_str());
    }
  }
  for (const auto& stop : stops) {
    std::printf("Stop: %s at %s (static %s) %s\n", debug::stop_reason_name(stop.info.reason),
                hex(stop.info.address).c_str(), hex(stop.static_address).c_str(),
                stop.function.c_str());
  }
  if (exit_code) {
    std::printf("Exited with code %d\n", *exit_code);
  } else if (run) {
    std::printf("Target did not exit; it was terminated (state was %s)\n", final_state.c_str());
  }
  return kExitOk;
}

static bool parse_hex_bytes(std::string_view text, std::vector<uint8_t>& out) {
  out.clear();
  std::string cleaned;
  for (char c : text) {
    if (std::isxdigit(static_cast<unsigned char>(c))) {
      cleaned.push_back(c);
    } else if (c == ' ' || c == ',' || c == '\t' || c == 'x' || c == 'X') {
      continue;
    } else {
      return false;
    }
  }
  if (cleaned.empty() || cleaned.size() % 2 != 0) return false;
  for (size_t i = 0; i < cleaned.size(); i += 2) {
    unsigned int val = 0;
    if (std::sscanf(cleaned.substr(i, 2).c_str(), "%x", &val) != 1) return false;
    out.push_back(static_cast<uint8_t>(val));
  }
  return true;
}

int command_patch(const std::vector<std::string_view>& arguments) {
  if (arguments.empty()) {
    return usage_error("patch needs a subcommand ('apply')");
  }

  const std::string_view subcommand = arguments[0];
  if (subcommand != "apply") {
    return usage_error("unknown patch subcommand (expected 'apply')");
  }

  std::string source_path;
  std::string dest_path;
  uint64_t offset = 0;
  bool has_offset = false;
  std::vector<uint8_t> original_bytes;
  std::vector<uint8_t> replacement_bytes;
  bool force = false;
  bool json = false;

  for (size_t i = 1; i < arguments.size(); ++i) {
    std::string_view arg = arguments[i];
    if (arg == "--json") {
      json = true;
    } else if (arg == "--force") {
      force = true;
    } else if (arg == "--offset") {
      std::string_view val;
      if (!take_value(arguments, i, val) || !parse_u64(val, offset)) {
        return usage_error("--offset needs a valid address or offset (e.g. 0x1000)");
      }
      has_offset = true;
    } else if (arg == "--output" || arg == "-o") {
      std::string_view val;
      if (!take_value(arguments, i, val)) {
        return usage_error("--output needs a file path");
      }
      dest_path = std::string(val);
    } else if (arg == "--replacement") {
      std::string_view val;
      if (!take_value(arguments, i, val) || !parse_hex_bytes(val, replacement_bytes)) {
        return usage_error("--replacement needs hex bytes (e.g. '90 90' or '9090')");
      }
    } else if (arg == "--original") {
      std::string_view val;
      if (!take_value(arguments, i, val) || !parse_hex_bytes(val, original_bytes)) {
        return usage_error("--original needs hex bytes (e.g. '55' or '554889e5')");
      }
    } else if (arg.starts_with("-")) {
      return usage_error("unknown patch option");
    } else if (source_path.empty()) {
      source_path = std::string(arg);
    } else {
      return usage_error("unexpected positional argument to patch apply");
    }
  }

  if (source_path.empty()) {
    return usage_error("patch apply needs a source binary path");
  }
  if (!has_offset) {
    return usage_error("patch apply needs --offset");
  }
  if (replacement_bytes.empty()) {
    return usage_error("patch apply needs --replacement bytes");
  }
  if (dest_path.empty()) {
    return usage_error("patch apply needs --output <destination>");
  }

  if (original_bytes.empty()) {
    std::ifstream src_file(source_path, std::ios::binary);
    if (src_file) {
      src_file.seekg(static_cast<std::streamoff>(offset));
      original_bytes.resize(replacement_bytes.size());
      src_file.read(reinterpret_cast<char*>(original_bytes.data()),
                    static_cast<std::streamsize>(replacement_bytes.size()));
      if (src_file.gcount() != static_cast<std::streamsize>(replacement_bytes.size())) {
        original_bytes.clear();
      }
    }
  }

  PatchManager manager;
  auto stage_res = manager.stage_patch(offset, original_bytes, replacement_bytes);
  if (!stage_res) {
    return fail(stage_res.diagnostic());
  }

  auto* patch_entry = const_cast<PatchEntry*>(manager.find_patch(stage_res.value()));
  if (patch_entry) {
    patch_entry->applied = true;
  }

  auto export_res = manager.export_patched_binary(source_path, dest_path, force);
  if (!export_res) {
    return fail(export_res.diagnostic());
  }

  const auto& exp = export_res.value();
  if (json) {
    std::string out;
    out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
    out += "  \"tool\": \"donkey-cli\",\n";
    out += "  \"tool_version\": " + quote(version()) + ",\n";
    out += "  \"status\": \"ok\",\n";
    out += "  \"source\": " + quote(source_path) + ",\n";
    out += "  \"destination\": " + quote(exp.path) + ",\n";
    out += "  \"offset\": " + quote(hex(offset)) + ",\n";
    out += "  \"bytes_written\": " + std::to_string(exp.bytes_written) + ",\n";
    out += "  \"sha256\": " + quote(exp.sha256) + ",\n";
    out += "  \"signature_invalidated\": " +
           std::string(exp.signature_invalidated ? "true" : "false") + ",\n";
    out += "  \"warnings\": [";
    for (size_t i = 0; i < exp.warnings.size(); ++i) {
      out += (i == 0 ? "" : ", ") + quote(exp.warnings[i]);
    }
    out += "]\n}\n";
    std::fwrite(out.data(), 1, out.size(), stdout);
    return kExitOk;
  }

  std::printf("Exported patched binary to: %s\n", exp.path.c_str());
  std::printf("  Size:     %llu bytes\n", static_cast<unsigned long long>(exp.bytes_written));
  std::printf("  SHA-256:  %s\n", exp.sha256.c_str());
  if (exp.signature_invalidated) {
    std::printf("  Warning:  Binary code signature or certificate invalidated.\n");
  }
  for (const auto& w : exp.warnings) {
    std::printf("  Note:     %s\n", w.c_str());
  }
  return kExitOk;
}

int command_plugin(const std::vector<std::string_view>& arguments) {
  if (arguments.empty()) {
    return usage_error("plugin needs a subcommand ('info' or 'run')");
  }

  const std::string_view subcommand = arguments[0];
  if (subcommand != "info" && subcommand != "run") {
    return usage_error("unknown plugin subcommand (expected 'info' or 'run')");
  }

  std::string lib_path;
  std::string input_json = "{}";
  bool isolate = false;
  bool json = false;
  std::optional<uint64_t> explicit_caps;

  for (size_t i = 1; i < arguments.size(); ++i) {
    std::string_view arg = arguments[i];
    if (arg == "--json") {
      json = true;
    } else if (arg == "--isolate") {
      isolate = true;
    } else if (arg == "--allow-all-caps") {
      explicit_caps = 0xFFFFFFFFFFFFFFFFULL;
    } else if (arg == "--caps") {
      std::string_view val;
      if (!take_value(arguments, i, val)) {
        return usage_error("--caps needs a value ('all', 'none', 'analysis', or hex integer)");
      }
      if (val == "all") {
        explicit_caps = 0xFFFFFFFFFFFFFFFFULL;
      } else if (val == "none") {
        explicit_caps = 0;
      } else if (val == "analysis") {
        explicit_caps = DONKEY_CAP_ANALYSIS;
      } else {
        uint64_t parsed = 0;
        if (!parse_u64(val, parsed)) {
          return usage_error(("--caps invalid number: " + std::string(val)).c_str());
        }
        explicit_caps = parsed;
      }
    } else if (arg == "--input") {
      std::string_view val;
      if (!take_value(arguments, i, val)) {
        return usage_error("--input needs a JSON string");
      }
      input_json = std::string(val);
    } else if (arg.starts_with("-")) {
      return usage_error("unknown plugin option");
    } else if (lib_path.empty()) {
      lib_path = std::string(arg);
    } else {
      return usage_error("unexpected positional argument to plugin");
    }
  }

  if (lib_path.empty()) {
    return usage_error("plugin needs a shared library path");
  }

  if (subcommand == "info") {
    // Safely inspect manifest in isolated process so hostile constructors never run in host
    // process. Fails closed on platforms lacking process isolation (Windows) to prevent unvetted
    // static init.
    auto manifest_res = PluginHost::inspect_manifest_isolated(lib_path);
    if (!manifest_res) {
      return fail(manifest_res.diagnostic());
    }
    const auto& m = manifest_res.value();
    if (json) {
      std::string out;
      out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
      out += "  \"tool\": \"donkey-cli\",\n";
      out += "  \"tool_version\": " + quote(version()) + ",\n";
      out += "  \"id\": " + quote(m.id) + ",\n";
      out += "  \"name\": " + quote(m.name) + ",\n";
      out += "  \"version\": " + quote(m.version) + ",\n";
      out += "  \"author\": " + quote(m.author) + ",\n";
      out += "  \"description\": " + quote(m.description) + ",\n";
      out += "  \"abi_version\": {\"major\": " + std::to_string(m.abi_version_major) +
             ", \"minor\": " + std::to_string(m.abi_version_minor) + "},\n";
      out += "  \"requested_capabilities\": " + std::to_string(m.requested_capabilities) + "\n";
      out += "}\n";
      std::fwrite(out.data(), 1, out.size(), stdout);
      return kExitOk;
    }

    std::printf("Plugin: %s (%s)\n", m.name.c_str(), m.id.c_str());
    std::printf("  Version:      %s\n", m.version.c_str());
    std::printf("  Author:       %s\n", m.author.c_str());
    std::printf("  Description:  %s\n", m.description.c_str());
    std::printf("  ABI Version:  %u.%u\n", m.abi_version_major, m.abi_version_minor);
    std::printf("  Capabilities: 0x%llx\n",
                static_cast<unsigned long long>(m.requested_capabilities));
    return kExitOk;
  }

  uint64_t granted_caps = explicit_caps.value_or(DONKEY_CAP_ANALYSIS);
  auto exec_res = isolate ? PluginHost::execute_isolated(lib_path, input_json, granted_caps)
                          : [&]() -> Result<PluginExecutionResult> {
    auto manifest_res = PluginHost::inspect_manifest(lib_path);
    if (!manifest_res) {
      return manifest_res.diagnostic();
    }
    return PluginHost::execute_trusted(lib_path, input_json, granted_caps);
  }();

  if (!exec_res) {
    return fail(exec_res.diagnostic());
  }

  const auto& res = exec_res.value();
  if (json) {
    std::string out;
    out += "{\n  \"schema_version\": " + std::to_string(kJsonSchemaVersion) + ",\n";
    out += "  \"tool\": \"donkey-cli\",\n";
    out += "  \"tool_version\": " + quote(version()) + ",\n";
    out += "  \"success\": " + std::string(res.success ? "true" : "false") + ",\n";
    out += "  \"crashed\": " + std::string(res.crashed ? "true" : "false") + ",\n";
    out += "  \"timed_out\": " + std::string(res.timed_out ? "true" : "false") + ",\n";
    out += "  \"exit_code\": " + std::to_string(res.exit_code) + ",\n";
    out += "  \"output\": " + quote(res.output_json) + ",\n";
    out += "  \"error_code\": " + quote(res.error_code) + ",\n";
    out += "  \"error_message\": " + quote(res.error_message) + "\n";
    out += "}\n";
    std::fwrite(out.data(), 1, out.size(), stdout);
    return res.success ? kExitOk : kExitFailure;
  }

  if (res.crashed) {
    std::fprintf(stderr, "Plugin crashed with signal %d (%s)\n", res.termination_signal,
                 res.error_message.c_str());
    return kExitFailure;
  }
  if (res.timed_out) {
    std::fprintf(stderr, "Plugin timed out (%s)\n", res.error_message.c_str());
    return kExitFailure;
  }
  if (!res.success) {
    std::fprintf(stderr, "Plugin execution failed [%s]: %s\n", res.error_code.c_str(),
                 res.error_message.c_str());
    return kExitFailure;
  }

  std::printf("%s\n", res.output_json.c_str());
  return kExitOk;
}

}  // namespace donkey::cli
