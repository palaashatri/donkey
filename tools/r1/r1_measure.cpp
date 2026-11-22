#include "r1_measure.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <limits>

#include "donkey/core/json.h"

namespace donkey::r1 {

namespace {

Diagnostic r1_error(std::string code, std::string message) {
  return Diagnostic::make(Status::InvalidInput, std::move(code), std::move(message), std::nullopt);
}

std::string string_member(const JsonValue& object, std::string_view key) {
  const JsonValue* value = object.find(key);
  return value != nullptr && value->is_string() ? value->text : std::string();
}

/// Limits for a document of `size` bytes: a JSON node takes at least one byte, so the node count
/// is bounded by the size, and the depth of these documents is small.
JsonLimits limits_for(std::size_t size) {
  JsonLimits limits;
  limits.max_bytes = std::max<std::size_t>(size, 1);
  limits.max_nodes = std::max<std::size_t>(size, 1);
  limits.max_depth = 16;
  return limits;
}

bool parse_hex(const std::string& text, std::uint64_t& out) {
  if (text.size() < 3 || text[0] != '0' || (text[1] != 'x' && text[1] != 'X') || text.size() > 18) {
    return false;
  }
  std::uint64_t value = 0;
  for (std::size_t i = 2; i < text.size(); ++i) {
    const char c = text[i];
    unsigned digit = 0;
    if (c >= '0' && c <= '9') {
      digit = static_cast<unsigned>(c - '0');
    } else if (c >= 'a' && c <= 'f') {
      digit = static_cast<unsigned>(c - 'a' + 10);
    } else if (c >= 'A' && c <= 'F') {
      digit = static_cast<unsigned>(c - 'A' + 10);
    } else {
      return false;
    }
    value = (value << 4U) | digit;
  }
  out = value;
  return true;
}

bool ends_with(std::string_view text, std::string_view suffix) {
  return text.size() >= suffix.size() && text.substr(text.size() - suffix.size()) == suffix;
}

bool starts_with(std::string_view text, std::string_view prefix) {
  return text.substr(0, prefix.size()) == prefix;
}

}  // namespace

Result<std::vector<Binary>> read_binaries(std::string_view json) {
  auto parsed = parse_json(json, limits_for(json.size()));
  if (!parsed) {
    return r1_error("r1.bad_binaries", "binaries.json is not JSON: " + parsed.diagnostic().message);
  }
  const JsonValue& root = parsed.value();
  const JsonValue* schema = root.find("schema");
  const JsonValue* binaries = root.find("binaries");
  if (!root.is_object() || schema == nullptr || !schema->is_number() || schema->text != "1" ||
      binaries == nullptr || !binaries->is_array()) {
    return r1_error("r1.bad_binaries", "binaries.json is not a schema 1 list of binaries");
  }
  std::vector<Binary> out;
  for (const JsonValue& entry : binaries->items) {
    if (!entry.is_object()) {
      return r1_error("r1.bad_binaries", "an entry of binaries.json is not an object");
    }
    Binary binary;
    binary.file = string_member(entry, "file");
    binary.build = string_member(entry, "build");
    binary.source = string_member(entry, "source");
    binary.toolchain = string_member(entry, "toolchain");
    binary.architecture = string_member(entry, "architecture");
    binary.level = string_member(entry, "level");
    binary.variant = string_member(entry, "variant");
    binary.unstripped = string_member(entry, "unstripped");
    binary.compiler = string_member(entry, "compiler");
    binary.sha256 = string_member(entry, "sha256");
    // A file name is used to build paths: it must be a plain name.
    if (binary.file.empty() || binary.file.find('/') != std::string::npos ||
        binary.file.find('\\') != std::string::npos || binary.file == "." || binary.file == ".." ||
        (binary.variant != "unstripped" && binary.variant != "stripped") ||
        (binary.variant == "stripped" &&
         (binary.unstripped.empty() || binary.unstripped.find('/') != std::string::npos ||
          binary.unstripped.find('\\') != std::string::npos)) ||
        binary.sha256.size() != 64) {
      return r1_error("r1.bad_binaries",
                      "an entry of binaries.json is incomplete: '" + binary.file + "'");
    }
    out.push_back(std::move(binary));
  }
  return out;
}

bool is_resource_limit(std::string_view code) {
  return code == "analysis.instruction_limit" || code == "analysis.block_limit" ||
         code == "analysis.traversal_limit";
}

bool leaves_starts_complete(std::string_view code) {
  // The one analysis diagnostic known to leave function discovery whole: whether an import
  // returns is not shown (G24-T3), so calls to it keep their fall-through.
  return code == "analysis.no_return_unverified";
}

bool is_generic_note(std::string_view note) {
  // The subset note of each architecture, the signature note, and the note that parameter names
  // came from debug information: every function carries them, Complete or not. A tail call that
  // was resolved (to a known function, or to a C library model) says how it was lifted, not why
  // the function is Partial.
  return ends_with(note, "locals are not recovered") ||
         starts_with(note, "signature inferred from ") ||
         note == "parameter names come from the debug information" ||
         starts_with(note, "a jump to a known function is lifted as a call") ||
         starts_with(note, "a conditional jump to a known function is lifted as a branch") ||
         starts_with(note, "a jump to a C library function is lifted as a call of its model") ||
         starts_with(note, "a conditional jump to a C library function is lifted as a branch");
}

std::string normalise_note(std::string_view note) {
  std::string out;
  out.reserve(note.size());
  std::size_t i = 0;
  while (i < note.size()) {
    const char c = note[i];
    if (c == '0' && i + 1 < note.size() && (note[i + 1] == 'x' || note[i + 1] == 'X') &&
        i + 2 < note.size() && std::isxdigit(static_cast<unsigned char>(note[i + 2])) != 0) {
      i += 2;
      while (i < note.size() && std::isxdigit(static_cast<unsigned char>(note[i])) != 0) {
        ++i;
      }
      out += "0xN";
      continue;
    }
    if (starts_with(note.substr(i), "sub_") &&
        (i == 0 || std::isalnum(static_cast<unsigned char>(note[i - 1])) == 0)) {
      std::size_t j = i + 4;
      while (j < note.size() && std::isxdigit(static_cast<unsigned char>(note[j])) != 0) {
        ++j;
      }
      if (j > i + 4) {
        out += "sub_N";
        i = j;
        continue;
      }
    }
    if (std::isdigit(static_cast<unsigned char>(c)) != 0) {
      // A digit inside a name (`xmm0`, `r12`, `x86-64`) is part of the name, not a count.
      const bool in_name = i > 0 && (std::isalpha(static_cast<unsigned char>(note[i - 1])) != 0 ||
                                     note[i - 1] == '-' || note[i - 1] == '_');
      std::size_t j = i;
      while (j < note.size() && std::isdigit(static_cast<unsigned char>(note[j])) != 0) {
        ++j;
      }
      if (in_name) {
        out.append(note.substr(i, j - i));
      } else {
        out += 'N';
      }
      i = j;
      continue;
    }
    out += c;
    ++i;
  }
  return out;
}

namespace {

const std::string kUnresolvedCallNote =
    "outgoing call arguments and return values follow no modelled ABI";

/// Whether a note's reason is an unresolved call: the call note, a tail call's, or the clobber
/// check's read of a register after a call that does not define it (an unresolved call defines
/// none, so the read is the call's consequence).
bool is_call_reason(const std::string& note) {
  static const std::string kClobber =
      " is read after a call that does not define it; the value is not the caller's, so the "
      "function is not Complete";
  return note == kUnresolvedCallNote ||
         note == "jump leaves the function; treated as a tail call" ||
         note == "conditional jump leaves the function; treated as a tail call" ||
         (note.rfind("register ", 0) == 0 && note.size() > kClobber.size() &&
          note.compare(note.size() - kClobber.size(), kClobber.size(), kClobber) == 0);
}

/// The call census of one Partial function (G21): its unresolved calls by kind, and, when the
/// only specific reasons are unresolved calls (is_call_reason), the kinds and imports that keep it
/// Partial.
void count_unresolved_calls(const JsonValue& function, const std::set<std::string>& reasons,
                            Measure& out) {
  const JsonValue* calls = function.find("unresolved_calls");
  if (calls == nullptr || !calls->is_array()) {
    out.has_call_census = false;
    return;
  }
  std::set<std::string> kinds;
  std::set<std::string> imports;
  for (const JsonValue& call : calls->items) {
    if (!call.is_object()) {
      continue;
    }
    std::string kind = string_member(call, "kind");
    const std::string name = string_member(call, "name");
    // An AArch64 call is unresolved whatever its target: the import ones are told apart.
    if (kind == "aarch64") {
      kind = name.empty() ? "aarch64_other" : "aarch64_import";
    }
    ++out.calls_by_kind[kind];
    kinds.insert(kind);
    if (!name.empty()) {
      imports.insert(name);
    }
  }
  if (kinds.empty() || reasons.empty() ||
      !std::all_of(reasons.begin(), reasons.end(), is_call_reason)) {
    return;
  }
  ++out.call_only_partial;
  std::string key;
  for (const std::string& kind : kinds) {
    key += (key.empty() ? "" : "+") + kind;
  }
  ++out.call_only_by_kinds[key];
  for (const std::string& name : imports) {
    ++out.call_only_imports[name];
  }
}

}  // namespace

Result<Measure> measure_decompile(std::string_view file, std::string_view json) {
  auto parsed = parse_json(json, limits_for(json.size()));
  if (!parsed) {
    return r1_error("r1.bad_decompile", std::string(file) + ": the decompile output is not JSON: " +
                                            parsed.diagnostic().message);
  }
  const JsonValue& root = parsed.value();
  const JsonValue* functions = root.find("functions");
  const JsonValue* truncated = root.find("truncated");
  if (!root.is_object() || functions == nullptr || !functions->is_array()) {
    return r1_error("r1.bad_decompile",
                    std::string(file) + ": the decompile output has no functions array");
  }
  // A capped run counts only the functions it printed: that is not a whole-binary measurement.
  if (truncated != nullptr && truncated->is_bool() && truncated->boolean) {
    return r1_error(
        "r1.bad_decompile",
        std::string(file) + ": the decompile output is truncated (raise --max-functions)");
  }
  Measure out;
  out.file = std::string(file);
  // An analysis that hit a resource limit stopped early: functions may be missing from the list,
  // so it is not a whole-binary measurement either. Other analysis notes are recorded. Output from
  // a CLI that predates these fields has neither, and is taken as it is.
  if (const JsonValue* partial = root.find("analysis_partial");
      partial != nullptr && partial->is_bool()) {
    out.analysis_partial = partial->boolean;
  }
  if (const JsonValue* codes = root.find("analysis_diagnostics");
      codes != nullptr && codes->is_array()) {
    for (const JsonValue& code : codes->items) {
      if (!code.is_string()) {
        continue;
      }
      if (is_resource_limit(code.text)) {
        return r1_error("r1.bad_decompile", std::string(file) +
                                                ": the analysis stopped at a limit (" + code.text +
                                                "); raise --max-instructions");
      }
      out.analysis_notes.push_back(code.text);
      if (!leaves_starts_complete(code.text)) {
        out.starts_may_be_missing = true;
      }
    }
  }
  for (const JsonValue& function : functions->items) {
    if (!function.is_object()) {
      return r1_error("r1.bad_decompile", std::string(file) + ": a function is not an object");
    }
    const std::string status = string_member(function, "status");
    const std::string address = string_member(function, "address");
    std::uint64_t start = 0;
    if (!parse_hex(address, start)) {
      return r1_error("r1.bad_decompile",
                      std::string(file) + ": a function has no address: '" + address + "'");
    }
    out.starts.insert(start);
    ++out.functions;
    // A lifted function of a CLI with the call census lists its unresolved calls, an empty list
    // when it has none (G21). Unsupported and InvalidIR entries were never lifted and carry none.
    if (status == "Complete" || status == "Partial") {
      const JsonValue* calls = function.find("unresolved_calls");
      if (calls == nullptr || !calls->is_array()) {
        out.has_call_census = false;
      }
    }
    if (status == "Complete") {
      ++out.complete;
    } else if (status == "Unsupported") {
      ++out.unsupported;
    } else if (status == "InvalidIR") {
      ++out.invalid_ir;
    } else if (status == "Partial") {
      ++out.partial;
      const JsonValue* notes = function.find("notes");
      if (notes == nullptr) {
        out.has_notes = false;
        continue;
      }
      if (!notes->is_array()) {
        return r1_error("r1.bad_decompile", std::string(file) + ": notes is not an array");
      }
      std::set<std::string> seen;
      bool first = true;
      for (const JsonValue& note : notes->items) {
        if (!note.is_string() || is_generic_note(note.text)) {
          continue;
        }
        const std::string normalised = normalise_note(note.text);
        if (first) {
          ++out.first_notes[normalised];
          first = false;
        }
        if (seen.insert(normalised).second) {
          ++out.all_notes[normalised];
        }
      }
      // An instruction that is not lifted makes a function Partial without a note of its own (the
      // statement's first word is its mnemonic). It is the first reason only when the lifter gave
      // no specific note: a note says more (the %fs canary load, say, is an Unsupported mov
      // explained by the thread-local storage note).
      if (const JsonValue* unsupported = function.find("unsupported");
          unsupported != nullptr && unsupported->is_array()) {
        for (const JsonValue& statement : unsupported->items) {
          if (!statement.is_string() || statement.text.empty()) {
            continue;
          }
          const std::string& text = statement.text;
          const std::string reason =
              text == "operand width is not modelled"
                  ? text
                  : "unsupported instruction '" + text.substr(0, text.find(' ')) + "'";
          if (first) {
            ++out.first_notes[reason];
            first = false;
          }
          if (seen.insert(reason).second) {
            ++out.all_notes[reason];
          }
        }
      }
      if (first) {
        out.unexplained.push_back(Unexplained{address, string_member(function, "name")});
      }
      count_unresolved_calls(function, seen, out);
    } else {
      return r1_error("r1.bad_decompile",
                      std::string(file) + ": a function has an unknown status '" + status + "'");
    }
  }
  return out;
}

std::set<std::uint64_t> function_symbol_starts(const BinaryImage& image) {
  std::set<std::uint64_t> starts;
  for (const Symbol& symbol : image.symbols) {
    if (symbol.kind != SymbolKind::Function || symbol.imported || symbol.address == 0) {
      continue;
    }
    const Section* section = image.section_for_va(symbol.address);
    if (section != nullptr && section->executable) {
      starts.insert(symbol.address);
    }
  }
  return starts;
}

std::set<std::uint64_t> starts_in_stub_sections(const BinaryImage& image,
                                                const std::set<std::uint64_t>& found) {
  std::set<std::uint64_t> stubs;
  for (const std::uint64_t start : found) {
    const Section* section = image.section_for_va(start);
    if (section != nullptr &&
        (section->name == ".plt" || section->name == ".plt.sec" || section->name == ".plt.got")) {
      stubs.insert(start);
    }
  }
  return stubs;
}

StartsComparison compare_starts(const std::set<std::uint64_t>& truth,
                                const std::set<std::uint64_t>& found,
                                const std::set<std::uint64_t>& stubs) {
  StartsComparison out;
  out.truth = truth.size();
  out.found = found.size();
  for (const std::uint64_t start : truth) {
    if (found.count(start) != 0) {
      ++out.matched;
    } else {
      ++out.missed;
    }
  }
  for (const std::uint64_t start : found) {
    if (truth.count(start) != 0) {
      continue;
    }
    if (stubs.count(start) != 0) {
      ++out.stubs;
    } else {
      ++out.extra;
    }
  }
  return out;
}

}  // namespace donkey::r1
