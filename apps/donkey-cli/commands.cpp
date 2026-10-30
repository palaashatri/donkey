#include "commands.h"

#include <algorithm>
#include <charconv>
#include <cinttypes>
#include <cstddef>
#include <cstdio>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/core/checked.h"
#include "donkey/core/status.h"
#include "donkey/core/version.h"
#include "donkey/decode/decode.h"
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
};

struct DisasmOptions {
  std::string path;
  std::string section;
  bool json = false;
  std::optional<std::uint64_t> address;
  std::size_t count = 64;
};

struct AnalysisRequest {
  std::string path;
  bool json = false;
  std::optional<std::uint64_t> address;
  std::size_t max_instructions = 1000000;
  std::size_t max_strings = 100000;
  std::size_t min_string_length = 4;
  std::size_t max_items = 1000;
};

void print_human_info(const BinaryImage& image, std::size_t max_symbols) {
  std::printf("File:      %s\n", image.path.c_str());
  std::printf("Size:      %" PRIu64 " bytes\n", image.file_size);
  std::printf("SHA-256:   %s\n", image.sha256.c_str());
  std::printf("Format:    %s (%s), %s-endian, %u-bit\n", format_name(image.format),
              image.format_detail.c_str(), endian_name(image.endian), image.bits);
  std::printf("Arch:      %s\n", architecture_name(image.architecture));
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
           ", \"name\": " + quote(symbol.name) + ", \"module\": " + quote(symbol.module) +
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

bool load(const std::string& path, LoadedBinary& loaded) {
  auto result = load_binary(path);
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
  if (!load(options.path, loaded)) {
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
  if (!load(request.path, loaded)) {
    return kExitFailure;
  }
  AnalysisOptions options;
  options.max_instructions = request.max_instructions;
  options.max_strings = request.max_strings;
  options.min_string_length = request.min_string_length;
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
               ", \"address\": " + quote(hex(function.address)) +
               ", \"exported\": " + (function.exported ? "true" : "false") +
               ", \"from_symbol\": " + (function.from_symbol ? "true" : "false") + "}";
      }
      out += analysis.functions.empty() ? "]\n" : "\n  ]\n";
      out += "}\n";
      std::fwrite(out.data(), 1, out.size(), stdout);
    } else {
      for (const auto& function : analysis.functions) {
        std::printf("%-18s %s%s\n", hex(function.address).c_str(),
                    display_name(function.name).c_str(), function.exported ? " [export]" : "");
      }
      std::printf("(%zu function seeds)\n", analysis.functions.size());
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
           ", \"strings\": " + std::to_string(analysis.strings.size()) + "},\n";
    out += "  \"functions\": [";
    for (std::size_t i = 0; i < analysis.functions.size(); ++i) {
      const auto& function = analysis.functions[i];
      out += i == 0 ? "\n" : ",\n";
      out += "    {\"name\": " + quote(display_name(function.name)) +
             ", \"address\": " + quote(hex(function.address)) +
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
    std::printf("Functions:    %zu seeds\n", analysis.functions.size());
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
  std::fprintf(out,
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
               "  donkey-cli functions <binary> [--json] [--max-instructions N]\n"
               "  donkey-cli xrefs <binary> [--json] [--address A]\n"
               "  donkey-cli analyze <binary> [--json] [--max-instructions N]\n"
               "\n"
               "All commands only read the file; nothing is executed.\n",
               std::string(version()).c_str());
}

int command_info(const std::vector<std::string_view>& arguments) {
  InfoOptions options;
  for (std::size_t i = 0; i < arguments.size(); ++i) {
    const std::string_view argument = arguments[i];
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
  if (!load(options.path, loaded)) {
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

int command_xrefs(const std::vector<std::string_view>& arguments) {
  AnalysisRequest request;
  for (std::size_t i = 0; i < arguments.size(); ++i) {
    const std::string_view argument = arguments[i];
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

}  // namespace donkey::cli
