#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/core/status.h"
#include "donkey/core/version.h"

namespace {

constexpr int kExitOk = 0;
constexpr int kExitFailure = 1;
constexpr int kExitUsage = 2;

std::string hex(std::uint64_t value) {
  char buffer[32];
  std::snprintf(buffer, sizeof(buffer), "0x%" PRIx64, value);
  return buffer;
}

std::string json_escape(std::string_view input) {
  std::string out;
  out.reserve(input.size() + 2);
  for (const char ch : input) {
    const auto byte = static_cast<unsigned char>(ch);
    switch (ch) {
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
        if (byte < 0x20U) {
          char escaped[8];
          std::snprintf(escaped, sizeof(escaped), "\\u%04x", byte);
          out += escaped;
        } else {
          out.push_back(ch);
        }
    }
  }
  return out;
}

std::string quote(std::string_view input) {
  return "\"" + json_escape(input) + "\"";
}

std::string permissions(bool readable, bool writable, bool executable) {
  std::string out = "---";
  out[0] = readable ? 'r' : '-';
  out[1] = writable ? 'w' : '-';
  out[2] = executable ? 'x' : '-';
  return out;
}

std::string permissions(const donkey::Section& section) {
  return permissions(section.readable, section.writable, section.executable);
}

std::string permissions(const donkey::Segment& segment) {
  return permissions(segment.readable, segment.writable, segment.executable);
}

void print_usage(std::FILE* out) {
  std::fprintf(out,
               "donkey-cli %s - headless binary analysis\n"
               "\n"
               "Usage:\n"
               "  donkey-cli --version\n"
               "  donkey-cli --help\n"
               "  donkey-cli info <binary> [--json] [--max-symbols N]\n"
               "\n"
               "All commands only read the file; nothing is executed.\n",
               std::string(donkey::version()).c_str());
}

void print_diagnostic(const donkey::Diagnostic& diagnostic) {
  std::fprintf(stderr, "error [%s]: %s", diagnostic.code.c_str(), diagnostic.message.c_str());
  if (diagnostic.offset.has_value()) {
    std::fprintf(stderr, " (at file offset 0x%" PRIx64 ")", *diagnostic.offset);
  }
  std::fprintf(stderr, "\n");
}

int parse_error_exit(const donkey::Diagnostic& diagnostic) {
  print_diagnostic(diagnostic);
  return kExitFailure;
}

struct InfoOptions {
  std::string path;
  bool json = false;
  std::size_t max_symbols = 10000;
};

void print_human(const donkey::BinaryImage& image, std::size_t max_symbols) {
  std::printf("File:      %s\n", image.path.c_str());
  std::printf("Size:      %" PRIu64 " bytes\n", image.file_size);
  std::printf("SHA-256:   %s\n", image.sha256.c_str());
  std::printf("Format:    %s (%s), %s-endian, %u-bit\n", donkey::format_name(image.format),
              image.format_detail.c_str(), donkey::endian_name(image.endian), image.bits);
  std::printf("Arch:      %s\n", donkey::architecture_name(image.architecture));
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
                permissions(section).c_str());
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
      std::printf("  [%s] %s: %s\n", donkey::status_name(diagnostic.status),
                  diagnostic.code.c_str(), diagnostic.message.c_str());
    }
  }
}

std::string info_json(const donkey::BinaryImage& image, std::size_t max_symbols) {
  std::string out;
  out.reserve(4096);
  out += "{\n";
  out += "  \"schema_version\": " + std::to_string(donkey::kJsonSchemaVersion) + ",\n";
  out += "  \"tool\": \"donkey-cli\",\n";
  out += "  \"tool_version\": " + quote(donkey::version()) + ",\n";
  out += "  \"status\": " + quote(image.partial ? "Partial" : "Complete") + ",\n";
  out += "  \"file\": {\n";
  out += "    \"path\": " + quote(image.path) + ",\n";
  out += "    \"size\": " + std::to_string(image.file_size) + ",\n";
  out += "    \"sha256\": " + quote(image.sha256) + "\n";
  out += "  },\n";
  out += "  \"image\": {\n";
  out += "    \"format\": " + quote(donkey::format_name(image.format)) + ",\n";
  out += "    \"format_detail\": " + quote(image.format_detail) + ",\n";
  out += "    \"bits\": " + std::to_string(image.bits) + ",\n";
  out += "    \"endian\": " + quote(donkey::endian_name(image.endian)) + ",\n";
  out += "    \"architecture\": " + quote(donkey::architecture_name(image.architecture)) + ",\n";
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
           ", \"file_size\": " + std::to_string(segment.file_size) +
           ", \"permissions\": " + quote(permissions(segment)) + "}";
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
           ", \"file_size\": " + std::to_string(section.file_size) +
           ", \"permissions\": " + quote(permissions(section)) + "}";
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
           ", \"binding\": " + quote(donkey::symbol_binding_name(symbol.binding)) + "}";
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
    out += "    {\"status\": " + quote(donkey::status_name(diagnostic.status)) +
           ", \"code\": " + quote(diagnostic.code) + ", \"message\": " + quote(diagnostic.message) +
           "}";
  }
  out += image.diagnostics.empty() ? "]\n" : "\n  ]\n";
  out += "}\n";
  return out;
}

int command_info(const std::vector<std::string_view>& arguments) {
  InfoOptions options;
  for (std::size_t i = 0; i < arguments.size(); ++i) {
    const std::string_view argument = arguments[i];
    if (argument == "--json") {
      options.json = true;
    } else if (argument == "--max-symbols") {
      if (i + 1 >= arguments.size()) {
        std::fprintf(stderr, "donkey-cli: --max-symbols needs a value\n");
        return kExitUsage;
      }
      const std::string value(arguments[++i]);
      try {
        const auto parsed = std::stoull(value);
        options.max_symbols = static_cast<std::size_t>(parsed);
      } catch (const std::exception&) {
        std::fprintf(stderr, "donkey-cli: invalid --max-symbols value\n");
        return kExitUsage;
      }
    } else if (!argument.empty() && argument.front() == '-') {
      std::fprintf(stderr, "donkey-cli: unknown option '%.*s'\n", static_cast<int>(argument.size()),
                   argument.data());
      return kExitUsage;
    } else if (options.path.empty()) {
      options.path = std::string(argument);
    } else {
      std::fprintf(stderr, "donkey-cli: info accepts exactly one file\n");
      return kExitUsage;
    }
  }
  if (options.path.empty()) {
    std::fprintf(stderr, "donkey-cli: info needs a file path\n");
    return kExitUsage;
  }

  auto image = donkey::load_binary_file(options.path);
  if (!image) {
    return parse_error_exit(image.diagnostic());
  }
  if (options.json) {
    const std::string output = info_json(image.value(), options.max_symbols);
    std::fwrite(output.data(), 1, output.size(), stdout);
  } else {
    print_human(image.value(), options.max_symbols);
  }
  return kExitOk;
}

}  // namespace

int main(int argc, char** argv) {
  std::vector<std::string_view> arguments;
  arguments.reserve(static_cast<std::size_t>(argc > 0 ? argc - 1 : 0));
  for (int i = 1; i < argc; ++i) {
    arguments.emplace_back(argv[i]);
  }

  if (arguments.empty()) {
    print_usage(stderr);
    return kExitUsage;
  }
  const std::string_view command = arguments[0];
  const std::vector<std::string_view> rest(arguments.begin() + 1, arguments.end());

  if (command == "--version" || command == "-V") {
    std::printf("donkey-cli %s\n", std::string(donkey::version()).c_str());
    return kExitOk;
  }
  if (command == "--help" || command == "-h") {
    print_usage(stdout);
    return kExitOk;
  }
  if (command == "info") {
    return command_info(rest);
  }

  std::fprintf(stderr, "donkey-cli: unknown command '%.*s'\n", static_cast<int>(command.size()),
               command.data());
  print_usage(stderr);
  return kExitUsage;
}
