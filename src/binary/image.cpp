#include "donkey/binary/image.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iterator>
#include <tuple>

#include "donkey/core/checked.h"
#include "donkey/core/sha256.h"
#include "parsers.h"

namespace donkey {
namespace {

Diagnostic error(Status status, std::string code, std::string message,
                 std::optional<std::uint64_t> offset = std::nullopt) {
  return Diagnostic::make(status, std::move(code), std::move(message), offset);
}

bool matches(std::span<const std::byte> data, std::uint64_t offset,
             std::initializer_list<unsigned char> bytes) {
  if (offset > data.size() || bytes.size() > data.size() - offset) {
    return false;
  }
  std::size_t i = 0;
  for (const unsigned char byte : bytes) {
    if (static_cast<unsigned char>(data[static_cast<std::size_t>(offset) + i]) != byte) {
      return false;
    }
    ++i;
  }
  return true;
}

Result<BinaryFormat> detect_format(std::span<const std::byte> data) {
  if (matches(data, 0, {0x7F, 'E', 'L', 'F'})) {
    return BinaryFormat::Elf;
  }
  if (matches(data, 0, {'M', 'Z'})) {
    return BinaryFormat::Pe;
  }
  if (data.size() >= 4) {
    ByteReader reader(data);
    auto magic = reader.u32(0, Endian::Little);
    if (magic) {
      switch (magic.value()) {
        case 0xFEEDFACEU:
        case 0xFEEDFACFU:
        case 0xCEFAEDFEU:
        case 0xCFFAEDFEU:
        case 0xCAFEBABEU:
        case 0xBEBAFECAU:
          return BinaryFormat::MachO;
        default:
          break;
      }
    }
  }
  return BinaryFormat::Raw;
}

Result<void> parse_raw(ByteReader reader, BinaryImage& image) {
  image.format = BinaryFormat::Raw;
  image.architecture = Architecture::Unknown;
  image.format_detail = "raw bytes";
  Section section;
  section.id = SectionId{1};
  section.name = "raw";
  section.type = "raw";
  section.file_offset = 0;
  section.file_size = reader.size();
  section.virtual_size = reader.size();
  section.address = 0;
  section.readable = true;
  image.sections.push_back(section);

  Segment segment;
  segment.index = 0;
  segment.name = "raw";
  segment.file_offset = 0;
  segment.file_size = reader.size();
  segment.virtual_size = reader.size();
  segment.virtual_address = 0;
  segment.readable = true;
  image.segments.push_back(segment);
  return {};
}

}  // namespace

const char* format_name(BinaryFormat format) noexcept {
  switch (format) {
    case BinaryFormat::Unknown:
      return "Unknown";
    case BinaryFormat::Raw:
      return "Raw";
    case BinaryFormat::Elf:
      return "ELF";
    case BinaryFormat::Pe:
      return "PE";
    case BinaryFormat::MachO:
      return "Mach-O";
  }
  return "Unknown";
}

const char* architecture_name(Architecture architecture) noexcept {
  switch (architecture) {
    case Architecture::Unknown:
      return "unknown";
    case Architecture::X86:
      return "x86";
    case Architecture::X86_64:
      return "x86_64";
    case Architecture::Arm:
      return "arm";
    case Architecture::AArch64:
      return "aarch64";
    case Architecture::RiscV64:
      return "riscv64";
  }
  return "unknown";
}

const char* symbol_kind_name(SymbolKind kind) noexcept {
  switch (kind) {
    case SymbolKind::Unknown:
      return "unknown";
    case SymbolKind::Function:
      return "function";
    case SymbolKind::Object:
      return "object";
    case SymbolKind::Section:
      return "section";
    case SymbolKind::File:
      return "file";
    case SymbolKind::Import:
      return "import";
    case SymbolKind::Export:
      return "export";
  }
  return "unknown";
}

const char* symbol_binding_name(SymbolBinding binding) noexcept {
  switch (binding) {
    case SymbolBinding::Unknown:
      return "unknown";
    case SymbolBinding::Local:
      return "local";
    case SymbolBinding::Global:
      return "global";
    case SymbolBinding::Weak:
      return "weak";
  }
  return "unknown";
}

void BinaryImage::add_diagnostic(Status status, std::string code, std::string message,
                                 std::optional<std::uint64_t> offset) {
  diagnostics.push_back(Diagnostic::make(status, std::move(code), std::move(message), offset));
}

Result<std::uint64_t> BinaryImage::va_to_file_offset(std::uint64_t va) const {
  for (const Segment& segment : segments) {
    if (segment.file_size == 0) {
      continue;
    }
    if (va >= segment.virtual_address && va - segment.virtual_address < segment.file_size) {
      std::uint64_t offset = 0;
      if (!checked::add_overflow(segment.file_offset, va - segment.virtual_address, offset)) {
        return offset;
      }
    }
  }
  for (const Section& section : sections) {
    // Sections without an address (ELF .symtab/.strtab/.shstrtab, Mach-O debug
    // data) live only in the file and must never claim VA space.
    if (section.address == 0 || !section.has_file_data || section.file_size == 0) {
      continue;
    }
    if (va >= section.address && va - section.address < section.file_size) {
      std::uint64_t offset = 0;
      if (!checked::add_overflow(section.file_offset, va - section.address, offset)) {
        return offset;
      }
    }
  }
  return error(Status::InvalidInput, "image.unmapped_va",
               "virtual address is not backed by file data", va);
}

Result<std::uint64_t> BinaryImage::file_offset_to_va(std::uint64_t file_offset) const {
  for (const Segment& segment : segments) {
    if (segment.file_size == 0) {
      continue;
    }
    if (file_offset >= segment.file_offset &&
        file_offset - segment.file_offset < segment.file_size) {
      std::uint64_t address = 0;
      if (!checked::add_overflow(segment.virtual_address, file_offset - segment.file_offset,
                                 address)) {
        return address;
      }
    }
  }
  for (const Section& section : sections) {
    if (section.address == 0 || !section.has_file_data || section.file_size == 0) {
      continue;
    }
    if (file_offset >= section.file_offset &&
        file_offset - section.file_offset < section.file_size) {
      std::uint64_t address = 0;
      if (!checked::add_overflow(section.address, file_offset - section.file_offset, address)) {
        return address;
      }
    }
  }
  return error(Status::InvalidInput, "image.unmapped_offset",
               "file offset is not backed by a mapped segment", file_offset);
}

const Section* BinaryImage::section_for_va(std::uint64_t va) const noexcept {
  for (const Section& section : sections) {
    if (section.address == 0) {
      continue;
    }
    if (va >= section.address && va - section.address < section.virtual_size) {
      return &section;
    }
  }
  return nullptr;
}

const Segment* BinaryImage::segment_for_va(std::uint64_t va) const noexcept {
  for (const Segment& segment : segments) {
    if (va >= segment.virtual_address && va - segment.virtual_address < segment.virtual_size) {
      return &segment;
    }
  }
  return nullptr;
}

const Symbol* BinaryImage::symbol_at(std::uint64_t va) const noexcept {
  for (const Symbol& symbol : symbols) {
    if (symbol.address == va && symbol.kind != SymbolKind::Import) {
      return &symbol;
    }
  }
  return nullptr;
}

Result<BinaryImage> parse_binary(std::span<const std::byte> data, std::string path) {
  BinaryImage image;
  image.path = std::move(path);
  image.file_size = static_cast<std::uint64_t>(data.size());
  image.sha256 = Sha256::hex(data);

  if (data.empty()) {
    return error(Status::InvalidInput, "image.empty_file", "the file is empty", 0);
  }

  const ByteReader reader(data);
  auto format = detect_format(data);
  if (!format) {
    return format.diagnostic();
  }
  image.format = format.value();

  switch (image.format) {
    case BinaryFormat::Elf:
      if (auto parsed = binary::detail::parse_elf(reader, image); !parsed) {
        return parsed.diagnostic();
      }
      break;
    case BinaryFormat::Pe:
      if (auto parsed = binary::detail::parse_pe(reader, image); !parsed) {
        return parsed.diagnostic();
      }
      break;
    case BinaryFormat::MachO:
      if (auto parsed = binary::detail::parse_macho(reader, image); !parsed) {
        return parsed.diagnostic();
      }
      break;
    case BinaryFormat::Raw:
      if (auto parsed = parse_raw(reader, image); !parsed) {
        return parsed.diagnostic();
      }
      break;
    case BinaryFormat::Unknown:
      return error(Status::InternalError, "image.unknown_format",
                   "format detection returned an unknown format", 0);
  }

  // Assign stable IDs in deterministic order.
  for (std::size_t i = 0; i < image.sections.size(); ++i) {
    image.sections[i].id = SectionId{i + 1};
  }
  for (std::size_t i = 0; i < image.symbols.size(); ++i) {
    image.symbols[i].id = SymbolId{i + 1};
  }
  return image;
}

Result<LoadedBinary> load_binary(const std::string& path, const LoadOptions& options) {
  std::ifstream file(path, std::ios::binary | std::ios::ate);
  if (!file) {
    return error(Status::InvalidInput, "io.open_failed", "could not open the file for reading");
  }
  const std::streampos end = file.tellg();
  if (end < 0) {
    return error(Status::InvalidInput, "io.size_failed", "could not determine the file size");
  }
  const auto size = static_cast<std::uint64_t>(end);
  if (size > options.max_file_bytes) {
    return error(Status::ResourceLimit, "io.file_too_large",
                 "file exceeds the configured size limit");
  }
  if (size == 0) {
    return error(Status::InvalidInput, "image.empty_file", "the file is empty");
  }

  std::vector<std::byte> data(static_cast<std::size_t>(size));
  file.seekg(0, std::ios::beg);
  file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
  if (!file || static_cast<std::uint64_t>(file.gcount()) != size) {
    return error(Status::InvalidInput, "io.read_failed", "could not read the whole file");
  }
  auto image = parse_binary(std::span<const std::byte>(data.data(), data.size()), path);
  if (!image) {
    return image.diagnostic();
  }
  return LoadedBinary{std::move(image.value()), std::move(data)};
}

Result<BinaryImage> load_binary_file(const std::string& path, const LoadOptions& options) {
  auto loaded = load_binary(path, options);
  if (!loaded) {
    return loaded.diagnostic();
  }
  return std::move(loaded.value().image);
}

}  // namespace donkey
