#include <algorithm>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include "donkey/core/checked.h"
#include "parsers.h"

namespace donkey::binary::detail {
namespace {

constexpr std::uint64_t kMaxSections = 65536;
constexpr std::uint64_t kMaxSegments = 4096;
constexpr std::uint64_t kMaxSymbols = 1'000'000;
constexpr std::uint64_t kMaxNameLength = 4096;

Diagnostic elf_error(Status status, std::string code, std::string message, std::uint64_t offset) {
  return Diagnostic::make(status, std::move(code), std::move(message), offset);
}

const char* elf_type_name(std::uint16_t type) noexcept {
  switch (type) {
    case 1:
      return "ET_REL";
    case 2:
      return "ET_EXEC";
    case 3:
      return "ET_DYN";
    case 4:
      return "ET_CORE";
    default:
      return "ET_UNKNOWN";
  }
}

Architecture machine_to_architecture(std::uint16_t machine) noexcept {
  switch (machine) {
    case 3:
      return Architecture::X86;
    case 62:
      return Architecture::X86_64;
    case 40:
      return Architecture::Arm;
    case 183:
      return Architecture::AArch64;
    case 243:
      return Architecture::RiscV64;
    default:
      return Architecture::Unknown;
  }
}

struct RawSection {
  std::uint32_t name_offset = 0;
  std::uint32_t type = 0;
  std::uint32_t link = 0;
  std::uint64_t flags = 0;
  std::uint64_t address = 0;
  std::uint64_t offset = 0;
  std::uint64_t size = 0;
  std::uint64_t alignment = 0;
  std::uint64_t entry_size = 0;
};

}  // namespace

Result<void> parse_elf(ByteReader reader, BinaryImage& image) {
  const auto ident = reader.slice(0, 16);
  if (!ident) {
    return ident.diagnostic();
  }
  const auto* bytes = ident.value().data();
  const auto elf_class = static_cast<std::uint8_t>(bytes[4]);
  const auto data_encoding = static_cast<std::uint8_t>(bytes[5]);
  if (elf_class != 2) {
    return elf_error(Status::Unsupported, "elf.unsupported_class",
                     "only 64-bit ELF images are supported", 4);
  }
  Endian endian = Endian::Little;
  if (data_encoding == 1) {
    endian = Endian::Little;
  } else if (data_encoding == 2) {
    endian = Endian::Big;
  } else {
    return elf_error(Status::InvalidInput, "elf.bad_data_encoding", "invalid ELF data encoding", 5);
  }
  if (static_cast<std::uint8_t>(bytes[6]) != 1) {
    return elf_error(Status::InvalidInput, "elf.unsupported_version",
                     "unsupported ELF identification version", 6);
  }

  image.endian = endian;
  image.bits = 64;

  auto read16 = [&](std::uint64_t offset) { return reader.u16(offset, endian); };
  auto read32 = [&](std::uint64_t offset) { return reader.u32(offset, endian); };
  auto read64 = [&](std::uint64_t offset) { return reader.u64(offset, endian); };

  auto type = read16(16);
  if (!type) return type.diagnostic();
  auto machine = read16(18);
  if (!machine) return machine.diagnostic();
  auto version = read32(20);
  if (!version) return version.diagnostic();
  auto entry = read64(24);
  if (!entry) return entry.diagnostic();
  auto program_offset = read64(32);
  if (!program_offset) return program_offset.diagnostic();
  auto section_offset = read64(40);
  if (!section_offset) return section_offset.diagnostic();
  auto program_entry_size = read16(54);
  if (!program_entry_size) return program_entry_size.diagnostic();
  auto program_count = read16(56);
  if (!program_count) return program_count.diagnostic();
  auto section_entry_size = read16(58);
  if (!section_entry_size) return section_entry_size.diagnostic();
  auto section_count = read16(60);
  if (!section_count) return section_count.diagnostic();
  auto shstr_index = read16(62);
  if (!shstr_index) return shstr_index.diagnostic();

  if (version.value() != 1) {
    return elf_error(Status::Unsupported, "elf.unsupported_version",
                     "unsupported ELF header version", 20);
  }

  image.architecture = machine_to_architecture(machine.value());
  image.entry_point = entry.value();
  image.format_detail = std::string(elf_type_name(type.value())) + " ELF64";

  // Program headers: mapped segments.
  std::uint64_t lowest_load = 0;
  bool have_load = false;
  const std::uint64_t ph_count = program_count.value();
  if (ph_count != 0) {
    if (program_entry_size.value() < 56) {
      return elf_error(Status::InvalidInput, "elf.bad_program_header_size",
                       "program header entry is too small", 54);
    }
    if (ph_count > kMaxSegments) {
      return elf_error(Status::ResourceLimit, "elf.too_many_segments",
                       "program header count exceeds the limit", 56);
    }
    for (std::uint64_t i = 0; i < ph_count; ++i) {
      std::uint64_t header_offset = 0;
      if (checked::add_overflow(program_offset.value(), i * program_entry_size.value(),
                                header_offset)) {
        return elf_error(Status::InvalidInput, "elf.program_header_overflow",
                         "program header table overflows", 32);
      }
      auto header = reader.slice(header_offset, 56);
      if (!header) {
        return header.diagnostic();
      }
      const ByteReader ph(header.value());
      auto p_type = ph.u32(0, endian);
      auto p_flags = ph.u32(4, endian);
      auto p_offset = ph.u64(8, endian);
      auto p_vaddr = ph.u64(16, endian);
      auto p_filesz = ph.u64(32, endian);
      auto p_memsz = ph.u64(40, endian);
      if (!p_type || !p_flags || !p_offset || !p_vaddr || !p_filesz || !p_memsz) {
        return elf_error(Status::InternalError, "elf.program_header_read",
                         "failed to read a validated program header", header_offset);
      }
      if (p_type.value() != 1) {
        continue;  // PT_LOAD only
      }
      if (!checked::in_range(p_offset.value(), p_filesz.value(), reader.size())) {
        return elf_error(Status::InvalidInput, "elf.segment_out_of_bounds",
                         "loadable segment extends past end of file", p_offset.value());
      }
      Segment segment;
      segment.index = static_cast<std::uint32_t>(image.segments.size());
      segment.name = "LOAD";
      segment.file_offset = p_offset.value();
      segment.file_size = p_filesz.value();
      segment.virtual_address = p_vaddr.value();
      segment.virtual_size = p_memsz.value();
      segment.readable = (p_flags.value() & 4U) != 0;
      segment.writable = (p_flags.value() & 2U) != 0;
      segment.executable = (p_flags.value() & 1U) != 0;
      image.segments.push_back(segment);
      if (!have_load || p_vaddr.value() < lowest_load) {
        lowest_load = p_vaddr.value();
        have_load = true;
      }
    }
  }
  image.image_base = have_load ? lowest_load : 0;

  // Section headers: two passes so names can be resolved after the string
  // table has been validated.
  std::uint64_t sh_count = section_count.value();
  if (sh_count == 0 && section_offset.value() != 0) {
    std::uint64_t extended_offset = 0;
    if (!checked::add_overflow(section_offset.value(), 32, extended_offset)) {
      return elf_error(Status::InvalidInput, "elf.section_header_overflow",
                       "section header table overflows", section_offset.value());
    }
    auto extended = read64(extended_offset);
    if (!extended) {
      return extended.diagnostic();
    }
    sh_count = extended.value();
    if (sh_count > kMaxSections) {
      return elf_error(Status::ResourceLimit, "elf.too_many_sections",
                       "extended section count exceeds the limit", 60);
    }
  }
  std::uint64_t shstr = shstr_index.value();
  if (shstr == 0xFFFFU && section_offset.value() != 0) {
    std::uint64_t extended_offset = 0;
    if (!checked::add_overflow(section_offset.value(), 40, extended_offset)) {
      return elf_error(Status::InvalidInput, "elf.section_header_overflow",
                       "section header table overflows", section_offset.value());
    }
    auto extended = read32(extended_offset);
    if (!extended) {
      return extended.diagnostic();
    }
    shstr = extended.value();
  }

  std::vector<RawSection> raw_sections;
  if (sh_count != 0) {
    if (section_entry_size.value() < 64) {
      return elf_error(Status::InvalidInput, "elf.bad_section_header_size",
                       "section header entry is too small", 58);
    }
    if (sh_count > kMaxSections) {
      return elf_error(Status::ResourceLimit, "elf.too_many_sections",
                       "section count exceeds the limit", 60);
    }
    raw_sections.reserve(static_cast<std::size_t>(sh_count));
    for (std::uint64_t i = 0; i < sh_count; ++i) {
      std::uint64_t header_offset = 0;
      if (checked::add_overflow(section_offset.value(), i * section_entry_size.value(),
                                header_offset)) {
        return elf_error(Status::InvalidInput, "elf.section_header_overflow",
                         "section header table overflows", 40);
      }
      auto header = reader.slice(header_offset, 64);
      if (!header) {
        return header.diagnostic();
      }
      const ByteReader sh(header.value());
      RawSection raw;
      auto name_offset = sh.u32(0, endian);
      auto sh_type = sh.u32(4, endian);
      auto flags = sh.u64(8, endian);
      auto address = sh.u64(16, endian);
      auto offset = sh.u64(24, endian);
      auto size = sh.u64(32, endian);
      auto link = sh.u32(40, endian);
      auto alignment = sh.u64(48, endian);
      auto entry_size = sh.u64(56, endian);
      if (!name_offset || !sh_type || !flags || !address || !offset || !size || !link ||
          !alignment || !entry_size) {
        return elf_error(Status::InternalError, "elf.section_header_read",
                         "failed to read a validated section header", header_offset);
      }
      raw.name_offset = name_offset.value();
      raw.type = sh_type.value();
      raw.flags = flags.value();
      raw.address = address.value();
      raw.offset = offset.value();
      raw.size = size.value();
      raw.link = link.value();
      raw.alignment = alignment.value();
      raw.entry_size = entry_size.value();
      if (raw.type != 8 /* SHT_NOBITS */ &&
          !checked::in_range(raw.offset, raw.size, reader.size())) {
        return elf_error(Status::InvalidInput, "elf.section_out_of_bounds",
                         "section extends past end of file", raw.offset);
      }
      raw_sections.push_back(raw);
    }
  }

  std::string_view string_table;
  if (shstr < raw_sections.size() && raw_sections[shstr].type != 8) {
    auto table = reader.slice(raw_sections[shstr].offset, raw_sections[shstr].size);
    if (!table) {
      return table.diagnostic();
    }
    string_table = std::string_view(reinterpret_cast<const char*>(table.value().data()),
                                    static_cast<std::size_t>(table.value().size()));
  }

  for (std::size_t i = 0; i < raw_sections.size(); ++i) {
    const RawSection& raw = raw_sections[i];
    Section section;
    section.id = SectionId{i + 1};
    if (!string_table.empty() && raw.name_offset < string_table.size()) {
      section.name = sanitize_name(string_table.substr(
          raw.name_offset, string_table.find('\0', raw.name_offset) - raw.name_offset));
    } else {
      section.name = "<unnamed>";
    }
    section.type = "elf_section";
    section.file_offset = raw.offset;
    section.file_size = raw.type == 8 ? 0 : raw.size;
    section.address = raw.address;
    section.virtual_size = raw.size;
    section.alignment = raw.alignment;
    section.has_file_data = raw.type != 8;
    section.readable = (raw.flags & 0x2U) != 0;    // SHF_ALLOC
    section.writable = (raw.flags & 0x1U) != 0;    // SHF_WRITE
    section.executable = (raw.flags & 0x4U) != 0;  // SHF_EXECINSTR
    image.sections.push_back(std::move(section));
  }

  // Symbols from .symtab and .dynsym.
  using Key = std::tuple<std::string, std::uint64_t, std::uint8_t, bool>;
  std::set<Key> seen;
  std::size_t symbol_count = 0;
  for (const RawSection& raw : raw_sections) {
    if (raw.type != 2 && raw.type != 11) {
      continue;
    }
    if (raw.entry_size < 24 || raw.link >= raw_sections.size()) {
      continue;
    }
    const RawSection& strings = raw_sections[raw.link];
    if (strings.type == 8 || strings.size == 0) {
      continue;
    }
    if (!checked::in_range(strings.offset, strings.size, reader.size())) {
      return elf_error(Status::InvalidInput, "elf.symbol_strings_out_of_bounds",
                       "symbol string table extends past end of file", strings.offset);
    }
    auto string_bytes = reader.slice(strings.offset, strings.size);
    if (!string_bytes) {
      return string_bytes.diagnostic();
    }
    const auto* str_data = reinterpret_cast<const char*>(string_bytes.value().data());
    const std::string_view str_view(str_data, static_cast<std::size_t>(strings.size));

    const std::uint64_t count = raw.size / raw.entry_size;
    for (std::uint64_t i = 0; i < count; ++i) {
      if (symbol_count >= kMaxSymbols) {
        return elf_error(Status::ResourceLimit, "elf.too_many_symbols",
                         "symbol count exceeds the limit", raw.offset);
      }
      std::uint64_t entry_offset = 0;
      if (checked::add_overflow(raw.offset, i * raw.entry_size, entry_offset)) {
        return elf_error(Status::InvalidInput, "elf.symbol_overflow", "symbol table overflows",
                         raw.offset);
      }
      auto symbol_entry = reader.slice(entry_offset, 24);
      if (!symbol_entry) {
        return symbol_entry.diagnostic();
      }
      const ByteReader sym(symbol_entry.value());
      auto name_offset = sym.u32(0, endian);
      auto info = sym.u8(4);
      auto other = sym.u8(5);
      auto section_index = sym.u16(6, endian);
      auto value = sym.u64(8, endian);
      auto size = sym.u64(16, endian);
      if (!name_offset || !info || !other || !section_index || !value || !size) {
        return elf_error(Status::InternalError, "elf.symbol_read",
                         "failed to read a validated symbol", entry_offset);
      }
      ++symbol_count;

      const std::uint8_t symbol_type = static_cast<std::uint8_t>(info.value() & 0x0FU);
      if (symbol_type == 3 || symbol_type == 4) {  // STT_SECTION, STT_FILE
        continue;
      }
      if (name_offset.value() == 0 || name_offset.value() >= str_view.size()) {
        continue;
      }
      const std::size_t available = str_view.size() - name_offset.value();
      const std::size_t max_length =
          available < kMaxNameLength ? available : static_cast<std::size_t>(kMaxNameLength);
      const std::string_view raw_name = str_view.substr(name_offset.value(), max_length);
      const std::size_t terminator = raw_name.find('\0');
      if (terminator == std::string_view::npos) {
        return elf_error(Status::InvalidInput, "elf.unterminated_symbol_name",
                         "symbol name is not NUL-terminated", entry_offset);
      }
      if (terminator == 0) {
        continue;
      }
      Symbol symbol;
      symbol.name = sanitize_name(raw_name.substr(0, terminator));
      symbol.address = value.value();
      symbol.size = size.value();
      symbol.imported = section_index.value() == 0;
      const std::uint8_t binding = static_cast<std::uint8_t>(info.value() >> 4U);
      symbol.binding = binding == 0   ? SymbolBinding::Local
                       : binding == 1 ? SymbolBinding::Global
                       : binding == 2 ? SymbolBinding::Weak
                                      : SymbolBinding::Unknown;
      symbol.kind = symbol_type == 2 || symbol_type == 10 ? SymbolKind::Function
                    : symbol_type == 1                    ? SymbolKind::Object
                                                          : SymbolKind::Unknown;
      symbol.exported = !symbol.imported && binding != 0;
      if (symbol.imported) {
        symbol.kind = SymbolKind::Import;
        symbol.exported = false;
      }
      if (symbol.name == "<unnamed>") {
        continue;
      }
      const bool inserted = seen.emplace(symbol.name, symbol.address,
                                         static_cast<std::uint8_t>(symbol.kind), symbol.imported)
                                .second;
      if (inserted) {
        image.symbols.push_back(std::move(symbol));
      }
    }
  }

  if (raw_sections.empty()) {
    image.partial = true;
    image.add_diagnostic(Status::Partial, "elf.no_sections",
                         "section headers are unavailable (stripped image)");
  }
  return {};
}

}  // namespace donkey::binary::detail
