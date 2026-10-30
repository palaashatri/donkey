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
  if (elf_class != 1 && elf_class != 2) {
    return elf_error(Status::Unsupported, "elf.unsupported_class",
                     "only 32-bit and 64-bit ELF images are supported", 4);
  }
  const bool is_64 = elf_class == 2;
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
  image.bits = is_64 ? 64 : 32;

  auto read16 = [&](std::uint64_t offset) { return reader.u16(offset, endian); };
  auto read32 = [&](std::uint64_t offset) { return reader.u32(offset, endian); };
  auto read64 = [&](std::uint64_t offset) { return reader.u64(offset, endian); };
  // ELF32 stores every address/offset in 32 bits; widen into the 64-bit fields.
  auto read_word = [&](std::uint64_t offset) -> Result<std::uint64_t> {
    if (is_64) {
      return read64(offset);
    }
    auto value = read32(offset);
    if (!value) {
      return value.diagnostic();
    }
    return static_cast<std::uint64_t>(value.value());
  };

  // e_entry, e_phoff, e_shoff and the entry-size/count pairs sit at different
  // offsets in the two header layouts (e_phoff/e_shoff in 32-bit are u32).
  const auto header_field = [&](std::uint64_t field_64, std::uint64_t field_32) {
    return is_64 ? field_64 : field_32;
  };

  auto type = read16(16);
  if (!type) return type.diagnostic();
  auto machine = read16(18);
  if (!machine) return machine.diagnostic();
  auto version = read32(20);
  if (!version) return version.diagnostic();
  auto entry = read_word(24);
  if (!entry) return entry.diagnostic();
  auto program_offset = read_word(header_field(32, 28));
  if (!program_offset) return program_offset.diagnostic();
  auto section_offset = read_word(header_field(40, 32));
  if (!section_offset) return section_offset.diagnostic();
  auto program_entry_size = read16(header_field(54, 42));
  if (!program_entry_size) return program_entry_size.diagnostic();
  auto program_count = read16(header_field(56, 44));
  if (!program_count) return program_count.diagnostic();
  auto section_entry_size = read16(header_field(58, 46));
  if (!section_entry_size) return section_entry_size.diagnostic();
  auto section_count = read16(header_field(60, 48));
  if (!section_count) return section_count.diagnostic();
  auto shstr_index = read16(header_field(62, 50));
  if (!shstr_index) return shstr_index.diagnostic();

  if (version.value() != 1) {
    return elf_error(Status::Unsupported, "elf.unsupported_version",
                     "unsupported ELF header version", 20);
  }

  image.architecture = machine_to_architecture(machine.value());
  image.entry_point = entry.value();
  image.format_detail = std::string(elf_type_name(type.value())) + (is_64 ? " ELF64" : " ELF32");

  // Program headers: mapped segments.
  std::uint64_t lowest_load = 0;
  bool have_load = false;
  const std::uint64_t ph_count = program_count.value();
  if (ph_count != 0) {
    const std::uint64_t program_header_size = is_64 ? 56 : 32;
    if (program_entry_size.value() < program_header_size) {
      return elf_error(Status::InvalidInput, "elf.bad_program_header_size",
                       "program header entry is too small", is_64 ? 54 : 42);
    }
    if (ph_count > kMaxSegments) {
      return elf_error(Status::ResourceLimit, "elf.too_many_segments",
                       "program header count exceeds the limit", is_64 ? 56 : 44);
    }
    for (std::uint64_t i = 0; i < ph_count; ++i) {
      std::uint64_t header_offset = 0;
      if (checked::add_overflow(program_offset.value(), i * program_entry_size.value(),
                                header_offset)) {
        return elf_error(Status::InvalidInput, "elf.program_header_overflow",
                         "program header table overflows", is_64 ? 32 : 28);
      }
      auto header = reader.slice(header_offset, program_header_size);
      if (!header) {
        return header.diagnostic();
      }
      const ByteReader ph(header.value());
      Result<std::uint32_t> p_type = elf_error(Status::InternalError, "elf.program_header_read",
                                               "internal program header read", header_offset);
      Result<std::uint32_t> p_flags = p_type;
      Result<std::uint64_t> p_offset = p_type.diagnostic();
      Result<std::uint64_t> p_vaddr = p_offset;
      Result<std::uint64_t> p_filesz = p_offset;
      Result<std::uint64_t> p_memsz = p_offset;
      if (is_64) {
        p_type = ph.u32(0, endian);
        p_flags = ph.u32(4, endian);
        p_offset = ph.u64(8, endian);
        p_vaddr = ph.u64(16, endian);
        p_filesz = ph.u64(32, endian);
        p_memsz = ph.u64(40, endian);
      } else {
        // Elf32_Phdr: type, offset, vaddr, paddr, filesz, memsz, flags, align.
        p_type = ph.u32(0, endian);
        auto offset32 = ph.u32(4, endian);
        auto vaddr32 = ph.u32(8, endian);
        auto filesz32 = ph.u32(16, endian);
        auto memsz32 = ph.u32(20, endian);
        p_flags = ph.u32(24, endian);
        if (offset32) p_offset = static_cast<std::uint64_t>(offset32.value());
        if (vaddr32) p_vaddr = static_cast<std::uint64_t>(vaddr32.value());
        if (filesz32) p_filesz = static_cast<std::uint64_t>(filesz32.value());
        if (memsz32) p_memsz = static_cast<std::uint64_t>(memsz32.value());
      }
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
    // ELF reserves sh_size of section 0 for the real count when shnum is 0.
    std::uint64_t extended_offset = 0;
    if (!checked::add_overflow(section_offset.value(), is_64 ? 32 : 20, extended_offset)) {
      return elf_error(Status::InvalidInput, "elf.section_header_overflow",
                       "section header table overflows", section_offset.value());
    }
    auto extended = read_word(extended_offset);
    if (!extended) {
      return extended.diagnostic();
    }
    sh_count = extended.value();
    if (sh_count > kMaxSections) {
      return elf_error(Status::ResourceLimit, "elf.too_many_sections",
                       "extended section count exceeds the limit", is_64 ? 60 : 48);
    }
  }
  std::uint64_t shstr = shstr_index.value();
  if (shstr == 0xFFFFU && section_offset.value() != 0) {
    // sh_link of section 0 holds the real string-table index.
    std::uint64_t extended_offset = 0;
    if (!checked::add_overflow(section_offset.value(), is_64 ? 40 : 24, extended_offset)) {
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
    const std::uint64_t section_header_size = is_64 ? 64 : 40;
    if (section_entry_size.value() < section_header_size) {
      return elf_error(Status::InvalidInput, "elf.bad_section_header_size",
                       "section header entry is too small", is_64 ? 58 : 46);
    }
    if (sh_count > kMaxSections) {
      return elf_error(Status::ResourceLimit, "elf.too_many_sections",
                       "section count exceeds the limit", is_64 ? 60 : 48);
    }
    raw_sections.reserve(static_cast<std::size_t>(sh_count));
    for (std::uint64_t i = 0; i < sh_count; ++i) {
      std::uint64_t header_offset = 0;
      if (checked::add_overflow(section_offset.value(), i * section_entry_size.value(),
                                header_offset)) {
        return elf_error(Status::InvalidInput, "elf.section_header_overflow",
                         "section header table overflows", is_64 ? 40 : 32);
      }
      auto header = reader.slice(header_offset, section_header_size);
      if (!header) {
        return header.diagnostic();
      }
      const ByteReader sh(header.value());
      RawSection raw;
      auto name_offset = sh.u32(0, endian);
      auto sh_type = sh.u32(4, endian);
      bool ok = name_offset.has_value() && sh_type.has_value();
      std::uint64_t flags = 0;
      std::uint64_t address = 0;
      std::uint64_t offset = 0;
      std::uint64_t size = 0;
      std::uint32_t link = 0;
      std::uint64_t alignment = 0;
      std::uint64_t entry_size = 0;
      if (is_64) {
        auto f = sh.u64(8, endian);
        auto a = sh.u64(16, endian);
        auto o = sh.u64(24, endian);
        auto s = sh.u64(32, endian);
        auto l = sh.u32(40, endian);
        auto al = sh.u64(48, endian);
        auto es = sh.u64(56, endian);
        ok = ok && f && a && o && s && l && al && es;
        if (ok) {
          flags = f.value();
          address = a.value();
          offset = o.value();
          size = s.value();
          link = l.value();
          alignment = al.value();
          entry_size = es.value();
        }
      } else {
        // Elf32_Shdr: flags and addresses are 32-bit.
        auto f = sh.u32(8, endian);
        auto a = sh.u32(12, endian);
        auto o = sh.u32(16, endian);
        auto s = sh.u32(20, endian);
        auto l = sh.u32(24, endian);
        auto al = sh.u32(32, endian);
        auto es = sh.u32(36, endian);
        ok = ok && f && a && o && s && l && al && es;
        if (ok) {
          flags = f.value();
          address = a.value();
          offset = o.value();
          size = s.value();
          link = l.value();
          alignment = al.value();
          entry_size = es.value();
        }
      }
      if (!ok) {
        return elf_error(Status::InternalError, "elf.section_header_read",
                         "failed to read a validated section header", header_offset);
      }
      raw.name_offset = name_offset.value();
      raw.type = sh_type.value();
      raw.flags = flags;
      raw.address = address;
      raw.offset = offset;
      raw.size = size;
      raw.link = link;
      raw.alignment = alignment;
      raw.entry_size = entry_size;
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
  const std::uint64_t symbol_entry_size = is_64 ? 24 : 16;
  for (const RawSection& raw : raw_sections) {
    if (raw.type != 2 && raw.type != 11) {
      continue;
    }
    if (raw.entry_size < symbol_entry_size || raw.link >= raw_sections.size()) {
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
      auto symbol_entry = reader.slice(entry_offset, symbol_entry_size);
      if (!symbol_entry) {
        return symbol_entry.diagnostic();
      }
      const ByteReader sym(symbol_entry.value());
      auto name_offset = sym.u32(0, endian);
      bool ok = name_offset.has_value();
      std::uint8_t info = 0;
      std::uint16_t section_index = 0;
      std::uint64_t value = 0;
      std::uint64_t size = 0;
      if (is_64) {
        // Elf64_Sym: name, info, other, shndx, value, size.
        auto info_byte = sym.u8(4);
        auto other_byte = sym.u8(5);
        auto shndx = sym.u16(6, endian);
        auto v = sym.u64(8, endian);
        auto s = sym.u64(16, endian);
        ok = ok && info_byte && other_byte && shndx && v && s;
        if (ok) {
          info = info_byte.value();
          section_index = shndx.value();
          value = v.value();
          size = s.value();
        }
      } else {
        // Elf32_Sym: name, value, size, info, other, shndx.
        auto v = sym.u32(4, endian);
        auto s = sym.u32(8, endian);
        auto info_byte = sym.u8(12);
        auto other_byte = sym.u8(13);
        auto shndx = sym.u16(14, endian);
        ok = ok && v && s && info_byte && other_byte && shndx;
        if (ok) {
          info = info_byte.value();
          section_index = shndx.value();
          value = v.value();
          size = s.value();
        }
      }
      if (!ok) {
        return elf_error(Status::InternalError, "elf.symbol_read",
                         "failed to read a validated symbol", entry_offset);
      }
      ++symbol_count;

      const std::uint8_t symbol_type = static_cast<std::uint8_t>(info & 0x0FU);
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
      symbol.address = value;
      symbol.size = size;
      symbol.imported = section_index == 0;
      const std::uint8_t binding = static_cast<std::uint8_t>(info >> 4U);
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
