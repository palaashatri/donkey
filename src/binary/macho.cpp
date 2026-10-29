#include <algorithm>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <tuple>

#include "donkey/core/checked.h"
#include "parsers.h"

namespace donkey::binary::detail {
namespace {

constexpr std::uint32_t kLcSegment64 = 0x19;
constexpr std::uint32_t kLcSymtab = 0x2;
constexpr std::uint32_t kLcMain = 0x80000028;
constexpr std::uint64_t kMaxLoadCommands = 4096;
constexpr std::uint64_t kMaxSections = 65536;
constexpr std::uint64_t kMaxSymbols = 1'000'000;
constexpr std::uint64_t kMaxFatArchitectures = 64;
constexpr std::uint64_t kMaxNameLength = 4096;

Diagnostic macho_error(Status status, std::string code, std::string message, std::uint64_t offset) {
  return Diagnostic::make(status, std::move(code), std::move(message), offset);
}

Architecture cpu_to_architecture(std::uint32_t cputype) noexcept {
  switch (cputype) {
    case 7:
      return Architecture::X86;
    case 0x01000007:
      return Architecture::X86_64;
    case 12:
      return Architecture::Arm;
    case 0x0100000C:
      return Architecture::AArch64;
    default:
      return Architecture::Unknown;
  }
}

const char* filetype_name(std::uint32_t filetype) noexcept {
  switch (filetype) {
    case 1:
      return "MH_OBJECT";
    case 2:
      return "MH_EXECUTE";
    case 6:
      return "MH_DYLIB";
    case 7:
      return "MH_DYLINKER";
    case 8:
      return "MH_BUNDLE";
    case 9:
      return "MH_DYLIB_STUB";
    case 10:
      return "MH_DSYM";
    default:
      return "MH_UNKNOWN";
  }
}

std::string fixed_name(const ByteReader& reader, std::uint64_t offset, std::uint64_t length) {
  auto bytes = reader.slice(offset, length);
  if (!bytes) {
    return {};
  }
  std::string name(reinterpret_cast<const char*>(bytes.value().data()),
                   static_cast<std::size_t>(bytes.value().size()));
  const std::size_t terminator = name.find('\0');
  if (terminator != std::string::npos) {
    name.resize(terminator);
  }
  return name;
}

bool is_zerofill(std::uint32_t flags) noexcept {
  const std::uint32_t type = flags & 0xFFU;
  return type == 0x1U || type == 0xCU || type == 0x12U;
}

Result<void> parse_thin(ByteReader reader, BinaryImage& image, std::uint64_t base, bool is_fat) {
  auto cputype = reader.u32(4, image.endian);
  if (!cputype) return cputype.diagnostic();
  auto filetype = reader.u32(12, image.endian);
  if (!filetype) return filetype.diagnostic();
  auto command_count = reader.u32(16, image.endian);
  if (!command_count) return command_count.diagnostic();
  auto command_bytes = reader.u32(20, image.endian);
  if (!command_bytes) return command_bytes.diagnostic();
  auto flags = reader.u32(24, image.endian);
  if (!flags) return flags.diagnostic();

  image.architecture = cpu_to_architecture(cputype.value());
  image.bits = 64;
  image.format_detail = std::string("Mach-O 64 (") + filetype_name(filetype.value()) +
                        (is_fat ? ", fat slice)" : ")");

  if (command_count.value() > kMaxLoadCommands) {
    return macho_error(Status::ResourceLimit, "macho.too_many_load_commands",
                       "load command count exceeds the limit", 16);
  }
  if (!checked::in_range(32, command_bytes.value(), reader.size())) {
    return macho_error(Status::InvalidInput, "macho.load_commands_out_of_bounds",
                       "load commands extend past end of file", 20);
  }

  struct SymbolTable {
    std::uint32_t symbol_offset = 0;
    std::uint32_t symbol_count = 0;
    std::uint32_t string_offset = 0;
    std::uint32_t string_size = 0;
    bool present = false;
  } symtab;
  std::optional<std::uint64_t> entry_offset;

  std::uint64_t command_offset = 32;
  const std::uint64_t command_limit = 32 + command_bytes.value();
  for (std::uint64_t i = 0; i < command_count.value(); ++i) {
    auto command_header = reader.slice(command_offset, 8);
    if (!command_header) {
      return command_header.diagnostic();
    }
    const ByteReader header(command_header.value());
    auto command = header.u32(0, image.endian);
    auto size = header.u32(4, image.endian);
    if (!command || !size) {
      return macho_error(Status::InternalError, "macho.command_read",
                         "failed to read a validated load command", command_offset);
    }
    if (size.value() < 8 || size.value() > command_limit - command_offset) {
      return macho_error(Status::InvalidInput, "macho.bad_load_command_size",
                         "load command size is invalid", command_offset);
    }

    if (command.value() == kLcSegment64) {
      if (size.value() < 72) {
        return macho_error(Status::InvalidInput, "macho.short_segment_command",
                           "LC_SEGMENT_64 is too small", command_offset);
      }
      auto segment_bytes = reader.slice(command_offset, size.value());
      if (!segment_bytes) {
        return segment_bytes.diagnostic();
      }
      const ByteReader segment(segment_bytes.value());
      const std::string segment_name = fixed_name(segment, 8, 16);
      auto vmaddr = segment.u64(24, image.endian);
      auto vmsize = segment.u64(32, image.endian);
      auto fileoff = segment.u64(40, image.endian);
      auto filesize = segment.u64(48, image.endian);
      auto initprot = segment.u32(60, image.endian);
      auto section_count = segment.u32(64, image.endian);
      if (!vmaddr || !vmsize || !fileoff || !filesize || !initprot || !section_count) {
        return macho_error(Status::InternalError, "macho.segment_read",
                           "failed to read a validated segment", command_offset);
      }
      if (section_count.value() > kMaxSections ||
          image.sections.size() + section_count.value() > kMaxSections) {
        return macho_error(Status::ResourceLimit, "macho.too_many_sections",
                           "section count exceeds the limit", command_offset);
      }
      const std::uint64_t section_bytes_needed =
          72 + static_cast<std::uint64_t>(section_count.value()) * 80;
      if (section_bytes_needed > size.value()) {
        return macho_error(Status::InvalidInput, "macho.truncated_sections",
                           "segment section list exceeds the load command", command_offset);
      }
      if (filesize.value() != 0 &&
          !checked::in_range(fileoff.value(), filesize.value(), reader.size())) {
        return macho_error(Status::InvalidInput, "macho.segment_out_of_bounds",
                           "segment extends past end of file", fileoff.value());
      }

      Segment parsed_segment;
      parsed_segment.index = static_cast<std::uint32_t>(image.segments.size());
      parsed_segment.name = sanitize_name(segment_name);
      parsed_segment.file_offset = base + fileoff.value();
      parsed_segment.file_size = filesize.value();
      parsed_segment.virtual_address = vmaddr.value();
      parsed_segment.virtual_size = vmsize.value();
      parsed_segment.readable = (initprot.value() & 1U) != 0;
      parsed_segment.writable = (initprot.value() & 2U) != 0;
      parsed_segment.executable = (initprot.value() & 4U) != 0;
      image.segments.push_back(parsed_segment);

      for (std::uint64_t s = 0; s < section_count.value(); ++s) {
        const std::uint64_t at = 72 + s * 80;
        auto name = fixed_name(segment, at, 16);
        auto segment_for_section = fixed_name(segment, at + 16, 16);
        auto address = segment.u64(at + 32, image.endian);
        auto section_size = segment.u64(at + 40, image.endian);
        auto file_offset = segment.u32(at + 48, image.endian);
        auto alignment = segment.u32(at + 52, image.endian);
        auto section_flags = segment.u32(at + 64, image.endian);
        if (!address || !section_size || !file_offset || !alignment || !section_flags) {
          return macho_error(Status::InternalError, "macho.section_read",
                             "failed to read a validated section", command_offset + at);
        }
        Section parsed_section;
        parsed_section.id = SectionId{image.sections.size() + 1};
        parsed_section.name =
            sanitize_name(segment_for_section.empty() ? name : segment_for_section + "," + name);
        parsed_section.type = "macho_section";
        parsed_section.address = address.value();
        parsed_section.virtual_size = section_size.value();
        const bool zerofill = is_zerofill(section_flags.value());
        parsed_section.has_file_data = !zerofill;
        parsed_section.file_size = zerofill ? 0 : section_size.value();
        parsed_section.file_offset = zerofill ? 0 : base + file_offset.value();
        parsed_section.alignment = alignment.value();
        parsed_section.executable = (section_flags.value() & 0x80000000U) != 0 ||
                                    (section_flags.value() & 0x00000400U) != 0;
        parsed_section.readable = parsed_segment.readable;
        parsed_section.writable = parsed_segment.writable;
        if (!zerofill && parsed_section.file_size != 0 &&
            !checked::in_range(parsed_section.file_offset, parsed_section.file_size,
                               image.file_size)) {
          return macho_error(Status::InvalidInput, "macho.section_out_of_bounds",
                             "section extends past end of file", parsed_section.file_offset);
        }
        image.sections.push_back(std::move(parsed_section));
      }
    } else if (command.value() == kLcMain) {
      if (size.value() < 16) {
        return macho_error(Status::InvalidInput, "macho.short_main_command", "LC_MAIN is too small",
                           command_offset);
      }
      auto offset = reader.u64(command_offset + 8, image.endian);
      if (!offset) {
        return offset.diagnostic();
      }
      entry_offset = offset.value();
    } else if (command.value() == kLcSymtab) {
      if (size.value() < 24) {
        return macho_error(Status::InvalidInput, "macho.short_symtab_command",
                           "LC_SYMTAB is too small", command_offset);
      }
      auto symbol_offset = reader.u32(command_offset + 8, image.endian);
      auto symbol_count = reader.u32(command_offset + 12, image.endian);
      auto string_offset = reader.u32(command_offset + 16, image.endian);
      auto string_size = reader.u32(command_offset + 20, image.endian);
      if (!symbol_offset || !symbol_count || !string_offset || !string_size) {
        return macho_error(Status::InternalError, "macho.symtab_read",
                           "failed to read a validated LC_SYMTAB", command_offset);
      }
      symtab = SymbolTable{symbol_offset.value(), symbol_count.value(), string_offset.value(),
                           string_size.value(), true};
    }

    command_offset += size.value();
  }

  // Preferred image base is the lowest file-backed segment address. Skip
  // __PAGEZERO, which has no file data and address 0.
  bool have_base = false;
  for (const Segment& segment : image.segments) {
    if (segment.file_size == 0 || segment.virtual_address == 0) {
      continue;
    }
    if (!have_base || segment.virtual_address < image.image_base) {
      image.image_base = segment.virtual_address;
      have_base = true;
    }
  }

  // Entry point: LC_MAIN stores a file offset relative to __TEXT.
  if (entry_offset.has_value()) {
    const Segment* text = nullptr;
    for (const Segment& segment : image.segments) {
      if (segment.name == "__TEXT") {
        text = &segment;
        break;
      }
    }
    if (text != nullptr) {
      auto text_fileoff = text->file_offset - base;
      if (entry_offset.value() >= text_fileoff) {
        image.entry_point = text->virtual_address + (entry_offset.value() - text_fileoff);
      }
    }
  } else if (filetype.value() == 2 || filetype.value() == 6 || filetype.value() == 7 ||
             filetype.value() == 8) {
    image.partial = true;
    image.add_diagnostic(Status::Partial, "macho.entry_point_unavailable",
                         "no LC_MAIN load command; entry point is unknown");
  }

  if (symtab.present) {
    if (symtab.symbol_count > kMaxSymbols) {
      return macho_error(Status::ResourceLimit, "macho.too_many_symbols",
                         "symbol count exceeds the limit", symtab.symbol_offset);
    }
    if (!checked::in_range(symtab.symbol_offset,
                           static_cast<std::uint64_t>(symtab.symbol_count) * 16, reader.size()) ||
        !checked::in_range(symtab.string_offset, symtab.string_size, reader.size())) {
      return macho_error(Status::InvalidInput, "macho.symbol_table_out_of_bounds",
                         "symbol table extends past end of file", symtab.symbol_offset);
    }
    auto strings = reader.slice(symtab.string_offset, symtab.string_size);
    if (!strings) {
      return strings.diagnostic();
    }
    const std::string_view strings_view(reinterpret_cast<const char*>(strings.value().data()),
                                        static_cast<std::size_t>(strings.value().size()));

    using Key = std::tuple<std::string, std::uint64_t, std::uint8_t>;
    std::set<Key> seen;
    for (std::uint64_t i = 0; i < symtab.symbol_count; ++i) {
      const std::uint64_t at = symtab.symbol_offset + i * 16;
      auto string_index = reader.u32(at, image.endian);
      auto type = reader.u8(at + 4);
      auto section_index = reader.u8(at + 5);
      auto value = reader.u64(at + 8, image.endian);
      if (!string_index || !type || !section_index || !value) {
        return macho_error(Status::InternalError, "macho.symbol_read",
                           "failed to read a validated symbol", at);
      }
      if ((type.value() & 0xE0U) != 0) {
        continue;  // N_STAB debug symbol
      }
      if (string_index.value() == 0 || string_index.value() >= strings_view.size()) {
        continue;
      }
      const std::size_t available = strings_view.size() - string_index.value();
      const std::size_t max_length =
          available < kMaxNameLength ? available : static_cast<std::size_t>(kMaxNameLength);
      const std::string_view raw_name = strings_view.substr(string_index.value(), max_length);
      const std::size_t terminator = raw_name.find('\0');
      if (terminator == std::string_view::npos) {
        return macho_error(Status::InvalidInput, "macho.unterminated_symbol_name",
                           "symbol name is not NUL-terminated", at);
      }
      if (terminator == 0) {
        continue;
      }
      Symbol symbol;
      symbol.name = sanitize_name(raw_name.substr(0, terminator));
      symbol.address = value.value();
      const std::uint8_t n_type = static_cast<std::uint8_t>(type.value() & 0x0EU);
      if (n_type == 0x0U) {
        symbol.kind = SymbolKind::Import;
        symbol.imported = true;
        symbol.binding = SymbolBinding::Global;
      } else {
        symbol.kind = SymbolKind::Object;
        if (n_type == 0xEU && section_index.value() >= 1 &&
            static_cast<std::size_t>(section_index.value()) <= image.sections.size()) {
          const Section& section = image.sections[section_index.value() - 1];
          if (section.executable) {
            symbol.kind = SymbolKind::Function;
          }
        }
        symbol.exported = (type.value() & 0x01U) != 0;
        symbol.binding = symbol.exported ? SymbolBinding::Global : SymbolBinding::Local;
      }
      const bool inserted =
          seen.emplace(symbol.name, symbol.address, static_cast<std::uint8_t>(symbol.kind)).second;
      if (inserted) {
        image.symbols.push_back(std::move(symbol));
      }
    }
  }
  return {};
}

}  // namespace

Result<void> parse_macho(ByteReader reader, BinaryImage& image) {
  const auto little = reader.u32(0, Endian::Little);
  const auto big = reader.u32(0, Endian::Big);
  if (!little || !big) {
    return macho_error(Status::InvalidInput, "macho.truncated_header", "Mach-O header is truncated",
                       0);
  }

  const bool thin64_little = little.value() == 0xFEEDFACFU;
  const bool thin64_big = big.value() == 0xFEEDFACFU;
  const bool thin32_little = little.value() == 0xFEEDFACEU;
  const bool thin32_big = big.value() == 0xFEEDFACEU;
  const bool fat_big = big.value() == 0xCAFEBABEU;
  const bool fat_little = little.value() == 0xCAFEBABEU;

  if (thin32_little || thin32_big) {
    return macho_error(Status::Unsupported, "macho.unsupported_32_bit",
                       "only 64-bit Mach-O images are supported", 0);
  }

  if (thin64_little || thin64_big) {
    image.endian = thin64_little ? Endian::Little : Endian::Big;
    return parse_thin(reader, image, 0, false);
  }

  if (!fat_big && !fat_little) {
    return macho_error(Status::InvalidInput, "macho.bad_magic", "unrecognized Mach-O magic", 0);
  }

  const Endian fat_endian = fat_big ? Endian::Big : Endian::Little;
  auto architecture_count = reader.u32(4, fat_endian);
  if (!architecture_count) {
    return architecture_count.diagnostic();
  }
  if (architecture_count.value() == 0 || architecture_count.value() > kMaxFatArchitectures) {
    return macho_error(Status::ResourceLimit, "macho.bad_fat_count",
                       "fat architecture count is invalid", 4);
  }

  struct Slice {
    std::uint32_t cpu = 0;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
  };
  std::optional<Slice> chosen;
  for (std::uint64_t i = 0; i < architecture_count.value(); ++i) {
    const std::uint64_t at = 8 + i * 20;
    auto cpu = reader.u32(at, fat_endian);
    auto offset = reader.u32(at + 8, fat_endian);
    auto size = reader.u32(at + 12, fat_endian);
    if (!cpu || !offset || !size) {
      return macho_error(Status::InternalError, "macho.fat_arch_read",
                         "failed to read a validated fat architecture", at);
    }
    if (!checked::in_range(offset.value(), size.value(), reader.size())) {
      return macho_error(Status::InvalidInput, "macho.fat_slice_out_of_bounds",
                         "fat slice extends past end of file", offset.value());
    }
    const Slice slice{cpu.value(), offset.value(), size.value()};
    if (!chosen.has_value()) {
      chosen = slice;
    }
    if (slice.cpu == 0x0100000CU) {  // arm64 preferred
      chosen = slice;
      break;
    }
    if (slice.cpu == 0x01000007U && chosen->cpu != 0x0100000CU) {
      chosen = slice;
    }
  }
  if (!chosen.has_value()) {
    return macho_error(Status::InvalidInput, "macho.empty_fat", "fat binary contains no slices", 4);
  }

  auto slice_bytes = reader.slice(chosen->offset, chosen->size);
  if (!slice_bytes) {
    return slice_bytes.diagnostic();
  }
  const ByteReader thin(slice_bytes.value());
  const auto thin_little = thin.u32(0, Endian::Little);
  const auto thin_big = thin.u32(0, Endian::Big);
  if (!thin_little || !thin_big) {
    return macho_error(Status::InvalidInput, "macho.truncated_slice",
                       "fat slice is too small for a Mach-O header", chosen->offset);
  }
  if (thin_little.value() == 0xFEEDFACFU) {
    image.endian = Endian::Little;
  } else if (thin_big.value() == 0xFEEDFACFU) {
    image.endian = Endian::Big;
  } else {
    return macho_error(Status::Unsupported, "macho.unsupported_slice",
                       "selected fat slice is not a 64-bit Mach-O image", chosen->offset);
  }
  return parse_thin(thin, image, chosen->offset, true);
}

}  // namespace donkey::binary::detail
