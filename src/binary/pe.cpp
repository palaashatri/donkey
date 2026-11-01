#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <utility>

#include "donkey/core/checked.h"
#include "parsers.h"

namespace donkey::binary::detail {
namespace {

constexpr std::uint64_t kMaxSections = 4096;
constexpr std::uint64_t kMaxImportDescriptors = 4096;
constexpr std::uint64_t kMaxThunks = 65536;
constexpr std::uint64_t kMaxExports = 65536;
constexpr std::uint64_t kMaxSymbols = 200000;
constexpr std::uint64_t kMaxNameLength = 512;

Diagnostic pe_error(Status status, std::string code, std::string message, std::uint64_t offset) {
  return Diagnostic::make(status, std::move(code), std::move(message), offset);
}

Architecture machine_to_architecture(std::uint16_t machine) noexcept {
  switch (machine) {
    case 0x014C:
      return Architecture::X86;
    case 0x8664:
      return Architecture::X86_64;
    case 0x01C0:
    case 0x01C4:
      return Architecture::Arm;
    case 0xAA64:
      return Architecture::AArch64;
    default:
      return Architecture::Unknown;
  }
}

struct SectionRecord {
  std::uint32_t virtual_address = 0;
  std::uint32_t virtual_size = 0;
  std::uint32_t raw_offset = 0;
  std::uint32_t raw_size = 0;
};

}  // namespace

Result<std::uint64_t> rva_to_file_offset(const BinaryImage& image, std::uint64_t rva) {
  for (const Section& section : image.sections) {
    if (!section.has_file_data || section.file_size == 0) {
      continue;
    }
    const std::uint64_t section_rva = section.address - image.image_base;
    if (rva >= section_rva && rva - section_rva < section.file_size) {
      std::uint64_t offset = 0;
      if (!checked::add_overflow(section.file_offset, rva - section_rva, offset)) {
        return offset;
      }
    }
  }
  if (rva < image.file_size) {
    return rva;  // headers and other non-section-backed data
  }
  return pe_error(Status::InvalidInput, "pe.unmapped_rva", "RVA is not backed by file data", rva);
}

Result<void> parse_pe(ByteReader reader, BinaryImage& image) {
  auto mz = reader.u16(0, Endian::Little);
  if (!mz || mz.value() != 0x5A4D) {
    return pe_error(Status::InvalidInput, "pe.bad_dos_magic", "missing MZ signature", 0);
  }
  auto lfanew = reader.u32(0x3C, Endian::Little);
  if (!lfanew) {
    return lfanew.diagnostic();
  }
  const std::uint64_t pe_offset = lfanew.value();
  auto signature = reader.slice(pe_offset, 4);
  if (!signature) {
    return signature.diagnostic();
  }
  const auto* sig = signature.value().data();
  if (static_cast<std::uint8_t>(sig[0]) != 'P' || static_cast<std::uint8_t>(sig[1]) != 'E' ||
      static_cast<std::uint8_t>(sig[2]) != 0 || static_cast<std::uint8_t>(sig[3]) != 0) {
    return pe_error(Status::InvalidInput, "pe.bad_signature", "missing PE signature", pe_offset);
  }

  const std::uint64_t coff = pe_offset + 4;
  auto machine = reader.u16(coff, Endian::Little);
  if (!machine) return machine.diagnostic();
  auto section_count = reader.u16(coff + 2, Endian::Little);
  if (!section_count) return section_count.diagnostic();
  auto symbol_table = reader.u32(coff + 8, Endian::Little);
  if (!symbol_table) return symbol_table.diagnostic();
  auto symbol_count = reader.u32(coff + 12, Endian::Little);
  if (!symbol_count) return symbol_count.diagnostic();
  auto optional_size = reader.u16(coff + 16, Endian::Little);
  if (!optional_size) return optional_size.diagnostic();
  auto characteristics = reader.u16(coff + 18, Endian::Little);
  if (!characteristics) return characteristics.diagnostic();

  image.architecture = machine_to_architecture(machine.value());
  image.endian = Endian::Little;

  const std::uint64_t optional = coff + 20;
  auto magic = reader.u16(optional, Endian::Little);
  if (!magic) return magic.diagnostic();
  const bool plus = magic.value() == 0x20B;
  if (!plus && magic.value() != 0x10B) {
    return pe_error(Status::Unsupported, "pe.unsupported_optional_magic",
                    "unknown PE optional header magic", optional);
  }
  image.bits = plus ? 64 : 32;
  image.format_detail = plus ? "PE32+" : "PE32";

  auto entry_rva = reader.u32(optional + 16, Endian::Little);
  if (!entry_rva) return entry_rva.diagnostic();
  auto image_base32 = reader.u32(optional + 28, Endian::Little);
  if (!image_base32) return image_base32.diagnostic();
  std::uint64_t image_base = image_base32.value();
  if (plus) {
    auto base64 = reader.u64(optional + 24, Endian::Little);
    if (!base64) return base64.diagnostic();
    image_base = base64.value();
  }
  image.image_base = image_base;
  image.entry_point = image_base + entry_rva.value();

  const std::uint64_t directory_count_offset = optional + (plus ? 108 : 92);
  const std::uint64_t directory_offset = optional + (plus ? 112 : 96);
  auto directory_count = reader.u32(directory_count_offset, Endian::Little);
  if (!directory_count) return directory_count.diagnostic();
  const std::uint64_t dirs = std::min<std::uint64_t>(directory_count.value(), 16);
  if (optional_size.value() < (directory_offset - optional) + dirs * 8) {
    return pe_error(Status::InvalidInput, "pe.truncated_data_directories",
                    "data directories extend past the optional header", optional);
  }

  struct DataDirectory {
    std::uint32_t rva = 0;
    std::uint32_t size = 0;
  };
  std::vector<DataDirectory> directories(static_cast<std::size_t>(dirs));
  for (std::uint64_t i = 0; i < dirs; ++i) {
    auto rva = reader.u32(directory_offset + i * 8, Endian::Little);
    auto size = reader.u32(directory_offset + i * 8 + 4, Endian::Little);
    if (!rva || !size) {
      return pe_error(Status::InternalError, "pe.directory_read",
                      "failed to read a validated data directory", directory_offset);
    }
    directories[i] = DataDirectory{rva.value(), size.value()};
  }

  // COFF string table: it follows the COFF symbol table and holds section
  // names longer than 8 bytes ("/N" in the header) and long symbol names.
  // MinGW puts ".debug_info" and friends there.
  std::uint64_t string_table_offset = 0;
  std::uint64_t string_table_size = 0;
  if (symbol_table.value() != 0) {
    std::uint64_t symbol_bytes = 0;
    std::uint64_t table_offset = 0;
    if (!checked::mul_overflow(symbol_count.value(), 18, symbol_bytes) &&
        !checked::add_overflow(symbol_table.value(), symbol_bytes, table_offset)) {
      auto declared = reader.u32(table_offset, Endian::Little);
      if (declared && declared.value() >= 4 &&
          checked::in_range(table_offset, declared.value(), reader.size())) {
        string_table_offset = table_offset;
        string_table_size = declared.value();
      }
    }
  }
  auto coff_string = [&](std::uint64_t offset) -> std::optional<std::string> {
    if (string_table_size == 0 || offset < 4 || offset >= string_table_size) {
      return std::nullopt;
    }
    const std::uint64_t limit = std::min<std::uint64_t>(kMaxNameLength, string_table_size - offset);
    auto text = reader.c_string(string_table_offset + offset, limit);
    if (!text) {
      return std::nullopt;
    }
    return sanitize_name(text.value());
  };

  if (section_count.value() > kMaxSections) {
    return pe_error(Status::ResourceLimit, "pe.too_many_sections",
                    "section count exceeds the limit", coff + 2);
  }
  const std::uint64_t section_table = optional + optional_size.value();
  if (!checked::in_range(section_table, std::uint64_t{section_count.value()} * 40, reader.size())) {
    return pe_error(Status::InvalidInput, "pe.section_table_out_of_bounds",
                    "section table extends past end of file", section_table);
  }

  std::vector<SectionRecord> records;
  records.reserve(section_count.value());
  for (std::uint64_t i = 0; i < section_count.value(); ++i) {
    const std::uint64_t offset = section_table + i * 40;
    auto header = reader.slice(offset, 40);
    if (!header) {
      return header.diagnostic();
    }
    const ByteReader sh(header.value());
    auto name = sh.slice(0, 8);
    auto virtual_size = sh.u32(8, Endian::Little);
    auto virtual_address = sh.u32(12, Endian::Little);
    auto raw_size = sh.u32(16, Endian::Little);
    auto raw_offset = sh.u32(20, Endian::Little);
    auto section_flags = sh.u32(36, Endian::Little);
    if (!name || !virtual_size || !virtual_address || !raw_size || !raw_offset || !section_flags) {
      return pe_error(Status::InternalError, "pe.section_read",
                      "failed to read a validated section header", offset);
    }
    const std::string raw_name(reinterpret_cast<const char*>(name.value().data()),
                               name.value().size());
    const std::size_t terminator = raw_name.find('\0');
    const std::string_view display_name = terminator == std::string::npos
                                              ? std::string_view(raw_name)
                                              : std::string_view(raw_name).substr(0, terminator);

    if (raw_size.value() != 0 &&
        !checked::in_range(raw_offset.value(), raw_size.value(), reader.size())) {
      return pe_error(Status::InvalidInput, "pe.section_out_of_bounds",
                      "section data extends past end of file", raw_offset.value());
    }

    Section section;
    section.id = SectionId{i + 1};
    section.name = sanitize_name(display_name);
    // "/123": the real name is at offset 123 of the COFF string table.
    if (display_name.size() > 1 && display_name.size() <= 8 && display_name[0] == '/' &&
        display_name.substr(1).find_first_not_of("0123456789") == std::string_view::npos) {
      const std::uint64_t at =
          std::strtoull(std::string(display_name.substr(1)).c_str(), nullptr, 10);
      if (auto long_name = coff_string(at); long_name.has_value() && !long_name->empty()) {
        section.name = *long_name;
      } else {
        image.add_diagnostic(Status::Partial, "pe.bad_long_section_name",
                             "section name refers outside the COFF string table", offset);
      }
    }
    section.type = "pe_section";
    section.file_offset = raw_offset.value();
    section.file_size = raw_size.value();
    section.address = image_base + virtual_address.value();
    section.virtual_size = std::max(virtual_size.value(), raw_size.value());
    section.has_file_data = raw_size.value() != 0;
    section.readable = (section_flags.value() & 0x40000000U) != 0;
    section.writable = (section_flags.value() & 0x80000000U) != 0;
    section.executable = (section_flags.value() & 0x20000000U) != 0;
    image.sections.push_back(section);

    Segment segment;
    segment.index = static_cast<std::uint32_t>(i);
    segment.name = section.name;
    segment.file_offset = section.file_offset;
    segment.file_size = section.file_size;
    segment.virtual_address = section.address;
    segment.virtual_size = section.virtual_size;
    segment.readable = section.readable;
    segment.writable = section.writable;
    segment.executable = section.executable;
    image.segments.push_back(segment);
    records.push_back(SectionRecord{virtual_address.value(), virtual_size.value(),
                                    raw_offset.value(), raw_size.value()});
  }

  auto read_c_string = [&](std::uint64_t rva, std::string& out) -> Result<void> {
    auto offset = rva_to_file_offset(image, rva);
    if (!offset) {
      return offset.diagnostic();
    }
    auto text = reader.c_string(offset.value(), kMaxNameLength);
    if (!text) {
      return text.diagnostic();
    }
    out = sanitize_name(text.value());
    return {};
  };

  auto add_symbol = [&](Symbol symbol) {
    if (image.symbols.size() >= kMaxSymbols) {
      return false;
    }
    image.symbols.push_back(std::move(symbol));
    return true;
  };

  // Imports (data directory index 1).
  if (directories.size() > 1 && directories[1].rva != 0) {
    auto descriptor_offset = rva_to_file_offset(image, directories[1].rva);
    if (!descriptor_offset) {
      return descriptor_offset.diagnostic();
    }
    const std::uint64_t pointer_size = plus ? 8 : 4;
    for (std::uint64_t i = 0; i < kMaxImportDescriptors; ++i) {
      const std::uint64_t offset = descriptor_offset.value() + i * 20;
      auto descriptor = reader.slice(offset, 20);
      if (!descriptor) {
        return descriptor.diagnostic();
      }
      const ByteReader entry(descriptor.value());
      auto original_thunk = entry.u32(0, Endian::Little);
      auto name_rva = entry.u32(12, Endian::Little);
      auto first_thunk = entry.u32(16, Endian::Little);
      if (!original_thunk || !name_rva || !first_thunk) {
        return pe_error(Status::InternalError, "pe.import_read",
                        "failed to read a validated import descriptor", offset);
      }
      if (original_thunk.value() == 0 && name_rva.value() == 0 && first_thunk.value() == 0) {
        break;
      }
      std::string module;
      auto module_result = read_c_string(name_rva.value(), module);
      if (!module_result) {
        return module_result.diagnostic();
      }
      const std::uint32_t lookup =
          original_thunk.value() != 0 ? original_thunk.value() : first_thunk.value();
      auto thunk_offset = rva_to_file_offset(image, lookup);
      if (!thunk_offset) {
        return thunk_offset.diagnostic();
      }
      for (std::uint64_t j = 0; j < kMaxThunks; ++j) {
        const std::uint64_t thunk_at = thunk_offset.value() + j * pointer_size;
        std::uint64_t value = 0;
        if (plus) {
          auto entry_value = reader.u64(thunk_at, Endian::Little);
          if (!entry_value) return entry_value.diagnostic();
          value = entry_value.value();
        } else {
          auto entry_value = reader.u32(thunk_at, Endian::Little);
          if (!entry_value) return entry_value.diagnostic();
          value = entry_value.value();
        }
        if (value == 0) {
          break;
        }
        Symbol symbol;
        symbol.module = module;
        symbol.kind = SymbolKind::Import;
        symbol.binding = SymbolBinding::Global;
        symbol.imported = true;
        symbol.address = image_base + first_thunk.value() + j * pointer_size;
        const std::uint64_t ordinal_mask = plus ? (1ULL << 63U) : (1ULL << 31U);
        if ((value & ordinal_mask) != 0) {
          symbol.name = "ordinal_" + std::to_string(value & 0xFFFFU);
        } else {
          auto symbol_name =
              read_c_string(static_cast<std::uint32_t>(value & 0x7FFFFFFFU) + 2U, symbol.name);
          if (!symbol_name) {
            return symbol_name.diagnostic();
          }
        }
        if (!add_symbol(std::move(symbol))) {
          return pe_error(Status::ResourceLimit, "pe.too_many_symbols",
                          "import count exceeds the limit", offset);
        }
      }
    }
  }

  // Exports (data directory index 0).
  if (!directories.empty() && directories[0].rva != 0) {
    auto export_offset = rva_to_file_offset(image, directories[0].rva);
    if (!export_offset) {
      return export_offset.diagnostic();
    }
    auto export_header = reader.slice(export_offset.value(), 40);
    if (!export_header) {
      return export_header.diagnostic();
    }
    const ByteReader header(export_header.value());
    auto module_name_rva = header.u32(12, Endian::Little);
    auto name_count = header.u32(24, Endian::Little);
    auto function_count = header.u32(20, Endian::Little);
    auto functions_rva = header.u32(28, Endian::Little);
    auto names_rva = header.u32(32, Endian::Little);
    auto ordinals_rva = header.u32(36, Endian::Little);
    if (!module_name_rva || !name_count || !function_count || !functions_rva || !names_rva ||
        !ordinals_rva) {
      return pe_error(Status::InternalError, "pe.export_read",
                      "failed to read a validated export directory", export_offset.value());
    }
    std::string module;
    if (module_name_rva.value() != 0) {
      auto module_result = read_c_string(module_name_rva.value(), module);
      if (!module_result) {
        return module_result.diagnostic();
      }
    }
    if (name_count.value() > kMaxExports || function_count.value() > kMaxExports) {
      return pe_error(Status::ResourceLimit, "pe.too_many_exports",
                      "export count exceeds the limit", export_offset.value());
    }
    auto names_offset = rva_to_file_offset(image, names_rva.value());
    auto ordinals_offset = rva_to_file_offset(image, ordinals_rva.value());
    auto functions_offset = rva_to_file_offset(image, functions_rva.value());
    if (!names_offset) return names_offset.diagnostic();
    if (!ordinals_offset) return ordinals_offset.diagnostic();
    if (!functions_offset) return functions_offset.diagnostic();

    for (std::uint64_t i = 0; i < name_count.value(); ++i) {
      auto name_pointer = reader.u32(names_offset.value() + i * 4, Endian::Little);
      auto ordinal = reader.u16(ordinals_offset.value() + i * 2, Endian::Little);
      if (!name_pointer || !ordinal) {
        return pe_error(Status::InternalError, "pe.export_name_read",
                        "failed to read a validated export name", names_offset.value());
      }
      if (ordinal.value() >= function_count.value()) {
        return pe_error(Status::InvalidInput, "pe.export_ordinal_out_of_range",
                        "export ordinal is outside the function table",
                        ordinals_offset.value() + i * 2);
      }
      auto function_rva =
          reader.u32(functions_offset.value() + ordinal.value() * 4, Endian::Little);
      if (!function_rva) {
        return function_rva.diagnostic();
      }
      if (function_rva.value() == 0) {
        continue;  // forwarder or unused slot
      }
      Symbol symbol;
      auto symbol_name = read_c_string(name_pointer.value(), symbol.name);
      if (!symbol_name) {
        return symbol_name.diagnostic();
      }
      symbol.module = module;
      symbol.address = image_base + function_rva.value();
      symbol.kind = SymbolKind::Export;
      symbol.binding = SymbolBinding::Global;
      symbol.exported = true;
      if (!add_symbol(std::move(symbol))) {
        return pe_error(Status::ResourceLimit, "pe.too_many_symbols",
                        "export count exceeds the limit", export_offset.value());
      }
    }
  }

  // COFF symbol table (MinGW and other GNU toolchains keep it in images):
  // names for functions and data that are not exported. Records are 18
  // bytes; auxiliary records are skipped.
  if (symbol_table.value() != 0 && symbol_count.value() != 0) {
    std::uint64_t table_bytes = 0;
    if (symbol_count.value() > kMaxSymbols ||
        checked::mul_overflow(symbol_count.value(), 18, table_bytes) ||
        !checked::in_range(symbol_table.value(), table_bytes, reader.size())) {
      image.partial = true;
      image.add_diagnostic(Status::Partial, "pe.coff_symbols_out_of_bounds",
                           "COFF symbol table is larger than the file or the symbol limit",
                           coff + 8);
    } else {
      // Exports already named some addresses; do not list them twice.
      std::set<std::pair<std::uint64_t, std::string>> known;
      for (const Symbol& existing : image.symbols) {
        if (!existing.imported) {
          known.emplace(existing.address, existing.name);
        }
      }
      for (std::uint64_t index = 0; index < symbol_count.value(); ++index) {
        const std::uint64_t at = symbol_table.value() + index * 18;
        auto record = reader.slice(at, 18);
        if (!record) {
          break;
        }
        const auto* bytes = reinterpret_cast<const unsigned char*>(record.value().data());
        auto le32 = [&](std::size_t o) {
          return static_cast<std::uint32_t>(bytes[o]) |
                 (static_cast<std::uint32_t>(bytes[o + 1]) << 8U) |
                 (static_cast<std::uint32_t>(bytes[o + 2]) << 16U) |
                 (static_cast<std::uint32_t>(bytes[o + 3]) << 24U);
        };
        const std::uint32_t value = le32(8);
        const auto section_number =
            static_cast<std::int16_t>(static_cast<std::uint16_t>(bytes[12] | (bytes[13] << 8U)));
        const std::uint16_t type = static_cast<std::uint16_t>(bytes[14] | (bytes[15] << 8U));
        const std::uint8_t storage = bytes[16];
        const std::uint8_t aux = bytes[17];
        index += aux;
        // External (2) or static (3) symbols defined in a section.
        if (section_number <= 0 ||
            static_cast<std::size_t>(section_number) > image.sections.size() ||
            (storage != 2 && storage != 3)) {
          continue;
        }
        std::string name;
        if (le32(0) == 0) {
          auto long_name = coff_string(le32(4));
          if (!long_name) {
            continue;
          }
          name = *long_name;
        } else {
          std::size_t length = 0;
          while (length < 8 && bytes[length] != 0) {
            ++length;
          }
          name = sanitize_name(std::string_view(reinterpret_cast<const char*>(bytes), length));
        }
        const Section& section = image.sections[static_cast<std::size_t>(section_number - 1)];
        // Section and file names, and compiler-internal labels, are not symbols.
        if (name.empty() || name.front() == '.' || (storage == 3 && value == 0 && aux != 0)) {
          continue;
        }
        Symbol symbol;
        symbol.name = std::move(name);
        symbol.address = section.address + value;
        symbol.binding = storage == 2 ? SymbolBinding::Global : SymbolBinding::Local;
        symbol.kind = (type >> 4U) == 2    ? SymbolKind::Function
                      : section.executable ? SymbolKind::Unknown
                                           : SymbolKind::Object;
        if (!known.emplace(symbol.address, symbol.name).second) {
          continue;
        }
        if (!add_symbol(std::move(symbol))) {
          image.partial = true;
          image.add_diagnostic(Status::ResourceLimit, "pe.too_many_symbols",
                               "symbol count exceeds the limit", at);
          break;
        }
      }
    }
  }
  image.format_detail += " (" + std::to_string(records.size()) + " sections)";
  return {};
}

}  // namespace donkey::binary::detail
