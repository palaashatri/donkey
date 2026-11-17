#include "elf_dynamic.h"

#include <algorithm>

#include "donkey/binary/byte_reader.h"

namespace donkey::binary::detail {

/// The names of the dynamic symbols, by index, as relocations refer to them.
std::vector<std::string> dynamic_symbol_names(const BinaryImage& image,
                                              std::span<const std::byte> data,
                                              std::optional<std::uint64_t>* unreadable_at) {
  const Section* symbols = nullptr;
  const Section* strings = nullptr;
  for (const Section& section : image.sections) {
    if (section.name == ".dynsym") {
      symbols = &section;
    } else if (section.name == ".dynstr") {
      strings = &section;
    }
  }
  std::vector<std::string> names;
  if (symbols == nullptr || strings == nullptr || !symbols->has_file_data ||
      !strings->has_file_data) {
    return names;
  }
  const ByteReader reader(data);
  const std::uint64_t count = symbols->file_size / kSymbolEntrySize;
  names.reserve(static_cast<std::size_t>(std::min<std::uint64_t>(count, kMaxRelocationEntries)));
  for (std::uint64_t i = 0; i < count && i < kMaxRelocationEntries; ++i) {
    const auto name_offset =
        reader.u32(symbols->file_offset + i * kSymbolEntrySize, Endian::Little);
    if (!name_offset) {
      if (unreadable_at != nullptr) {
        *unreadable_at = symbols->file_offset;
      }
      break;
    }
    const auto name = reader.c_string(strings->file_offset + name_offset.value(), 4096);
    names.emplace_back(name ? std::string(name.value()) : std::string());
  }
  return names;
}

std::vector<bool> dynamic_symbol_undefined(const BinaryImage& image,
                                           std::span<const std::byte> data) {
  const Section* symbols = nullptr;
  for (const Section& section : image.sections) {
    if (section.name == ".dynsym") {
      symbols = &section;
    }
  }
  std::vector<bool> undefined;
  if (symbols == nullptr || !symbols->has_file_data) {
    return undefined;
  }
  const ByteReader reader(data);
  const std::uint64_t count = symbols->file_size / kSymbolEntrySize;
  undefined.reserve(
      static_cast<std::size_t>(std::min<std::uint64_t>(count, kMaxRelocationEntries)));
  for (std::uint64_t i = 0; i < count && i < kMaxRelocationEntries; ++i) {
    // Elf64_Sym: st_name (4), st_info (1), st_other (1), st_shndx (2).
    const auto section_index =
        reader.u16(symbols->file_offset + i * kSymbolEntrySize + 6, Endian::Little);
    if (!section_index) {
      break;
    }
    undefined.push_back(i != 0 && section_index.value() == 0);
  }
  return undefined;
}

}  // namespace donkey::binary::detail
