#pragma once

// ELF helpers shared by the readers that follow relocations and the dynamic symbol table (rtti.cpp,
// plt.cpp). Internal to donkey_binary: nothing outside src/binary includes this header.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "donkey/binary/image.h"

namespace donkey::binary::detail {

constexpr std::uint64_t kRelaEntrySize = 24;    // Elf64_Rela
constexpr std::uint64_t kSymbolEntrySize = 24;  // Elf64_Sym

/// Entries read from one table before the reader stops, so a hostile table cannot allocate
/// without bound.
constexpr std::size_t kMaxRelocationEntries = 1'000'000;

/// The names of the dynamic symbols, by index, as relocations refer to them. Reads `.dynsym` and
/// `.dynstr`. An unreadable entry ends the list, and `unreadable_at` (when given) receives the file
/// offset of the symbol table. Empty when either section is missing.
[[nodiscard]] std::vector<std::string> dynamic_symbol_names(
    const BinaryImage& image, std::span<const std::byte> data,
    std::optional<std::uint64_t>* unreadable_at = nullptr);

}  // namespace donkey::binary::detail
