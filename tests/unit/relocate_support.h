#pragma once

// Helpers for the relocation tests: loading the fixture objects and reading the linked
// image. Each is small and independent of the relocator, so a test checks the result
// against what the instructions say rather than against the relocator's own logic.

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

#include "donkey/binary/image.h"

namespace relocate_support {

inline std::string object_path(const char* name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/objects/" + name;
}

inline const donkey::Symbol* defined_symbol(const donkey::BinaryImage& image,
                                            const std::string& name) {
  for (const donkey::Symbol& symbol : image.symbols) {
    if (symbol.name == name && !symbol.imported) {
      return &symbol;
    }
  }
  return nullptr;
}

/// The section that holds `address` in memory, or nullptr.
inline const donkey::Section* section_holding(const donkey::BinaryImage& image,
                                              std::uint64_t address) {
  for (const donkey::Section& section : image.sections) {
    if (address >= section.address && address - section.address < section.virtual_size) {
      return &section;
    }
  }
  return nullptr;
}

/// File offset of `address`, if a section with file data holds it.
inline bool offset_of(const donkey::BinaryImage& image, std::uint64_t address,
                      std::uint64_t& offset) {
  for (const donkey::Section& section : image.sections) {
    if (!section.has_file_data || address < section.address ||
        address - section.address >= section.file_size) {
      continue;
    }
    offset = section.file_offset + (address - section.address);
    return true;
  }
  return false;
}

inline std::uint64_t little_endian(std::span<const std::byte> bytes, std::uint64_t offset,
                                   unsigned width) {
  std::uint64_t value = 0;
  for (unsigned i = 0; i < width; ++i) {
    value |= static_cast<std::uint64_t>(std::to_integer<unsigned>(bytes[offset + i])) << (8U * i);
  }
  return value;
}

/// No relocation was left unapplied because of its type, its GOT slot or its range.
inline void expect_no_relocation_gaps(const donkey::BinaryImage& image) {
  for (const donkey::Diagnostic& diagnostic : image.diagnostics) {
    EXPECT_NE(diagnostic.code, "elf.relocation_type") << diagnostic.message;
    EXPECT_NE(diagnostic.code, "elf.relocation_got") << diagnostic.message;
    EXPECT_NE(diagnostic.code, "elf.relocation_range") << diagnostic.message;
  }
}

/// The page an ADRP at `site` names: its 21-bit page offset times 4 KiB, relative to the
/// page of the instruction.
inline std::uint64_t adrp_target_page(std::uint32_t word, std::uint64_t site) {
  const std::uint64_t immhi = (word >> 5U) & 0x7'FFFFU;
  const std::uint64_t immlo = (word >> 29U) & 0x3U;
  std::int64_t pages = static_cast<std::int64_t>((immhi << 2U) | immlo);
  if ((pages & (std::int64_t{1} << 20)) != 0) {
    pages -= std::int64_t{1} << 21;
  }
  return static_cast<std::uint64_t>(static_cast<std::int64_t>(site & ~std::uint64_t{0xFFF}) +
                                    (pages << 12));
}

}  // namespace relocate_support
