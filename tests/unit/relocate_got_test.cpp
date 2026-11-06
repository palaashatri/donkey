#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

#include "donkey/binary/image.h"

namespace {

std::string object_path(const char* name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/objects/" + name;
}

const donkey::Symbol* defined_symbol(const donkey::BinaryImage& image, const std::string& name) {
  for (const donkey::Symbol& symbol : image.symbols) {
    if (symbol.name == name && !symbol.imported) {
      return &symbol;
    }
  }
  return nullptr;
}

/// The section that holds `address` in memory, or nullptr.
const donkey::Section* section_holding(const donkey::BinaryImage& image, std::uint64_t address) {
  for (const donkey::Section& section : image.sections) {
    if (address >= section.address && address - section.address < section.virtual_size) {
      return &section;
    }
  }
  return nullptr;
}

/// File offset of `address`, if a section with file data holds it.
bool offset_of(const donkey::BinaryImage& image, std::uint64_t address, std::uint64_t& offset) {
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

std::uint64_t little_endian(std::span<const std::byte> bytes, std::uint64_t offset,
                            unsigned width) {
  std::uint64_t value = 0;
  for (unsigned i = 0; i < width; ++i) {
    value |= static_cast<std::uint64_t>(std::to_integer<unsigned>(bytes[offset + i])) << (8U * i);
  }
  return value;
}

void expect_no_relocation_gaps(const donkey::BinaryImage& image) {
  for (const donkey::Diagnostic& diagnostic : image.diagnostics) {
    EXPECT_NE(diagnostic.code, "elf.relocation_type") << diagnostic.message;
    EXPECT_NE(diagnostic.code, "elf.relocation_got") << diagnostic.message;
    EXPECT_NE(diagnostic.code, "elf.relocation_range") << diagnostic.message;
  }
}

/// The page an ADRP at `site` names: its 21-bit page offset times 4 KiB, relative to the
/// page of the instruction.
std::uint64_t adrp_target_page(std::uint32_t word, std::uint64_t site) {
  const std::uint64_t immhi = (word >> 5U) & 0x7'FFFFU;
  const std::uint64_t immlo = (word >> 29U) & 0x3U;
  std::int64_t pages = static_cast<std::int64_t>((immhi << 2U) | immlo);
  if ((pages & (std::int64_t{1} << 20)) != 0) {
    pages -= std::int64_t{1} << 21;
  }
  return static_cast<std::uint64_t>(static_cast<std::int64_t>(site & ~std::uint64_t{0xFFF}) +
                                    (pages << 12));
}

}  // namespace

// Position-independent code reads a defined global through its GOT slot:
// `mov rax, [rip + disp]` where disp reaches the slot. The slot must sit in the linked
// .got section and hold the global's address, so the load yields the global's address.
TEST(RelocateGot, X86_64GotLoadReachesASlotHoldingTheAddress) {
  auto loaded = donkey::load_binary(object_path("reloc-got-x86_64.o"));
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  const donkey::BinaryImage& image = loaded.value().image;
  const std::span<const std::byte> bytes = loaded.value().data.span();
  expect_no_relocation_gaps(image);

  const donkey::Symbol* function = defined_symbol(image, "get_value_address");
  const donkey::Symbol* value = defined_symbol(image, "value");
  ASSERT_NE(function, nullptr);
  ASSERT_NE(value, nullptr);
  bool found = false;
  for (std::uint64_t site = function->address; site + 7 <= function->address + function->size;
       ++site) {
    std::uint64_t at = 0;
    if (!offset_of(image, site, at)) {
      continue;
    }
    // REX.W mov r64, [rip+disp32] is 48 8b 05; read little-endian, the three bytes are 0x058b48.
    if (little_endian(bytes, at, 3) != 0x058B48U) {
      continue;
    }
    const auto disp = static_cast<std::int32_t>(little_endian(bytes, at + 3, 4));
    const auto slot = static_cast<std::uint64_t>(static_cast<std::int64_t>(site) + 7 + disp);
    const donkey::Section* got = section_holding(image, slot);
    ASSERT_NE(got, nullptr) << "the displacement names no section";
    EXPECT_EQ(got->name, ".got");
    std::uint64_t slot_at = 0;
    ASSERT_TRUE(offset_of(image, slot, slot_at));
    EXPECT_EQ(little_endian(bytes, slot_at, 8), value->address);
    found = true;
    break;
  }
  EXPECT_TRUE(found) << "get_value_address has no GOT load";
}

// AArch64 position-independent code: ADRP names the page of the GOT slot, and the LDR
// that follows carries the slot's low 12 bits, scaled by 8.
TEST(RelocateGot, AArch64GotLoadReachesASlotHoldingTheAddress) {
  auto loaded = donkey::load_binary(object_path("reloc-got-aarch64.o"));
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  const donkey::BinaryImage& image = loaded.value().image;
  const std::span<const std::byte> bytes = loaded.value().data.span();
  expect_no_relocation_gaps(image);

  const donkey::Symbol* function = defined_symbol(image, "get_value_address");
  const donkey::Symbol* value = defined_symbol(image, "value");
  ASSERT_NE(function, nullptr);
  ASSERT_NE(value, nullptr);
  std::uint64_t site_at = 0;
  std::uint64_t next_at = 0;
  ASSERT_TRUE(offset_of(image, function->address, site_at));
  ASSERT_TRUE(offset_of(image, function->address + 4, next_at));
  const auto adrp = static_cast<std::uint32_t>(little_endian(bytes, site_at, 4));
  const auto ldr = static_cast<std::uint32_t>(little_endian(bytes, next_at, 4));
  ASSERT_EQ(adrp & 0x9F00'0000U, 0x9000'0000U) << "the first instruction is not an ADRP";
  const std::uint64_t slot =
      adrp_target_page(adrp, function->address) + (((ldr >> 10U) & 0xFFFU) << 3U);
  const donkey::Section* got = section_holding(image, slot);
  ASSERT_NE(got, nullptr) << "the slot is not in a linked section";
  EXPECT_EQ(got->name, ".got");
  std::uint64_t slot_at = 0;
  ASSERT_TRUE(offset_of(image, slot, slot_at));
  EXPECT_EQ(little_endian(bytes, slot_at, 8), value->address);
}
