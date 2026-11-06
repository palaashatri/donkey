#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

#include "donkey/binary/image.h"

namespace {

std::string fixture_path() {
  return std::string(DONKEY_FIXTURE_DIR) + "/objects/reloc-aarch64.o";
}

const donkey::Section* section_named(const donkey::BinaryImage& image, const std::string& name) {
  for (const donkey::Section& section : image.sections) {
    if (section.name == name) {
      return &section;
    }
  }
  return nullptr;
}

const donkey::Symbol* symbol_named(const donkey::BinaryImage& image, const std::string& name) {
  for (const donkey::Symbol& symbol : image.symbols) {
    if (symbol.name == name && !symbol.imported) {
      return &symbol;
    }
  }
  return nullptr;
}

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

}  // namespace

TEST(RelocateAArch64, DataAndBranchRelocationsReachTheirTargets) {
  auto loaded = donkey::load_binary(fixture_path());
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  const donkey::BinaryImage& image = loaded.value().image;
  const std::span<const std::byte> bytes = loaded.value().data.span();
  ASSERT_NE(section_named(image, ".text"), nullptr);

  // int *pointer = &value; is R_AARCH64_ABS64: the 8 bytes hold value's address.
  const donkey::Symbol* pointer = symbol_named(image, "pointer");
  const donkey::Symbol* value = symbol_named(image, "value");
  ASSERT_NE(pointer, nullptr);
  ASSERT_NE(value, nullptr);
  std::uint64_t offset = 0;
  ASSERT_TRUE(offset_of(image, pointer->address, offset));
  EXPECT_EQ(little_endian(bytes, offset, 8), value->address);

  // A BL (opcode 100101 in the top six bits) inside call_global whose 26-bit word offset
  // lands on global_helper: R_AARCH64_CALL26 was applied.
  const donkey::Symbol* caller = symbol_named(image, "call_global");
  const donkey::Symbol* callee = symbol_named(image, "global_helper");
  ASSERT_NE(caller, nullptr);
  ASSERT_NE(callee, nullptr);
  bool reached = false;
  for (std::uint64_t site = caller->address; site + 4 <= caller->address + caller->size;
       site += 4) {
    std::uint64_t at = 0;
    if (!offset_of(image, site, at)) {
      continue;
    }
    const auto word = static_cast<std::uint32_t>(little_endian(bytes, at, 4));
    if ((word >> 26U) != 0x25U) {
      continue;
    }
    std::int64_t words = word & 0x03FF'FFFFU;
    if ((words & 0x0200'0000) != 0) {
      words -= std::int64_t{1} << 26;  // sign-extend the 26-bit field
    }
    if (static_cast<std::int64_t>(site) + words * 4 == static_cast<std::int64_t>(callee->address)) {
      reached = true;
      break;
    }
  }
  EXPECT_TRUE(reached) << "no BL in call_global reaches global_helper";
}

TEST(RelocateAArch64, UndefinedCalleeIsReportedAndNoRelocationIsUnsupported) {
  auto loaded = donkey::load_binary(fixture_path());
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  const donkey::BinaryImage& image = loaded.value().image;
  EXPECT_TRUE(image.partial);

  bool unresolved = false;
  for (const donkey::Diagnostic& diagnostic : image.diagnostics) {
    // The .eh_frame PREL32 relocations are applied, so only the external call is reported.
    EXPECT_NE(diagnostic.code, "elf.relocation_type") << diagnostic.message;
    if (diagnostic.code == "elf.relocation_unresolved" &&
        diagnostic.message.find("external_function") != std::string::npos) {
      unresolved = true;
    }
  }
  EXPECT_TRUE(unresolved);
}

namespace {

std::string forms_fixture_path() {
  return std::string(DONKEY_FIXTURE_DIR) + "/objects/reloc-forms-aarch64.o";
}

/// The page an ADRP at `site` names: its 21-bit page offset (immhi:immlo) times 4 KiB,
/// relative to the page of the instruction.
std::uint64_t adrp_target_page(std::uint32_t word, std::uint64_t site) {
  const std::uint64_t immhi = (word >> 5U) & 0x7'FFFFU;
  const std::uint64_t immlo = (word >> 29U) & 0x3U;
  std::int64_t pages = static_cast<std::int64_t>((immhi << 2U) | immlo);
  if ((pages & (std::int64_t{1} << 20)) != 0) {
    pages -= std::int64_t{1} << 21;  // sign-extend the 21-bit field
  }
  return static_cast<std::uint64_t>(static_cast<std::int64_t>(site & ~std::uint64_t{0xFFF}) +
                                    (pages << 12));
}

}  // namespace

// Each function reads or writes one global. Its ADRP names the global's page, and the
// instruction after it carries the low 12 bits: a load or store scales them by its access
// size, an ADD does not. Together they must name the global's linked address.
TEST(RelocateAArch64, PageAndLowBitRelocationsReachTheirData) {
  auto loaded = donkey::load_binary(forms_fixture_path());
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  const donkey::BinaryImage& image = loaded.value().image;
  const std::span<const std::byte> bytes = loaded.value().data.span();

  for (const donkey::Diagnostic& diagnostic : image.diagnostics) {
    EXPECT_NE(diagnostic.code, "elf.relocation_type") << diagnostic.message;
    EXPECT_NE(diagnostic.code, "elf.relocation_range") << diagnostic.message;
  }

  struct Access {
    const char* function;
    const char* data;
    unsigned scale;  // log2 of the access size; 0 for an ADD
  };
  const Access accesses[] = {
      {"read_counter", "counter", 2}, {"write_counter", "counter", 2},
      {"read_half", "half", 1},       {"read_byte", "byte_value", 0},
      {"read_wide", "wide", 3},       {"address_of_table", "table", 0},
  };
  for (const Access& access : accesses) {
    const donkey::Symbol* function = symbol_named(image, access.function);
    const donkey::Symbol* data = symbol_named(image, access.data);
    ASSERT_NE(function, nullptr) << access.function;
    ASSERT_NE(data, nullptr) << access.data;
    bool found = false;
    for (std::uint64_t site = function->address; site + 8 <= function->address + function->size;
         site += 4) {
      std::uint64_t at = 0;
      std::uint64_t next_at = 0;
      if (!offset_of(image, site, at) || !offset_of(image, site + 4, next_at)) {
        continue;
      }
      const auto word = static_cast<std::uint32_t>(little_endian(bytes, at, 4));
      if ((word & 0x9F00'0000U) != 0x9000'0000U) {
        continue;  // not an ADRP
      }
      const auto next = static_cast<std::uint32_t>(little_endian(bytes, next_at, 4));
      const std::uint64_t immediate = (next >> 10U) & 0xFFFU;
      const std::uint64_t address = adrp_target_page(word, site) + (immediate << access.scale);
      EXPECT_EQ(address, data->address) << access.function << " reaches the wrong address";
      found = true;
      break;
    }
    EXPECT_TRUE(found) << access.function << " has no ADRP";
  }
}
