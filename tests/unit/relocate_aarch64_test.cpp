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
