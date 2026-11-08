#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

#include "donkey/binary/image.h"

namespace {

std::string fixture_path() {
  return std::string(DONKEY_FIXTURE_DIR) + "/objects/reloc-x86_64.o";
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

/// The byte offset in the analysed bytes of a laid-out address, or nullopt when no
/// section with file data holds it.
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

TEST(Relocate, LaysOutTheAllocatedSectionsAndTheSymbols) {
  auto loaded = donkey::load_binary(fixture_path());
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  const donkey::BinaryImage& image = loaded.value().image;
  EXPECT_EQ(image.format, donkey::BinaryFormat::Elf);

  const donkey::Section* text = section_named(image, ".text");
  ASSERT_NE(text, nullptr);
  EXPECT_TRUE(text->executable);
  EXPECT_GE(text->address, 0x1000U);  // laid out from the object base, never at zero

  const donkey::Section* data = section_named(image, ".data");
  ASSERT_NE(data, nullptr);
  EXPECT_GT(data->address, text->address);

  const donkey::Symbol* call = symbol_named(image, "call_global");
  ASSERT_NE(call, nullptr);
  EXPECT_GE(call->address, text->address);
  EXPECT_LT(call->address, text->address + text->virtual_size);
  EXPECT_GT(call->size, 0U);

  const donkey::Symbol* value = symbol_named(image, "value");
  ASSERT_NE(value, nullptr);
  EXPECT_GE(value->address, data->address);
  EXPECT_LT(value->address, data->address + data->virtual_size);
}

TEST(Relocate, AbsoluteDataRelocationHoldsTheTargetAddress) {
  auto loaded = donkey::load_binary(fixture_path());
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  const donkey::BinaryImage& image = loaded.value().image;
  const donkey::Symbol* pointer = symbol_named(image, "pointer");
  const donkey::Symbol* value = symbol_named(image, "value");
  ASSERT_NE(pointer, nullptr);
  ASSERT_NE(value, nullptr);

  // int *pointer = &value; is an R_X86_64_64 relocation: the 8 bytes hold value's address.
  std::uint64_t offset = 0;
  ASSERT_TRUE(offset_of(image, pointer->address, offset));
  EXPECT_EQ(little_endian(loaded.value().data.span(), offset, 8), value->address);
}

TEST(Relocate, CallToAGlobalFunctionReachesItsAddress) {
  auto loaded = donkey::load_binary(fixture_path());
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  const donkey::BinaryImage& image = loaded.value().image;
  const donkey::Symbol* caller = symbol_named(image, "call_global");
  const donkey::Symbol* callee = symbol_named(image, "global_helper");
  ASSERT_NE(caller, nullptr);
  ASSERT_NE(callee, nullptr);

  // A call (E8 rel32) inside call_global whose displacement lands on global_helper.
  bool reached = false;
  for (std::uint64_t site = caller->address; site + 5 <= caller->address + caller->size; ++site) {
    std::uint64_t offset = 0;
    if (!offset_of(image, site, offset) ||
        std::to_integer<unsigned>(loaded.value().data.span()[offset]) != 0xE8U) {
      continue;
    }
    const auto displacement =
        static_cast<std::int32_t>(little_endian(loaded.value().data.span(), offset + 1, 4));
    const auto target =
        static_cast<std::int64_t>(site) + 5 + static_cast<std::int64_t>(displacement);
    if (target == static_cast<std::int64_t>(callee->address)) {
      reached = true;
      break;
    }
  }
  EXPECT_TRUE(reached) << "no call in call_global reaches global_helper";
}

TEST(Relocate, UndefinedCalleeIsReportedAndTheObjectStillLoads) {
  auto loaded = donkey::load_binary(fixture_path());
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  const donkey::BinaryImage& image = loaded.value().image;
  EXPECT_TRUE(image.partial);

  bool reported = false;
  for (const donkey::Diagnostic& diagnostic : image.diagnostics) {
    // The .eh_frame PC32 relocations are applied, so only the external call is reported.
    EXPECT_NE(diagnostic.code, "elf.relocation_type") << diagnostic.message;
    if (diagnostic.code == "elf.relocation_unresolved" &&
        diagnostic.message.find("external_function") != std::string::npos) {
      reported = true;
    }
  }
  EXPECT_TRUE(reported);
}
