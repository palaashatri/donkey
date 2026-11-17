// LC_FUNCTION_STARTS (G23-T3): the reader against llvm-objdump's list for the stripped fixtures,
// its refusals, and the seeds the analysis takes from it. Fixtures and oracle:
// tests/fixtures/function_starts/PROVENANCE.md.

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/function_starts.h"
#include "donkey/binary/image.h"

namespace {

std::string fixture(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/function_starts/" + name;
}

std::vector<std::byte> bytes(std::initializer_list<int> values) {
  std::vector<std::byte> out;
  for (const int value : values) {
    out.push_back(static_cast<std::byte>(value));
  }
  return out;
}

}  // namespace

// `llvm-objdump --macho --function-starts` lists four starts in each stripped fixture.
TEST(FunctionStarts, MatchTheOracle) {
  const std::vector<std::pair<std::string, std::vector<std::uint64_t>>> expected = {
      {"starts_x86_64", {0x1000003b0, 0x1000003c0, 0x1000003d0, 0x1000003f0}},
      {"starts_arm64", {0x100000360, 0x100000368, 0x100000370, 0x100000388}},
  };
  for (const auto& [name, starts] : expected) {
    auto loaded = donkey::load_binary(fixture(name));
    ASSERT_TRUE(loaded.has_value()) << name << ": " << loaded.diagnostic().message;
    EXPECT_NE(loaded.value().image.function_starts_size, 0U) << name;
    auto read = donkey::read_function_starts_of_image(loaded.value().image, loaded.value().data);
    ASSERT_TRUE(read.has_value()) << name << ": " << read.diagnostic().message;
    EXPECT_EQ(read.value(), starts) << name;
  }
}

TEST(FunctionStarts, AnImageWithoutATableHasNoStarts) {
  auto loaded = donkey::load_binary(std::string(DONKEY_FIXTURE_DIR) + "/binaries/tiny-macho-arm64");
  ASSERT_TRUE(loaded.has_value());
  EXPECT_EQ(loaded.value().image.function_starts_size, 0U);
  auto read = donkey::read_function_starts_of_image(loaded.value().image, loaded.value().data);
  ASSERT_TRUE(read.has_value());
  EXPECT_TRUE(read.value().empty());
}

TEST(FunctionStarts, DecodesDeltasAndStopsAtZero) {
  // 0x3b0 (two bytes), 0x10, 0x20, then the end and padding that is not read.
  const auto table = bytes({0xb0, 0x07, 0x10, 0x20, 0x00, 0x7f, 0x7f});
  auto read = donkey::read_function_starts(table, 0x1000, 0x1000, false);
  ASSERT_TRUE(read.has_value()) << read.diagnostic().message;
  EXPECT_EQ(read.value(), (std::vector<std::uint64_t>{0x13b0, 0x13c0, 0x13e0}));
  // Thumb starts lose their low bit.
  auto thumb = donkey::read_function_starts(bytes({0x81, 0x02, 0x04, 0x00}), 0x1000, 0x1000, true);
  ASSERT_TRUE(thumb.has_value());
  EXPECT_EQ(thumb.value(), (std::vector<std::uint64_t>{0x1100, 0x1104}));
}

TEST(FunctionStarts, RefusesBrokenTables) {
  // A ULEB128 longer than 10 bytes.
  auto long_uleb = donkey::read_function_starts(
      bytes({0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}), 0x1000, 0x1000,
      false);
  ASSERT_FALSE(long_uleb.has_value());
  EXPECT_EQ(long_uleb.diagnostic().code, "function_starts.bad_uleb128");
  // A tenth byte with bits past 64.
  auto wide = donkey::read_function_starts(
      bytes({0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02}), 0x1000, 0x1000, false);
  ASSERT_FALSE(wide.has_value());
  EXPECT_EQ(wide.diagnostic().code, "function_starts.bad_uleb128");
  // The data ends inside a delta.
  auto cut = donkey::read_function_starts(bytes({0x10, 0x80}), 0x1000, 0x1000, false);
  ASSERT_FALSE(cut.has_value());
  EXPECT_EQ(cut.diagnostic().code, "function_starts.bad_uleb128");
  // A start past __TEXT: 0x800 + 0x900 > 0x1000.
  auto outside =
      donkey::read_function_starts(bytes({0x80, 0x10, 0x80, 0x12}), 0x1000, 0x1000, false);
  ASSERT_FALSE(outside.has_value());
  EXPECT_EQ(outside.diagnostic().code, "function_starts.outside_text");
  // More starts than the limit.
  auto many = donkey::read_function_starts(bytes({0x01, 0x01, 0x01}), 0x1000, 0x1000, false, 2);
  ASSERT_FALSE(many.has_value());
  EXPECT_EQ(many.diagnostic().code, "function_starts.too_many");
}

// The loader refuses a table that lies outside the file: the fixture with the table's size raised
// past the end.
TEST(FunctionStarts, LoaderRefusesATableOutsideTheFile) {
  auto loaded = donkey::load_binary(fixture("starts_x86_64"));
  ASSERT_TRUE(loaded.has_value());
  std::vector<std::byte> data(loaded.value().data.begin(), loaded.value().data.end());
  // Find LC_FUNCTION_STARTS (0x26) among the load commands and give it a huge datasize.
  const auto u32 = [&](std::size_t at) {
    std::uint32_t value = 0;
    for (int byte = 3; byte >= 0; --byte) {
      value =
          (value << 8U) | std::to_integer<std::uint32_t>(data[at + static_cast<std::size_t>(byte)]);
    }
    return value;
  };
  std::size_t at = 32;
  const std::uint32_t commands = u32(16);
  bool patched = false;
  for (std::uint32_t i = 0; i < commands; ++i) {
    if (u32(at) == 0x26) {
      data[at + 15] = std::byte{0x7f};
      patched = true;
      break;
    }
    at += u32(at + 4);
  }
  ASSERT_TRUE(patched);
  auto refused = donkey::parse_binary(data, "starts_x86_64");
  ASSERT_FALSE(refused.has_value());
  EXPECT_EQ(refused.diagnostic().code, "macho.bad_function_starts");
}

// Stripped, the image names only its entry point; the table gives the other three functions, each
// marked with its provenance.
TEST(Analysis, MachOFunctionStartsSeedAStrippedBinary) {
  for (const std::string name : {"starts_x86_64", "starts_arm64"}) {
    auto loaded = donkey::load_binary(fixture(name));
    ASSERT_TRUE(loaded.has_value());
    auto analysis = donkey::analyze(loaded.value().image, loaded.value().data);
    ASSERT_TRUE(analysis.has_value()) << analysis.diagnostic().message;
    auto starts = donkey::read_function_starts_of_image(loaded.value().image, loaded.value().data);
    ASSERT_TRUE(starts.has_value());
    for (const std::uint64_t start : starts.value()) {
      const auto& functions = analysis.value().functions;
      const auto found =
          std::find_if(functions.begin(), functions.end(),
                       [&](const donkey::Function& f) { return f.address == start; });
      ASSERT_NE(found, functions.end()) << name << " " << std::hex << start;
      EXPECT_TRUE(found->from_function_starts) << name << " " << std::hex << start;
    }
  }
}
