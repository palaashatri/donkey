#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"

// User code starts and data ranges (G12-T1), on the tiny x86-64 ELF: a function at 0x400100 that
// calls 0x400109 (nop; pop rbp; ret), and padding from 0x40010c on.

namespace {

std::string fixture(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/binaries/" + name;
}

donkey::LoadedBinary load_tiny() {
  auto loaded = donkey::load_binary(fixture("tiny-elf-x86_64"));
  EXPECT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  return loaded.has_value() ? std::move(loaded.value()) : donkey::LoadedBinary{};
}

bool has_instruction(const donkey::AnalysisResult& result, std::uint64_t address) {
  return std::any_of(
      result.instructions.begin(), result.instructions.end(),
      [&](const donkey::Instruction& instruction) { return instruction.address == address; });
}

bool has_function(const donkey::AnalysisResult& result, std::uint64_t address) {
  return std::any_of(result.functions.begin(), result.functions.end(),
                     [&](const donkey::Function& function) { return function.address == address; });
}

donkey::AnalysisResult analyze_with(const donkey::LoadedBinary& loaded,
                                    const donkey::AnalysisOptions& options) {
  auto result = donkey::analyze(loaded.image, loaded.data, options);
  EXPECT_TRUE(result.has_value()) << result.diagnostic().message;
  return result.has_value() ? std::move(result.value()) : donkey::AnalysisResult{};
}

}  // namespace

// A declared data range is not decoded, and decoding resumes at the true address after it. The
// baseline comes first so the expectations cannot pass on an image that never had the code.
TEST(UserRanges, DataIsNotDecodedAndDecodingResumesAfterIt) {
  const auto loaded = load_tiny();
  const auto baseline = analyze_with(loaded, {});
  ASSERT_TRUE(has_instruction(baseline, 0x400109));
  ASSERT_TRUE(has_function(baseline, 0x400109));

  donkey::AnalysisOptions options;
  options.user_data_ranges.push_back(donkey::UserDataRange{0x400109, 0, 1});
  const auto result = analyze_with(loaded, options);
  EXPECT_FALSE(has_instruction(result, 0x400109));
  EXPECT_TRUE(has_instruction(result, 0x400104)) << "the call before the range is still decoded";
  EXPECT_TRUE(has_instruction(result, 0x40010a)) << "pop rbp is decoded from its own address";
  EXPECT_TRUE(has_instruction(result, 0x40010b));
  // A call still targets 0x400109, but no start may lie inside declared data.
  EXPECT_FALSE(has_function(result, 0x400109));
}

// Adjacent and overlapping ranges are cut out once each, and the bytes between them still decode.
TEST(UserRanges, AdjacentAndOverlappingRangesAreMerged) {
  const auto loaded = load_tiny();
  donkey::AnalysisOptions options;
  options.user_data_ranges.push_back(donkey::UserDataRange{0x400109, 0, 1});
  options.user_data_ranges.push_back(donkey::UserDataRange{0x40010a, 1, 1});
  options.user_data_ranges.push_back(donkey::UserDataRange{0x40010a, 0, 1});
  const auto result = analyze_with(loaded, options);
  EXPECT_FALSE(has_instruction(result, 0x400109));
  EXPECT_FALSE(has_instruction(result, 0x40010a));
  EXPECT_TRUE(has_instruction(result, 0x40010b));
}

// A user code start seeds a function. A code start inside declared data is refused, because data
// wins over any start.
TEST(UserRanges, CodeStartSeedsAFunctionUnlessItIsDeclaredData) {
  const auto loaded = load_tiny();
  donkey::AnalysisOptions options;
  options.user_code_starts.push_back(0x40010c);
  const auto seeded = analyze_with(loaded, options);
  EXPECT_TRUE(has_function(seeded, 0x40010c));

  options.user_data_ranges.push_back(donkey::UserDataRange{0x40010c, 1, 1});
  const auto refused = analyze_with(loaded, options);
  EXPECT_FALSE(has_function(refused, 0x40010c));
  EXPECT_FALSE(has_instruction(refused, 0x40010c));
}

// Ranges that are empty, or whose end would pass the top of the address space, are ignored and
// change nothing. They must not crash or make the analysis skip everything.
TEST(UserRanges, EmptyAndOverflowingRangesAreIgnored) {
  const auto loaded = load_tiny();
  const auto baseline = analyze_with(loaded, {});
  donkey::AnalysisOptions options;
  options.user_data_ranges.push_back(donkey::UserDataRange{0x400109, 0, 0});
  options.user_data_ranges.push_back(donkey::UserDataRange{0xffffffffffffff00ULL, 8, 1000});
  options.user_data_ranges.push_back(donkey::UserDataRange{0xfffffffffffffff0ULL, 1, 1ULL << 62});
  const auto result = analyze_with(loaded, options);
  EXPECT_EQ(result.instructions.size(), baseline.instructions.size());
  EXPECT_TRUE(has_instruction(result, 0x400109));
  EXPECT_TRUE(has_function(result, 0x400109));
}
