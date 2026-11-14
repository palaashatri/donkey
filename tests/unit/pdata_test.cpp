#include <gtest/gtest.h>

#include <cstdint>
#include <string>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/binary/pdata.h"

namespace {

std::string fixture_path() {
  return std::string(DONKEY_FIXTURE_DIR) + "/binaries/pdata-pe-x86_64.dll";
}

const donkey::PdataFunction* find_start(const donkey::PdataReadResult& read, std::uint64_t start) {
  for (const donkey::PdataFunction& function : read.functions) {
    if (function.start == start) {
      return &function;
    }
  }
  return nullptr;
}

}  // namespace

// G23-T2: the RUNTIME_FUNCTION entries of the x64 DLL. Its three functions are at the addresses
// objdump prints; hidden_fn is never called or exported, so only this directory names it.
TEST(Pdata, ReadsTheExceptionDirectoryOfAnX64Dll) {
  auto loaded = donkey::load_binary(fixture_path());
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  auto read = donkey::read_pdata_of_image(loaded.value().image, loaded.value().data);
  ASSERT_TRUE(read.has_value()) << read.diagnostic().message;
  EXPECT_EQ(read.value().entries, 40U);
  EXPECT_EQ(read.value().functions.size(), 40U);
  EXPECT_EQ(read.value().chained, 0U);
  EXPECT_EQ(read.value().malformed, 0U);
  EXPECT_FALSE(read.value().truncated);
  const auto* hidden = find_start(read.value(), 0x2c8251390ULL);
  ASSERT_NE(hidden, nullptr);
  EXPECT_EQ(hidden->size, 0x16U);  // EndAddress 0x2C82513A6 in llvm-readobj --unwind
  EXPECT_NE(find_start(read.value(), 0x2c82513b0ULL), nullptr);
  EXPECT_NE(find_start(read.value(), 0x2c82513d0ULL), nullptr);
}

TEST(Pdata, EntryLimitTruncatesTheDirectory) {
  auto loaded = donkey::load_binary(fixture_path());
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  auto read = donkey::read_pdata_of_image(loaded.value().image, loaded.value().data, 5);
  ASSERT_TRUE(read.has_value()) << read.diagnostic().message;
  EXPECT_TRUE(read.value().truncated);
  EXPECT_EQ(read.value().entries, 5U);
  EXPECT_EQ(read.value().functions.size(), 5U);
}

TEST(Pdata, NonPeImageYieldsNothing) {
  donkey::BinaryImage image;
  image.format = donkey::BinaryFormat::Elf;
  image.architecture = donkey::Architecture::X86_64;
  auto read = donkey::read_pdata_of_image(image, {});
  ASSERT_TRUE(read.has_value()) << read.diagnostic().message;
  EXPECT_TRUE(read.value().functions.empty());
}

// The analysis marks a start found only by the exception directory with the unwind provenance.
TEST(Pdata, AnalysisSeedsHiddenFunctionWithUnwindProvenance) {
  auto loaded = donkey::load_binary(fixture_path());
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  auto analyzed = donkey::analyze(loaded.value().image, loaded.value().data);
  ASSERT_TRUE(analyzed.has_value()) << analyzed.diagnostic().message;
  bool found = false;
  for (const donkey::Function& function : analyzed.value().functions) {
    if (function.address == 0x2c8251390ULL) {
      found = true;
      EXPECT_TRUE(function.from_unwind);
    }
  }
  EXPECT_TRUE(found);
}
