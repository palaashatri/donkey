#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "donkey/analysis/search.h"
#include "donkey/binary/image.h"
#include "donkey/core/cancellation.h"
#include "donkey/decode/decode.h"

namespace {

using donkey::BinaryImage;
using donkey::Instruction;
using donkey::Section;

constexpr std::uint64_t kBase = 0x401000;

// One executable section holding `file`, at kBase.
BinaryImage image_of(std::size_t size) {
  BinaryImage image;
  image.path = "<search test>";
  image.architecture = donkey::Architecture::X86_64;
  image.format = donkey::BinaryFormat::Raw;
  image.bits = 64;
  image.file_size = size;
  image.entry_point = kBase;
  Section section;
  section.id = donkey::SectionId{1};
  section.name = ".text";
  section.type = "synthetic";
  section.file_offset = 0;
  section.file_size = size;
  section.address = kBase;
  section.virtual_size = size;
  section.readable = true;
  section.executable = true;
  section.has_file_data = true;
  image.sections.push_back(section);
  return image;
}

Instruction insn(std::uint64_t address, std::string mnemonic, std::string operands) {
  Instruction instruction;
  instruction.address = address;
  instruction.length = 4;
  instruction.mnemonic = std::move(mnemonic);
  instruction.operands = std::move(operands);
  return instruction;
}

}  // namespace

TEST(Search, ABytePatternWithWildcardsMatchesAtItsVirtualAddress) {
  // 48 8b 04 24 at offset 4, and 48 8b 4c 24 at offset 12; the wildcard matches the third byte.
  const std::vector<std::byte> file = {
      std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90},
      std::byte{0x48}, std::byte{0x8b}, std::byte{0x04}, std::byte{0x24},
      std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90},
      std::byte{0x48}, std::byte{0x8b}, std::byte{0x4c}, std::byte{0x24}};
  auto hits = donkey::search_bytes(image_of(file.size()), file, "48 8b ?? 24");
  ASSERT_TRUE(hits.has_value()) << hits.diagnostic().code;
  EXPECT_EQ(hits.value().addresses, (std::vector<std::uint64_t>{kBase + 4, kBase + 12}));
  EXPECT_FALSE(hits.value().truncated);
}

TEST(Search, ABytePatternIsCaseInsensitiveAndAllowsAnyWhitespace) {
  const std::vector<std::byte> file = {std::byte{0xab}, std::byte{0xcd}};
  auto hits = donkey::search_bytes(image_of(file.size()), file, "  AB\tCd ");
  ASSERT_TRUE(hits.has_value()) << hits.diagnostic().code;
  EXPECT_EQ(hits.value().addresses, (std::vector<std::uint64_t>{kBase}));
}

TEST(Search, ABadBytePatternIsRefusedWithItsReason) {
  const std::vector<std::byte> file(8, std::byte{0});
  const BinaryImage image = image_of(file.size());
  for (const char* bad : {"", "   ", "zz", "4", "48 8", "??", "?? ??", "123"}) {
    auto refused = donkey::search_bytes(image, file, bad);
    ASSERT_FALSE(refused.has_value()) << "'" << bad << "'";
    EXPECT_EQ(refused.diagnostic().code, "search.pattern") << "'" << bad << "'";
  }
  // A pattern longer than the limit is refused before any byte is compared.
  std::string long_pattern;
  for (int i = 0; i < 300; ++i) {
    long_pattern += "00 ";
  }
  auto refused = donkey::search_bytes(image, file, long_pattern);
  ASSERT_FALSE(refused.has_value());
  EXPECT_EQ(refused.diagnostic().code, "search.pattern");
}

TEST(Search, AByteSearchStopsAtTheHitLimit) {
  const std::vector<std::byte> file(100, std::byte{0x90});
  donkey::SearchOptions options;
  options.max_hits = 5;
  auto hits = donkey::search_bytes(image_of(file.size()), file, "90", options);
  ASSERT_TRUE(hits.has_value());
  EXPECT_EQ(hits.value().addresses.size(), 5U);
  EXPECT_TRUE(hits.value().truncated);
}

TEST(Search, ACancelledByteSearchReportsItsCancellation) {
  const std::vector<std::byte> file(64, std::byte{0x90});
  donkey::CancellationToken token;
  token.cancel();
  auto hits = donkey::search_bytes(image_of(file.size()), file, "90", {}, token);
  ASSERT_TRUE(hits.has_value());
  EXPECT_TRUE(hits.value().cancelled);
  EXPECT_TRUE(hits.value().addresses.empty());
}

TEST(Search, OperandNumbersAreReadInDecimalAndHexWithoutTakingRegisterNames) {
  EXPECT_EQ(donkey::operand_numbers("0x10(%rbp)"), (std::vector<std::uint64_t>{16}));
  EXPECT_EQ(donkey::operand_numbers("$0x1f, %eax"), (std::vector<std::uint64_t>{31}));
  EXPECT_EQ(donkey::operand_numbers("-0x8(%rsp)"), (std::vector<std::uint64_t>{8}));
  EXPECT_EQ(donkey::operand_numbers("#42"), (std::vector<std::uint64_t>{42}));
  EXPECT_EQ(donkey::operand_numbers("rax, rdx"), (std::vector<std::uint64_t>{}));
  EXPECT_EQ(donkey::operand_numbers("xmm0, eax"), (std::vector<std::uint64_t>{}));
  EXPECT_EQ(donkey::operand_numbers("r8d, 0x2a"), (std::vector<std::uint64_t>{42}));
  // A digit inside a name is not the start of a number.
  EXPECT_EQ(donkey::operand_numbers("sym4, x1"), (std::vector<std::uint64_t>{}));
}

TEST(Search, AnImmediateSearchFindsTheInstructionsThatContainTheValue) {
  const std::vector<Instruction> instructions = {
      insn(kBase, "mov", "$0x2a, %eax"), insn(kBase + 4, "add", "%eax, %edx"),
      insn(kBase + 8, "cmp", "$0x2b, %eax"), insn(kBase + 12, "sub", "$42, %ecx")};
  auto hits = donkey::search_immediate(instructions, 42);
  ASSERT_TRUE(hits.has_value());
  EXPECT_EQ(hits.value().addresses, (std::vector<std::uint64_t>{kBase, kBase + 12}));
}

TEST(Search, ARegularExpressionMatchesTheMnemonicAndOperandText) {
  const std::vector<Instruction> instructions = {insn(kBase, "call", "0x401100"),
                                                 insn(kBase + 4, "mov", "%rsp, %rbp"),
                                                 insn(kBase + 8, "callq", "*%rax")};
  auto calls = donkey::search_text(instructions, "^call");
  ASSERT_TRUE(calls.has_value()) << calls.diagnostic().code;
  // "^call" matches "callq" too: the search is a regular expression, not a mnemonic list.
  EXPECT_EQ(calls.value().addresses, (std::vector<std::uint64_t>{kBase, kBase + 8}));
  auto rsp = donkey::search_text(instructions, "rsp, %rbp$");
  ASSERT_TRUE(rsp.has_value());
  EXPECT_EQ(rsp.value().addresses, (std::vector<std::uint64_t>{kBase + 4}));
}

TEST(Search, ABadRegularExpressionIsRefusedWithItsReason) {
  const std::vector<Instruction> instructions = {insn(kBase, "nop", "")};
  for (const char* bad : {"(", "[a-", "*x"}) {
    auto refused = donkey::search_text(instructions, bad);
    ASSERT_FALSE(refused.has_value()) << bad;
    EXPECT_EQ(refused.diagnostic().code, "search.regex") << bad;
  }
  auto empty = donkey::search_text(instructions, "");
  ASSERT_FALSE(empty.has_value());
  EXPECT_EQ(empty.diagnostic().code, "search.regex");
}
