#include <gtest/gtest.h>

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/decode/decode.h"

// The A32 and RV64GC decoders (G13), checked against llvm-objdump
// (tests/fixtures/isa/PROVENANCE.md). The listings are the addresses and lengths llvm-objdump gives
// for every instruction of each image.

namespace {

std::string fixture(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/isa/" + name;
}

struct Listed {
  std::uint64_t address = 0;
  std::uint64_t length = 0;
};

std::vector<Listed> read_listing(const std::string& name) {
  std::ifstream file(fixture(name + ".objdump-lengths.txt"));
  std::vector<Listed> out;
  std::string address;
  std::uint64_t length = 0;
  while (file >> address >> length) {
    out.push_back(Listed{std::stoull(address, nullptr, 16), length});
  }
  return out;
}

donkey::LoadedBinary load(const std::string& name) {
  auto loaded = donkey::load_binary(fixture(name + ".elf"));
  EXPECT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  return loaded.has_value() ? std::move(loaded.value()) : donkey::LoadedBinary{};
}

// Decodes the image's .text section from its first byte, the way the analysis does.
donkey::DecodeStream decode_text(const donkey::LoadedBinary& loaded, donkey::Architecture arch) {
  const donkey::Section* text = nullptr;
  for (const donkey::Section& section : loaded.image.sections) {
    if (section.name == ".text") {
      text = &section;
    }
  }
  EXPECT_NE(text, nullptr);
  if (text == nullptr) {
    return {};
  }
  auto decoder = donkey::Decoder::create(arch, donkey::Endian::Little);
  EXPECT_TRUE(decoder.has_value()) << decoder.diagnostic().code;
  if (!decoder.has_value()) {
    return {};
  }
  const auto bytes = loaded.data.span().subspan(static_cast<std::size_t>(text->file_offset),
                                                static_cast<std::size_t>(text->file_size));
  auto stream = decoder.value().decode(bytes, text->address, 100'000);
  EXPECT_TRUE(stream.has_value()) << stream.diagnostic().code;
  return stream.has_value() ? stream.value() : donkey::DecodeStream{};
}

const donkey::Instruction* at(const donkey::DecodeStream& stream, std::uint64_t address) {
  for (const donkey::Instruction& instruction : stream.instructions) {
    if (instruction.address == address) {
      return &instruction;
    }
  }
  return nullptr;
}

void expect_listing_matches(const donkey::DecodeStream& stream,
                            const std::vector<Listed>& listing) {
  ASSERT_EQ(stream.instructions.size(), listing.size());
  for (std::size_t i = 0; i < listing.size(); ++i) {
    EXPECT_EQ(stream.instructions[i].address, listing[i].address) << "instruction " << i;
    EXPECT_EQ(stream.instructions[i].length, listing[i].length)
        << "at " << std::hex << listing[i].address;
  }
}

}  // namespace

TEST(DecodeIsa, ArmA32MatchesTheListingOfEveryInstruction) {
  const auto loaded = load("arm-a32");
  EXPECT_EQ(loaded.image.architecture, donkey::Architecture::Arm);
  expect_listing_matches(decode_text(loaded, donkey::Architecture::Arm), read_listing("arm-a32"));
}

TEST(DecodeIsa, RiscV64MatchesTheListingOfEveryInstruction) {
  const auto loaded = load("riscv64");
  EXPECT_EQ(loaded.image.architecture, donkey::Architecture::RiscV64);
  expect_listing_matches(decode_text(loaded, donkey::Architecture::RiscV64),
                         read_listing("riscv64"));
}

// A32 conditions: `blt` and `bhi` are conditional branches with their absolute targets, and the
// suffix is read whole, so `lt` is a condition and not a link bit.
TEST(DecodeIsa, ArmA32ConditionalBranchesAreConditionalWithTheirTargets) {
  const auto loaded = load("arm-a32");
  const auto stream = decode_text(loaded, donkey::Architecture::Arm);
  const donkey::Instruction* blt = at(stream, 0x20150);
  ASSERT_NE(blt, nullptr);
  EXPECT_EQ(blt->mnemonic, "blt");
  EXPECT_EQ(blt->classification, donkey::InstructionClass::ConditionalJump);
  EXPECT_EQ(blt->direct_target, std::optional<std::uint64_t>(0x20170));
  const donkey::Instruction* bhi = at(stream, 0x20130);
  ASSERT_NE(bhi, nullptr);
  EXPECT_EQ(bhi->classification, donkey::InstructionClass::ConditionalJump);
  EXPECT_EQ(bhi->direct_target, std::optional<std::uint64_t>(0x2011c));
}

// RISC-V branch immediates are offsets from the instruction: a self-jump's target is its own
// address. `jalr` takes its immediate from a register, so it has no direct target.
TEST(DecodeIsa, RiscV64BranchTargetsAreAbsoluteAndJalrHasNone) {
  const auto loaded = load("riscv64");
  const auto stream = decode_text(loaded, donkey::Architecture::RiscV64);
  const donkey::Instruction* spin = at(stream, 0x111e4);
  ASSERT_NE(spin, nullptr);
  EXPECT_EQ(spin->classification, donkey::InstructionClass::Jump);
  EXPECT_EQ(spin->direct_target, std::optional<std::uint64_t>(0x111e4));
  const donkey::Instruction* bltu = at(stream, 0x1116e);
  ASSERT_NE(bltu, nullptr);
  EXPECT_EQ(bltu->classification, donkey::InstructionClass::ConditionalJump);
  EXPECT_EQ(bltu->direct_target, std::optional<std::uint64_t>(0x11166));
  for (const donkey::Instruction& instruction : stream.instructions) {
    if (instruction.mnemonic == "jalr" || instruction.mnemonic == "c.jr" ||
        instruction.mnemonic == "c.jalr") {
      EXPECT_FALSE(instruction.direct_target.has_value()) << std::hex << instruction.address;
    }
  }
}

// Big-endian A32 and RISC-V are not decoded, and the decoder says so rather than reading the bytes
// backwards.
TEST(DecodeIsa, BigEndianArmAndRiscVAreRefusedByName) {
  auto arm = donkey::Decoder::create(donkey::Architecture::Arm, donkey::Endian::Big);
  ASSERT_FALSE(arm.has_value());
  EXPECT_EQ(arm.diagnostic().code, "decode.big_endian_arm");
  auto riscv = donkey::Decoder::create(donkey::Architecture::RiscV64, donkey::Endian::Big);
  ASSERT_FALSE(riscv.has_value());
  EXPECT_EQ(riscv.diagnostic().code, "decode.big_endian_riscv");
}
