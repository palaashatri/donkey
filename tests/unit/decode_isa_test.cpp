#include <gtest/gtest.h>

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/decode/decode.h"

// The A32, RV64GC, MIPS32 and PPC32 decoders (G13), checked against llvm-objdump
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

// Decodes the image's .text section from its first byte, the way the analysis does, in the image's
// own byte order.
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
  auto decoder = donkey::Decoder::create(arch, loaded.image.endian);
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

// MIPS32 in both byte orders. The branch delay slots are decoded as ordinary instructions, because
// the decoder does not model them, so the lengths and addresses still match llvm-objdump.
TEST(DecodeIsa, MipsLittleEndianMatchesTheListingOfEveryInstruction) {
  const auto loaded = load("mips32el");
  EXPECT_EQ(loaded.image.architecture, donkey::Architecture::Mips32);
  EXPECT_EQ(loaded.image.endian, donkey::Endian::Little);
  expect_listing_matches(decode_text(loaded, donkey::Architecture::Mips32),
                         read_listing("mips32el"));
}

TEST(DecodeIsa, MipsBigEndianMatchesTheListingOfEveryInstruction) {
  const auto loaded = load("mips32be");
  EXPECT_EQ(loaded.image.architecture, donkey::Architecture::Mips32);
  EXPECT_EQ(loaded.image.endian, donkey::Endian::Big);
  expect_listing_matches(decode_text(loaded, donkey::Architecture::Mips32),
                         read_listing("mips32be"));
}

// PowerPC32 in both byte orders.
TEST(DecodeIsa, PowerPc32BigEndianMatchesTheListingOfEveryInstruction) {
  const auto loaded = load("ppc32");
  EXPECT_EQ(loaded.image.architecture, donkey::Architecture::Ppc32);
  EXPECT_EQ(loaded.image.endian, donkey::Endian::Big);
  expect_listing_matches(decode_text(loaded, donkey::Architecture::Ppc32), read_listing("ppc32"));
}

TEST(DecodeIsa, PowerPc32LittleEndianMatchesTheListingOfEveryInstruction) {
  const auto loaded = load("ppc32le");
  EXPECT_EQ(loaded.image.architecture, donkey::Architecture::Ppc32);
  EXPECT_EQ(loaded.image.endian, donkey::Endian::Little);
  expect_listing_matches(decode_text(loaded, donkey::Architecture::Ppc32), read_listing("ppc32le"));
}

// MIPS32: `blez` and `bne` fall through, with absolute targets. `j` to its own address is an
// unconditional Jump, `jal` is a Call, and `jr $ra` is a Return.
TEST(DecodeIsa, MipsBranchesHaveTheirClassesAndTargets) {
  const auto loaded = load("mips32el");
  const auto stream = decode_text(loaded, donkey::Architecture::Mips32);
  const donkey::Instruction* blez = at(stream, 0x20180);
  ASSERT_NE(blez, nullptr);
  EXPECT_EQ(blez->mnemonic, "blez");
  EXPECT_EQ(blez->classification, donkey::InstructionClass::ConditionalJump);
  EXPECT_EQ(blez->direct_target, std::optional<std::uint64_t>(0x201b8));
  const donkey::Instruction* bne = at(stream, 0x201a8);
  ASSERT_NE(bne, nullptr);
  EXPECT_EQ(bne->mnemonic, "bne");
  EXPECT_EQ(bne->classification, donkey::InstructionClass::ConditionalJump);
  EXPECT_EQ(bne->direct_target, std::optional<std::uint64_t>(0x20194));
  const donkey::Instruction* jal = at(stream, 0x201cc);
  ASSERT_NE(jal, nullptr);
  EXPECT_EQ(jal->classification, donkey::InstructionClass::Call);
  EXPECT_EQ(jal->direct_target, std::optional<std::uint64_t>(0x20180));
  const donkey::Instruction* self_jump = at(stream, 0x201d4);
  ASSERT_NE(self_jump, nullptr);
  EXPECT_EQ(self_jump->classification, donkey::InstructionClass::Jump);
  EXPECT_EQ(self_jump->direct_target, std::optional<std::uint64_t>(0x201d4));
  const donkey::Instruction* ret = at(stream, 0x201b0);
  ASSERT_NE(ret, nullptr);
  EXPECT_EQ(ret->classification, donkey::InstructionClass::Return);
}

// PowerPC32 (big-endian): `bf`, `bt` and `bdnz` fall through with absolute targets, `b` to a
// nearby address and to its own address are unconditional Jumps, `bl` is a Call, and `blr` is a
// Return.
TEST(DecodeIsa, PowerPc32BranchesHaveTheirClassesAndTargets) {
  const auto loaded = load("ppc32");
  const auto stream = decode_text(loaded, donkey::Architecture::Ppc32);
  const donkey::Instruction* bf = at(stream, 0x10010150);
  ASSERT_NE(bf, nullptr);
  EXPECT_EQ(bf->classification, donkey::InstructionClass::ConditionalJump);
  EXPECT_EQ(bf->direct_target, std::optional<std::uint64_t>(0x1001018c));
  const donkey::Instruction* bt = at(stream, 0x10010168);
  ASSERT_NE(bt, nullptr);
  EXPECT_EQ(bt->classification, donkey::InstructionClass::ConditionalJump);
  EXPECT_EQ(bt->direct_target, std::optional<std::uint64_t>(0x10010174));
  const donkey::Instruction* b = at(stream, 0x10010170);
  ASSERT_NE(b, nullptr);
  EXPECT_EQ(b->classification, donkey::InstructionClass::Jump);
  EXPECT_EQ(b->direct_target, std::optional<std::uint64_t>(0x10010178));
  const donkey::Instruction* bdnz = at(stream, 0x10010184);
  ASSERT_NE(bdnz, nullptr);
  EXPECT_EQ(bdnz->classification, donkey::InstructionClass::ConditionalJump);
  EXPECT_EQ(bdnz->direct_target, std::optional<std::uint64_t>(0x10010164));
  const donkey::Instruction* bl = at(stream, 0x100101a8);
  ASSERT_NE(bl, nullptr);
  EXPECT_EQ(bl->classification, donkey::InstructionClass::Call);
  EXPECT_EQ(bl->direct_target, std::optional<std::uint64_t>(0x1001014c));
  const donkey::Instruction* self_jump = at(stream, 0x100101ac);
  ASSERT_NE(self_jump, nullptr);
  EXPECT_EQ(self_jump->classification, donkey::InstructionClass::Jump);
  EXPECT_EQ(self_jump->direct_target, std::optional<std::uint64_t>(0x100101ac));
  const donkey::Instruction* ret = at(stream, 0x10010188);
  ASSERT_NE(ret, nullptr);
  EXPECT_EQ(ret->classification, donkey::InstructionClass::Return);
}

// The MIPS graph (G13-T3): a branch, call or return runs the instruction after it (its delay slot)
// first, so the slot stays in the same block as its branch. The path after a conditional branch
// starts after the slot. The image has only ordinary branches, so nothing is left unmodelled.
const donkey::BasicBlock* block_at(const donkey::ControlFlowGraph& cfg, std::uint64_t address) {
  for (const donkey::BasicBlock& block : cfg.blocks) {
    if (block.address == address) {
      return &block;
    }
  }
  return nullptr;
}

bool has_edge(const donkey::ControlFlowGraph& cfg, std::uint64_t from, std::uint64_t to,
              donkey::CfgEdgeKind kind) {
  for (const donkey::CfgEdge& edge : cfg.edges) {
    if (edge.from == from && edge.to == to && edge.kind == kind) {
      return true;
    }
  }
  return false;
}

TEST(DecodeIsa, MipsDelaySlotsStayWithTheirBranchesInTheGraph) {
  const auto loaded = load("mips32el");
  auto result = donkey::analyze(loaded.image, loaded.data.span());
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  const donkey::ControlFlowGraph& cfg = result.value().cfg;
  EXPECT_FALSE(cfg.partial);

  // blez at 0x20180 and its slot (nop) at 0x20184: one block of two instructions. Taken to 0x201b8,
  // and not taken to 0x20188, which is after the slot.
  const donkey::BasicBlock* head = block_at(cfg, 0x20180);
  ASSERT_NE(head, nullptr);
  EXPECT_EQ(head->instruction_count, 2U);
  EXPECT_EQ(head->end_address, 0x20188U);
  EXPECT_TRUE(has_edge(cfg, 0x20180, 0x201b8, donkey::CfgEdgeKind::ConditionalTrue));
  EXPECT_TRUE(has_edge(cfg, 0x20180, 0x20188, donkey::CfgEdgeKind::ConditionalFalse));

  // jr $ra at 0x201b8 and its slot (addiu $2, $zero, 0) at 0x201bc: the slot belongs to the return.
  const donkey::BasicBlock* exit = block_at(cfg, 0x201b8);
  ASSERT_NE(exit, nullptr);
  EXPECT_EQ(exit->instruction_count, 2U);
  EXPECT_EQ(exit->end_address, 0x201c0U);

  // A return has no fall-through: the instruction after its slot is not an edge of the return.
  for (const donkey::CfgEdge& edge : cfg.edges) {
    if (edge.from == 0x201b0 || edge.from == 0x201b8) {
      EXPECT_NE(edge.kind, donkey::CfgEdgeKind::ConditionalFalse) << std::hex << edge.from;
    }
  }

  // The self-jump `j` at 0x201d4 and its slot at 0x201d8 are one block, and the call at 0x201cc
  // returns after its slot, at 0x201d4.
  const donkey::BasicBlock* spin = block_at(cfg, 0x201d4);
  ASSERT_NE(spin, nullptr);
  EXPECT_EQ(spin->instruction_count, 2U);
  EXPECT_TRUE(has_edge(cfg, 0x201cc, 0x20180, donkey::CfgEdgeKind::Call));
  EXPECT_TRUE(has_edge(cfg, 0x201d4, 0x201d4, donkey::CfgEdgeKind::Jump));
}

// 64-bit MIPS and PowerPC (G13): the images decode in their 64-bit modes, and the listings agree.
// They were refused before this change, when the decoder had no 64-bit modes.
TEST(DecodeIsa, SixtyFourBitMipsAndPowerPcMatchTheirListings) {
  const auto mips = load("mips64el");
  EXPECT_EQ(mips.image.architecture, donkey::Architecture::Mips64);
  expect_listing_matches(decode_text(mips, donkey::Architecture::Mips64), read_listing("mips64el"));
  const auto ppc = load("ppc64");
  EXPECT_EQ(ppc.image.architecture, donkey::Architecture::Ppc64);
  EXPECT_EQ(ppc.image.endian, donkey::Endian::Big);
  expect_listing_matches(decode_text(ppc, donkey::Architecture::Ppc64), read_listing("ppc64"));
}

// MIPS16 and microMIPS code is not decoded by the MIPS32 backend. Their e_flags say so, and the
// image is Unknown with the reason recorded, rather than read as MIPS32 code. The fixtures are a
// microMIPS build of the MIPS fixture and a small MIPS16 assembly image (their flags are checked by
// the tests through the diagnostic, not by hand-written constants).
TEST(DecodeIsa, MipsSixteenAndMicroMipsImagesAreRefusedWithTheirReason) {
  for (const char* name : {"mips32el-micromips", "mips32el-mips16"}) {
    const auto loaded = load(name);
    EXPECT_EQ(loaded.image.architecture, donkey::Architecture::Unknown) << name;
    bool recorded = false;
    for (const donkey::Diagnostic& diagnostic : loaded.image.diagnostics) {
      recorded = recorded || diagnostic.code == "elf.mips_isa_extension";
    }
    EXPECT_TRUE(recorded) << name;
  }
}
