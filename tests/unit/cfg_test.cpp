#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "test_io.h"

namespace {

using donkey::AnalysisOptions;
using donkey::Architecture;
using donkey::BasicBlock;
using donkey::BinaryImage;
using donkey::CfgEdge;
using donkey::CfgEdgeKind;
using donkey::Section;

std::string fixture_path(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/binaries/" + name;
}

/// Small x86-64 function with a forward conditional branch:
///   push rbp; mov rbp, rsp; test rax, rax; je 0x100c; xor eax, eax; ret;
///   0x100c: mov eax, 1; ret
std::vector<std::byte> branchy_function() {
  const std::uint8_t bytes[] = {
      0x55,                          // push rbp
      0x48, 0x89, 0xe5,              // mov rbp, rsp
      0x48, 0x85, 0xc0,              // test rax, rax
      0x74, 0x03,                    // je 0x100c
      0x31, 0xc0,                    // xor eax, eax
      0xc3,                          // ret
      0xb8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1
      0xc3,                          // ret
  };
  std::vector<std::byte> out(sizeof(bytes));
  for (std::size_t i = 0; i < sizeof(bytes); ++i) {
    out[i] = static_cast<std::byte>(bytes[i]);
  }
  return out;
}

BinaryImage synthetic_image(std::size_t size) {
  BinaryImage image;
  image.path = "<synthetic>";
  image.architecture = Architecture::X86_64;
  image.format = donkey::BinaryFormat::Raw;
  image.bits = 64;
  image.file_size = size;
  image.entry_point = 0x1000;
  Section section;
  section.id = donkey::SectionId{1};
  section.name = ".text";
  section.type = "synthetic";
  section.file_offset = 0;
  section.file_size = size;
  section.address = 0x1000;
  section.virtual_size = size;
  section.readable = true;
  section.executable = true;
  section.has_file_data = true;
  image.sections.push_back(section);
  donkey::Segment segment;
  segment.index = 0;
  segment.name = ".text";
  segment.file_offset = 0;
  segment.file_size = size;
  segment.virtual_address = 0x1000;
  segment.virtual_size = size;
  segment.readable = true;
  segment.executable = true;
  image.segments.push_back(segment);
  return image;
}

const BasicBlock* block_at(const donkey::ControlFlowGraph& cfg, std::uint64_t address) {
  for (const BasicBlock& block : cfg.blocks) {
    if (block.address == address) {
      return &block;
    }
  }
  return nullptr;
}

const CfgEdge* edge_between(const donkey::ControlFlowGraph& cfg, std::uint64_t from,
                            std::uint64_t to) {
  for (const CfgEdge& edge : cfg.edges) {
    if (edge.from == from && edge.to == to) {
      return &edge;
    }
  }
  return nullptr;
}

TEST(Cfg, BuildsBlocksAndConditionalEdges) {
  const auto data = branchy_function();
  const auto image = synthetic_image(data.size());
  auto result = donkey::analyze(image, data);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;

  const auto& analysis = result.value();
  ASSERT_EQ(analysis.functions.size(), 1U);
  const auto& function = analysis.functions.front();
  EXPECT_EQ(function.address, 0x1000U);
  EXPECT_TRUE(function.has_extent);
  EXPECT_EQ(function.end_address, 0x1012U);
  EXPECT_EQ(function.block_count, 3U);
  EXPECT_FALSE(function.estimated);

  const auto* entry = block_at(analysis.cfg, 0x1000);
  ASSERT_NE(entry, nullptr);
  EXPECT_EQ(entry->end_address, 0x1009U);
  EXPECT_EQ(entry->instruction_count, 4U);

  const auto* taken = block_at(analysis.cfg, 0x100c);
  ASSERT_NE(taken, nullptr);
  EXPECT_EQ(taken->end_address, 0x1012U);
  EXPECT_EQ(taken->instruction_count, 2U);

  const auto* fallthrough = block_at(analysis.cfg, 0x1009);
  ASSERT_NE(fallthrough, nullptr);
  EXPECT_EQ(fallthrough->end_address, 0x100cU);

  const CfgEdge* conditional = edge_between(analysis.cfg, 0x1007, 0x100c);
  ASSERT_NE(conditional, nullptr);
  EXPECT_EQ(conditional->kind, CfgEdgeKind::ConditionalTrue);
  const CfgEdge* other = edge_between(analysis.cfg, 0x1007, 0x1009);
  ASSERT_NE(other, nullptr);
  EXPECT_EQ(other->kind, CfgEdgeKind::ConditionalFalse);

  EXPECT_EQ(analysis.cfg.edges.size(), 2U);
}

TEST(Cfg, LinearFunctionHasOneBlockAndNoBranches) {
  auto loaded = donkey::load_binary_file(fixture_path("tiny-elf-x86_64"));
  ASSERT_TRUE(loaded.has_value());
  auto data = [&]() {
    std::ifstream file(fixture_path("tiny-elf-x86_64"), std::ios::binary);
    const auto chars = donkey_test::read_stream<std::vector<char>>(file);
    std::vector<std::byte> bytes(chars.size());
    for (std::size_t i = 0; i < chars.size(); ++i) {
      bytes[i] = static_cast<std::byte>(static_cast<unsigned char>(chars[i]));
    }
    return bytes;
  }();
  auto result = donkey::analyze(loaded.value(), data);
  ASSERT_TRUE(result.has_value());

  const auto& analysis = result.value();
  // Entry plus the call target 0x400109.
  ASSERT_EQ(analysis.functions.size(), 2U);
  EXPECT_EQ(analysis.functions[0].address, 0x400100U);
  EXPECT_EQ(analysis.functions[0].end_address, 0x40010cU);
  EXPECT_EQ(analysis.functions[0].block_count, 1U);

  const CfgEdge* call = edge_between(analysis.cfg, 0x400104, 0x400109);
  ASSERT_NE(call, nullptr);
  EXPECT_EQ(call->kind, CfgEdgeKind::Call);
}

TEST(Cfg, TruncatedInputsNeverHangOrCrash) {
  std::ifstream file(fixture_path("tiny-elf-x86_64"), std::ios::binary);
  const auto chars = donkey_test::read_stream<std::vector<char>>(file);
  std::vector<std::byte> full(chars.size());
  for (std::size_t i = 0; i < chars.size(); ++i) {
    full[i] = static_cast<std::byte>(static_cast<unsigned char>(chars[i]));
  }

  for (std::size_t length = 0; length <= full.size(); ++length) {
    const std::vector<std::byte> prefix(full.begin(),
                                        full.begin() + static_cast<std::ptrdiff_t>(length));
    auto loaded = donkey::parse_binary(prefix, fixture_path("tiny-elf-x86_64"));
    if (!loaded) {
      continue;  // Rejection is a valid outcome; the point is not to crash.
    }
    AnalysisOptions options;
    options.max_instructions = 10'000;
    options.max_strings = 1'000;
    auto result = donkey::analyze(loaded.value(), prefix, options);
    ASSERT_TRUE(result.has_value()) << "length " << length;
    for (const auto& function : result.value().functions) {
      if (function.has_extent) {
        EXPECT_GE(function.end_address, function.address) << "length " << length;
      }
    }
    for (const auto& block : result.value().cfg.blocks) {
      EXPECT_GT(block.end_address, block.address) << "length " << length;
      EXPECT_LE(block.first_instruction + block.instruction_count,
                result.value().instructions.size())
          << "length " << length;
    }
  }
}

/// An AArch64 image for jump-table tests: `.text` at 0x1000 holds `words`, and
/// a read-only `.rodata` at 0x2000 holds `table` at 0x2010, which is the
/// address the code's `adrp` and `add` reach.
struct AArch64DispatchImage {
  BinaryImage image;
  std::vector<std::byte> data;
};

/// `table` is the table's bytes in memory order, so the caller chooses the entry
/// size and byte order; `endian` orders the instruction words.
AArch64DispatchImage aarch64_dispatch_image(const std::vector<std::uint32_t>& words,
                                            const std::vector<std::uint8_t>& table,
                                            donkey::Endian endian = donkey::Endian::Little) {
  AArch64DispatchImage out;
  out.data.assign(0x100, std::byte{0});
  std::size_t at = 0;
  for (const std::uint32_t word : words) {
    for (std::size_t i = 0; i < 4; ++i) {
      const std::size_t significance = endian == donkey::Endian::Big ? 3 - i : i;
      out.data[at++] = static_cast<std::byte>((word >> (8U * significance)) & 0xffU);
    }
  }
  at = 0x90;
  for (const std::uint8_t byte : table) {
    out.data[at++] = static_cast<std::byte>(byte);
  }
  BinaryImage& image = out.image;
  image.path = "<synthetic>";
  image.architecture = Architecture::AArch64;
  image.endian = endian;
  image.format = donkey::BinaryFormat::Raw;
  image.bits = 64;
  image.file_size = out.data.size();
  image.entry_point = 0x1000;
  Section text;
  text.id = donkey::SectionId{1};
  text.name = ".text";
  text.type = "synthetic";
  text.file_offset = 0;
  text.file_size = 0x80;
  text.address = 0x1000;
  text.virtual_size = 0x80;
  text.readable = true;
  text.executable = true;
  text.has_file_data = true;
  image.sections.push_back(text);
  Section rodata = text;
  rodata.id = donkey::SectionId{2};
  rodata.name = ".rodata";
  rodata.file_offset = 0x80;
  rodata.address = 0x2000;
  rodata.executable = false;
  image.sections.push_back(rodata);
  donkey::Segment code_segment;
  code_segment.index = 0;
  code_segment.name = ".text";
  code_segment.file_offset = 0;
  code_segment.file_size = 0x80;
  code_segment.virtual_address = 0x1000;
  code_segment.virtual_size = 0x80;
  code_segment.readable = true;
  code_segment.executable = true;
  image.segments.push_back(code_segment);
  donkey::Segment data_segment = code_segment;
  data_segment.index = 1;
  data_segment.name = ".rodata";
  data_segment.file_offset = 0x80;
  data_segment.virtual_address = 0x2000;
  data_segment.executable = false;
  image.segments.push_back(data_segment);
  return out;
}

/// What GCC emits at -O2 for a dense 4-case switch on AArch64, placed at
/// 0x1000 (assembled with llvm-mc). The bounds check is `b.ls`, whose taken
/// edge enters the table block; `bounds_branch` can replace it.
std::vector<std::uint32_t> gcc_dispatch(std::uint32_t bounds_branch = 0x54000069U) {
  return {0x71000c1fU, bounds_branch, 0x12800000U, 0xd65f03c0U, 0xb0000002U, 0x91004042U,
          0x38604842U, 0x10000060U,   0x8b228802U, 0xd61f0040U, 0x11000420U, 0xd65f03c0U,
          0x11000820U, 0xd65f03c0U,   0x11000c20U, 0xd65f03c0U, 0x11001020U, 0xd65f03c0U};
}

/// What Clang emits at -O2 for the same switch: the bounds check is `b.hi`
/// whose fall-through enters the table block.
std::vector<std::uint32_t> clang_dispatch() {
  return {0x71000c1fU, 0x54000208U, 0x2a0003e8U, 0xb0000009U, 0x91004129U, 0x1000008aU, 0x3868692bU,
          0x8b0b094aU, 0xd61f0140U, 0x11000420U, 0xd65f03c0U, 0x11000820U, 0xd65f03c0U, 0x11000c20U,
          0xd65f03c0U, 0x11001020U, 0xd65f03c0U, 0x12800000U, 0xd65f03c0U};
}

TEST(Cfg, AArch64GccShapedJumpTableIsRecovered) {
  const auto dispatch = aarch64_dispatch_image(gcc_dispatch(), {0x00, 0x02, 0x04, 0x06});
  auto result = donkey::analyze(dispatch.image, dispatch.data);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  const auto& cfg = result.value().cfg;
  ASSERT_EQ(cfg.jump_tables.size(), 1U);
  const auto& table = cfg.jump_tables.front();
  EXPECT_EQ(table.jump_address, 0x1024U);
  EXPECT_EQ(table.check_address, 0x1000U);
  EXPECT_EQ(table.default_target, 0x1008U);
  EXPECT_EQ(table.targets, (std::vector<std::uint64_t>{0x1028U, 0x1030U, 0x1038U, 0x1040U}));
  for (const std::uint64_t target : table.targets) {
    const CfgEdge* edge = edge_between(cfg, 0x1024, target);
    ASSERT_NE(edge, nullptr) << "no jump-table edge to " << target;
    EXPECT_EQ(edge->kind, CfgEdgeKind::JumpTable);
  }
}

/// gcc_dispatch() with 16-bit entries: `ldrh w2, [x2, w0, uxtw #1]` and
/// `add x2, x0, w2, sxth #2` replace the byte load and the sxtb add.
std::vector<std::uint32_t> gcc_halfword_dispatch() {
  std::vector<std::uint32_t> words = gcc_dispatch();
  words[6] = 0x78605842U;
  words[8] = 0x8b22a802U;
  return words;
}

/// The four targets of gcc_dispatch(), from a table at 0x2010 read with the
/// image's byte order.
void expect_four_target_table(const AArch64DispatchImage& dispatch) {
  auto result = donkey::analyze(dispatch.image, dispatch.data);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  const auto& cfg = result.value().cfg;
  ASSERT_EQ(cfg.jump_tables.size(), 1U);
  const auto& table = cfg.jump_tables.front();
  EXPECT_EQ(table.targets, (std::vector<std::uint64_t>{0x1028U, 0x1030U, 0x1038U, 0x1040U}));
  for (const std::uint64_t target : table.targets) {
    const CfgEdge* edge = edge_between(cfg, 0x1024, target);
    ASSERT_NE(edge, nullptr) << "no jump-table edge to " << target;
    EXPECT_EQ(edge->kind, CfgEdgeKind::JumpTable);
  }
}

TEST(Cfg, AArch64HalfwordTableIsRecoveredInLittleEndian) {
  expect_four_target_table(aarch64_dispatch_image(
      gcc_halfword_dispatch(), {0x00, 0x00, 0x02, 0x00, 0x04, 0x00, 0x06, 0x00}));
}

TEST(Cfg, AArch64HalfwordTableIsRecoveredInBigEndian) {
  // Big-endian image: the instruction words and the 16-bit entries are both
  // big-endian. Reading the entries little-endian would give 0x0200 for the second
  // entry, which is not an instruction start, so no table would be recovered.
  expect_four_target_table(aarch64_dispatch_image(gcc_halfword_dispatch(),
                                                  {0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x00, 0x06},
                                                  donkey::Endian::Big));
}

TEST(Cfg, AArch64ClangShapedJumpTableIsRecovered) {
  const auto dispatch = aarch64_dispatch_image(clang_dispatch(), {0x00, 0x02, 0x04, 0x06});
  auto result = donkey::analyze(dispatch.image, dispatch.data);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  const auto& cfg = result.value().cfg;
  ASSERT_EQ(cfg.jump_tables.size(), 1U);
  const auto& table = cfg.jump_tables.front();
  EXPECT_EQ(table.jump_address, 0x1020U);
  EXPECT_EQ(table.check_address, 0x1000U);
  EXPECT_EQ(table.default_target, 0x1044U);
  EXPECT_EQ(table.targets, (std::vector<std::uint64_t>{0x1024U, 0x102cU, 0x1034U, 0x103cU}));
}

// `b.hi` takes its branch when the selector is out of range, so a table behind
// its taken edge is on the wrong side and must not be recovered.
TEST(Cfg, AArch64TableOnTheOutOfRangeSideIsNotRecovered) {
  const auto dispatch = aarch64_dispatch_image(gcc_dispatch(0x54000068U), {0x00, 0x02, 0x04, 0x06});
  auto result = donkey::analyze(dispatch.image, dispatch.data);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  EXPECT_TRUE(result.value().cfg.jump_tables.empty());
}

// An entry that lands outside the code is not an instruction start, so the
// whole table is unproven and no table is recovered.
TEST(Cfg, AArch64TableEntryOutsideTheCodeIsNotRecovered) {
  const auto dispatch = aarch64_dispatch_image(gcc_dispatch(), {0x00, 0x02, 0x04, 0x40});
  auto result = donkey::analyze(dispatch.image, dispatch.data);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  EXPECT_TRUE(result.value().cfg.jump_tables.empty());
}

TEST(Cfg, RespectsInstructionLimit) {
  const auto data = branchy_function();
  const auto image = synthetic_image(data.size());
  AnalysisOptions options;
  options.max_instructions = 2;
  auto result = donkey::analyze(image, data, options);
  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result.value().partial);
  EXPECT_EQ(result.value().instructions.size(), 2U);
}

}  // namespace
