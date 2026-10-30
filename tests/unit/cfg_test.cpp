#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"

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
    const std::vector<char> chars((std::istreambuf_iterator<char>(file)),
                                  std::istreambuf_iterator<char>());
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
  const std::vector<char> chars((std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());
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
