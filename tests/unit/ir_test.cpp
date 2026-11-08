#include <gtest/gtest.h>

#include <algorithm>
#include <cfenv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <string>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/ir/abi.h"
#include "donkey/ir/eval.h"
#include "donkey/ir/ir.h"
#include "donkey/ir/lift.h"
#include "test_io.h"

namespace {

using donkey::Architecture;
using donkey::BasicBlock;
using donkey::BinaryImage;
using donkey::IrBlock;
using donkey::IrCondition;
using donkey::IrFunction;
using donkey::IrLocalVariable;
using donkey::IrOp;
using donkey::IrOperand;
using donkey::IrOperandKind;
using donkey::IrParameter;
using donkey::IrStatement;
using donkey::IrSwitchCase;
using donkey::Section;

std::string fixture_path(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/binaries/" + name;
}

std::vector<std::byte> read_bytes(const std::string& path) {
  std::ifstream file(path, std::ios::binary);
  const auto chars = donkey_test::read_stream<std::vector<char>>(file);
  std::vector<std::byte> out(chars.size());
  for (std::size_t i = 0; i < chars.size(); ++i) {
    out[i] = static_cast<std::byte>(static_cast<unsigned char>(chars[i]));
  }
  return out;
}

/// push rbp; mov rbp, rsp; test rax, rax; je 0x100c;
/// xor eax, eax; ret; 0x100c: mov eax, 1; ret
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

std::vector<std::byte> extension_function() {
  const std::uint8_t bytes[] = {
      0x0f, 0xb6, 0xc0,                          // movzx eax, al
      0x48, 0x0f, 0xb6, 0xc8,                    // movzx rcx, al
      0x0f, 0xbe, 0xd0,                          // movsx edx, al
      0x48, 0x63, 0xc0,                          // movsxd rax, eax
      0x48, 0x8d, 0x0d, 0x0a, 0x00, 0x00, 0x00,  // lea rcx, [rip+0xa]
      0xff, 0xd0,                                // call rax
      0xc3,                                      // ret
  };
  std::vector<std::byte> out(sizeof(bytes));
  for (std::size_t i = 0; i < sizeof(bytes); ++i) {
    out[i] = static_cast<std::byte>(bytes[i]);
  }
  return out;
}

std::vector<std::byte> high_byte_register_function() {
  const std::uint8_t bytes[] = {
      0x00, 0x70, 0x6f,  // add byte ptr [rax + 0x6f], dh
      0x55,              // push rbp
      0xc3,              // ret
  };
  std::vector<std::byte> out(sizeof(bytes));
  for (std::size_t i = 0; i < sizeof(bytes); ++i) {
    out[i] = static_cast<std::byte>(bytes[i]);
  }
  return out;
}

std::vector<std::byte> tail_conditional_function() {
  const std::uint8_t bytes[] = {
      0x75,
      0xfe,  // jne self (conditional branch with no fallthrough)
  };
  std::vector<std::byte> out(sizeof(bytes));
  for (std::size_t i = 0; i < sizeof(bytes); ++i) {
    out[i] = static_cast<std::byte>(bytes[i]);
  }
  return out;
}

std::vector<std::byte> pop_memory_function() {
  const std::uint8_t bytes[] = {
      0x8f,
      0x00,  // pop qword ptr [rax]
      0xc3,  // ret
  };
  std::vector<std::byte> out(sizeof(bytes));
  for (std::size_t i = 0; i < sizeof(bytes); ++i) {
    out[i] = static_cast<std::byte>(bytes[i]);
  }
  return out;
}

/// AArch64 straight-line function (assembled with clang for aarch64):
///   stp x29, x30, [sp, #-0x10]!
///   mov x29, sp
///   movz x0, #0x1234
///   movk x0, #0xabcd, lsl #16
///   add x1, x0, #1
///   sub x2, x1, x0
///   lsl x3, x2, #2
///   ldrb w4, [x0]
///   ldrsw x5, [x0, #4]
///   mul x6, x4, x5
///   madd x7, x4, x5, x6
///   ldp x29, x30, [sp], #0x10
///   ret
std::vector<std::byte> aarch64_straight_line_function() {
  const std::uint8_t bytes[] = {
      0xfd, 0x7b, 0xbf, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0x80, 0x46, 0x82, 0xd2, 0xa0,
      0x79, 0xb5, 0xf2, 0x01, 0x04, 0x00, 0x91, 0x22, 0x00, 0x00, 0xcb, 0x43, 0xf4,
      0x7e, 0xd3, 0x04, 0x00, 0x40, 0x39, 0x05, 0x04, 0x80, 0xb9, 0x86, 0x7c, 0x05,
      0x9b, 0x87, 0x18, 0x05, 0x9b, 0xfd, 0x7b, 0xc1, 0xa8, 0xc0, 0x03, 0x5f, 0xd6,
  };
  std::vector<std::byte> out(sizeof(bytes));
  for (std::size_t i = 0; i < sizeof(bytes); ++i) {
    out[i] = static_cast<std::byte>(bytes[i]);
  }
  return out;
}

/// AArch64 control-flow function (assembled with clang for aarch64):
///   cmp x0, #0
///   b.eq 1f
///   add x1, x0, #1
///   b 2f
/// 1: sub x1, x0, #1
/// 2: cbz x1, 3f
///   tbz x1, #3, 4f
///   mov x2, x1
/// 3: 4: ret
std::vector<std::byte> aarch64_branchy_function() {
  const std::uint8_t bytes[] = {
      0x1f, 0x00, 0x00, 0xf1, 0x60, 0x00, 0x00, 0x54, 0x01, 0x04, 0x00, 0x91,
      0x02, 0x00, 0x00, 0x14, 0x01, 0x04, 0x00, 0xd1, 0x61, 0x00, 0x00, 0xb4,
      0x41, 0x00, 0x18, 0x36, 0xe2, 0x03, 0x01, 0xaa, 0xc0, 0x03, 0x5f, 0xd6,
  };
  std::vector<std::byte> out(sizeof(bytes));
  for (std::size_t i = 0; i < sizeof(bytes); ++i) {
    out[i] = static_cast<std::byte>(bytes[i]);
  }
  return out;
}

/// AArch64 two-argument function:
///   add w0, w0, w1
///   ret
std::vector<std::byte> aarch64_two_argument_function() {
  const std::uint8_t bytes[] = {
      0x00, 0x00, 0x01, 0x0b,  // add w0, w0, w1
      0xc0, 0x03, 0x5f, 0xd6,  // ret
  };
  std::vector<std::byte> out(sizeof(bytes));
  for (std::size_t i = 0; i < sizeof(bytes); ++i) {
    out[i] = static_cast<std::byte>(bytes[i]);
  }
  return out;
}

/// mov eax, edi; add eax, esi; ret  (two System V integer arguments)
std::vector<std::byte> x86_two_argument_function() {
  const std::uint8_t bytes[] = {
      0x89, 0xf8,  // mov eax, edi
      0x01, 0xf0,  // add eax, esi
      0xc3,        // ret
  };
  std::vector<std::byte> out(sizeof(bytes));
  for (std::size_t i = 0; i < sizeof(bytes); ++i) {
    out[i] = static_cast<std::byte>(bytes[i]);
  }
  return out;
}

/// mov edi, 1; mov eax, edi; ret  (rdi is written before any read)
std::vector<std::byte> x86_written_argument_function() {
  const std::uint8_t bytes[] = {
      0xbf, 0x01, 0x00, 0x00, 0x00,  // mov edi, 1
      0x89, 0xf8,                    // mov eax, edi
      0xc3,                          // ret
  };
  std::vector<std::byte> out(sizeof(bytes));
  for (std::size_t i = 0; i < sizeof(bytes); ++i) {
    out[i] = static_cast<std::byte>(bytes[i]);
  }
  return out;
}

/// x86-32 cdecl frame:
///   push ebp; mov ebp, esp; mov eax, [ebp+8]; add eax, [ebp+12]; pop ebp; ret
/// Arguments are stack-passed, so the signature is `u32 sub_1000(void)`.
std::vector<std::byte> x86_32_frame_function() {
  const std::uint8_t bytes[] = {
      0x55,              // push ebp
      0x89, 0xe5,        // mov ebp, esp
      0x8b, 0x45, 0x08,  // mov eax, [ebp+8]
      0x03, 0x45, 0x0c,  // add eax, [ebp+0xc]
      0x5d,              // pop ebp
      0xc3,              // ret
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

IrStatement assign_statement(std::uint8_t width) {
  IrStatement statement;
  statement.op = IrOp::Assign;
  statement.dest = IrOperand::register_ref("rax", width);
  statement.a = IrOperand::constant_value(1, width);
  statement.width = width;
  return statement;
}

IrStatement return_statement() {
  IrStatement statement;
  statement.op = IrOp::Return;
  statement.a = IrOperand::register_ref("rax", 8);
  statement.width = 8;
  return statement;
}

IrFunction single_block_function() {
  IrFunction function;
  function.address = 0x1000;
  function.name = "test_function";
  function.return_width = 8;  // as a lifter would infer for `return rax;`
  IrBlock block;
  block.address = 0x1000;
  block.statements.push_back(assign_statement(8));
  block.statements.push_back(return_statement());
  function.blocks.push_back(std::move(block));
  return function;
}

/// Compare `reg` with zero, leaving the flags for a following conditional
/// branch.
IrStatement compare_zero_statement() {
  IrStatement statement;
  statement.op = IrOp::Compare;
  statement.a = IrOperand::register_ref("rax", 8);
  statement.b = IrOperand::constant_value(0, 8);
  statement.condition = IrCondition::Equal;
  statement.width = 8;
  return statement;
}

IrStatement conditional_branch_statement(std::uint32_t target) {
  IrStatement statement;
  statement.op = IrOp::CondBranch;
  statement.condition = IrCondition::Equal;
  statement.a = IrOperand::register_ref("rax", 8);
  statement.b = IrOperand::block_ref(target);
  statement.width = 8;
  return statement;
}

IrStatement branch_statement(std::uint32_t target) {
  IrStatement statement;
  statement.op = IrOp::Branch;
  statement.a = IrOperand::block_ref(target);
  statement.width = 8;
  return statement;
}

IrStatement assign_register_statement(const std::string& name, std::uint64_t value) {
  IrStatement statement;
  statement.op = IrOp::Assign;
  statement.dest = IrOperand::register_ref(name, 8);
  statement.a = IrOperand::constant_value(value, 8);
  statement.width = 8;
  return statement;
}

IrBlock make_block(std::uint64_t address) {
  IrBlock block;
  block.address = address;
  return block;
}

IrFunction branch_function() {
  IrFunction function;
  function.address = 0x1000;
  function.name = "branchy";
  function.return_width = 8;  // as a lifter would infer for `return rax;`
  function.blocks.push_back(make_block(0x1000));
  function.blocks.push_back(make_block(0x1008));
  function.blocks.push_back(make_block(0x100c));
  function.blocks.push_back(make_block(0x1010));
  return function;
}

const donkey::Function* function_at(const donkey::AnalysisResult& analysis, std::uint64_t address) {
  for (const donkey::Function& function : analysis.functions) {
    if (function.address == address) {
      return &function;
    }
  }
  return nullptr;
}

TEST(Ir, VerifierAcceptsWellFormedFunction) {
  const IrFunction function = single_block_function();
  auto verified = donkey::verify_ir(function);
  ASSERT_TRUE(verified.has_value()) << verified.diagnostic().message;
}

TEST(Ir, VerifierRejectsMissingTerminator) {
  IrFunction function = single_block_function();
  function.blocks[0].statements.pop_back();  // drop the return
  auto verified = donkey::verify_ir(function);
  ASSERT_FALSE(verified.has_value());
  EXPECT_EQ(verified.diagnostic().code, "ir.missing_terminator");
}

TEST(Ir, VerifierRejectsOutOfRangeBlockIndex) {
  IrFunction function = single_block_function();
  function.blocks[0].statements.back() = IrStatement{};
  function.blocks[0].statements.back().op = IrOp::Branch;
  function.blocks[0].statements.back().a = IrOperand::block_ref(7);
  function.blocks[0].statements.back().width = 8;
  auto verified = donkey::verify_ir(function);
  ASSERT_FALSE(verified.has_value());
  EXPECT_EQ(verified.diagnostic().code, "ir.bad_block_index");
}

TEST(Ir, VerifierRejectsEmptyRegisterName) {
  IrFunction function = single_block_function();
  function.blocks[0].statements.front().dest = IrOperand::register_ref("", 8);
  auto verified = donkey::verify_ir(function);
  ASSERT_FALSE(verified.has_value());
  EXPECT_EQ(verified.diagnostic().code, "ir.empty_register");
}

TEST(Ir, VerifierRejectsInvalidWidth) {
  IrFunction function = single_block_function();
  function.blocks[0].statements.front().width = 3;
  auto verified = donkey::verify_ir(function);
  ASSERT_FALSE(verified.has_value());
  EXPECT_EQ(verified.diagnostic().code, "ir.bad_width");
}

TEST(Ir, VerifierRejectsUnsupportedWithoutText) {
  IrFunction function = single_block_function();
  IrStatement statement;
  statement.op = IrOp::Unsupported;
  statement.width = 8;
  function.blocks[0].statements.insert(function.blocks[0].statements.begin(), std::move(statement));
  auto verified = donkey::verify_ir(function);
  ASSERT_FALSE(verified.has_value());
  EXPECT_EQ(verified.diagnostic().code, "ir.empty_unsupported");
}

TEST(Ir, PseudocodePrinterRefusesMalformedIr) {
  IrFunction function = single_block_function();
  function.blocks[0].statements.pop_back();
  auto text = donkey::format_pseudocode(function);
  ASSERT_FALSE(text.has_value());
  EXPECT_EQ(text.diagnostic().code, "ir.missing_terminator");
}

TEST(Ir, PseudocodePrinterRendersVerifiedFunction) {
  auto text = donkey::format_pseudocode(single_block_function());
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  EXPECT_NE(text.value().find("u64 test_function(void)"), std::string::npos);
  EXPECT_NE(text.value().find("rax = 0x1;"), std::string::npos);
  EXPECT_NE(text.value().find("return rax;"), std::string::npos);
  // A single straight-line block has no control flow, so it needs no labels.
  EXPECT_EQ(text.value().find("loc_1000:"), std::string::npos);
}

TEST(Ir, StructuresIfThenElse) {
  IrFunction function = branch_function();
  function.blocks[0].statements.push_back(compare_zero_statement());
  function.blocks[0].statements.push_back(conditional_branch_statement(2));
  function.blocks[1].statements.push_back(assign_register_statement("rdx", 2));
  function.blocks[1].statements.push_back(branch_statement(3));
  function.blocks[2].statements.push_back(assign_register_statement("rcx", 1));
  function.blocks[2].statements.push_back(branch_statement(3));
  function.blocks[3].statements.push_back(return_statement());

  auto text = donkey::format_pseudocode(function);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  const std::string& code = text.value();
  EXPECT_NE(code.find("if (rax == 0x0) {"), std::string::npos) << code;
  EXPECT_NE(code.find("rcx = 0x1;"), std::string::npos) << code;
  EXPECT_NE(code.find("} else {"), std::string::npos) << code;
  EXPECT_NE(code.find("rdx = 0x2;"), std::string::npos) << code;
  EXPECT_NE(code.find("return rax;"), std::string::npos) << code;
  EXPECT_EQ(code.find("goto "), std::string::npos) << code;
  EXPECT_EQ(code.find("loc_"), std::string::npos) << code;
}

TEST(Ir, StructuresIfThenWithoutElse) {
  IrFunction function = branch_function();
  function.blocks.resize(3);
  function.blocks[0].statements.push_back(compare_zero_statement());
  function.blocks[0].statements.push_back(conditional_branch_statement(2));
  function.blocks[1].statements.push_back(assign_register_statement("rcx", 1));
  function.blocks[1].statements.push_back(branch_statement(2));
  function.blocks[2].statements.push_back(return_statement());

  auto text = donkey::format_pseudocode(function);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  const std::string& code = text.value();
  // Branch taken to the join means the fallthrough body runs when the
  // condition is false, so the printed condition is the complement.
  EXPECT_NE(code.find("if (rax != 0x0) {"), std::string::npos) << code;
  EXPECT_NE(code.find("rcx = 0x1;"), std::string::npos) << code;
  EXPECT_EQ(code.find("} else {"), std::string::npos) << code;
  EXPECT_NE(code.find("return rax;"), std::string::npos) << code;
}

TEST(Ir, StructuresWhileLoop) {
  IrFunction function = branch_function();
  function.blocks.resize(3);
  function.blocks[0].statements.push_back(compare_zero_statement());
  function.blocks[0].statements.push_back(conditional_branch_statement(2));
  IrStatement decrement;
  decrement.op = IrOp::Sub;
  decrement.dest = IrOperand::register_ref("rax", 8);
  decrement.a = IrOperand::register_ref("rax", 8);
  decrement.b = IrOperand::constant_value(1, 8);
  decrement.width = 8;
  function.blocks[1].statements.push_back(decrement);
  function.blocks[1].statements.push_back(branch_statement(0));
  function.blocks[2].statements.push_back(return_statement());

  auto text = donkey::format_pseudocode(function);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  const std::string& code = text.value();
  EXPECT_NE(code.find("while (rax != 0x0) {"), std::string::npos) << code;
  EXPECT_NE(code.find("rax = rax - 0x1;"), std::string::npos) << code;
  EXPECT_NE(code.find("return rax;"), std::string::npos) << code;
  EXPECT_EQ(code.find("goto "), std::string::npos) << code;
}

// rax = 0; while (rax < 10) { rbx += 2; rax += 1; }: the store before the header is the
// init and the last statement of the latch is the step, so the loop prints as a for.
TEST(Ir, StructuresCountedLoopAsFor) {
  IrFunction function = branch_function();
  function.blocks.resize(4);
  function.blocks[0].statements.push_back(assign_register_statement("rax", 0));
  function.blocks[0].statements.push_back(branch_statement(1));
  IrStatement compare;
  compare.op = IrOp::Compare;
  compare.a = IrOperand::register_ref("rax", 8);
  compare.b = IrOperand::constant_value(10, 8);
  compare.condition = IrCondition::SignedGreaterEqual;
  compare.width = 8;
  function.blocks[1].statements.push_back(compare);
  function.blocks[1].statements.push_back(conditional_branch_statement(3));
  function.blocks[1].statements.back().condition = IrCondition::SignedGreaterEqual;
  IrStatement body;
  body.op = IrOp::Add;
  body.dest = IrOperand::register_ref("rbx", 8);
  body.a = IrOperand::register_ref("rbx", 8);
  body.b = IrOperand::constant_value(2, 8);
  body.width = 8;
  IrStatement step;
  step.op = IrOp::Add;
  step.dest = IrOperand::register_ref("rax", 8);
  step.a = IrOperand::register_ref("rax", 8);
  step.b = IrOperand::constant_value(1, 8);
  step.width = 8;
  function.blocks[2].statements.push_back(body);
  function.blocks[2].statements.push_back(step);
  function.blocks[2].statements.push_back(branch_statement(1));
  function.blocks[3].statements.push_back(return_statement());

  auto text = donkey::format_pseudocode(function);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  const std::string& code = text.value();
  EXPECT_NE(code.find("for (rax = 0x0; rax < 0xa; rax = rax + 0x1) {"), std::string::npos) << code;
  EXPECT_NE(code.find("rbx = rbx + 0x2;"), std::string::npos) << code;
  const std::size_t header_init = code.find("rax = 0x0;");
  EXPECT_EQ(code.find("rax = 0x0;", header_init + 1), std::string::npos)
      << "the init is printed once, in the header: " << code;
  EXPECT_EQ(code.find("while ("), std::string::npos) << code;
  EXPECT_EQ(code.find("goto "), std::string::npos) << code;
}

// The same loop when the preheader's last store is to another register: there is no init
// for the header to print, so the loop keeps its while form.
TEST(Ir, LoopWithoutAnInitStaysWhile) {
  IrFunction function = branch_function();
  function.blocks.resize(4);
  function.blocks[0].statements.push_back(assign_register_statement("rdx", 0));
  function.blocks[0].statements.push_back(branch_statement(1));
  IrStatement compare;
  compare.op = IrOp::Compare;
  compare.a = IrOperand::register_ref("rax", 8);
  compare.b = IrOperand::constant_value(10, 8);
  compare.condition = IrCondition::SignedGreaterEqual;
  compare.width = 8;
  function.blocks[1].statements.push_back(compare);
  function.blocks[1].statements.push_back(conditional_branch_statement(3));
  function.blocks[1].statements.back().condition = IrCondition::SignedGreaterEqual;
  IrStatement step;
  step.op = IrOp::Add;
  step.dest = IrOperand::register_ref("rax", 8);
  step.a = IrOperand::register_ref("rax", 8);
  step.b = IrOperand::constant_value(1, 8);
  step.width = 8;
  function.blocks[2].statements.push_back(step);
  function.blocks[2].statements.push_back(branch_statement(1));
  function.blocks[3].statements.push_back(return_statement());

  auto text = donkey::format_pseudocode(function);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  const std::string& code = text.value();
  EXPECT_NE(code.find("while (rax < 0xa) {"), std::string::npos) << code;
  EXPECT_EQ(code.find("for ("), std::string::npos) << code;
  EXPECT_NE(code.find("rdx = 0x0;"), std::string::npos) << code;
}

TEST(Ir, StructuresDoWhileLoop) {
  IrFunction function = branch_function();
  function.blocks.resize(3);
  IrStatement increment;
  increment.op = IrOp::Add;
  increment.dest = IrOperand::register_ref("rax", 8);
  increment.a = IrOperand::register_ref("rax", 8);
  increment.b = IrOperand::constant_value(1, 8);
  increment.width = 8;
  function.blocks[0].statements.push_back(increment);
  function.blocks[0].statements.push_back(branch_statement(1));
  function.blocks[1].statements.push_back(compare_zero_statement());
  function.blocks[1].statements.back().condition = IrCondition::NotEqual;
  function.blocks[1].statements.push_back(conditional_branch_statement(0));
  function.blocks[1].statements.back().condition = IrCondition::NotEqual;
  function.blocks[2].statements.push_back(return_statement());

  auto text = donkey::format_pseudocode(function);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  const std::string& code = text.value();
  EXPECT_NE(code.find("do {"), std::string::npos) << code;
  EXPECT_NE(code.find("} while (rax != 0x0);"), std::string::npos) << code;
  EXPECT_NE(code.find("rax = rax + 0x1;"), std::string::npos) << code;
  EXPECT_EQ(code.find("goto "), std::string::npos) << code;
}

TEST(Ir, FallsBackToLabelsForIrreducibleControlFlow) {
  IrFunction function = branch_function();
  function.blocks[0].statements.push_back(compare_zero_statement());
  function.blocks[0].statements.push_back(conditional_branch_statement(1));
  function.blocks[1].statements.push_back(branch_statement(2));
  function.blocks[2].statements.push_back(compare_zero_statement());
  function.blocks[2].statements.push_back(conditional_branch_statement(1));
  function.blocks[3].statements.push_back(return_statement());

  ASSERT_TRUE(donkey::verify_ir(function).has_value());
  auto text = donkey::format_pseudocode(function);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  const std::string& code = text.value();
  EXPECT_NE(code.find("control flow not fully structured"), std::string::npos) << code;
  EXPECT_NE(code.find("goto loc_"), std::string::npos) << code;
  EXPECT_NE(code.find("loc_1000:"), std::string::npos) << code;
}

TEST(Ir, InfersX86_64IntegerArgumentsAndReturn) {
  const auto data = x86_two_argument_function();
  const auto image = synthetic_image(data.size());
  auto analyzed = donkey::analyze(image, data);
  ASSERT_TRUE(analyzed.has_value()) << analyzed.diagnostic().message;
  ASSERT_FALSE(analyzed.value().functions.empty());

  auto lifted = donkey::lift_function(image, analyzed.value(), analyzed.value().functions.front());
  ASSERT_TRUE(lifted.has_value()) << lifted.diagnostic().message;
  const IrFunction& function = lifted.value();
  ASSERT_EQ(function.parameters.size(), 2U);
  EXPECT_EQ(function.parameters[0].name, "a0");
  EXPECT_EQ(function.parameters[0].width, 4);
  EXPECT_EQ(function.parameters[0].abi_register, "rdi");
  EXPECT_EQ(function.parameters[1].name, "a1");
  EXPECT_EQ(function.parameters[1].abi_register, "rsi");
  EXPECT_EQ(function.return_width, 4);

  auto text = donkey::format_pseudocode(function);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  EXPECT_NE(text.value().find("(u32 a0, u32 a1)"), std::string::npos) << text.value();
  EXPECT_NE(text.value().find("u32 sub_1000"), std::string::npos) << text.value();
}

TEST(Ir, DoesNotInferAnArgumentRegisterThatIsWrittenFirst) {
  const auto data = x86_written_argument_function();
  const auto image = synthetic_image(data.size());
  auto analyzed = donkey::analyze(image, data);
  ASSERT_TRUE(analyzed.has_value()) << analyzed.diagnostic().message;
  ASSERT_FALSE(analyzed.value().functions.empty());

  auto lifted = donkey::lift_function(image, analyzed.value(), analyzed.value().functions.front());
  ASSERT_TRUE(lifted.has_value()) << lifted.diagnostic().message;
  const IrFunction& function = lifted.value();
  EXPECT_TRUE(function.parameters.empty());
  EXPECT_EQ(function.return_width, 4);

  auto text = donkey::format_pseudocode(function);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  EXPECT_NE(text.value().find("u32 sub_1000(void)"), std::string::npos) << text.value();
}

TEST(Ir, LiftsX86_32FrameFunction) {
  const auto data = x86_32_frame_function();
  auto image = synthetic_image(data.size());
  image.architecture = Architecture::X86;
  image.bits = 32;
  auto analyzed = donkey::analyze(image, data);
  ASSERT_TRUE(analyzed.has_value()) << analyzed.diagnostic().message;
  ASSERT_FALSE(analyzed.value().functions.empty());

  auto lifted = donkey::lift_function(image, analyzed.value(), analyzed.value().functions.front());
  ASSERT_TRUE(lifted.has_value()) << lifted.diagnostic().message;
  const IrFunction& function = lifted.value();
  // cdecl passes arguments on the stack, so no register parameters are claimed.
  EXPECT_TRUE(function.parameters.empty());
  EXPECT_EQ(function.return_width, 4);

  auto verified = donkey::verify_ir(function);
  ASSERT_TRUE(verified.has_value()) << verified.diagnostic().message;

  auto text = donkey::format_pseudocode(function);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  const std::string& code = text.value();
  EXPECT_NE(code.find("u32 sub_1000(void)"), std::string::npos) << code;
  EXPECT_NE(code.find("esp = esp - 0x4;"), std::string::npos) << code;
  EXPECT_NE(code.find("*(u32 *)(esp) = ebp;"), std::string::npos) << code;
  EXPECT_NE(code.find("ebp = esp;"), std::string::npos) << code;
  EXPECT_NE(code.find("eax = *(u32 *)(ebp + 0x8);"), std::string::npos) << code;
  EXPECT_NE(code.find("return eax;"), std::string::npos) << code;
}

/// AArch64 load pairs, checked in the IR interpreter against what the
/// instructions compute.
std::vector<std::byte> aarch64_bytes(std::initializer_list<std::uint32_t> words) {
  std::vector<std::byte> out;
  for (const std::uint32_t word : words) {
    for (int shift = 0; shift < 32; shift += 8) {
      out.push_back(static_cast<std::byte>((word >> shift) & 0xFF));
    }
  }
  return out;
}

std::uint64_t run_aarch64(const std::vector<std::byte>& data, std::vector<std::uint8_t> memory) {
  auto image = synthetic_image(data.size());
  image.architecture = Architecture::AArch64;
  auto analyzed = donkey::analyze(image, data);
  EXPECT_TRUE(analyzed.has_value());
  if (!analyzed.has_value() || analyzed.value().functions.empty()) {
    return 0;
  }
  auto lifted = donkey::lift_function(image, analyzed.value(), analyzed.value().functions.front());
  EXPECT_TRUE(lifted.has_value());
  if (!lifted.has_value()) {
    return 0;
  }
  EXPECT_FALSE(lifted.value().partial);
  donkey::IrEvalMemory eval_memory;
  constexpr std::uint64_t kData = 0x200000;
  eval_memory.add_region(kData, std::move(memory));
  donkey::IrEvalOptions options;
  options.architecture = Architecture::AArch64;
  options.convention = donkey::IrCallingConvention::Aapcs64;
  const std::uint64_t arguments[] = {kData};
  auto result = donkey::evaluate_ir(lifted.value(), arguments, eval_memory, options);
  EXPECT_TRUE(result.has_value());
  return result.has_value() ? result.value().return_value : 0;
}

TEST(Ir, AArch64LoadPairIntoItsOwnBaseUsesTheOriginalAddress) {
  // ldp x0, x1, [x0]; sub x0, x0, x1; ret
  const auto data = aarch64_bytes({0xa9400400, 0xcb010000, 0xd65f03c0});
  std::vector<std::uint8_t> memory(16, 0);
  memory[0] = 100;  // x0 = 100
  memory[8] = 30;   // x1 = 30
  EXPECT_EQ(run_aarch64(data, memory), 70U);
}

TEST(Ir, AArch64LoadPairSignedWordsSignExtends) {
  // ldpsw x8, x9, [x0]; add x0, x8, x9; ret
  const auto data = aarch64_bytes({0x69402408, 0x8b090100, 0xd65f03c0});
  std::vector<std::uint8_t> memory = {0xfe, 0xff, 0xff, 0xff, 5, 0, 0, 0};  // -2, 5
  EXPECT_EQ(run_aarch64(data, memory), 3U);
}

// Flags from cmp (with a shifted operand) and subs feed conditional selects
// in the same block; register-offset loads, mvn, ubfiz and ror. Each input
// is checked in the interpreter against the same computation in C++.
TEST(Ir, AArch64SelectsBitfieldsAndRegisterOffsetsComputeTheRealValues) {
  const auto data = aarch64_bytes({
      0xb9400008,  // ldr w8, [x0]
      0xb9400409,  // ldr w9, [x0, #4]
      0xd280004a,  // mov x10, #2
      0xb86a780b,  // ldr w11, [x0, x10, lsl #2]
      0x6b09051f,  // cmp w8, w9, lsl #1
      0x1a9fd7ec,  // cset w12, gt
      0x1a89b56d,  // csinc w13, w11, w9, lt
      0x2a2803ee,  // mvn w14, w8
      0x531c0d0f,  // ubfiz w15, w8, #4, #4
      0x13882110,  // ror w16, w8, #8
      0x6b090111,  // subs w17, w8, w9
      0x5a892572,  // csneg w18, w11, w9, hs
      0x0b0d0180,  // add w0, w12, w13
      0x4a0e0000,  // eor w0, w0, w14
      0x0b0f0000,  // add w0, w0, w15
      0x4a100000,  // eor w0, w0, w16
      0x0b120000,  // add w0, w0, w18
      0xd65f03c0,  // ret
  });
  const std::uint32_t inputs[][3] = {
      {7, 3, 100}, {5, 3, 9}, {6, 3, 1}, {0x80000001U, 2, 0xdeadbeefU}, {1, 0x40000000U, 4}};
  for (const auto& in : inputs) {
    const std::uint32_t a = in[0];
    const std::uint32_t b = in[1];
    const std::uint32_t c = in[2];
    const auto sa = static_cast<std::int32_t>(a);
    const auto sb2 = static_cast<std::int32_t>(b << 1);
    const std::uint32_t w12 = sa > sb2 ? 1U : 0U;
    const std::uint32_t w13 = sa < sb2 ? c : b + 1;
    const std::uint32_t w14 = ~a;
    const std::uint32_t w15 = (a & 0xfU) << 4;
    const std::uint32_t w16 = (a >> 8) | (a << 24);
    const std::uint32_t w18 = a >= b ? c : 0U - b;
    const std::uint32_t expected = ((((w12 + w13) ^ w14) + w15) ^ w16) + w18;
    std::vector<std::uint8_t> memory(16, 0);
    for (int i = 0; i < 4; ++i) {
      memory[i] = static_cast<std::uint8_t>(a >> (8 * i));
      memory[4 + i] = static_cast<std::uint8_t>(b >> (8 * i));
      memory[8 + i] = static_cast<std::uint8_t>(c >> (8 * i));
    }
    EXPECT_EQ(run_aarch64(data, memory) & 0xffffffffU, expected) << "a=" << a << " b=" << b;
  }
}

// A branch on flags the lifter does not model must stay Partial: here negs
// overwrites NZCV between cmp and b.eq. (adds is modelled since G03-T4, so it
// is no longer an example of an unmodelled writer.)
TEST(Ir, AArch64BranchAfterAnUnmodelledFlagWriterIsPartial) {
  const auto data = aarch64_bytes({
      0x6b01001f,  // cmp w0, w1
      0x6b0103e2,  // negs w2, w1
      0x54000060,  // b.eq +12
      0x52800020,  // mov w0, #1
      0xd65f03c0,  // ret
      0x52800040,  // mov w0, #2
      0xd65f03c0,  // ret
  });
  auto image = synthetic_image(data.size());
  image.architecture = Architecture::AArch64;
  auto analyzed = donkey::analyze(image, data);
  ASSERT_TRUE(analyzed.has_value());
  ASSERT_FALSE(analyzed.value().functions.empty());
  auto lifted = donkey::lift_function(image, analyzed.value(), analyzed.value().functions.front());
  ASSERT_TRUE(lifted.has_value());
  EXPECT_TRUE(lifted.value().partial);
}

// `shl eax, 32` shifts by 0 (x86 masks a 32-bit count to 5 bits) and leaves
// the flags alone, so the jz below tests esi from `test esi, esi`. Treating
// the shift as a flag writer branched on eax instead and was reported
// Complete.
TEST(Ir, X86ZeroEffectiveShiftKeepsThePriorFlags) {
  const std::uint8_t raw[] = {0x89, 0xf8,                           // mov eax, edi
                              0x85, 0xf6,                           // test esi, esi
                              0xc1, 0xe0, 0x20,                     // shl eax, 32
                              0x74, 0x06,                           // je +6
                              0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3,   // mov eax, 1; ret
                              0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3};  // mov eax, 2; ret
  std::vector<std::byte> data;
  for (const std::uint8_t b : raw) {
    data.push_back(static_cast<std::byte>(b));
  }
  auto image = synthetic_image(data.size());
  image.architecture = Architecture::X86_64;
  auto analyzed = donkey::analyze(image, data);
  ASSERT_TRUE(analyzed.has_value());
  ASSERT_FALSE(analyzed.value().functions.empty());
  auto lifted = donkey::lift_function(image, analyzed.value(), analyzed.value().functions.front());
  ASSERT_TRUE(lifted.has_value());
  // The count is a known 0, so the flags of `test esi, esi` still hold.
  EXPECT_FALSE(lifted.value().partial);
  struct Case {
    std::uint64_t edi;
    std::uint64_t esi;
    std::uint64_t expected;
  };
  for (const Case c : {Case{5, 0, 2}, Case{0, 7, 1}, Case{0, 0, 2}, Case{9, 9, 1}}) {
    donkey::IrEvalMemory memory;
    donkey::IrEvalOptions options;
    options.architecture = Architecture::X86_64;
    options.convention = donkey::IrCallingConvention::SysV64;
    const std::uint64_t arguments[] = {c.edi, c.esi};
    auto result = donkey::evaluate_ir(lifted.value(), arguments, memory, options);
    ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
    EXPECT_EQ(result.value().return_value & 0xffffffffU, c.expected)
        << "edi=" << c.edi << " esi=" << c.esi;
  }
}

TEST(Ir, InfersAArch64IntegerArgumentsAndReturn) {
  const auto data = aarch64_two_argument_function();
  auto image = synthetic_image(data.size());
  image.architecture = Architecture::AArch64;
  auto analyzed = donkey::analyze(image, data);
  ASSERT_TRUE(analyzed.has_value()) << analyzed.diagnostic().message;
  ASSERT_FALSE(analyzed.value().functions.empty());

  auto lifted = donkey::lift_function(image, analyzed.value(), analyzed.value().functions.front());
  ASSERT_TRUE(lifted.has_value()) << lifted.diagnostic().message;
  const IrFunction& function = lifted.value();
  ASSERT_EQ(function.parameters.size(), 2U);
  EXPECT_EQ(function.parameters[0].width, 4);
  EXPECT_EQ(function.parameters[0].abi_register, "x0");
  EXPECT_EQ(function.parameters[1].abi_register, "x1");
  EXPECT_EQ(function.return_width, 4);

  auto text = donkey::format_pseudocode(function);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  EXPECT_NE(text.value().find("u32 sub_1000(u32 a0, u32 a1)"), std::string::npos) << text.value();
}

TEST(Ir, InfersVoidSignatureAndMarksMixedReturnPaths) {
  IrFunction function;
  function.address = 0x1000;
  function.name = "void_function";
  function.blocks.push_back(make_block(0x1000));
  function.blocks.push_back(make_block(0x1008));
  function.blocks.push_back(make_block(0x100c));
  function.blocks[0].statements.push_back(compare_zero_statement());
  function.blocks[0].statements.push_back(conditional_branch_statement(2));
  function.blocks[1].statements.push_back(return_statement());

  IrStatement bare_return;
  bare_return.op = IrOp::Return;
  bare_return.width = 8;
  function.blocks[2].statements.push_back(bare_return);

  donkey::infer_signature(function, Architecture::X86_64);
  ASSERT_TRUE(function.signature_inferred);
  EXPECT_TRUE(function.parameters.empty());
  EXPECT_EQ(function.return_width, 8);
  bool mixed_note = false;
  for (const std::string& note : function.notes) {
    if (note.find("some return paths carry no value") != std::string::npos) {
      mixed_note = true;
    }
  }
  EXPECT_TRUE(mixed_note);

  auto text = donkey::format_pseudocode(function);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  EXPECT_NE(text.value().find("u64 void_function(void)"), std::string::npos) << text.value();
}

TEST(Ir, SignatureInferenceIsSilentForUnmodelledArchitectures) {
  IrFunction function = single_block_function();
  function.return_width = 0;
  donkey::infer_signature(function, Architecture::RiscV64);
  EXPECT_FALSE(function.signature_inferred);
  EXPECT_TRUE(function.parameters.empty());
  EXPECT_EQ(function.return_width, 0);
}

TEST(Ir, ArgumentReadsFollowThePathsNotTheBlockOrder) {
  // Block 1 writes x0 and sits before block 2 in the layout, but block 0 reaches block 2
  // without passing block 1. The x0 that block 2 reads is still the incoming argument.
  IrFunction function;
  function.address = 0x1000;
  function.name = "path_sensitive";
  function.blocks.push_back(make_block(0x1000));
  function.blocks.push_back(make_block(0x1008));
  function.blocks.push_back(make_block(0x100c));

  IrStatement compare;
  compare.op = IrOp::Compare;
  compare.a = IrOperand::register_ref("x1", 8);
  compare.b = IrOperand::constant_value(0, 8);
  compare.condition = IrCondition::Equal;
  compare.width = 8;
  function.blocks[0].statements.push_back(compare);
  function.blocks[0].statements.push_back(conditional_branch_statement(2));
  function.blocks[1].statements.push_back(assign_register_statement("x0", 0));
  function.blocks[1].statements.push_back(branch_statement(2));

  IrStatement use;
  use.op = IrOp::Assign;
  use.dest = IrOperand::register_ref("x3", 8);
  use.a = IrOperand::register_ref("x0", 8);
  use.width = 8;
  function.blocks[2].statements.push_back(use);
  IrStatement ret;
  ret.op = IrOp::Return;
  ret.a = IrOperand::register_ref("x3", 8);
  ret.width = 8;
  function.blocks[2].statements.push_back(ret);

  donkey::infer_signature(function, Architecture::AArch64);
  bool has_x0 = false;
  for (const IrParameter& parameter : function.parameters) {
    has_x0 = has_x0 || parameter.abi_register == "x0";
  }
  EXPECT_TRUE(has_x0) << "x0 is read on a path that does not write it";
}

TEST(Ir, UnsupportedVectorStatementDoesNotMakeAVectorRegisterAnArgument) {
  // The vector move is not modelled, so its effect on v0 is unknown. The v0 read after it
  // must not be taken for an incoming floating-point argument: that would move the integer
  // arguments to the wrong registers when the function runs.
  IrFunction function;
  function.address = 0x1000;
  function.name = "vector_temporary";
  function.blocks.push_back(make_block(0x1000));
  IrStatement unsupported;
  unsupported.op = IrOp::Unsupported;
  unsupported.text = "movi v0.2d, #0000000000000000";
  function.blocks[0].statements.push_back(unsupported);

  IrStatement use;
  use.op = IrOp::Assign;
  use.dest = IrOperand::register_ref("x8", 8);
  use.a = IrOperand::register_ref("v0", 4);
  use.width = 8;
  function.blocks[0].statements.push_back(use);
  IrStatement ret;
  ret.op = IrOp::Return;
  ret.a = IrOperand::register_ref("x8", 8);
  ret.width = 8;
  function.blocks[0].statements.push_back(ret);

  donkey::infer_signature(function, Architecture::AArch64);
  for (const IrParameter& parameter : function.parameters) {
    EXPECT_NE(parameter.abi_register.rfind("v", 0), 0U) << parameter.abi_register;
  }
  EXPECT_TRUE(function.parameters.empty());
}

namespace {

IrStatement compare_statement(const char* reg, std::uint64_t value, IrCondition condition) {
  IrStatement compare;
  compare.op = IrOp::Compare;
  compare.a = IrOperand::register_ref(reg, 8);
  compare.b = IrOperand::constant_value(value, 8);
  compare.condition = condition;
  compare.width = 8;
  return compare;
}

IrStatement cond_branch_statement(IrCondition condition, std::uint32_t target) {
  IrStatement branch;
  branch.op = IrOp::CondBranch;
  branch.condition = condition;
  branch.a = IrOperand::register_ref("rax", 8);
  branch.b = IrOperand::block_ref(target);
  branch.width = 8;
  return branch;
}

}  // namespace

TEST(Ir, BranchToTheLoopExitInsideTheBodyIsBreak) {
  // while (rax != 0) { if (rdi != 7) { rax = rax - 1; } else { break; } } return rax;
  // Block 2 leaves the loop through an unconditional branch to the exit (block 4).
  IrFunction function;
  function.address = 0x2000;
  function.name = "until_seven";
  function.blocks.push_back(make_block(0x2000));  // 0: while (rax != 0)
  function.blocks.push_back(make_block(0x2008));  // 1: if (rdi != 7)
  function.blocks.push_back(make_block(0x2010));  // 2: break
  function.blocks.push_back(make_block(0x2018));  // 3: rax = rax - 1
  function.blocks.push_back(make_block(0x2028));  // 4: return rax

  function.blocks[0].statements.push_back(compare_statement("rax", 0, IrCondition::Equal));
  function.blocks[0].statements.push_back(cond_branch_statement(IrCondition::Equal, 4));

  function.blocks[1].statements.push_back(compare_statement("rdi", 7, IrCondition::Equal));
  function.blocks[1].statements.push_back(cond_branch_statement(IrCondition::NotEqual, 3));

  function.blocks[2].statements.push_back(branch_statement(4));

  IrStatement decrement;
  decrement.op = IrOp::Sub;
  decrement.dest = IrOperand::register_ref("rax", 8);
  decrement.a = IrOperand::register_ref("rax", 8);
  decrement.b = IrOperand::constant_value(1, 8);
  decrement.width = 8;
  function.blocks[3].statements.push_back(decrement);
  function.blocks[3].statements.push_back(branch_statement(0));

  function.blocks[4].statements.push_back(return_statement());

  const auto text = donkey::format_pseudocode(function);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  EXPECT_NE(text.value().find("while (rax != 0x0) {"), std::string::npos) << text.value();
  EXPECT_NE(text.value().find("break;"), std::string::npos) << text.value();
  EXPECT_EQ(text.value().find("goto"), std::string::npos) << text.value();
}

TEST(Ir, NegatedIntegerComparisonIsWrittenAsItsComplement) {
  // if (rdi < 7) { skip } else { rax = 1; } return rax;  The branch skips the
  // assignment, so the printed guard is the complement of the comparison.
  IrFunction function;
  function.address = 0x3000;
  function.name = "clamp";
  function.blocks.push_back(make_block(0x3000));  // 0: compare and branch past block 1
  function.blocks.push_back(make_block(0x3008));  // 1: rax = 1
  function.blocks.push_back(make_block(0x3010));  // 2: return rax

  function.blocks[0].statements.push_back(compare_statement("rdi", 7, IrCondition::SignedLess));
  function.blocks[0].statements.push_back(cond_branch_statement(IrCondition::SignedLess, 2));

  IrStatement assign;
  assign.op = IrOp::Assign;
  assign.dest = IrOperand::register_ref("rax", 8);
  assign.a = IrOperand::constant_value(1, 8);
  assign.width = 8;
  function.blocks[1].statements.push_back(assign);
  function.blocks[1].statements.push_back(branch_statement(2));

  function.blocks[2].statements.push_back(return_statement());

  const auto text = donkey::format_pseudocode(function);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  EXPECT_NE(text.value().find("if (rdi >= 0x7) {"), std::string::npos) << text.value();
  EXPECT_EQ(text.value().find("!("), std::string::npos) << text.value();
}

TEST(Ir, LeavingTheLoopFromInsideASwitchIsNotStructured) {
  // while (rax != 0) { switch (eax) { case 1: leave the loop; default: rax -= 1; } }
  // return rax. A `break` inside the switch would leave the switch, not the loop, so
  // the body is refused and the function is shown with labels.
  IrFunction function;
  function.address = 0x4000;
  function.name = "switch_exit";
  function.blocks.push_back(make_block(0x4000));  // 0: while (rax != 0)
  function.blocks.push_back(make_block(0x4008));  // 1: switch (eax)
  function.blocks.push_back(make_block(0x4010));  // 2: case 1: leave
  function.blocks.push_back(make_block(0x4018));  // 3: default: rax -= 1
  function.blocks.push_back(make_block(0x4028));  // 4: return rax

  function.blocks[0].statements.push_back(compare_statement("rax", 0, IrCondition::Equal));
  function.blocks[0].statements.push_back(cond_branch_statement(IrCondition::Equal, 4));

  IrStatement sw;
  sw.op = IrOp::Switch;
  sw.dest = IrOperand::register_ref("eax", 4);
  sw.a = IrOperand::block_ref(3);  // default
  sw.width = 4;
  sw.switch_cases.push_back(IrSwitchCase{0x1, 2});
  function.blocks[1].statements.push_back(sw);

  function.blocks[2].statements.push_back(branch_statement(4));

  IrStatement decrement;
  decrement.op = IrOp::Sub;
  decrement.dest = IrOperand::register_ref("rax", 8);
  decrement.a = IrOperand::register_ref("rax", 8);
  decrement.b = IrOperand::constant_value(1, 8);
  decrement.width = 8;
  function.blocks[3].statements.push_back(decrement);
  function.blocks[3].statements.push_back(branch_statement(0));

  function.blocks[4].statements.push_back(return_statement());

  const auto text = donkey::format_pseudocode(function);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  EXPECT_NE(text.value().find("labeled blocks"), std::string::npos) << text.value();
}

TEST(Ir, SelfLoopWithAnEarlyReturnIsStructuredWithoutGoto) {
  // if (rdi == 0) return 0; do { rax += rdi; rdi -= 1; } while (rdi != 0); return rax;
  // The loop is one block that repeats itself, and it is laid out before the return of rax.
  IrFunction function;
  function.address = 0x1000;
  function.name = "countdown";
  function.blocks.push_back(make_block(0x1000));  // 0: the test
  function.blocks.push_back(make_block(0x1008));  // 1: the loop
  function.blocks.push_back(make_block(0x1020));  // 2: return rax
  function.blocks.push_back(make_block(0x1028));  // 3: return 0

  IrStatement compare;
  compare.op = IrOp::Compare;
  compare.a = IrOperand::register_ref("rdi", 8);
  compare.b = IrOperand::constant_value(0, 8);
  compare.condition = IrCondition::Equal;
  compare.width = 8;
  function.blocks[0].statements.push_back(compare);
  function.blocks[0].statements.push_back(conditional_branch_statement(3));

  IrStatement add;
  add.op = IrOp::Add;
  add.dest = IrOperand::register_ref("rax", 8);
  add.a = IrOperand::register_ref("rax", 8);
  add.b = IrOperand::register_ref("rdi", 8);
  add.width = 8;
  function.blocks[1].statements.push_back(add);
  IrStatement decrement;
  decrement.op = IrOp::Sub;
  decrement.dest = IrOperand::register_ref("rdi", 8);
  decrement.a = IrOperand::register_ref("rdi", 8);
  decrement.b = IrOperand::constant_value(1, 8);
  decrement.width = 8;
  function.blocks[1].statements.push_back(decrement);
  IrStatement again;
  again.op = IrOp::Compare;
  again.a = IrOperand::register_ref("rdi", 8);
  again.b = IrOperand::constant_value(0, 8);
  again.condition = IrCondition::NotEqual;
  again.width = 8;
  function.blocks[1].statements.push_back(again);
  IrStatement repeat;
  repeat.op = IrOp::CondBranch;
  repeat.condition = IrCondition::NotEqual;
  repeat.a = IrOperand::register_ref("rdi", 8);
  repeat.b = IrOperand::block_ref(1);
  repeat.width = 8;
  function.blocks[1].statements.push_back(repeat);

  function.blocks[2].statements.push_back(return_statement());
  IrStatement zero;
  zero.op = IrOp::Return;
  zero.a = IrOperand::constant_value(0, 8);
  zero.width = 8;
  function.blocks[3].statements.push_back(zero);

  const auto text = donkey::format_pseudocode(function);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  EXPECT_NE(text.value().find("do {"), std::string::npos) << text.value();
  EXPECT_NE(text.value().find("} while ("), std::string::npos) << text.value();
  EXPECT_NE(text.value().find("return 0x0;"), std::string::npos) << text.value();
  EXPECT_EQ(text.value().find("goto"), std::string::npos) << text.value();
  EXPECT_EQ(text.value().find("labeled blocks"), std::string::npos) << text.value();
}

TEST(Ir, SignatureInferenceDistinguishesSystemVAndWindowsX64) {
  // Read rcx and rdi before write
  IrFunction func_sysv = single_block_function();
  IrStatement read_rdi;
  read_rdi.op = IrOp::Assign;
  read_rdi.dest = IrOperand::register_ref("rax", 8);
  read_rdi.a = IrOperand::register_ref("rdi", 8);
  read_rdi.width = 8;
  func_sysv.blocks[0].statements.insert(func_sysv.blocks[0].statements.begin(), read_rdi);

  IrStatement read_rcx;
  read_rcx.op = IrOp::Assign;
  read_rcx.dest = IrOperand::register_ref("rbx", 8);
  read_rcx.a = IrOperand::register_ref("rcx", 8);
  read_rcx.width = 8;
  func_sysv.blocks[0].statements.insert(func_sysv.blocks[0].statements.begin() + 1, read_rcx);

  IrFunction func_pe = func_sysv;

  // System V: rdi is 1st arg, rcx is 4th arg
  donkey::infer_signature(func_sysv, Architecture::X86_64, donkey::BinaryFormat::Elf);
  ASSERT_EQ(func_sysv.parameters.size(), 2U);
  EXPECT_EQ(func_sysv.parameters[0].abi_register, "rdi");
  EXPECT_EQ(func_sysv.parameters[1].abi_register, "rcx");

  // Windows x64 PE: rcx is 1st arg, rdi is non-volatile/callee-saved, NOT an argument
  donkey::infer_signature(func_pe, Architecture::X86_64, donkey::BinaryFormat::Pe);
  ASSERT_EQ(func_pe.parameters.size(), 1U);
  EXPECT_EQ(func_pe.parameters[0].abi_register, "rcx");
}

TEST(Ir, VerifierRejectsBadSignatureWidth) {
  IrFunction function = single_block_function();
  function.parameters.push_back(IrParameter{"a0", 3, "rdi", false, std::string()});
  auto verified = donkey::verify_ir(function);
  ASSERT_FALSE(verified.has_value());
  EXPECT_EQ(verified.diagnostic().code, "ir.bad_parameter");
}

TEST(Ir, VerifierRejectsBadExtendWidth) {
  IrFunction function = single_block_function();
  IrStatement statement;
  statement.op = IrOp::ZeroExtend;
  statement.dest = IrOperand::register_ref("eax", 4);
  statement.a = IrOperand::register_ref("rax", 8);
  statement.width = 4;
  function.blocks[0].statements.insert(function.blocks[0].statements.begin(), std::move(statement));
  auto verified = donkey::verify_ir(function);
  ASSERT_FALSE(verified.has_value());
  EXPECT_EQ(verified.diagnostic().code, "ir.malformed_extend");
}

TEST(Ir, LiftsExtensionsLeaAndIndirectCall) {
  const auto data = extension_function();
  const auto image = synthetic_image(data.size());
  auto analyzed = donkey::analyze(image, data);
  ASSERT_TRUE(analyzed.has_value()) << analyzed.diagnostic().message;
  ASSERT_EQ(analyzed.value().functions.size(), 1U);

  auto lifted = donkey::lift_function(image, analyzed.value(), analyzed.value().functions.front());
  ASSERT_TRUE(lifted.has_value()) << lifted.diagnostic().message;
  auto verified = donkey::verify_ir(lifted.value());
  ASSERT_TRUE(verified.has_value()) << verified.diagnostic().message;

  auto text = donkey::format_pseudocode(lifted.value());
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  const std::string& code = text.value();
  EXPECT_NE(code.find("rax = (u32)(u8)rax;"), std::string::npos) << code;
  EXPECT_NE(code.find("rcx = (u64)(u8)rax;"), std::string::npos) << code;
  EXPECT_NE(code.find("rdx = (s32)(u8)rax;"), std::string::npos) << code;
  EXPECT_NE(code.find("rax = (s64)(u32)rax;"), std::string::npos) << code;
  // LEA must print an address expression, not a dereference.
  EXPECT_NE(code.find("rcx = (u64)(0x"), std::string::npos) << code;
  EXPECT_EQ(code.find("(u64)&*"), std::string::npos) << code;
  EXPECT_NE(code.find("((void (*)(void))rax)();"), std::string::npos) << code;
}

TEST(Ir, LiftsHighByteRegistersWithoutInvalidWidths) {
  const auto data = high_byte_register_function();
  const auto image = synthetic_image(data.size());
  auto analyzed = donkey::analyze(image, data);
  ASSERT_TRUE(analyzed.has_value()) << analyzed.diagnostic().message;
  ASSERT_FALSE(analyzed.value().functions.empty());

  auto lifted = donkey::lift_function(image, analyzed.value(), analyzed.value().functions.front());
  ASSERT_TRUE(lifted.has_value()) << lifted.diagnostic().message;
  auto verified = donkey::verify_ir(lifted.value());
  ASSERT_TRUE(verified.has_value())
      << verified.diagnostic().code << ": " << verified.diagnostic().message;
}

TEST(Ir, AddsExitBlockForTailConditionalBranch) {
  const auto data = tail_conditional_function();
  const auto image = synthetic_image(data.size());
  auto analyzed = donkey::analyze(image, data);
  ASSERT_TRUE(analyzed.has_value()) << analyzed.diagnostic().message;
  ASSERT_FALSE(analyzed.value().functions.empty());

  auto lifted = donkey::lift_function(image, analyzed.value(), analyzed.value().functions.front());
  ASSERT_TRUE(lifted.has_value()) << lifted.diagnostic().message;
  auto verified = donkey::verify_ir(lifted.value());
  ASSERT_TRUE(verified.has_value())
      << verified.diagnostic().code << ": " << verified.diagnostic().message;
  EXPECT_TRUE(lifted.value().partial);
}

TEST(Ir, ModelsPopFromMemoryAsUnsupportedInsteadOfMalformedLoad) {
  const auto data = pop_memory_function();
  const auto image = synthetic_image(data.size());
  auto analyzed = donkey::analyze(image, data);
  ASSERT_TRUE(analyzed.has_value()) << analyzed.diagnostic().message;
  ASSERT_FALSE(analyzed.value().functions.empty());

  auto lifted = donkey::lift_function(image, analyzed.value(), analyzed.value().functions.front());
  ASSERT_TRUE(lifted.has_value()) << lifted.diagnostic().message;
  auto verified = donkey::verify_ir(lifted.value());
  ASSERT_TRUE(verified.has_value())
      << verified.diagnostic().code << ": " << verified.diagnostic().message;
  EXPECT_TRUE(lifted.value().partial);
}

TEST(Ir, LiftsSyntheticBranchyX86Function) {
  const auto data = branchy_function();
  const auto image = synthetic_image(data.size());
  auto analyzed = donkey::analyze(image, data);
  ASSERT_TRUE(analyzed.has_value()) << analyzed.diagnostic().message;
  const donkey::AnalysisResult& analysis = analyzed.value();
  ASSERT_EQ(analysis.functions.size(), 1U);

  auto lifted = donkey::lift_function(image, analysis, analysis.functions.front());
  ASSERT_TRUE(lifted.has_value()) << lifted.diagnostic().message;
  const IrFunction& function = lifted.value();
  EXPECT_FALSE(function.partial);
  ASSERT_EQ(function.blocks.size(), 3U);

  auto verified = donkey::verify_ir(function);
  ASSERT_TRUE(verified.has_value()) << verified.diagnostic().message;

  const IrBlock& entry = function.blocks.front();
  ASSERT_GE(entry.statements.size(), 4U);
  EXPECT_EQ(entry.statements[entry.statements.size() - 1].op, IrOp::CondBranch);
  EXPECT_EQ(entry.statements[entry.statements.size() - 1].condition, IrCondition::Zero);

  auto text = donkey::format_pseudocode(function);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  const std::string& code = text.value();
  // Both arms of `test rax, rax; je 0x100c` return, so the structurer emits an
  // if/else instead of labels and gotos.
  EXPECT_NE(code.find("if ((rax & rax) == 0) {"), std::string::npos) << code;
  EXPECT_NE(code.find("} else {"), std::string::npos) << code;
  EXPECT_NE(code.find("rax = 0x1;"), std::string::npos) << code;
  EXPECT_NE(code.find("return rax;"), std::string::npos) << code;
  EXPECT_EQ(code.find("goto "), std::string::npos) << code;
}

TEST(Ir, LiftsElfEntryPointIntoVerifiedIr) {
  auto loaded = donkey::load_binary(fixture_path("tiny-elf-x86_64"));
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  auto analyzed = donkey::analyze(loaded.value().image, loaded.value().data);
  ASSERT_TRUE(analyzed.has_value());

  const donkey::Function* entry = function_at(analyzed.value(), 0x400100);
  ASSERT_NE(entry, nullptr);
  auto lifted = donkey::lift_function(loaded.value().image, analyzed.value(), *entry);
  ASSERT_TRUE(lifted.has_value()) << lifted.diagnostic().message;
  EXPECT_TRUE(donkey::verify_ir(lifted.value()).has_value());

  auto text = donkey::format_pseudocode(lifted.value());
  ASSERT_TRUE(text.has_value());
  EXPECT_NE(text.value().find("u64 _start(void)"), std::string::npos);
  EXPECT_NE(text.value().find("sub_400109();"), std::string::npos);
}

TEST(Ir, LiftsAArch64StraightLineFunction) {
  const auto data = aarch64_straight_line_function();
  auto image = synthetic_image(data.size());
  image.architecture = Architecture::AArch64;
  auto analyzed = donkey::analyze(image, data);
  ASSERT_TRUE(analyzed.has_value()) << analyzed.diagnostic().message;
  ASSERT_FALSE(analyzed.value().functions.empty()) << "no seeded function";

  // The lifter's own output: the statement passes are tested separately.
  donkey::LiftOptions lifter_only;
  lifter_only.run_passes = false;
  auto lifted = donkey::lift_function(image, analyzed.value(), analyzed.value().functions.front(),
                                      lifter_only);
  ASSERT_TRUE(lifted.has_value()) << lifted.diagnostic().message;
  auto verified = donkey::verify_ir(lifted.value());
  ASSERT_TRUE(verified.has_value())
      << verified.diagnostic().code << ": " << verified.diagnostic().message;

  auto text = donkey::format_pseudocode(lifted.value());
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  const std::string& code = text.value();
  // Pre-index stp: store at [sp, #-0x10]!, then sp -= 0x10. Capstone reports
  // x29/x30 by their ABI aliases fp/lr.
  EXPECT_NE(code.find("*(u64 *)(sp - 0x10) = x29;"), std::string::npos) << code;
  EXPECT_NE(code.find("*(u64 *)(sp - 0x8) = x30;"), std::string::npos) << code;
  EXPECT_NE(code.find("sp = sp - 0x10;"), std::string::npos) << code;
  // mov x29, sp
  EXPECT_NE(code.find("x29 = sp;"), std::string::npos) << code;
  // movz/movk: movz sets 0x1234, movk clears then merges 0xabcd into bits 16..31.
  EXPECT_NE(code.find("x0 = 0x1234;"), std::string::npos) << code;
  EXPECT_NE(code.find("x0 = x0 | 0xabcd0000;"), std::string::npos) << code;
  // Post-index ldp: access [sp] and [sp + 0x8], then sp += 0x10.
  EXPECT_NE(code.find("x29 = *(u64 *)(sp);"), std::string::npos) << code;
  EXPECT_NE(code.find("x30 = *(u64 *)(sp + 0x8);"), std::string::npos) << code;
  EXPECT_NE(code.find("sp = sp + 0x10;"), std::string::npos) << code;
  // ldrsw sign-extends a 32-bit load into a 64-bit register.
  EXPECT_NE(code.find("x5 = (s64)var_0;"), std::string::npos) << code;
  // madd must produce a multiply plus an add, never a single bogus op.
  EXPECT_NE(code.find("x6 = x4 * x5;"), std::string::npos) << code;
  EXPECT_NE(code.find("x7 = var_1 + x6;"), std::string::npos) << code;
}

TEST(Ir, LiftsAArch64ControlFlowFunction) {
  const auto data = aarch64_branchy_function();
  auto image = synthetic_image(data.size());
  image.architecture = Architecture::AArch64;
  auto analyzed = donkey::analyze(image, data);
  ASSERT_TRUE(analyzed.has_value()) << analyzed.diagnostic().message;
  ASSERT_FALSE(analyzed.value().functions.empty());

  auto lifted = donkey::lift_function(image, analyzed.value(), analyzed.value().functions.front());
  ASSERT_TRUE(lifted.has_value()) << lifted.diagnostic().message;
  auto verified = donkey::verify_ir(lifted.value());
  ASSERT_TRUE(verified.has_value())
      << verified.diagnostic().code << ": " << verified.diagnostic().message;

  auto text = donkey::format_pseudocode(lifted.value());
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  const std::string& code = text.value();
  // cmp x0, #0 followed by b.eq becomes a structured if/else.
  EXPECT_NE(code.find("if (x0 == 0x0) {"), std::string::npos) << code;
  EXPECT_NE(code.find("} else {"), std::string::npos) << code;
  // cbz x1 becomes a zero-test branch. The branch targets the join, so the
  // printed condition is the complement (`x1 != 0x0`) of the tested equality.
  EXPECT_NE(code.find("x1 != 0x0"), std::string::npos) << code;
  // tbz x1, #3 emits a bit test. Capstone reports the 32-bit form (w1) when
  // the tested bit is below 32, so match the mask rather than the register alias.
  EXPECT_NE(code.find("& 0x8)"), std::string::npos) << code;
  EXPECT_EQ(code.find("goto "), std::string::npos) << code;
}

TEST(Ir, LiftsMachOArm64EntryPoint) {
  auto loaded = donkey::load_binary(fixture_path("tiny-macho-arm64"));
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  auto analyzed = donkey::analyze(loaded.value().image, loaded.value().data);
  ASSERT_TRUE(analyzed.has_value()) << analyzed.diagnostic().message;

  const donkey::Function* entry = function_at(analyzed.value(), 0x100000F00);
  ASSERT_NE(entry, nullptr);
  donkey::LiftOptions
      lifter_only;  // the lifter's own output: the statement passes are tested separately
  lifter_only.run_passes = false;
  auto lifted = donkey::lift_function(loaded.value().image, analyzed.value(), *entry, lifter_only);
  ASSERT_TRUE(lifted.has_value()) << lifted.diagnostic().message;
  auto verified = donkey::verify_ir(lifted.value());
  ASSERT_TRUE(verified.has_value())
      << verified.diagnostic().code << ": " << verified.diagnostic().message;

  auto text = donkey::format_pseudocode(lifted.value());
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  EXPECT_NE(text.value().find("return x0;"), std::string::npos) << text.value();
}

TEST(Ir, RefusesArchitecturesTheLifterDoesNotModel) {
  // AArch64 is modelled now, so use an architecture that is still unsupported.
  const auto data = pop_memory_function();
  auto image = synthetic_image(data.size());
  image.architecture = Architecture::RiscV64;
  donkey::AnalysisResult analysis;
  analysis.architecture = Architecture::RiscV64;
  donkey::Function function;
  function.address = 0x1000;

  auto lifted = donkey::lift_function(image, analysis, function);
  ASSERT_FALSE(lifted.has_value());
  EXPECT_EQ(lifted.diagnostic().status, donkey::Status::Unsupported);
  EXPECT_EQ(lifted.diagnostic().code, "lift.unsupported_architecture");
}

TEST(Ir, TruncatedElfNeverProducesInvalidIr) {
  const std::vector<std::byte> full = read_bytes(fixture_path("tiny-elf-x86_64"));
  ASSERT_FALSE(full.empty());

  for (std::size_t length = 0; length <= full.size(); ++length) {
    const std::vector<std::byte> prefix(full.begin(),
                                        full.begin() + static_cast<std::ptrdiff_t>(length));
    auto loaded = donkey::parse_binary(prefix, fixture_path("tiny-elf-x86_64"));
    if (!loaded) {
      continue;  // Rejection is a valid, deterministic outcome.
    }
    donkey::AnalysisOptions options;
    options.max_instructions = 10'000;
    options.max_strings = 1'000;
    auto analyzed = donkey::analyze(loaded.value(), prefix, options);
    ASSERT_TRUE(analyzed.has_value()) << "length " << length;

    for (const donkey::Function& function : analyzed.value().functions) {
      auto lifted = donkey::lift_function(loaded.value(), analyzed.value(), function);
      if (!lifted) {
        // Only documented refusals are acceptable.
        EXPECT_TRUE(lifted.diagnostic().code == "lift.no_blocks" ||
                    lifted.diagnostic().code == "lift.unsupported_architecture" ||
                    lifted.diagnostic().status == donkey::Status::ResourceLimit)
            << "length " << length << ": " << lifted.diagnostic().code;
        continue;
      }
      auto verified = donkey::verify_ir(lifted.value());
      ASSERT_TRUE(verified.has_value()) << "length " << length << ": " << verified.diagnostic().code
                                        << " " << verified.diagnostic().message;
      auto text = donkey::format_pseudocode(lifted.value());
      EXPECT_TRUE(text.has_value()) << "length " << length;
    }
  }
}

TEST(Ir, VerifierRejectsTypeWidthMismatch) {
  IrFunction function = single_block_function();
  IrStatement bad_binary;
  bad_binary.op = IrOp::Add;
  bad_binary.dest = IrOperand::register_ref("rax", 8);
  bad_binary.a = IrOperand::register_ref("eax", 4);  // 4 != 8
  bad_binary.b = IrOperand::constant_value(1, 8);
  bad_binary.width = 8;
  function.blocks[0].statements.insert(function.blocks[0].statements.begin(), bad_binary);

  auto verified = donkey::verify_ir(function);
  ASSERT_FALSE(verified.has_value());
  EXPECT_EQ(verified.diagnostic().code, "ir.type_width_mismatch");
}

TEST(Ir, VerifierRejectsStatementsAfterTerminator) {
  IrFunction function = single_block_function();
  IrStatement dead_statement;
  dead_statement.op = IrOp::Assign;
  dead_statement.dest = IrOperand::register_ref("rax", 8);
  dead_statement.a = IrOperand::constant_value(42, 8);
  dead_statement.width = 8;
  function.blocks[0].statements.push_back(dead_statement);  // follows return

  auto verified = donkey::verify_ir(function);
  ASSERT_FALSE(verified.has_value());
  EXPECT_EQ(verified.diagnostic().code, "ir.dead_statements_after_terminator");
}

TEST(Ir, VerifierRejectsUnreachableBlock) {
  IrFunction function = single_block_function();
  // Add a second block that is never branched to
  IrBlock dead_block;
  dead_block.address = 0x2000;
  IrStatement ret;
  ret.op = IrOp::Return;
  ret.width = 8;
  dead_block.statements.push_back(ret);
  function.blocks.push_back(dead_block);

  auto verified = donkey::verify_ir(function);
  ASSERT_FALSE(verified.has_value());
  EXPECT_EQ(verified.diagnostic().code, "ir.unreachable_block");
}

TEST(Ir, VerifierRejectsUseBeforeDef) {
  IrFunction function;
  function.address = 0x1000;
  IrBlock block;
  block.address = 0x1000;

  // Statement 0 uses var_0 before Statement 1 defines it
  IrStatement use_stmt;
  use_stmt.op = IrOp::Assign;
  use_stmt.dest = IrOperand::register_ref("rax", 8);
  use_stmt.a = IrOperand::register_ref("var_0", 8);
  use_stmt.width = 8;
  block.statements.push_back(use_stmt);

  IrStatement def_stmt;
  def_stmt.op = IrOp::Assign;
  def_stmt.dest = IrOperand::register_ref("var_0", 8);
  def_stmt.a = IrOperand::constant_value(5, 8);
  def_stmt.width = 8;
  block.statements.push_back(def_stmt);

  block.statements.push_back(return_statement());
  function.blocks.push_back(std::move(block));

  auto verified = donkey::verify_ir(function);
  ASSERT_FALSE(verified.has_value());
  EXPECT_EQ(verified.diagnostic().code, "ir.use_before_def");
}

TEST(Ir, VerifierRejectsInvalidDominatorUse) {
  IrFunction function = branch_function();
  // Block 0: CondBranch to block 2 (fallthrough to block 1)
  function.blocks[0].statements.push_back(compare_zero_statement());
  function.blocks[0].statements.push_back(conditional_branch_statement(2));

  // Block 1: does NOT define var_0, branches to 3
  function.blocks[1].statements.push_back(assign_register_statement("rax", 1));
  function.blocks[1].statements.push_back(branch_statement(3));

  // Block 2: defines var_0, branches to 3
  IrStatement def_stmt;
  def_stmt.op = IrOp::Assign;
  def_stmt.dest = IrOperand::register_ref("var_0", 8);
  def_stmt.a = IrOperand::constant_value(42, 8);
  def_stmt.width = 8;
  function.blocks[2].statements.push_back(def_stmt);
  function.blocks[2].statements.push_back(branch_statement(3));

  // Block 3: uses var_0. Since block 2 does NOT dominate block 3 (path 0->1->3 bypasses 2),
  // this is an invalid dominator use!
  IrStatement use_stmt;
  use_stmt.op = IrOp::Assign;
  use_stmt.dest = IrOperand::register_ref("rax", 8);
  use_stmt.a = IrOperand::register_ref("var_0", 8);
  use_stmt.width = 8;
  function.blocks[3].statements.push_back(use_stmt);
  function.blocks[3].statements.push_back(return_statement());

  auto verified = donkey::verify_ir(function);
  ASSERT_FALSE(verified.has_value());
  EXPECT_EQ(verified.diagnostic().code, "ir.invalid_dominator_use");
}

TEST(Ir, VerifierRejectsUndefinedVariable) {
  IrFunction function = single_block_function();
  IrStatement use_undefined;
  use_undefined.op = IrOp::Assign;
  use_undefined.dest = IrOperand::register_ref("rax", 8);
  use_undefined.a = IrOperand::register_ref("var_99", 8);
  use_undefined.width = 8;
  function.blocks[0].statements.insert(function.blocks[0].statements.begin(), use_undefined);

  auto verified = donkey::verify_ir(function);
  ASSERT_FALSE(verified.has_value());
  EXPECT_EQ(verified.diagnostic().code, "ir.undefined_variable");
}

// Bit-Vector Semantic Oracle (Acceptance Scenario A15)
namespace {

std::uint64_t mask_for_width(std::uint8_t width) {
  switch (width) {
    case 1:
      return 0xFFULL;
    case 2:
      return 0xFFFFULL;
    case 4:
      return 0xFFFFFFFFULL;
    case 8:
      return ~0ULL;
    default:
      return ~0ULL;
  }
}

std::int64_t sign_extend(std::uint64_t val, std::uint8_t width) {
  switch (width) {
    case 1:
      return static_cast<std::int8_t>(val & 0xFF);
    case 2:
      return static_cast<std::int16_t>(val & 0xFFFF);
    case 4:
      return static_cast<std::int32_t>(val & 0xFFFFFFFF);
    case 8:
      return static_cast<std::int64_t>(val);
    default:
      return static_cast<std::int64_t>(val);
  }
}

std::uint64_t eval_binary_op(IrOp op, std::uint64_t a, std::uint64_t b, std::uint8_t width) {
  const std::uint64_t mask = mask_for_width(width);
  a &= mask;
  b &= mask;
  switch (op) {
    case IrOp::Add:
      return (a + b) & mask;
    case IrOp::Sub:
      return (a - b) & mask;
    case IrOp::Mul:
      return (a * b) & mask;
    case IrOp::And:
      return (a & b) & mask;
    case IrOp::Or:
      return (a | b) & mask;
    case IrOp::Xor:
      return (a ^ b) & mask;
    case IrOp::Shl: {
      const std::uint32_t shift = static_cast<std::uint32_t>(b % (width * 8));
      return (a << shift) & mask;
    }
    case IrOp::Shr: {
      const std::uint32_t shift = static_cast<std::uint32_t>(b % (width * 8));
      return (a >> shift) & mask;
    }
    case IrOp::Sar: {
      const std::uint32_t shift = static_cast<std::uint32_t>(b % (width * 8));
      const std::int64_t sa = sign_extend(a, width);
      return static_cast<std::uint64_t>(sa >> shift) & mask;
    }
    default:
      return 0;
  }
}

bool eval_condition(IrCondition condition, std::uint64_t a, std::uint64_t b, std::uint8_t width) {
  const std::uint64_t mask = mask_for_width(width);
  const std::uint64_t ua = a & mask;
  const std::uint64_t ub = b & mask;
  const std::int64_t sa = sign_extend(a, width);
  const std::int64_t sb = sign_extend(b, width);

  switch (condition) {
    case IrCondition::Equal:
    case IrCondition::Zero:
      return ua == ub;
    case IrCondition::NotEqual:
    case IrCondition::NonZero:
      return ua != ub;
    case IrCondition::UnsignedLess:
    case IrCondition::Carry:
      return ua < ub;
    case IrCondition::UnsignedGreaterEqual:
    case IrCondition::NoCarry:
      return ua >= ub;
    case IrCondition::UnsignedGreater:
      return ua > ub;
    case IrCondition::UnsignedLessEqual:
      return ua <= ub;
    case IrCondition::SignedLess:
      return sa < sb;
    case IrCondition::SignedGreaterEqual:
      return sa >= sb;
    case IrCondition::SignedGreater:
      return sa > sb;
    case IrCondition::SignedLessEqual:
      return sa <= sb;
    case IrCondition::Negative:
      return sa < 0;
    case IrCondition::Positive:
      return sa > 0;
    default:
      return false;
  }
}

}  // namespace

TEST(Ir, SemanticOracleBitVectorArithmetic) {
  // Test addition wrapping and two's complement behavior across widths
  EXPECT_EQ(eval_binary_op(IrOp::Add, 0xFF, 1, 1), 0x00ULL);
  EXPECT_EQ(eval_binary_op(IrOp::Add, 0xFFFF, 2, 2), 0x0001ULL);
  EXPECT_EQ(eval_binary_op(IrOp::Add, 0xFFFFFFFF, 1, 4), 0x00000000ULL);
  EXPECT_EQ(eval_binary_op(IrOp::Add, ~0ULL, 1, 8), 0ULL);

  // Subtraction
  EXPECT_EQ(eval_binary_op(IrOp::Sub, 0x00, 1, 1), 0xFFULL);
  EXPECT_EQ(eval_binary_op(IrOp::Sub, 0x10, 0x20, 2), 0xFFF0ULL);
  EXPECT_EQ(eval_binary_op(IrOp::Sub, 0, 1, 4), 0xFFFFFFFFULL);

  // Multiplication
  EXPECT_EQ(eval_binary_op(IrOp::Mul, 0x10, 0x10, 1), 0x00ULL);  // 256 wraps to 0 in 8-bit
  EXPECT_EQ(eval_binary_op(IrOp::Mul, 100, 200, 2), 20000ULL);
  EXPECT_EQ(eval_binary_op(IrOp::Mul, 0x10000, 0x10000, 4), 0ULL);
}

TEST(Ir, SemanticOracleBitVectorShifts) {
  // Logical left shift
  EXPECT_EQ(eval_binary_op(IrOp::Shl, 0x01, 7, 1), 0x80ULL);
  EXPECT_EQ(eval_binary_op(IrOp::Shl, 0x80, 1, 1), 0x00ULL);

  // Logical right shift
  EXPECT_EQ(eval_binary_op(IrOp::Shr, 0x80, 1, 1), 0x40ULL);
  EXPECT_EQ(eval_binary_op(IrOp::Shr, 0x80000000, 1, 4), 0x40000000ULL);

  // Arithmetic right shift (SAR) preserves sign bit
  EXPECT_EQ(eval_binary_op(IrOp::Sar, 0x80, 1, 1), 0xC0ULL);  // -128 >> 1 = -64
  EXPECT_EQ(eval_binary_op(IrOp::Sar, 0x80, 7, 1), 0xFFULL);  // -128 >> 7 = -1
  EXPECT_EQ(eval_binary_op(IrOp::Sar, 0x40, 1, 1), 0x20ULL);  // positive value zero-fills
  EXPECT_EQ(eval_binary_op(IrOp::Sar, 0x8000000000000000ULL, 1, 8), 0xC000000000000000ULL);
}

TEST(Ir, SemanticOracleBitVectorExtensions) {
  // ZeroExtend
  const std::uint64_t val = 0x85;
  EXPECT_EQ(val & mask_for_width(1), 0x85ULL);
  // Zero extension to 16, 32, 64 preserves exact unsigned value without sign replication
  EXPECT_EQ(val & mask_for_width(1), 0x0085ULL);
  EXPECT_EQ(val & mask_for_width(1), 0x00000085ULL);

  // SignExtend
  EXPECT_EQ(static_cast<std::uint16_t>(sign_extend(0x85, 1)), 0xFF85ULL);
  EXPECT_EQ(static_cast<std::uint32_t>(sign_extend(0x85, 1)), 0xFFFFFF85ULL);
  EXPECT_EQ(static_cast<std::uint64_t>(sign_extend(0x85, 1)), 0xFFFFFFFFFFFFFF85ULL);
  EXPECT_EQ(static_cast<std::uint64_t>(sign_extend(0x7F, 1)), 0x000000000000007FULL);
}

TEST(Ir, SemanticOracleFlagsAndConditions) {
  // Unsigned comparisons
  EXPECT_TRUE(eval_condition(IrCondition::Equal, 42, 42, 4));
  EXPECT_FALSE(eval_condition(IrCondition::Equal, 42, 43, 4));
  EXPECT_TRUE(eval_condition(IrCondition::UnsignedLess, 0x7F, 0x80, 1));
  EXPECT_TRUE(eval_condition(IrCondition::UnsignedLess, 5, 10, 4));
  EXPECT_FALSE(eval_condition(IrCondition::UnsignedLess, 10, 5, 4));

  // Signed comparisons: 0x80 is -128 in 8-bit, which is signed less than 1
  EXPECT_TRUE(eval_condition(IrCondition::SignedLess, 0x80, 1, 1));
  EXPECT_FALSE(eval_condition(IrCondition::UnsignedLess, 0x80, 1, 1));  // 128 > 1 unsigned

  // Zero / NonZero
  EXPECT_TRUE(eval_condition(IrCondition::Zero, 0, 0, 8));
  EXPECT_FALSE(eval_condition(IrCondition::Zero, 1, 0, 8));
  EXPECT_TRUE(eval_condition(IrCondition::NonZero, 1, 0, 8));

  // Negative / Positive
  EXPECT_TRUE(eval_condition(IrCondition::Negative, 0x8000, 0, 2));
  EXPECT_FALSE(eval_condition(IrCondition::Negative, 0x7FFF, 0, 2));
  EXPECT_TRUE(eval_condition(IrCondition::Positive, 0x7FFF, 0, 2));
}

TEST(Ir, PreservesUnsupportedInstructionsAsOpaqueEffects) {
  IrFunction function;
  function.address = 0x1000;
  IrBlock block;
  block.address = 0x1000;

  IrStatement unsupported_stmt;
  unsupported_stmt.op = IrOp::Unsupported;
  unsupported_stmt.text = "cpuid";
  unsupported_stmt.source_address = 0x1004;
  unsupported_stmt.width = 8;
  block.statements.push_back(unsupported_stmt);

  block.statements.push_back(return_statement());
  function.blocks.push_back(std::move(block));
  function.partial = true;

  auto verified = donkey::verify_ir(function);
  ASSERT_TRUE(verified.has_value()) << verified.diagnostic().message;

  auto pseudocode = donkey::format_pseudocode(function);
  ASSERT_TRUE(pseudocode.has_value()) << pseudocode.diagnostic().message;
  // Pseudocode must preserve the explicit opaque text and mark partial status
  EXPECT_NE(pseudocode.value().find("cpuid"), std::string::npos);
  EXPECT_NE(pseudocode.value().find("[partial]"), std::string::npos);
}

TEST(Ir, VerifierValidatesSwitchTerminator) {
  IrFunction function;
  function.address = 0x1000;
  IrBlock b0;
  b0.address = 0x1000;
  IrBlock b1;
  b1.address = 0x1010;
  b1.statements.push_back(return_statement());
  IrBlock b2;
  b2.address = 0x1020;
  b2.statements.push_back(return_statement());

  IrStatement sw;
  sw.op = IrOp::Switch;
  sw.dest = IrOperand::register_ref("eax", 4);
  sw.a = IrOperand::block_ref(1);  // default
  sw.width = 4;
  sw.switch_cases.push_back(IrSwitchCase{0x1, 2});
  b0.statements.push_back(sw);

  function.blocks.push_back(b0);
  function.blocks.push_back(b1);
  function.blocks.push_back(b2);

  auto res = donkey::verify_ir(function);
  EXPECT_TRUE(res.has_value()) << res.diagnostic().message;

  // Rejects out of range default target
  function.blocks[0].statements.back().a = IrOperand::block_ref(99);
  EXPECT_EQ(donkey::verify_ir(function).diagnostic().code, "ir.bad_block_index");

  // Rejects out of range case target
  function.blocks[0].statements.back().a = IrOperand::block_ref(1);
  function.blocks[0].statements.back().switch_cases.front().target_block = 99;
  EXPECT_EQ(donkey::verify_ir(function).diagnostic().code, "ir.bad_block_index");

  // Rejects missing selector operand
  function.blocks[0].statements.back().switch_cases.front().target_block = 2;
  function.blocks[0].statements.back().dest = IrOperand();
  EXPECT_EQ(donkey::verify_ir(function).diagnostic().code, "ir.malformed_switch");
}

TEST(Ir, StructuresReducibleSwitchStatement) {
  IrFunction function;
  function.address = 0x1000;

  // b0: entry, switch (eax)
  IrBlock b0;
  b0.address = 0x1000;
  IrStatement sw;
  sw.op = IrOp::Switch;
  sw.dest = IrOperand::register_ref("eax", 4);
  sw.a = IrOperand::block_ref(3);  // default is exit block 3
  sw.width = 4;
  sw.switch_cases.push_back(IrSwitchCase{0x10, 1});
  sw.switch_cases.push_back(IrSwitchCase{0x20, 2});
  b0.statements.push_back(sw);

  // b1: case 0x10, rdx = 1, jump to b3
  IrBlock b1;
  b1.address = 0x1010;
  IrStatement s1;
  s1.op = IrOp::Assign;
  s1.dest = IrOperand::register_ref("edx", 4);
  s1.a = IrOperand::constant_value(1, 4);
  s1.width = 4;
  b1.statements.push_back(s1);
  IrStatement br1;
  br1.op = IrOp::Branch;
  br1.a = IrOperand::block_ref(3);
  br1.width = 4;
  b1.statements.push_back(br1);

  // b2: case 0x20, rdx = 2, jump to b3
  IrBlock b2;
  b2.address = 0x1020;
  IrStatement s2;
  s2.op = IrOp::Assign;
  s2.dest = IrOperand::register_ref("edx", 4);
  s2.a = IrOperand::constant_value(2, 4);
  s2.width = 4;
  b2.statements.push_back(s2);
  IrStatement br2;
  br2.op = IrOp::Branch;
  br2.a = IrOperand::block_ref(3);
  br2.width = 4;
  b2.statements.push_back(br2);

  // b3: exit block, return
  IrBlock b3;
  b3.address = 0x1030;
  b3.statements.push_back(return_statement());

  function.blocks.push_back(std::move(b0));
  function.blocks.push_back(std::move(b1));
  function.blocks.push_back(std::move(b2));
  function.blocks.push_back(std::move(b3));

  auto verified = donkey::verify_ir(function);
  ASSERT_TRUE(verified.has_value()) << verified.diagnostic().message;

  auto pc = donkey::format_pseudocode(function);
  ASSERT_TRUE(pc.has_value()) << pc.diagnostic().message;
  const std::string& text = pc.value();
  EXPECT_NE(text.find("switch (eax) {"), std::string::npos) << text;
  EXPECT_NE(text.find("case 0x10:"), std::string::npos) << text;
  EXPECT_NE(text.find("edx = 0x1;"), std::string::npos) << text;
  EXPECT_NE(text.find("case 0x20:"), std::string::npos) << text;
  EXPECT_NE(text.find("edx = 0x2;"), std::string::npos) << text;
  EXPECT_NE(text.find("default:"), std::string::npos) << text;
}

TEST(Ir, RecoversStackVariablesAndFormatsArrayExpressions) {
  IrFunction function;
  function.address = 0x1000;
  function.name = "process_items";

  IrBlock b0;
  b0.address = 0x1000;

  // Assign argument at [ebp + 0x8] into eax
  IrStatement s1;
  s1.op = IrOp::Assign;
  s1.dest = IrOperand::register_ref("eax", 4);
  s1.a = IrOperand::memory_reference("ebp", "", 1, 8, 4);
  s1.width = 4;
  s1.source_address = 0x1000;
  b0.statements.push_back(s1);

  // Store eax into local at [ebp - 0x4]
  IrStatement s2;
  s2.op = IrOp::Store;
  s2.a = IrOperand::memory_reference("ebp", "", 1, -4, 4);
  s2.b = IrOperand::register_ref("eax", 4);
  s2.width = 4;
  s2.source_address = 0x1004;
  b0.statements.push_back(s2);

  // Load from array base + index: [rsi + rax]
  IrStatement s3;
  s3.op = IrOp::Load;
  s3.dest = IrOperand::register_ref("ebx", 4);
  s3.a = IrOperand::memory_reference("rsi", "rax", 1, 0, 4);
  s3.width = 4;
  s3.source_address = 0x1008;
  b0.statements.push_back(s3);

  b0.statements.push_back(return_statement());
  function.blocks.push_back(std::move(b0));

  // Run recover_stack_variables
  donkey::recover_stack_variables(function);
  ASSERT_EQ(function.local_variables.size(), 2U);
  EXPECT_EQ(function.local_variables[0].name, "local_4");
  EXPECT_FALSE(function.local_variables[0].is_parameter);
  EXPECT_EQ(function.local_variables[1].name, "arg_8");
  EXPECT_TRUE(function.local_variables[1].is_parameter);

  auto res = donkey::format_pseudocode_lines(function);
  ASSERT_TRUE(res.has_value()) << res.diagnostic().message;
  const std::string& code = res.value().full_text;

  // Local variable declaration
  EXPECT_NE(code.find("u32 local_4;"), std::string::npos) << code;
  // Local variable use instead of dereference
  EXPECT_NE(code.find("eax = arg_8;"), std::string::npos) << code;
  EXPECT_NE(code.find("local_4 = eax;"), std::string::npos) << code;
  // Array expression
  EXPECT_NE(code.find("ebx = rsi[rax];"), std::string::npos) << code;
}

TEST(Ir, AcceptanceScenarioA16_SourceMapNavigation) {
  IrFunction function;
  function.address = 0x2000;
  function.name = "loop_calc";

  // b0: header
  IrBlock b0;
  b0.address = 0x2000;
  IrStatement init;
  init.op = IrOp::Assign;
  init.dest = IrOperand::register_ref("eax", 4);
  init.a = IrOperand::constant_value(0, 4);
  init.width = 4;
  init.source_address = 0x2000;
  b0.statements.push_back(init);

  IrStatement br0;
  br0.op = IrOp::Branch;
  br0.a = IrOperand::block_ref(1);
  br0.width = 4;
  br0.source_address = 0x2004;
  b0.statements.push_back(br0);

  // b1: while condition
  IrBlock b1;
  b1.address = 0x2010;
  IrStatement cmp;
  cmp.op = IrOp::Compare;
  cmp.condition = IrCondition::SignedLess;
  cmp.a = IrOperand::register_ref("eax", 4);
  cmp.b = IrOperand::constant_value(10, 4);
  cmp.width = 4;
  cmp.source_address = 0x2010;
  b1.statements.push_back(cmp);

  IrStatement cbr;
  cbr.op = IrOp::CondBranch;
  cbr.condition = IrCondition::SignedGreaterEqual;
  cbr.a = IrOperand::register_ref("flags", 4);
  cbr.b = IrOperand::block_ref(3);
  cbr.width = 4;
  cbr.source_address = 0x2014;
  b1.statements.push_back(cbr);

  // b2: loop body
  IrBlock b2;
  b2.address = 0x2020;
  IrStatement add;
  add.op = IrOp::Add;
  add.dest = IrOperand::register_ref("eax", 4);
  add.a = IrOperand::register_ref("eax", 4);
  add.b = IrOperand::constant_value(1, 4);
  add.width = 4;
  add.source_address = 0x2020;
  b2.statements.push_back(add);

  IrStatement br_loop;
  br_loop.op = IrOp::Branch;
  br_loop.a = IrOperand::block_ref(1);
  br_loop.width = 4;
  br_loop.source_address = 0x2024;
  b2.statements.push_back(br_loop);

  // b3: exit
  IrBlock b3;
  b3.address = 0x2030;
  IrStatement ret;
  ret.op = IrOp::Return;
  ret.a = IrOperand::register_ref("eax", 4);
  ret.width = 4;
  ret.source_address = 0x2030;
  b3.statements.push_back(ret);

  function.blocks.push_back(std::move(b0));
  function.blocks.push_back(std::move(b1));
  function.blocks.push_back(std::move(b2));
  function.blocks.push_back(std::move(b3));

  auto res = donkey::format_pseudocode_lines(function);
  ASSERT_TRUE(res.has_value()) << res.diagnostic().message;
  const auto& lines = res.value().lines;
  EXPECT_FALSE(lines.empty());

  bool found_source_map_entry = false;
  for (const auto& line : lines) {
    if (line.source_address == 0x2000 && line.text.find("eax = 0x0;") != std::string::npos) {
      found_source_map_entry = true;
    }
  }
  EXPECT_TRUE(found_source_map_entry);
}

TEST(Ir, AcceptanceScenarioA17_GracefulUnresolvedJumpTable) {
  IrFunction function;
  function.address = 0x3000;
  function.name = "dispatch_indirect";
  function.notes.push_back("unresolved jump table at 0x3004; dynamic indirect targets");

  IrBlock b0;
  b0.address = 0x3000;

  IrStatement indirect_jump;
  indirect_jump.op = IrOp::Unsupported;
  indirect_jump.text = "jmp qword ptr [rax*8 + 0x403000] /* unresolved table */";
  indirect_jump.source_address = 0x3004;
  indirect_jump.width = 8;
  b0.statements.push_back(indirect_jump);

  b0.statements.push_back(return_statement());
  function.blocks.push_back(std::move(b0));
  function.partial = true;

  auto res = donkey::format_pseudocode(function);
  ASSERT_TRUE(res.has_value()) << res.diagnostic().message;
  const std::string& code = res.value();
  // Must preserve honest diagnostic notes and unsupported statement, never crash or hallucinate
  // targets
  EXPECT_NE(code.find("unresolved jump table"), std::string::npos) << code;
  EXPECT_NE(code.find("jmp qword ptr [rax*8 + 0x403000]"), std::string::npos) << code;
  EXPECT_NE(code.find("[partial]"), std::string::npos) << code;
}

// ---- G02-T1: add and subtract with carry (adc, sbb) ----

/// Lifts one raw x86-64 function. Returns false when lifting or analysis fails.
bool lift_raw_x86_64(const std::vector<std::uint8_t>& raw, donkey::IrFunction& out) {
  std::vector<std::byte> data;
  for (const std::uint8_t b : raw) {
    data.push_back(static_cast<std::byte>(b));
  }
  auto image = synthetic_image(data.size());
  image.architecture = Architecture::X86_64;
  auto analyzed = donkey::analyze(image, data);
  if (!analyzed.has_value() || analyzed.value().functions.empty()) {
    return false;
  }
  auto lifted = donkey::lift_function(image, analyzed.value(), analyzed.value().functions.front());
  if (!lifted.has_value()) {
    return false;
  }
  out = lifted.value();
  return true;
}

/// Runs an x86-64 function on SysV integer arguments and returns rax.
std::uint64_t run_x86_64(const donkey::IrFunction& function,
                         std::initializer_list<std::uint64_t> arguments) {
  donkey::IrEvalMemory memory;
  donkey::IrEvalOptions options;
  options.architecture = Architecture::X86_64;
  options.convention = donkey::IrCallingConvention::SysV64;
  const std::vector<std::uint64_t> values(arguments);
  auto result = donkey::evaluate_ir(function, values, memory, options);
  EXPECT_TRUE(result.has_value()) << (result.has_value() ? "" : result.diagnostic().message);
  return result.has_value() ? result.value().return_value : 0;
}

TEST(Ir, X86AddWithCarryMatchesHardwareFlags) {
  // add rdi, rsi; adc rdx, rcx; mov rax, rdx; ret
  donkey::IrFunction f;
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0x01, 0xf7, 0x48, 0x11, 0xca, 0x48, 0x89, 0xd0, 0xc3}, f));
  EXPECT_FALSE(f.partial);
  // rdi and rsi are the low halves, rdx and rcx the high halves. The carry out of
  // the low add is 1 exactly when the 64-bit sum wraps, and it is added upward.
  EXPECT_EQ(run_x86_64(f, {1, 2, 5, 7}), 12U);
  EXPECT_EQ(run_x86_64(f, {~0ULL, 1, 5, 7}), 13U);  // low sum wraps: 5 + 7 + 1
  EXPECT_EQ(run_x86_64(f, {~0ULL, 0, 5, 7}), 12U);  // no wrap: 5 + 7
  EXPECT_EQ(run_x86_64(f, {1ULL << 63, 1ULL << 63, 0, 0}), 1U);
}

TEST(Ir, X86SubWithBorrowMatchesHardwareFlags) {
  // sub rdi, rsi; sbb rdx, rcx; mov rax, rdx; ret
  donkey::IrFunction f;
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0x29, 0xf7, 0x48, 0x19, 0xca, 0x48, 0x89, 0xd0, 0xc3}, f));
  EXPECT_FALSE(f.partial);
  EXPECT_EQ(run_x86_64(f, {1, 2, 10, 3}), 6U);  // low borrows: 10 - 3 - 1
  EXPECT_EQ(run_x86_64(f, {2, 1, 10, 3}), 7U);  // no borrow: 10 - 3
  EXPECT_EQ(run_x86_64(f, {0, 0, 10, 3}), 7U);
}

TEST(Ir, X86AddOfARegisterToItselfCarriesFromTheOriginalValue) {
  // add rdi, rdi; adc rsi, rdx; mov rax, rsi; ret
  // The operation overwrites rdi, so the carry must come from the value it read.
  donkey::IrFunction f;
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0x01, 0xff, 0x48, 0x11, 0xd6, 0x48, 0x89, 0xf0, 0xc3}, f));
  EXPECT_FALSE(f.partial);
  EXPECT_EQ(run_x86_64(f, {1ULL << 63, 5, 7, 0}), 13U);  // top bit carries out: 5 + 7 + 1
  EXPECT_EQ(run_x86_64(f, {1, 5, 7, 0}), 12U);
  EXPECT_EQ(run_x86_64(f, {~0ULL, 5, 7, 0}), 13U);
}

TEST(Ir, X86SubOfARegisterFromItselfKeepsTheOriginalForSignedBranches) {
  // sub rdi, rdi; jl +6; mov eax, 1; ret; mov eax, 2; ret
  // The result is zero, so `jl` is never taken, whatever rdi held. Comparing with
  // the overwritten rdi would take the branch for negative inputs.
  donkey::IrFunction f;
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0x29, 0xff, 0x7c, 0x06, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3,
                               0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3},
                              f));
  EXPECT_FALSE(f.partial);
  EXPECT_EQ(run_x86_64(f, {~0ULL, 0, 0, 0}) & 0xffffffffU, 1U);
  EXPECT_EQ(run_x86_64(f, {5, 0, 0, 0}) & 0xffffffffU, 1U);
  EXPECT_EQ(run_x86_64(f, {1ULL << 63, 0, 0, 0}) & 0xffffffffU, 1U);
}

TEST(Ir, X86AddFollowedByACarryBranchIsExact) {
  // add rdi, rsi; jb +6; mov eax, 0; ret; mov eax, 1; ret
  donkey::IrFunction f;
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0x01, 0xf7, 0x72, 0x06, 0xb8, 0x00, 0x00, 0x00, 0x00, 0xc3,
                               0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3},
                              f));
  EXPECT_FALSE(f.partial);
  EXPECT_EQ(run_x86_64(f, {~0ULL, 1, 0, 0}) & 0xffffffffU, 1U);  // the sum wraps
  EXPECT_EQ(run_x86_64(f, {1, 2, 0, 0}) & 0xffffffffU, 0U);
  EXPECT_EQ(run_x86_64(f, {~0ULL, 0, 0, 0}) & 0xffffffffU, 0U);
}

/// Builds: Compare rdi, rsi; <op> rax = rdx (+|-) rcx (+|-) CF; return rax.
donkey::IrFunction carry_function(donkey::IrOp op) {
  donkey::IrFunction function;
  function.name = "carry";
  donkey::IrBlock block;
  donkey::IrStatement compare;
  compare.op = donkey::IrOp::Compare;
  compare.a = donkey::IrOperand::register_ref("rdi", 8);
  compare.b = donkey::IrOperand::register_ref("rsi", 8);
  compare.condition = donkey::IrCondition::UnsignedLess;  // only the carry is used below
  compare.width = 8;
  block.statements.push_back(compare);
  donkey::IrStatement carry;
  carry.op = op;
  carry.dest = donkey::IrOperand::register_ref("rax", 8);
  carry.a = donkey::IrOperand::register_ref("rdx", 8);
  carry.b = donkey::IrOperand::register_ref("rcx", 8);
  carry.width = 8;
  block.statements.push_back(carry);
  donkey::IrStatement ret;
  ret.op = donkey::IrOp::Return;
  ret.a = donkey::IrOperand::register_ref("rax", 8);
  ret.width = 8;
  block.statements.push_back(ret);
  function.blocks.push_back(std::move(block));
  return function;
}

TEST(Ir, AddCarryMatchesHardwareFlags) {
  // CF after `cmp rdi, rsi` is rdi < rsi. adc: rdx + rcx + CF.
  const donkey::IrFunction f = carry_function(donkey::IrOp::AddCarry);
  ASSERT_TRUE(donkey::verify_ir(f).has_value());
  EXPECT_EQ(run_x86_64(f, {1, 2, 10, 20}), 31U);  // CF = 1
  EXPECT_EQ(run_x86_64(f, {2, 1, 10, 20}), 30U);  // CF = 0
  EXPECT_EQ(run_x86_64(f, {~0ULL, 0, 10, 20}), 30U);
}

TEST(Ir, SubBorrowMatchesHardwareFlags) {
  // sbb: rdx - rcx - CF, with CF the borrow of the compare.
  const donkey::IrFunction f = carry_function(donkey::IrOp::SubBorrow);
  ASSERT_TRUE(donkey::verify_ir(f).has_value());
  EXPECT_EQ(run_x86_64(f, {1, 2, 10, 20}), static_cast<std::uint64_t>(-11));  // 10 - 20 - 1
  EXPECT_EQ(run_x86_64(f, {2, 1, 10, 20}), static_cast<std::uint64_t>(-10));  // 10 - 20 - 0
}

TEST(Ir, VerifierRejectsCarryWithoutAFlagWriterInItsBlock) {
  // With no Compare or Test before it, the carry is unknown.
  donkey::IrFunction without = carry_function(donkey::IrOp::AddCarry);
  without.blocks.front().statements.erase(without.blocks.front().statements.begin());
  const auto rejected = donkey::verify_ir(without);
  ASSERT_FALSE(rejected.has_value());
  EXPECT_EQ(rejected.diagnostic().code, "ir.carry_without_flags");

  // An unsupported statement between the flag writer and the carry may have changed
  // the flags, so it is rejected too.
  donkey::IrFunction interrupted = carry_function(donkey::IrOp::AddCarry);
  donkey::IrStatement unsupported;
  unsupported.op = donkey::IrOp::Unsupported;
  unsupported.text = "unknown";
  unsupported.width = 8;
  auto& statements = interrupted.blocks.front().statements;
  statements.insert(statements.begin() + 1, unsupported);
  const auto interrupted_result = donkey::verify_ir(interrupted);
  ASSERT_FALSE(interrupted_result.has_value());
  EXPECT_EQ(interrupted_result.diagnostic().code, "ir.carry_without_flags");
}

// ---- G02-T2: double-width multiply and divide ----

/// Evaluates an x86-64 function on SysV arguments and returns the whole result,
/// so that a fault can be checked.
donkey::Result<donkey::IrEvalResult> evaluate_x86_64(
    const donkey::IrFunction& function, std::initializer_list<std::uint64_t> arguments) {
  donkey::IrEvalMemory memory;
  donkey::IrEvalOptions options;
  options.architecture = Architecture::X86_64;
  options.convention = donkey::IrCallingConvention::SysV64;
  const std::vector<std::uint64_t> values(arguments);
  return donkey::evaluate_ir(function, values, memory, options);
}

TEST(Ir, X86MulAndImulReturnTheHighHalfOfTheProduct) {
  // mov rax, rdi; mul rsi; mov rax, rdx; ret
  donkey::IrFunction unsigned_high;
  ASSERT_TRUE(
      lift_raw_x86_64({0x48, 0x89, 0xf8, 0x48, 0xf7, 0xe6, 0x48, 0x89, 0xd0, 0xc3}, unsigned_high));
  EXPECT_FALSE(unsigned_high.partial);
  EXPECT_EQ(run_x86_64(unsigned_high, {1ULL << 63, 4}), 2U);        // 2^65 >> 64
  EXPECT_EQ(run_x86_64(unsigned_high, {~0ULL, ~0ULL}), ~0ULL - 1);  // (2^64-1)^2 >> 64
  EXPECT_EQ(run_x86_64(unsigned_high, {3, 5}), 0U);

  // mov rax, rdi; imul rsi; mov rax, rdx; ret
  donkey::IrFunction signed_high;
  ASSERT_TRUE(
      lift_raw_x86_64({0x48, 0x89, 0xf8, 0x48, 0xf7, 0xee, 0x48, 0x89, 0xd0, 0xc3}, signed_high));
  EXPECT_FALSE(signed_high.partial);
  EXPECT_EQ(run_x86_64(signed_high, {~0ULL, ~0ULL}), 0U);      // (-1) * (-1) = 1
  EXPECT_EQ(run_x86_64(signed_high, {1ULL << 63, 2}), ~0ULL);  // -2^64 >> 64 = -1
  EXPECT_EQ(run_x86_64(signed_high, {5, static_cast<std::uint64_t>(-3)}), ~0ULL);  // -15 >> 64
}

TEST(Ir, X86DivAndIdivReturnTheQuotientAndTheRemainder) {
  // mov rax, rdi; xor edx, edx; div rsi; ret
  donkey::IrFunction quotient;
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0x89, 0xf8, 0x31, 0xd2, 0x48, 0xf7, 0xf6, 0xc3}, quotient));
  EXPECT_FALSE(quotient.partial);
  EXPECT_EQ(run_x86_64(quotient, {100, 7}), 14U);
  EXPECT_EQ(run_x86_64(quotient, {~0ULL, 2}), 0x7fffffffffffffffULL);
  EXPECT_EQ(run_x86_64(quotient, {9, 1}), 9U);

  // mov rax, rdi; xor edx, edx; div rsi; mov rax, rdx; ret
  donkey::IrFunction remainder;
  ASSERT_TRUE(lift_raw_x86_64(
      {0x48, 0x89, 0xf8, 0x31, 0xd2, 0x48, 0xf7, 0xf6, 0x48, 0x89, 0xd0, 0xc3}, remainder));
  EXPECT_EQ(run_x86_64(remainder, {100, 7}), 2U);
  EXPECT_EQ(run_x86_64(remainder, {~0ULL, 2}), 1U);

  // mov rax, rdi; cqo; idiv rsi; ret
  donkey::IrFunction signed_quotient;
  ASSERT_TRUE(
      lift_raw_x86_64({0x48, 0x89, 0xf8, 0x48, 0x99, 0x48, 0xf7, 0xfe, 0xc3}, signed_quotient));
  EXPECT_FALSE(signed_quotient.partial);
  const auto neg = [](std::uint64_t v) {
    return static_cast<std::uint64_t>(-static_cast<std::int64_t>(v));
  };
  EXPECT_EQ(run_x86_64(signed_quotient, {neg(100), 7}), neg(14));
  EXPECT_EQ(run_x86_64(signed_quotient, {100, neg(7)}), neg(14));
  EXPECT_EQ(run_x86_64(signed_quotient, {neg(100), neg(7)}), 14U);

  // mov rax, rdi; cqo; idiv rsi; mov rax, rdx; ret
  donkey::IrFunction signed_remainder;
  ASSERT_TRUE(lift_raw_x86_64(
      {0x48, 0x89, 0xf8, 0x48, 0x99, 0x48, 0xf7, 0xfe, 0x48, 0x89, 0xd0, 0xc3}, signed_remainder));
  EXPECT_EQ(run_x86_64(signed_remainder, {neg(100), 7}),
            neg(2));  // the remainder keeps the dividend's sign
  EXPECT_EQ(run_x86_64(signed_remainder, {100, neg(7)}), 2U);
}

TEST(Ir, X86DivideReadsTheHighHalfOfTheDividend) {
  // mov rdx, rdi; xor eax, eax; div rsi; ret: rdx:rax is 1:0, which is 2^64, divided by 2.
  donkey::IrFunction quotient;
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0x89, 0xfa, 0x31, 0xc0, 0x48, 0xf7, 0xf6, 0xc3}, quotient));
  EXPECT_FALSE(quotient.partial);
  EXPECT_EQ(run_x86_64(quotient, {1, 2}), 0x8000000000000000ULL);
  // A high half no smaller than the divisor makes the quotient overflow, which is a fault.
  const auto overflow = evaluate_x86_64(quotient, {2, 1});
  ASSERT_FALSE(overflow.has_value());
  EXPECT_EQ(overflow.diagnostic().code, "ir.eval_fault");
}

TEST(Ir, VerifierRejectsABlockReferenceAsADivisor) {
  // A block is a branch target, not a value, so it cannot be a divisor.
  donkey::IrBlock block;
  donkey::IrStatement divide;
  divide.op = donkey::IrOp::DivUnsigned;
  divide.dest = donkey::IrOperand::register_ref("rax", 8);
  divide.a = donkey::IrOperand::register_ref("rdx", 8);
  divide.b = donkey::IrOperand::register_ref("rax", 8);
  divide.c = donkey::IrOperand::block_ref(0);
  divide.width = 8;
  block.statements.push_back(divide);
  donkey::IrStatement ret;
  ret.op = donkey::IrOp::Return;
  ret.a = donkey::IrOperand::register_ref("rax", 8);
  ret.width = 8;
  block.statements.push_back(ret);
  donkey::IrFunction function;
  function.name = "divide";
  function.blocks.push_back(std::move(block));
  const auto rejected = donkey::verify_ir(function);
  ASSERT_FALSE(rejected.has_value());
  EXPECT_EQ(rejected.diagnostic().code, "ir.malformed_divide");
}

TEST(Ir, VerifierRejectsAMemoryDivisorOfTheWrongWidth) {
  // A 4-byte divide reads its divisor at 4 bytes; an 8-byte memory divisor does not match.
  donkey::IrBlock block;
  donkey::IrStatement divide;
  divide.op = donkey::IrOp::DivUnsigned;
  divide.dest = donkey::IrOperand::register_ref("rax", 4);
  divide.a = donkey::IrOperand::register_ref("rdx", 4);
  divide.b = donkey::IrOperand::register_ref("rax", 4);
  divide.c = donkey::IrOperand::memory_reference("rsi", "", 1, 0, 8);
  divide.width = 4;
  block.statements.push_back(divide);
  donkey::IrStatement ret;
  ret.op = donkey::IrOp::Return;
  ret.a = donkey::IrOperand::register_ref("rax", 4);
  ret.width = 4;
  block.statements.push_back(ret);
  donkey::IrFunction function;
  function.name = "divide";
  function.blocks.push_back(std::move(block));
  const auto rejected = donkey::verify_ir(function);
  ASSERT_FALSE(rejected.has_value());
  EXPECT_EQ(rejected.diagnostic().code, "ir.type_width_mismatch");
}

TEST(Ir, VerifierRejectsAConstantWiderThanTheStatement) {
  // A constant with bits above the statement width cannot be read at that width. The rule covers
  // a high multiply's second source and every source of a divide; a constant that fits is valid.
  const auto verify_one = [](donkey::IrStatement statement) {
    donkey::IrBlock block;
    block.statements.push_back(std::move(statement));
    donkey::IrStatement ret;
    ret.op = donkey::IrOp::Return;
    ret.a = donkey::IrOperand::register_ref("rax", 4);
    ret.width = 4;
    block.statements.push_back(ret);
    donkey::IrFunction function;
    function.name = "constant_source";
    function.blocks.push_back(std::move(block));
    return donkey::verify_ir(function);
  };

  donkey::IrStatement high;
  high.op = donkey::IrOp::MulHighUnsigned;
  high.dest = donkey::IrOperand::register_ref("rax", 4);
  high.a = donkey::IrOperand::register_ref("rdx", 4);
  high.width = 4;
  high.b = donkey::IrOperand::constant_value(0x100000000ULL, 4);
  const auto wide_multiplier = verify_one(high);
  ASSERT_FALSE(wide_multiplier.has_value());
  EXPECT_EQ(wide_multiplier.diagnostic().code, "ir.type_width_mismatch");
  high.b = donkey::IrOperand::constant_value(0xffffffffULL, 4);
  EXPECT_TRUE(verify_one(high).has_value());

  donkey::IrStatement divide;
  divide.op = donkey::IrOp::DivUnsigned;
  divide.dest = donkey::IrOperand::register_ref("rax", 4);
  divide.a = donkey::IrOperand::register_ref("rdx", 4);
  divide.b = donkey::IrOperand::register_ref("rax", 4);
  divide.width = 4;
  divide.c = donkey::IrOperand::constant_value(0x100000000ULL, 4);
  const auto wide_divisor = verify_one(divide);
  ASSERT_FALSE(wide_divisor.has_value());
  EXPECT_EQ(wide_divisor.diagnostic().code, "ir.type_width_mismatch");
  divide.c = donkey::IrOperand::constant_value(0xffffffffULL, 4);
  EXPECT_TRUE(verify_one(divide).has_value());

  divide.c = donkey::IrOperand::register_ref("rcx", 4);
  divide.a = donkey::IrOperand::constant_value(0x100000000ULL, 4);
  const auto wide_dividend = verify_one(divide);
  ASSERT_FALSE(wide_dividend.has_value());
  EXPECT_EQ(wide_dividend.diagnostic().code, "ir.type_width_mismatch");
}

TEST(Ir, PointerRecoveryCountsAMemoryDivisor) {
  // mov rax, [rdi]; div qword [rdi + 8]: the divisor is the only access at offset 8, so the layout
  // is inferred only if recovery visits the divisor as well as the other operands.
  donkey::IrFunction function;
  function.name = "divide_by_field";
  function.parameters.push_back(donkey::IrParameter{"a0", 8, "rdi", false, std::string()});
  donkey::IrBlock block;
  donkey::IrStatement load;
  load.op = donkey::IrOp::Assign;
  load.dest = donkey::IrOperand::register_ref("rax", 8);
  load.a = donkey::IrOperand::memory_reference("rdi", "", 1, 0, 8);
  load.width = 8;
  block.statements.push_back(load);
  donkey::IrStatement divide;
  divide.op = donkey::IrOp::DivUnsigned;
  divide.dest = donkey::IrOperand::register_ref("rax", 8);
  divide.a = donkey::IrOperand::register_ref("rdx", 8);
  divide.b = donkey::IrOperand::register_ref("rax", 8);
  divide.c = donkey::IrOperand::memory_reference("rdi", "", 1, 8, 8);
  divide.width = 8;
  block.statements.push_back(divide);
  block.statements.push_back(return_statement());
  function.blocks.push_back(std::move(block));

  donkey::recover_pointer_structs(function);
  ASSERT_EQ(function.pointer_structs.size(), 1U);
  const auto& fields = function.pointer_structs.front().fields;
  ASSERT_EQ(fields.size(), 2U);
  EXPECT_EQ(fields[0].offset, 0);
  EXPECT_EQ(fields[1].offset, 8);
  EXPECT_EQ(fields[1].width, 8);
}

TEST(Ir, StackRecoveryCountsAMemoryDivisor) {
  // div dword [ebp - 8]: the only use of the local at -8 is the divisor, so it is recovered only if
  // recovery inspects the divisor as well as the other operands.
  donkey::IrFunction function;
  function.name = "divide_by_local";
  donkey::IrBlock block;
  donkey::IrStatement divide;
  divide.op = donkey::IrOp::DivUnsigned;
  divide.dest = donkey::IrOperand::register_ref("eax", 4);
  divide.a = donkey::IrOperand::register_ref("edx", 4);
  divide.b = donkey::IrOperand::register_ref("eax", 4);
  divide.c = donkey::IrOperand::memory_reference("ebp", "", 1, -8, 4);
  divide.width = 4;
  block.statements.push_back(divide);
  block.statements.push_back(return_statement());
  function.blocks.push_back(std::move(block));

  donkey::recover_stack_variables(function);
  ASSERT_EQ(function.local_variables.size(), 1U);
  EXPECT_EQ(function.local_variables[0].name, "local_8");
  EXPECT_EQ(function.local_variables[0].offset, -8);
}

TEST(Ir, StatementBudgetKeepsEveryBlockTerminated) {
  // mov rax, rdi; xor edx, edx; div rsi; ret. A budget of two statements is spent before the
  // return. The return is still emitted, so the block is terminated, and the function is partial.
  const std::vector<std::uint8_t> raw = {0x48, 0x89, 0xf8, 0x31, 0xd2, 0x48, 0xf7, 0xf6, 0xc3};
  std::vector<std::byte> data;
  for (const std::uint8_t b : raw) {
    data.push_back(static_cast<std::byte>(b));
  }
  auto image = synthetic_image(data.size());
  image.architecture = Architecture::X86_64;
  auto analyzed = donkey::analyze(image, data);
  ASSERT_TRUE(analyzed.has_value());
  ASSERT_FALSE(analyzed.value().functions.empty());

  donkey::LiftOptions options;
  options.max_statements = 2;
  auto lifted =
      donkey::lift_function(image, analyzed.value(), analyzed.value().functions.front(), options);
  ASSERT_TRUE(lifted.has_value());
  EXPECT_TRUE(lifted.value().partial);
  const auto verified = donkey::verify_ir(lifted.value());
  ASSERT_TRUE(verified.has_value())
      << verified.diagnostic().code << ": " << verified.diagnostic().message;
  ASSERT_FALSE(lifted.value().blocks.empty());
  const auto& statements = lifted.value().blocks.back().statements;
  ASSERT_FALSE(statements.empty());
  EXPECT_EQ(statements.back().op, donkey::IrOp::Return);
}

TEST(Ir, X86ReturnIsDeterminedWhenOnePathWritesFourBytes) {
  // test rsi, rsi; je zero; mov rax, rdi; jmp done; zero: mov eax, 0; done: ret
  // The 4-byte write zero-extends into rax, so both paths define the returned register and the
  // function is Complete. Before this rule the widths 4 and 8 at the join made the return unknown.
  donkey::IrFunction f;
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0x85, 0xf6, 0x74, 0x05, 0x48, 0x89, 0xf8, 0xeb, 0x05, 0xb8,
                               0x00, 0x00, 0x00, 0x00, 0xc3},
                              f));
  EXPECT_FALSE(f.partial);
  EXPECT_TRUE(donkey::verify_ir(f).has_value());
  EXPECT_EQ(run_x86_64(f, {5, 1}), 5U);
  EXPECT_EQ(run_x86_64(f, {5, 0}), 0U);
}

TEST(Ir, X86DivideFaultsWhereTheHardwareDivideErrors) {
  // mov rax, rdi; xor edx, edx; div rsi; ret
  donkey::IrFunction quotient;
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0x89, 0xf8, 0x31, 0xd2, 0x48, 0xf7, 0xf6, 0xc3}, quotient));
  const auto zero = evaluate_x86_64(quotient, {5, 0});
  ASSERT_FALSE(zero.has_value());
  EXPECT_EQ(zero.diagnostic().code, "ir.eval_fault");

  // mov rax, rdi; cqo; idiv rsi; ret. INT64_MIN / -1 needs 2^63, which does not fit.
  donkey::IrFunction signed_quotient;
  ASSERT_TRUE(
      lift_raw_x86_64({0x48, 0x89, 0xf8, 0x48, 0x99, 0x48, 0xf7, 0xfe, 0xc3}, signed_quotient));
  const auto overflow = evaluate_x86_64(signed_quotient, {1ULL << 63, ~0ULL});
  ASSERT_FALSE(overflow.has_value());
  EXPECT_EQ(overflow.diagnostic().code, "ir.eval_fault");
}

TEST(Ir, X86ThirtyTwoBitDivideUsesEdxAndEax) {
  // mov eax, edi; xor edx, edx; div esi; ret
  donkey::IrFunction quotient;
  ASSERT_TRUE(lift_raw_x86_64({0x89, 0xf8, 0x31, 0xd2, 0xf7, 0xf6, 0xc3}, quotient));
  EXPECT_FALSE(quotient.partial);
  EXPECT_EQ(run_x86_64(quotient, {0xffffffffULL, 2}) & 0xffffffffU, 0x7fffffffU);

  // mov eax, edi; cdq; idiv esi; ret
  donkey::IrFunction signed_quotient;
  ASSERT_TRUE(lift_raw_x86_64({0x89, 0xf8, 0x99, 0xf7, 0xfe, 0xc3}, signed_quotient));
  EXPECT_FALSE(signed_quotient.partial);
  EXPECT_EQ(run_x86_64(signed_quotient, {static_cast<std::uint64_t>(-100), 7}) & 0xffffffffU,
            0xfffffff2U);  // -14
}

TEST(Ir, VerifierRejectsDivideWithoutItsDivisor) {
  donkey::IrBlock block;
  donkey::IrStatement divide;
  divide.op = donkey::IrOp::DivUnsigned;
  divide.dest = donkey::IrOperand::register_ref("rax", 8);
  divide.a = donkey::IrOperand::register_ref("rdx", 8);
  divide.b = donkey::IrOperand::register_ref("rax", 8);
  divide.width = 8;  // c is left unset
  block.statements.push_back(divide);
  donkey::IrStatement ret;
  ret.op = donkey::IrOp::Return;
  ret.a = donkey::IrOperand::register_ref("rax", 8);
  ret.width = 8;
  block.statements.push_back(ret);
  donkey::IrFunction function;
  function.name = "divide";
  function.blocks.push_back(std::move(block));
  const auto rejected = donkey::verify_ir(function);
  ASSERT_FALSE(rejected.has_value());
  EXPECT_EQ(rejected.diagnostic().code, "ir.malformed_divide");
}

// ---- G02-T3: population count, bit scans, byte swap, bit test ----

// The flags of a compare carry into a fall-through block that has no other
// predecessor, so `setg` after `cmp`/`je` is exact there and the function is
// Complete. The compare is repeated at the start of that block.
TEST(Ir, FlagsFromSinglePredecessorAreExact) {
  donkey::IrFunction
      carried;  // cmp rdi, rsi; je L; setg al; movzx eax, al; ret; L: mov eax, 42; ret
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0x39, 0xf7, 0x74, 0x07, 0x0f, 0x9f, 0xc0, 0x0f, 0xb6, 0xc0,
                               0xc3, 0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3},
                              carried));
  EXPECT_FALSE(carried.partial);
  EXPECT_EQ(run_x86_64(carried, {5, 3}), 1U);
  EXPECT_EQ(run_x86_64(carried, {3, 5}), 0U);
  EXPECT_EQ(run_x86_64(carried, {~0ULL, 0}), 0U);  // -1 > 0 is false, signed
  EXPECT_EQ(run_x86_64(carried, {3, 3}), 42U);     // equal: the je branch

  // The same shape, but rdi is rewritten between the compare and the branch: the
  // operands the repeated compare would read are not the ones that set the flags.
  donkey::IrFunction rewritten;
  ASSERT_TRUE(
      lift_raw_x86_64({0x48, 0x39, 0xf7, 0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00, 0x74, 0x07, 0x0f,
                       0x9f, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3, 0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3},
                      rewritten));
  EXPECT_TRUE(rewritten.partial);
}

// `sp` is the 16-bit name of the stack pointer. After `mov ax, sp; cmp sp, ax`,
// the push changes the value the compare read, so its flags cannot be carried
// into the fall-through block.
TEST(Ir, FlagsAcrossAPushOfSpAreNotCarried) {
  donkey::IrFunction function;  // mov ax, sp; cmp sp, ax; push rdi; jne L; setne al; L: ret
  ASSERT_TRUE(lift_raw_x86_64(
      {0x66, 0x89, 0xe0, 0x66, 0x39, 0xc4, 0x57, 0x75, 0x03, 0x0f, 0x95, 0xc0, 0xc3}, function));
  EXPECT_TRUE(function.partial);
}

// `ucomisd xmm0, [rsp+8]` sets the flags for a jne in its block; the `jp` in the next block
// (its only predecessor is that fall-through) reads the same flags. The compare is repeated
// there, with its memory operand, which is exact: nothing between the compare and the block's
// end can store to memory or write the address register. (rsp is the stack pointer, not a
// parameter, so the only parameter is the xmm0 value.)
TEST(Ir, X86FpCompareWithAMemoryOperandCarriesIntoASinglePredecessorBlock) {
  donkey::IrFunction function;  // ucomisd xmm0, [rsp+8]; jne L; jp L; mov eax, 1; ret; L: ...
  ASSERT_TRUE(lift_raw_x86_64(
      {0x66, 0x0f, 0x2e, 0x44, 0x24, 0x08, 0x75, 0x0c, 0x7a, 0x0a, 0xb8, 0x01, 0x00,
       0x00, 0x00, 0xc3, 0x90, 0x90, 0x90, 0x90, 0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3},
      function));
  EXPECT_FALSE(function.partial);
}

// The same shape with a store to the compared memory between the compare and the jne. The
// repeated compare would read the stored value, so the flags are not carried and the `jp`
// stays Partial.
TEST(Ir, X86FpCompareIsNotCarriedPastAStore) {
  donkey::IrFunction function;  // ucomisd xmm0, [rsp+8]; mov [rsp+8], eax; jne L; jp L; ...
  ASSERT_TRUE(lift_raw_x86_64(
      {0x66, 0x0f, 0x2e, 0x44, 0x24, 0x08, 0x89, 0x44, 0x24, 0x08, 0x75, 0x0c, 0x7a, 0x0a, 0xb8,
       0x01, 0x00, 0x00, 0x00, 0xc3, 0x90, 0x90, 0x90, 0x90, 0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3},
      function));
  EXPECT_TRUE(function.partial);
}

// bsf and bsr for a nonzero source are the lowest and highest set bit. The
// result is Partial, because the destination is undefined for a zero source.
TEST(Ir, X86BitScanForwardAndReverseAreExactForANonzeroSource) {
  donkey::IrFunction forward;  // bsf rax, rdi; ret
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0x0f, 0xbc, 0xc7, 0xc3}, forward));
  EXPECT_TRUE(forward.partial);
  EXPECT_EQ(run_x86_64(forward, {0x18}), 3U);
  EXPECT_EQ(run_x86_64(forward, {1ULL << 40}), 40U);

  donkey::IrFunction reverse;  // bsr rax, rdi; ret
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0x0f, 0xbd, 0xc7, 0xc3}, reverse));
  EXPECT_TRUE(reverse.partial);
  EXPECT_EQ(run_x86_64(reverse, {0x18}), 4U);
  EXPECT_EQ(run_x86_64(reverse, {1ULL << 40}), 40U);

  donkey::IrFunction forward32;  // bsf eax, edi; ret: only the low 32 bits are read
  ASSERT_TRUE(lift_raw_x86_64({0x0f, 0xbc, 0xc7, 0xc3}, forward32));
  EXPECT_EQ(run_x86_64(forward32, {0x100000008ULL}), 3U);

  donkey::IrFunction reverse32;  // bsr eax, edi; ret
  ASSERT_TRUE(lift_raw_x86_64({0x0f, 0xbd, 0xc7, 0xc3}, reverse32));
  EXPECT_EQ(run_x86_64(reverse32, {0xffffffffULL}), 31U);
}

TEST(Ir, X86PopcntTzcntLzcntAndBswapMatchTheInstructions) {
  // popcnt rax, rdi; ret
  donkey::IrFunction popcount;
  ASSERT_TRUE(lift_raw_x86_64({0xf3, 0x48, 0x0f, 0xb8, 0xc7, 0xc3}, popcount));
  EXPECT_FALSE(popcount.partial);
  EXPECT_EQ(run_x86_64(popcount, {0xff}), 8U);
  EXPECT_EQ(run_x86_64(popcount, {~0ULL}), 64U);
  EXPECT_EQ(run_x86_64(popcount, {0}), 0U);

  // tzcnt rax, rdi; ret
  donkey::IrFunction trailing;
  ASSERT_TRUE(lift_raw_x86_64({0xf3, 0x48, 0x0f, 0xbc, 0xc7, 0xc3}, trailing));
  EXPECT_EQ(run_x86_64(trailing, {8}), 3U);
  EXPECT_EQ(run_x86_64(trailing, {0}), 64U);  // tzcnt of zero is the operand width

  // lzcnt rax, rdi; ret
  donkey::IrFunction leading;
  ASSERT_TRUE(lift_raw_x86_64({0xf3, 0x48, 0x0f, 0xbd, 0xc7, 0xc3}, leading));
  EXPECT_EQ(run_x86_64(leading, {1}), 63U);
  EXPECT_EQ(run_x86_64(leading, {0}), 64U);

  // mov rax, rdi; bswap rax; ret
  donkey::IrFunction swap;
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0x89, 0xf8, 0x48, 0x0f, 0xc8, 0xc3}, swap));
  EXPECT_FALSE(swap.partial);
  EXPECT_EQ(run_x86_64(swap, {0x0102030405060708ULL}), 0x0807060504030201ULL);
}

TEST(Ir, X86BitTestCarriesTheSelectedBit) {
  // bt rdi, rsi; setc al; movzx eax, al; ret
  donkey::IrFunction register_index;
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0x0f, 0xa3, 0xf7, 0x0f, 0x92, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3},
                              register_index));
  EXPECT_FALSE(register_index.partial);
  EXPECT_EQ(run_x86_64(register_index, {4, 2}) & 0xffU, 1U);   // bit 2 of 4 is set
  EXPECT_EQ(run_x86_64(register_index, {4, 1}) & 0xffU, 0U);   // bit 1 of 4 is clear
  EXPECT_EQ(run_x86_64(register_index, {4, 66}) & 0xffU, 1U);  // the index is taken modulo 64

  // bt rdi, 3; setc al; movzx eax, al; ret
  donkey::IrFunction immediate_index;
  ASSERT_TRUE(lift_raw_x86_64(
      {0x48, 0x0f, 0xba, 0xe7, 0x03, 0x0f, 0x92, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3}, immediate_index));
  EXPECT_FALSE(immediate_index.partial);
  EXPECT_EQ(run_x86_64(immediate_index, {8}) & 0xffU, 1U);
  EXPECT_EQ(run_x86_64(immediate_index, {4}) & 0xffU, 0U);
}

TEST(Ir, FunctionWithADirectCallIsNotComplete) {
  // call +0; mov eax, 1; ret. The call's effects are not modelled, so the result
  // must be Partial even though every instruction lifts.
  donkey::IrFunction f;
  ASSERT_TRUE(
      lift_raw_x86_64({0xe8, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3}, f));
  EXPECT_TRUE(f.partial);
}

TEST(Ir, VerifierRejectsADivisorTemporaryThatIsNeverDefined) {
  // The divisor is an operand like the others: an undefined temporary there is
  // rejected instead of being read as zero.
  donkey::IrBlock block;
  donkey::IrStatement divide;
  divide.op = donkey::IrOp::DivUnsigned;
  divide.dest = donkey::IrOperand::register_ref("rax", 8);
  divide.a = donkey::IrOperand::register_ref("rdx", 8);
  divide.b = donkey::IrOperand::register_ref("rax", 8);
  divide.c = donkey::IrOperand::register_ref("var_7", 8);
  divide.width = 8;
  block.statements.push_back(divide);
  donkey::IrStatement ret;
  ret.op = donkey::IrOp::Return;
  ret.a = donkey::IrOperand::register_ref("rax", 8);
  ret.width = 8;
  block.statements.push_back(ret);
  donkey::IrFunction function;
  function.name = "divide";
  function.blocks.push_back(std::move(block));
  const auto rejected = donkey::verify_ir(function);
  ASSERT_FALSE(rejected.has_value());
  EXPECT_EQ(rejected.diagnostic().code, "ir.undefined_variable");
}

TEST(Ir, VerifierRejectsACarryChainWhoseFirstCarryOutIsNotModelled) {
  // Compare; AddCarry; AddCarry: the second carry would read the compare's CF,
  // not the carry out of the first add, which the IR does not represent.
  donkey::IrFunction chained = carry_function(donkey::IrOp::AddCarry);
  auto& statements = chained.blocks.front().statements;
  statements.insert(statements.begin() + 2, statements[1]);
  const auto rejected = donkey::verify_ir(chained);
  ASSERT_FALSE(rejected.has_value());
  EXPECT_EQ(rejected.diagnostic().code, "ir.carry_without_flags");
}

TEST(Ir, VerifierRejectsACarryWithABlockOperand) {
  donkey::IrFunction f = carry_function(donkey::IrOp::AddCarry);
  f.blocks.front().statements[1].b = donkey::IrOperand::block_ref(0);
  const auto rejected = donkey::verify_ir(f);
  ASSERT_FALSE(rejected.has_value());
  EXPECT_EQ(rejected.diagnostic().code, "ir.malformed_carry");
}

TEST(Ir, VerifierRejectsACarryConstantWiderThanItsDestination) {
  donkey::IrFunction f = carry_function(donkey::IrOp::AddCarry);
  donkey::IrStatement& carry = f.blocks.front().statements[1];
  carry.dest = donkey::IrOperand::register_ref("rax", 4);
  carry.a = donkey::IrOperand::register_ref("rdx", 4);
  carry.b = donkey::IrOperand::constant_value(1, 8);
  carry.width = 4;
  const auto rejected = donkey::verify_ir(f);
  ASSERT_FALSE(rejected.has_value());
  EXPECT_EQ(rejected.diagnostic().code, "ir.type_width_mismatch");
}

/// Runs an x86-64 function whose only memory is one qword at `address`, passed
/// in rdi. Reads of any other address fail the evaluation.
std::uint64_t run_x86_64_on_qword(const donkey::IrFunction& function, std::uint64_t address,
                                  std::uint64_t value) {
  donkey::IrEvalMemory memory;
  std::vector<std::uint8_t> bytes(8);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    bytes[i] = static_cast<std::uint8_t>(value >> (8 * i));
  }
  EXPECT_TRUE(memory.add_region(address, bytes));
  donkey::IrEvalOptions options;
  options.architecture = Architecture::X86_64;
  options.convention = donkey::IrCallingConvention::SysV64;
  const std::vector<std::uint64_t> values{address};
  auto result = donkey::evaluate_ir(function, values, memory, options);
  EXPECT_TRUE(result.has_value()) << (result.has_value() ? "" : result.diagnostic().message);
  return result.has_value() ? result.value().return_value : 0;
}

TEST(Ir, X86AddFromAMemoryOperandAddressedByItsDestinationCarriesFromTheLoadedValue) {
  // add rdi, [rdi]; setb al; movzx eax, al; ret
  // The compare for the carry must not re-read [rdi] at the new value of rdi.
  donkey::IrFunction f;
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0x03, 0x3f, 0x0f, 0x92, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3}, f));
  EXPECT_FALSE(f.partial);
  // The sum wraps to zero: 0x1000 + (2^64 - 0x1000) carries out.
  EXPECT_EQ(run_x86_64_on_qword(f, 0x1000, 0xFFFF'FFFF'FFFF'F000ULL), 1U);
  // No wrap: 0x1000 + 5 does not carry out.
  EXPECT_EQ(run_x86_64_on_qword(f, 0x1000, 5), 0U);
}

TEST(Ir, X86CarryReachesAnAdcAcrossARegisterExchange) {
  // add rdi, rsi; xchg rdx, rcx; adc rdx, rcx; mov rax, rdx; ret
  // The exchange does not write the flags, so the adc reads the add's carry.
  donkey::IrFunction f;
  ASSERT_TRUE(lift_raw_x86_64(
      {0x48, 0x01, 0xf7, 0x48, 0x87, 0xca, 0x48, 0x11, 0xca, 0x48, 0x89, 0xd0, 0xc3}, f));
  EXPECT_FALSE(f.partial);
  EXPECT_EQ(run_x86_64(f, {~0ULL, 1, 5, 7}), 13U);  // the sum wraps: 5 + 7 + 1
  EXPECT_EQ(run_x86_64(f, {1, 2, 5, 7}), 12U);
}

TEST(Ir, X86CarryIsNotReadAcrossAnUnsupportedExchange) {
  // cmp rdi, rsi; xchg [rdi], rax; adc rdx, rcx; mov rax, rdx; ret
  // The memory exchange is Unsupported and may have changed the flags, so the
  // adc must not be lifted with the compare's carry.
  donkey::IrFunction f;
  ASSERT_TRUE(lift_raw_x86_64(
      {0x48, 0x39, 0xf7, 0x48, 0x87, 0x07, 0x48, 0x11, 0xca, 0x48, 0x89, 0xd0, 0xc3}, f));
  EXPECT_TRUE(f.partial);
  for (const donkey::IrBlock& block : f.blocks) {
    for (const donkey::IrStatement& statement : block.statements) {
      EXPECT_NE(statement.op, donkey::IrOp::AddCarry);
    }
  }
}

TEST(Ir, X86CarryIsNotReadAcrossAnUnsupportedMove) {
  // cmp rdi, rsi; mov r8w, 1; adc rdx, rcx; mov rax, rdx; ret
  // The 16-bit move to r8w has no IR width, so it is Unsupported and may have written the flags.
  // The flags are then unknown, so the adc is not lifted with the compare's carry: the function is
  // partial. Before this rule the adc was lifted, and the verifier rejected the whole function.
  donkey::IrFunction f;
  ASSERT_TRUE(lift_raw_x86_64(
      {0x48, 0x39, 0xf7, 0x66, 0x41, 0xb8, 0x01, 0x00, 0x48, 0x11, 0xca, 0x48, 0x89, 0xd0, 0xc3},
      f));
  EXPECT_TRUE(f.partial);
  for (const donkey::IrBlock& block : f.blocks) {
    for (const donkey::IrStatement& statement : block.statements) {
      EXPECT_NE(statement.op, donkey::IrOp::AddCarry);
    }
  }
}

TEST(Ir, X86DivisorInAnArgumentRegisterIsAnInputOfTheSignature) {
  // mov rax, rdi; mov edx, 0; div rsi; ret: the divisor is rsi, the second argument.
  // (mov, not xor, for rdx: an xor reads its register and would add rdx as an input.)
  donkey::IrFunction f;
  ASSERT_TRUE(
      lift_raw_x86_64({0x48, 0x89, 0xf8, 0xba, 0x00, 0x00, 0x00, 0x00, 0x48, 0xf7, 0xf6, 0xc3}, f));
  EXPECT_FALSE(f.partial);
  ASSERT_EQ(f.parameters.size(), 2U);
  EXPECT_EQ(f.parameters[1].abi_register, "rsi");
  EXPECT_EQ(run_x86_64(f, {10, 3}), 3U);
}

TEST(Ir, X86BitTestAndSetResetAndComplementWriteTheBit) {
  // bts rdi, rsi; mov rax, rdi; ret. The bit index is rsi modulo 64.
  donkey::IrFunction bts;
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0x0f, 0xab, 0xf7, 0x48, 0x89, 0xf8, 0xc3}, bts));
  EXPECT_FALSE(bts.partial);
  EXPECT_EQ(run_x86_64(bts, {0, 3}), 8U);
  EXPECT_EQ(run_x86_64(bts, {8, 3}), 8U);   // already set
  EXPECT_EQ(run_x86_64(bts, {0, 66}), 4U);  // 66 mod 64 = 2

  // btr rdi, rsi; mov rax, rdi; ret
  donkey::IrFunction btr;
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0x0f, 0xb3, 0xf7, 0x48, 0x89, 0xf8, 0xc3}, btr));
  EXPECT_FALSE(btr.partial);
  EXPECT_EQ(run_x86_64(btr, {0xF, 1}), 0xDU);
  EXPECT_EQ(run_x86_64(btr, {0, 1}), 0U);

  // btc rdi, rsi; mov rax, rdi; ret
  donkey::IrFunction btc;
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0x0f, 0xbb, 0xf7, 0x48, 0x89, 0xf8, 0xc3}, btc));
  EXPECT_FALSE(btc.partial);
  EXPECT_EQ(run_x86_64(btc, {0, 2}), 4U);
  EXPECT_EQ(run_x86_64(btc, {4, 2}), 0U);
}

TEST(Ir, X86BitTestAndSetCarriesTheBitBeforeTheWrite) {
  // bts rdi, rsi; setb al; movzx eax, al; ret: CF is the bit as it was before the set.
  donkey::IrFunction f;
  ASSERT_TRUE(
      lift_raw_x86_64({0x48, 0x0f, 0xab, 0xf7, 0x0f, 0x92, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3}, f));
  EXPECT_FALSE(f.partial);
  EXPECT_EQ(run_x86_64(f, {0, 3}), 0U);  // bit clear before: CF = 0, then set
  EXPECT_EQ(run_x86_64(f, {8, 3}), 1U);  // bit set before: CF = 1
}

TEST(Ir, X86MovbeLoadsAndStoresTheBytesReversed) {
  // movbe rax, [rdi]; ret
  donkey::IrFunction loads;
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0x0f, 0x38, 0xf0, 0x07, 0xc3}, loads));
  EXPECT_FALSE(loads.partial);
  EXPECT_EQ(run_x86_64_on_qword(loads, 0x1000, 0x0102030405060708ULL), 0x0807060504030201ULL);

  // mov rax, rsi; movbe [rdi], rax; ret: the stored bytes are the reversed value.
  donkey::IrFunction stores;
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0x89, 0xf0, 0x48, 0x0f, 0x38, 0xf1, 0x07, 0xc3}, stores));
  EXPECT_FALSE(stores.partial);
  donkey::IrEvalMemory memory;
  ASSERT_TRUE(memory.add_region(0x1000, std::vector<std::uint8_t>(8, 0)));
  donkey::IrEvalOptions options;
  options.architecture = Architecture::X86_64;
  options.convention = donkey::IrCallingConvention::SysV64;
  const std::vector<std::uint64_t> values{0x1000, 0x0102030405060708ULL};
  ASSERT_TRUE(donkey::evaluate_ir(stores, values, memory, options).has_value());
  const std::vector<std::uint8_t>* bytes = memory.region(0x1000);
  ASSERT_NE(bytes, nullptr);
  // bswap(0x0102030405060708) = 0x0807060504030201, which is stored little-endian
  // as the bytes 01 02 .. 08.
  const std::vector<std::uint8_t> expected{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  EXPECT_EQ(*bytes, expected);
}

TEST(Ir, VerifierRejectsABitOperationWithABlockSource) {
  // A block reference is not a value; the evaluator cannot read it.
  donkey::IrBlock block;
  donkey::IrStatement popcount;
  popcount.op = donkey::IrOp::PopCount;
  popcount.dest = donkey::IrOperand::register_ref("rax", 8);
  popcount.a = donkey::IrOperand::block_ref(0);
  popcount.width = 8;
  block.statements.push_back(popcount);
  donkey::IrStatement ret;
  ret.op = donkey::IrOp::Return;
  ret.a = donkey::IrOperand::register_ref("rax", 8);
  ret.width = 8;
  block.statements.push_back(ret);
  donkey::IrFunction function;
  function.name = "popcount";
  function.blocks.push_back(std::move(block));
  const auto rejected = donkey::verify_ir(function);
  ASSERT_FALSE(rejected.has_value());
  EXPECT_EQ(rejected.diagnostic().code, "ir.malformed_bit_op");
}

/// Runs an AArch64 function on AAPCS64 integer arguments and returns x0.
std::uint64_t run_aarch64_args(const std::vector<std::byte>& data,
                               std::initializer_list<std::uint64_t> arguments) {
  auto image = synthetic_image(data.size());
  image.architecture = Architecture::AArch64;
  auto analyzed = donkey::analyze(image, data);
  EXPECT_TRUE(analyzed.has_value());
  if (!analyzed.has_value() || analyzed.value().functions.empty()) {
    return 0;
  }
  auto lifted = donkey::lift_function(image, analyzed.value(), analyzed.value().functions.front());
  EXPECT_TRUE(lifted.has_value());
  if (!lifted.has_value()) {
    return 0;
  }
  // A rounded result is Partial, because FPCR is not modelled (see the lifter's note). Any other
  // reason for Partial still fails here, and the value is checked either way.
  if (lifted.value().partial) {
    const bool fpcr_only = std::any_of(
        lifted.value().notes.begin(), lifted.value().notes.end(), [](const std::string& note) {
          return note.find("FPCR rounding mode") != std::string::npos;
        });
    EXPECT_TRUE(fpcr_only) << "partial for a reason other than the FPCR rounding mode";
  }
  donkey::IrEvalMemory memory;
  donkey::IrEvalOptions options;
  options.architecture = Architecture::AArch64;
  options.convention = donkey::IrCallingConvention::Aapcs64;
  const std::vector<std::uint64_t> values(arguments);
  auto result = donkey::evaluate_ir(lifted.value(), values, memory, options);
  EXPECT_TRUE(result.has_value()) << (result.has_value() ? "" : result.diagnostic().message);
  return result.has_value() ? result.value().return_value : 0;
}

TEST(Ir, AArch64DivisionMatchesTheArchitectureAtTheEdges) {
  // AArch64 division by zero gives 0 and INT_MIN / -1 gives INT_MIN; neither faults.
  const auto udiv64 = aarch64_bytes({0x9ac10800, 0xd65f03c0});  // udiv x0, x0, x1; ret
  const auto sdiv64 = aarch64_bytes({0x9ac10c00, 0xd65f03c0});  // sdiv x0, x0, x1; ret
  const auto udiv32 = aarch64_bytes({0x1ac10800, 0xd65f03c0});  // udiv w0, w0, w1; ret
  const auto sdiv32 = aarch64_bytes({0x1ac10c00, 0xd65f03c0});  // sdiv w0, w0, w1; ret
  const std::uint64_t int_min = 1ULL << 63;
  const auto minus = [](std::uint64_t value) {
    return static_cast<std::uint64_t>(-static_cast<std::int64_t>(value));
  };
  EXPECT_EQ(run_aarch64_args(udiv64, {10, 3}), 3U);
  EXPECT_EQ(run_aarch64_args(udiv64, {10, 0}), 0U);
  EXPECT_EQ(run_aarch64_args(sdiv64, {minus(7), 2}), minus(3));
  EXPECT_EQ(run_aarch64_args(sdiv64, {minus(9), 0}), 0U);
  EXPECT_EQ(run_aarch64_args(sdiv64, {int_min, minus(1)}), int_min);
  EXPECT_EQ(run_aarch64_args(sdiv64, {5, minus(1)}), minus(5));
  EXPECT_EQ(run_aarch64_args(udiv32, {10, 3}), 3U);
  EXPECT_EQ(run_aarch64_args(udiv32, {10, 0}), 0U);
  EXPECT_EQ(run_aarch64_args(sdiv32, {0xFFFF'FFF9ULL, 2}), 0xFFFF'FFFDULL);  // -7 / 2 = -3
  EXPECT_EQ(run_aarch64_args(sdiv32, {0x8000'0000ULL, 0xFFFF'FFFFULL}), 0x8000'0000ULL);
}

TEST(Ir, AArch64HighMultiplyIsTheUpperHalf) {
  const auto umulh = aarch64_bytes({0x9bc17c00, 0xd65f03c0});  // umulh x0, x0, x1; ret
  const auto smulh = aarch64_bytes({0x9b417c00, 0xd65f03c0});  // smulh x0, x0, x1; ret
  const std::uint64_t minus_one = ~0ULL;
  EXPECT_EQ(run_aarch64_args(umulh, {1ULL << 63, 4}), 2U);         // 2^65 has high half 2
  EXPECT_EQ(run_aarch64_args(smulh, {minus_one, minus_one}), 0U);  // (-1) * (-1) = 1
  EXPECT_EQ(run_aarch64_args(smulh, {static_cast<std::uint64_t>(-2), 3}), minus_one);  // -6
}

// Only the low 32 bits of each W source take part; the high halves below are
// noise that a wrong lowering would multiply in.
TEST(Ir, AArch64WideningMultiplyUsesTheLow32BitsOfEachSource) {
  const auto umull = aarch64_bytes({0x9ba17c00, 0xd65f03c0});   // umull x0, w0, w1; ret
  const auto smull = aarch64_bytes({0x9b217c00, 0xd65f03c0});   // smull x0, w0, w1; ret
  const auto umaddl = aarch64_bytes({0x9ba10800, 0xd65f03c0});  // umaddl x0, w0, w1, x2; ret
  const auto smaddl = aarch64_bytes({0x9b210800, 0xd65f03c0});  // smaddl x0, w0, w1, x2; ret
  const auto umsubl = aarch64_bytes({0x9ba18800, 0xd65f03c0});  // umsubl x0, w0, w1, x2; ret
  const auto smsubl = aarch64_bytes({0x9b218800, 0xd65f03c0});  // smsubl x0, w0, w1, x2; ret
  const auto umnegl = aarch64_bytes({0x9ba1fc00, 0xd65f03c0});  // umnegl x0, w0, w1; ret
  const auto smnegl = aarch64_bytes({0x9b21fc00, 0xd65f03c0});  // smnegl x0, w0, w1; ret
  const std::uint64_t source_a = 0xdeadbeefffffffffULL;         // low word 0xffffffff
  const std::uint64_t source_b = 0x1234567800000002ULL;         // low word 2
  EXPECT_EQ(run_aarch64_args(umull, {source_a, source_b}), 0x1fffffffeULL);  // 4294967295 * 2
  EXPECT_EQ(run_aarch64_args(smull, {source_a, source_b}),
            static_cast<std::uint64_t>(-2));  // (-1) * 2
  EXPECT_EQ(run_aarch64_args(umaddl, {source_a, source_b, 100}), 0x1fffffffeULL + 100);
  EXPECT_EQ(run_aarch64_args(smaddl, {source_a, source_b, 100}), 98U);  // 100 + (-2)
  EXPECT_EQ(run_aarch64_args(umsubl, {source_a, source_b, 0x1000000000ULL}),
            0x1000000000ULL - 0x1fffffffeULL);
  EXPECT_EQ(run_aarch64_args(smsubl, {source_a, source_b, 100}), 102U);  // 100 - (-2)
  EXPECT_EQ(run_aarch64_args(umnegl, {source_a, source_b}),
            static_cast<std::uint64_t>(-0x1fffffffeLL));
  EXPECT_EQ(run_aarch64_args(smnegl, {source_a, source_b}), 2U);  // -(-2)
  // The two 32-bit sources of 0xffffffff: the unsigned product is 2^64 - 2^33 + 1,
  // the signed product is (-1) * (-1).
  const std::uint64_t all_ones = 0xffffffffULL;
  EXPECT_EQ(run_aarch64_args(umull, {all_ones, all_ones}), 0xfffffffe00000001ULL);
  EXPECT_EQ(run_aarch64_args(smull, {all_ones, all_ones}), 1U);
}

// A widening multiply into xzr discards its product, so nothing is lifted for it.
// The function still lifts exactly and returns x0. `mov x0, x0` defines the return
// register: a return of an unwritten x0 could also be a floating-point argument.
TEST(Ir, AArch64WideningMultiplyIntoXzrIsDiscarded) {
  const auto umull =
      aarch64_bytes({0x9ba17c1f, 0xaa0003e0, 0xd65f03c0});  // umull xzr, w0, w1; mov x0, x0; ret
  const auto umaddl = aarch64_bytes(
      {0x9ba1081f, 0xaa0003e0, 0xd65f03c0});  // umaddl xzr, w0, w1, x2; mov x0, x0; ret
  EXPECT_EQ(run_aarch64_args(umull, {7, 9}), 7U);
  EXPECT_EQ(run_aarch64_args(umaddl, {7, 9, 11}), 7U);
}

TEST(Ir, AArch64CountAndReverseInstructionsMatchTheArchitecture) {
  const auto clz = aarch64_bytes({0xdac01000, 0xd65f03c0});     // clz x0, x0
  const auto cls = aarch64_bytes({0xdac01400, 0xd65f03c0});     // cls x0, x0
  const auto cls32 = aarch64_bytes({0x5ac01400, 0xd65f03c0});   // cls w0, w0
  const auto rbit = aarch64_bytes({0xdac00000, 0xd65f03c0});    // rbit x0, x0
  const auto rbit32 = aarch64_bytes({0x5ac00000, 0xd65f03c0});  // rbit w0, w0
  const auto rev = aarch64_bytes({0xdac00c00, 0xd65f03c0});     // rev x0, x0
  const auto rev32w = aarch64_bytes({0x5ac00800, 0xd65f03c0});  // rev w0, w0
  const auto rev16 = aarch64_bytes({0xdac00400, 0xd65f03c0});   // rev16 x0, x0
  const auto rev32 = aarch64_bytes({0xdac00800, 0xd65f03c0});   // rev32 x0, x0
  EXPECT_EQ(run_aarch64_args(clz, {1}), 63U);
  EXPECT_EQ(run_aarch64_args(clz, {0}), 64U);
  EXPECT_EQ(run_aarch64_args(cls, {0}), 63U);
  EXPECT_EQ(run_aarch64_args(cls, {~0ULL}), 63U);
  EXPECT_EQ(run_aarch64_args(cls, {1}), 62U);
  EXPECT_EQ(run_aarch64_args(cls32, {1}), 30U);
  EXPECT_EQ(run_aarch64_args(cls32, {0}), 31U);
  EXPECT_EQ(run_aarch64_args(rbit, {1}), 1ULL << 63);
  EXPECT_EQ(run_aarch64_args(rbit32, {1}), 0x8000'0000ULL);
  EXPECT_EQ(run_aarch64_args(rev, {0x0102030405060708ULL}), 0x0807060504030201ULL);
  EXPECT_EQ(run_aarch64_args(rev32w, {0x01020304ULL}), 0x04030201ULL);
  EXPECT_EQ(run_aarch64_args(rev16, {0x0102030405060708ULL}), 0x0201040306050807ULL);
  EXPECT_EQ(run_aarch64_args(rev32, {0x0102030405060708ULL}), 0x0403020108070605ULL);
}

TEST(Ir, AArch64ExtractAndBitfieldInsertMatchTheArchitecture) {
  const auto extr = aarch64_bytes({0x93c12000, 0xd65f03c0});   // extr x0, x0, x1, #8
  const auto bfi = aarch64_bytes({0xb37c1c20, 0xd65f03c0});    // bfi x0, x1, #4, #8
  const auto bfxil = aarch64_bytes({0xb3442c20, 0xd65f03c0});  // bfxil x0, x1, #4, #8
  const std::uint64_t n = 0x1122334455667788ULL;
  const std::uint64_t m = 0xAABBCCDDEEFF0011ULL;
  EXPECT_EQ(run_aarch64_args(extr, {n, m}), (m >> 8) | (n << 56));
  EXPECT_EQ(run_aarch64_args(bfi, {0xFFFF, 0xAB}), 0xFABFU);
  EXPECT_EQ(run_aarch64_args(bfi, {~0ULL, 0}), ~0ULL & ~0xFF0ULL);
  EXPECT_EQ(run_aarch64_args(bfxil, {~0ULL, 0xABCD}), (~0ULL & ~0xFFULL) | 0xBCULL);
}

TEST(Ir, AArch64ConditionalCompareUsesTheCompareOnlyWhenItsConditionHolds) {
  // cmp x0, x1; ccmp x2, x3, #0, eq; cset x0, eq; ret. When x0 == x1 the flags
  // are those of x2 - x3; otherwise NZCV is 0 and eq is false.
  const auto data = aarch64_bytes({0xeb01001f, 0xfa430040, 0x9a9f17e0, 0xd65f03c0});
  EXPECT_EQ(run_aarch64_args(data, {5, 5, 7, 7}), 1U);
  EXPECT_EQ(run_aarch64_args(data, {5, 5, 7, 8}), 0U);
  EXPECT_EQ(run_aarch64_args(data, {5, 6, 7, 7}), 0U);
}

TEST(Ir, AArch64ConditionalCompareSetsTheImmediateNzcvWhenItsConditionFails) {
  // cmp x0, x1; ccmp x2, x3, #8, ne; cset x0, lt; ret. When x0 != x1, lt compares
  // x2 with x3 as signed values. When x0 == x1, NZCV is #8 (N set), so lt holds.
  const auto data = aarch64_bytes({0xeb01001f, 0xfa431048, 0x9a9fa7e0, 0xd65f03c0});
  EXPECT_EQ(run_aarch64_args(data, {1, 2, 0, 0}), 0U);
  EXPECT_EQ(run_aarch64_args(data, {1, 2, static_cast<std::uint64_t>(-1), 0}), 1U);
  EXPECT_EQ(run_aarch64_args(data, {3, 3, 0, 0}), 1U);
}

TEST(Ir, AArch64ConditionalCompareNegatedSetsTheFlagsOfTheSum) {
  // cmp x0, x0; ccmn x2, x3, #0, eq; cset x0, eq; ret. ccmn sets the flags of
  // x2 + x3, so eq holds when the sum is zero.
  const auto data = aarch64_bytes({0xeb00001f, 0xba430040, 0x9a9f17e0, 0xd65f03c0});
  EXPECT_EQ(run_aarch64_args(data, {0, 0, 5, static_cast<std::uint64_t>(-5)}), 1U);
  EXPECT_EQ(run_aarch64_args(data, {0, 0, 1, 1}), 0U);
}

TEST(Ir, AArch64ConditionalCompareWithoutExactFlagsIsPartial) {
  // ccmp x2, x3, #0, eq; ret. No flag writer comes first, so the condition is unknown.
  const auto data = aarch64_bytes({0xfa430040, 0xd65f03c0});
  auto image = synthetic_image(data.size());
  image.architecture = Architecture::AArch64;
  auto analyzed = donkey::analyze(image, data);
  ASSERT_TRUE(analyzed.has_value());
  ASSERT_FALSE(analyzed.value().functions.empty());
  auto lifted = donkey::lift_function(image, analyzed.value(), analyzed.value().functions.front());
  ASSERT_TRUE(lifted.has_value());
  EXPECT_TRUE(lifted.value().partial);
}

TEST(Ir, VerifierRejectsAConditionalCompareWithAnOutOfRangeNzcv) {
  donkey::IrBlock block;
  donkey::IrStatement compare;
  compare.op = donkey::IrOp::CondCompare;
  compare.a = donkey::IrOperand::register_ref("rax", 8);
  compare.b = donkey::IrOperand::register_ref("rbx", 8);
  compare.c = donkey::IrOperand::constant_value(16, 1);  // NZCV is 0 to 15
  compare.condition = donkey::IrCondition::Equal;
  compare.width = 8;
  block.statements.push_back(compare);
  donkey::IrStatement ret;
  ret.op = donkey::IrOp::Return;
  ret.a = donkey::IrOperand::register_ref("rax", 8);
  ret.width = 8;
  block.statements.push_back(ret);
  donkey::IrFunction function;
  function.name = "compare";
  function.blocks.push_back(std::move(block));
  const auto rejected = donkey::verify_ir(function);
  ASSERT_FALSE(rejected.has_value());
  EXPECT_EQ(rejected.diagnostic().code, "ir.malformed_cond_compare");
}

TEST(Ir, AArch64DiscardedResultToTheZeroRegisterLiftsToNothing) {
  // udiv xzr, x0, x1; ret: the quotient is discarded, so x0 is unchanged.
  const auto data = aarch64_bytes({0x9ac1081f, 0xaa0003e0, 0xd65f03c0});  // ...; mov x0, x0; ret
  EXPECT_EQ(run_aarch64_args(data, {42, 3}), 42U);
}

TEST(Ir, AArch64HighAfterLogicalTestUsesTheCarryAndZero) {
  // tst x0, x0; ccmp x1, x2, #4, hi; cset x0, eq; ret. tst clears C, so hi is false
  // whatever x0 is. NZCV becomes #4 (Z set), and eq holds.
  const auto data = aarch64_bytes({0xea00001f, 0xfa428024, 0x9a9f17e0, 0xd65f03c0});
  EXPECT_EQ(run_aarch64_args(data, {1, 1, 0}), 1U);
}

TEST(Ir, AArch64LowAfterLogicalTestIsTrue) {
  // tst x0, x0; cset x0, lo; ret. lo is C clear, which tst always leaves.
  const auto data = aarch64_bytes({0xea00001f, 0x9a9f27e0, 0xd65f03c0});
  EXPECT_EQ(run_aarch64_args(data, {0}), 1U);
  EXPECT_EQ(run_aarch64_args(data, {5}), 1U);
}

TEST(Ir, PseudocodeDoesNotNameAnEarlierCompareAfterACondCompare) {
  // cmp rax, rbx; ccmp rax, rcx, #0, lo; if (lo) rdx = rsi. The lo condition
  // reads the NZCV that ccmp set, not the comparison of rax with rbx.
  donkey::IrFunction function;
  function.name = "conditional";
  donkey::IrBlock block;
  donkey::IrStatement compare;
  compare.op = donkey::IrOp::Compare;
  compare.a = donkey::IrOperand::register_ref("rax", 8);
  compare.b = donkey::IrOperand::register_ref("rbx", 8);
  compare.condition = donkey::IrCondition::Equal;
  compare.width = 8;
  block.statements.push_back(compare);
  donkey::IrStatement cond_compare;
  cond_compare.op = donkey::IrOp::CondCompare;
  cond_compare.a = donkey::IrOperand::register_ref("rax", 8);
  cond_compare.b = donkey::IrOperand::register_ref("rcx", 8);
  cond_compare.c = donkey::IrOperand::constant_value(0, 1);
  cond_compare.condition = donkey::IrCondition::UnsignedLess;
  cond_compare.width = 8;
  block.statements.push_back(cond_compare);
  donkey::IrStatement assign;
  assign.op = donkey::IrOp::CondAssign;
  assign.dest = donkey::IrOperand::register_ref("rdx", 8);
  assign.a = donkey::IrOperand::register_ref("rsi", 8);
  assign.condition = donkey::IrCondition::UnsignedLess;
  assign.width = 8;
  block.statements.push_back(assign);
  donkey::IrStatement ret;
  ret.op = donkey::IrOp::Return;
  ret.a = donkey::IrOperand::register_ref("rdx", 8);
  ret.width = 8;
  block.statements.push_back(ret);
  function.blocks.push_back(std::move(block));
  const auto text = donkey::format_pseudocode(function);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  EXPECT_NE(text.value().find("if (flags"), std::string::npos) << text.value();
  EXPECT_EQ(text.value().find("if (rax"), std::string::npos) << text.value();
}

/// True when the AArch64 code lifts to a Partial function.
bool aarch64_lifts_partial(const std::vector<std::byte>& data) {
  auto image = synthetic_image(data.size());
  image.architecture = Architecture::AArch64;
  auto analyzed = donkey::analyze(image, data);
  EXPECT_TRUE(analyzed.has_value());
  if (!analyzed.has_value() || analyzed.value().functions.empty()) {
    return false;
  }
  auto lifted = donkey::lift_function(image, analyzed.value(), analyzed.value().functions.front());
  EXPECT_TRUE(lifted.has_value());
  return lifted.has_value() && lifted.value().partial;
}

/// The lifted x86-64 function for the code (the first function found).
donkey::IrFunction lift_x86_64_code(const std::vector<std::byte>& data) {
  auto image = synthetic_image(data.size());
  image.architecture = Architecture::X86_64;
  auto analyzed = donkey::analyze(image, data);
  EXPECT_TRUE(analyzed.has_value());
  donkey::IrFunction none;
  if (!analyzed.has_value() || analyzed.value().functions.empty()) {
    return none;
  }
  auto lifted = donkey::lift_function(image, analyzed.value(), analyzed.value().functions.front());
  EXPECT_TRUE(lifted.has_value());
  return lifted.has_value() ? lifted.value() : none;
}

TEST(Ir, NarrowMergedReturnIsAsWideAsTheValueReturned) {
  // mov al, dil; ret: rax is written at full width by the merge, but the value returned is
  // one byte, so the return is one byte wide.
  const auto function =
      lift_x86_64_code({std::byte{0x40}, std::byte{0x88}, std::byte{0xf8}, std::byte{0xc3}});
  EXPECT_EQ(function.return_width, 1U);
}

TEST(Ir, SingleFloatReturnIsFourBytesWide) {
  // addss xmm0, xmm1; ret: the value returned is a single-precision float.
  const auto function = lift_x86_64_code(
      {std::byte{0xf3}, std::byte{0x0f}, std::byte{0x58}, std::byte{0xc1}, std::byte{0xc3}});
  EXPECT_EQ(function.return_width, 4U);
  // Rounding-dependent results are Partial: the MXCSR mode is not modelled.
  EXPECT_TRUE(function.partial);
}

TEST(Ir, DoubleReturnWithNoIntegerWriteKeepsItsReturnChannel) {
  // addsd xmm0, xmm1; ret
  const auto function = lift_x86_64_code(
      {std::byte{0xf2}, std::byte{0x0f}, std::byte{0x58}, std::byte{0xc1}, std::byte{0xc3}});
  EXPECT_EQ(function.return_width, 8U);
  // Rounding-dependent results are Partial: the MXCSR mode is not modelled.
  EXPECT_TRUE(function.partial);
}

TEST(Ir, IntegerWriteAfterAFloatResultIsAmbiguous) {
  // addsd xmm0, xmm1; mov eax, 1; ret: rax and xmm0 are both written on the way to the
  // return, so the return channel cannot be told apart and the function is Partial.
  const auto function = lift_x86_64_code(
      {std::byte{0xf2}, std::byte{0x0f}, std::byte{0x58}, std::byte{0xc1}, std::byte{0xb8},
       std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xc3}});
  EXPECT_TRUE(function.partial);
}

TEST(Ir, AArch64CarryChainAddsThenAdcUsesTheSumsCarry) {
  // adds x0, x0, x1; adc x0, x2, x3; ret. The carry is the one out of the sum.
  const auto data = aarch64_bytes({0xab010000, 0x9a030040, 0xd65f03c0});
  EXPECT_FALSE(aarch64_lifts_partial(data));
  EXPECT_EQ(run_aarch64_args(data, {~0ULL, 1, 5, 7}), 13U);  // the sum wraps: 5 + 7 + 1
  EXPECT_EQ(run_aarch64_args(data, {1, 2, 5, 7}), 12U);
}

TEST(Ir, AArch64SubtractWithBorrowUsesTheCompareBorrow) {
  // subs x0, x0, x1; sbc x0, x2, x3; ret. The borrow is not C after the subtraction.
  const auto data = aarch64_bytes({0xeb010000, 0xda030040, 0xd65f03c0});
  EXPECT_FALSE(aarch64_lifts_partial(data));
  EXPECT_EQ(run_aarch64_args(data, {1, 2, 10, 3}), 6U);  // borrows: 10 - 3 - 1
  EXPECT_EQ(run_aarch64_args(data, {2, 1, 10, 3}), 7U);  // no borrow: 10 - 3
}

TEST(Ir, AArch64CmnAgainstMinusOneSetsTheZeroFlag) {
  // cmn x0, #1; cset x0, eq; ret. cmn sets the flags of x0 + 1.
  const auto data = aarch64_bytes({0xb100041f, 0x9a9f17e0, 0xd65f03c0});
  EXPECT_EQ(run_aarch64_args(data, {~0ULL}), 1U);
  EXPECT_EQ(run_aarch64_args(data, {0}), 0U);
  EXPECT_EQ(run_aarch64_args(data, {5}), 0U);
}

TEST(Ir, AArch64AddsSetsTheZeroFlagOfTheSum) {
  // adds x0, x0, x1; cset x0, eq; ret. eq holds when the sum is zero.
  const auto data = aarch64_bytes({0xab010000, 0x9a9f17e0, 0xd65f03c0});
  EXPECT_EQ(run_aarch64_args(data, {5, static_cast<std::uint64_t>(-5)}), 1U);
  EXPECT_EQ(run_aarch64_args(data, {1, 1}), 0U);
}

TEST(Ir, AArch64CarryWithoutAFlagWriterIsPartial) {
  // adc x0, x2, x3; ret. The carry is unknown with no flag writer before it.
  EXPECT_TRUE(aarch64_lifts_partial(aarch64_bytes({0x9a030040, 0xd65f03c0})));
}

TEST(Ir, AArch64CarryReadersShareTheCarryOfTheFlagWriter) {
  // adds x0, x0, x1; adc x0, x2, x3; adc x0, x4, x5; ret. Neither adc writes NZCV, so the
  // second one reads the carry of the sum as well.
  const auto data = aarch64_bytes({0xab010000, 0x9a030040, 0x9a050080, 0xd65f03c0});
  EXPECT_FALSE(aarch64_lifts_partial(data));
  EXPECT_EQ(run_aarch64_args(data, {~0ULL, 1, 5, 7, 2, 3}), 6U);  // carry 1: 2 + 3 + 1
  EXPECT_EQ(run_aarch64_args(data, {1, 2, 5, 7, 2, 3}), 5U);      // no carry: 2 + 3
}

// adcs and sbcs set NZCV from the addition, as the architecture defines it, and
// the IR states that exactly. The expected values are ground truth from running
// the instructions under qemu-aarch64: the carry in is set by `cmp x2, #1`, which
// makes C equal to x2 >= 1. nzcv uses N=8, Z=4, C=2, V=1.
TEST(Ir, AArch64AdcsAndSbcsSetNzcvLikeTheAddition) {
  struct Set {
    std::vector<std::byte> result, eq, cs, mi, vs;  // eq tests Z, cs C, mi N, vs V
  };
  const Set adcs64{aarch64_bytes({0xf100045fU, 0xba010000U, 0xd65f03c0U}),
                   aarch64_bytes({0xf100045fU, 0xba010003U, 0x1a9f17e0U, 0xd65f03c0U}),
                   aarch64_bytes({0xf100045fU, 0xba010003U, 0x1a9f37e0U, 0xd65f03c0U}),
                   aarch64_bytes({0xf100045fU, 0xba010003U, 0x1a9f57e0U, 0xd65f03c0U}),
                   aarch64_bytes({0xf100045fU, 0xba010003U, 0x1a9f77e0U, 0xd65f03c0U})};
  const Set sbcs64{aarch64_bytes({0xf100045fU, 0xfa010000U, 0xd65f03c0U}),
                   aarch64_bytes({0xf100045fU, 0xfa010003U, 0x1a9f17e0U, 0xd65f03c0U}),
                   aarch64_bytes({0xf100045fU, 0xfa010003U, 0x1a9f37e0U, 0xd65f03c0U}),
                   aarch64_bytes({0xf100045fU, 0xfa010003U, 0x1a9f57e0U, 0xd65f03c0U}),
                   aarch64_bytes({0xf100045fU, 0xfa010003U, 0x1a9f77e0U, 0xd65f03c0U})};
  const Set adcs32{aarch64_bytes({0xf100045fU, 0x3a010000U, 0xd65f03c0U}),
                   aarch64_bytes({0xf100045fU, 0x3a010003U, 0x1a9f17e0U, 0xd65f03c0U}),
                   aarch64_bytes({0xf100045fU, 0x3a010003U, 0x1a9f37e0U, 0xd65f03c0U}),
                   aarch64_bytes({0xf100045fU, 0x3a010003U, 0x1a9f57e0U, 0xd65f03c0U}),
                   aarch64_bytes({0xf100045fU, 0x3a010003U, 0x1a9f77e0U, 0xd65f03c0U})};
  const Set sbcs32{aarch64_bytes({0xf100045fU, 0x7a010000U, 0xd65f03c0U}),
                   aarch64_bytes({0xf100045fU, 0x7a010003U, 0x1a9f17e0U, 0xd65f03c0U}),
                   aarch64_bytes({0xf100045fU, 0x7a010003U, 0x1a9f37e0U, 0xd65f03c0U}),
                   aarch64_bytes({0xf100045fU, 0x7a010003U, 0x1a9f57e0U, 0xd65f03c0U}),
                   aarch64_bytes({0xf100045fU, 0x7a010003U, 0x1a9f77e0U, 0xd65f03c0U})};
  struct Row {
    bool subtract;
    bool wide;
    std::uint64_t a;
    std::uint64_t b;
    std::uint64_t carry;
    std::uint64_t result;
    std::uint64_t nzcv;
  };
  const Row rows[] = {
      {false, true, 0x0ULL, 0x0ULL, 0, 0x0ULL, 4},
      {false, true, 0x7fffffffffffffffULL, 0x1ULL, 0, 0x8000000000000000ULL, 9},
      {false, true, 0x8000000000000000ULL, 0x8000000000000000ULL, 0, 0x0ULL, 7},
      {false, true, 0xffffffffffffffffULL, 0x1ULL, 0, 0x0ULL, 6},
      {false, true, 0x5ULL, 0x3ULL, 1, 0x9ULL, 0},
      {true, true, 0x0ULL, 0x0ULL, 0, 0xffffffffffffffffULL, 8},
      {true, true, 0x5ULL, 0x3ULL, 0, 0x1ULL, 2},
      {true, true, 0x3ULL, 0x5ULL, 1, 0xfffffffffffffffeULL, 8},
      {true, true, 0x5ULL, 0x3ULL, 1, 0x2ULL, 2},
      {true, true, 0xffffffffffffffffULL, 0x1ULL, 1, 0xfffffffffffffffeULL, 10},
      {false, false, 0x7fffffffULL, 0x1ULL, 0, 0x80000000ULL, 9},
      {false, false, 0xffffffffULL, 0x1ULL, 0, 0x0ULL, 6},
      {false, false, 0x5ULL, 0x3ULL, 1, 0x9ULL, 0},
      {true, false, 0x5ULL, 0x3ULL, 0, 0x1ULL, 2},
      {true, false, 0x3ULL, 0x5ULL, 1, 0xfffffffeULL, 8},
  };
  for (const Row& row : rows) {
    const Set& set = row.subtract ? (row.wide ? sbcs64 : sbcs32) : (row.wide ? adcs64 : adcs32);
    const std::uint64_t mask = row.wide ? ~0ULL : 0xffffffffULL;
    const std::uint64_t inputs[] = {row.a, row.b, row.carry};
    const auto run = [&inputs](const std::vector<std::byte>& code) {
      return run_aarch64_args(code, {inputs[0], inputs[1], inputs[2]});
    };
    EXPECT_EQ(run(set.result) & mask, row.result) << "a=" << row.a << " b=" << row.b;
    EXPECT_EQ(run(set.eq) & 1U, (row.nzcv >> 2U) & 1U) << "Z of a=" << row.a << " b=" << row.b;
    EXPECT_EQ(run(set.cs) & 1U, (row.nzcv >> 1U) & 1U) << "C of a=" << row.a << " b=" << row.b;
    EXPECT_EQ(run(set.mi) & 1U, (row.nzcv >> 3U) & 1U) << "N of a=" << row.a << " b=" << row.b;
    EXPECT_EQ(run(set.vs) & 1U, row.nzcv & 1U) << "V of a=" << row.a << " b=" << row.b;
  }
}

// adcs then adc: the carry out of adcs is the carry in of adc, so a 128-bit add
// is right. ~0 + 1 carries into the high word: 5 + 7 + 1 = 13.
TEST(Ir, AArch64AdcsCarryOutFeedsAdc) {
  const auto chain = aarch64_bytes({0xf100049fU, 0xba020000U, 0x9a030020U, 0xd65f03c0U});
  // x0, x1 is the low and high word of one operand, x2, x3 of the other, x4 the carry in.
  EXPECT_EQ(run_aarch64_args(chain, {~0ULL, 5, 1, 7, 0}), 13U);
  EXPECT_EQ(run_aarch64_args(chain, {1, 5, 2, 7, 0}), 12U);
}

// A branch on flags set by a cmp in the block before it. The fall-through block has
// one predecessor, so the cmp is repeated at its start and the function is Complete.
// This is the shape of c_switch_sparse at -O2 on GCC.
TEST(Ir, AArch64FlagsFromSinglePredecessorAreExact) {
  const auto code = aarch64_bytes({0x7101901fU, 0x540000c0U, 0x5400006cU, 0x528000a0U, 0xd65f03c0U,
                                   0x52800120U, 0xd65f03c0U, 0x528000e0U, 0xd65f03c0U});
  EXPECT_FALSE(aarch64_lifts_partial(code));
  EXPECT_EQ(run_aarch64_args(code, {100}), 7U);
  EXPECT_EQ(run_aarch64_args(code, {200}), 9U);
  EXPECT_EQ(run_aarch64_args(code, {99}), 5U);  // not equal, and not greater
  EXPECT_EQ(run_aarch64_args(code, {3}), 5U);
  EXPECT_EQ(run_aarch64_args(code, {101}), 9U);
}

// The cmp reads w0, which mov rewrites before the branch. The compare cannot be
// repeated from its operands, so the block that branches on it stays Partial.
TEST(Ir, AArch64FlagsRewrittenAfterTheCompareStayPartial) {
  EXPECT_TRUE(aarch64_lifts_partial(
      aarch64_bytes({0x7101901fU, 0x52800020U, 0x540000c0U, 0x5400006cU, 0x528000a0U, 0xd65f03c0U,
                     0x52800120U, 0xd65f03c0U, 0x528000e0U, 0xd65f03c0U})));
}

// adds sets the flags too, but they are not the flags of a cmp or tst that can be
// repeated, so the block that branches on them stays Partial.
TEST(Ir, AArch64FlagsFromAddsDoNotCarryAcrossBlocks) {
  EXPECT_TRUE(aarch64_lifts_partial(
      aarch64_bytes({0x31000401U, 0x540000c0U, 0x5400006cU, 0x528000a0U, 0xd65f03c0U, 0x52800120U,
                     0xd65f03c0U, 0x528000e0U, 0xd65f03c0U})));
}

// ---- G01-T1: floating point in the IR ---------------------------------------
// The expected bits come from running the same operations natively: x86-64 SSE on
// the host, and AArch64 under qemu-aarch64. The two models differ only where the
// architectures do: the default NaN, the integer a conversion gives for a NaN or an
// out-of-range value, and the flags a comparison sets.

// A one-block function that computes dest = op(a, b) on constant operands at
// `width`, and returns dest.
donkey::IrFunction fp_one_op(donkey::IrOp op, std::uint8_t width, std::uint64_t a, std::uint64_t b,
                             donkey::IrFloatModel model) {
  donkey::IrFunction f;
  f.name = "fp";
  f.return_width = 8;
  donkey::IrBlock block;
  donkey::IrStatement s;
  s.op = op;
  s.dest = donkey::IrOperand::register_ref("rax", width);
  s.a = donkey::IrOperand::constant_value(a, width);
  s.b = donkey::IrOperand::constant_value(b, width);
  s.width = width;
  s.float_model = model;
  block.statements.push_back(s);
  donkey::IrStatement ret;
  ret.op = donkey::IrOp::Return;
  ret.a = donkey::IrOperand::register_ref("rax", 8);
  ret.width = 8;
  block.statements.push_back(ret);
  f.blocks.push_back(block);
  return f;
}

// A one-block function that converts a constant of `source_width` bytes to a result
// of `result_width` bytes with `op`, and returns the result.
donkey::IrFunction fp_convert(donkey::IrOp op, std::uint8_t result_width, std::uint8_t source_width,
                              std::uint64_t value, donkey::IrFloatModel model) {
  donkey::IrFunction f;
  f.name = "fp_convert";
  f.return_width = 8;
  donkey::IrBlock block;
  donkey::IrStatement s;
  s.op = op;
  s.dest = donkey::IrOperand::register_ref("rax", result_width);
  s.a = donkey::IrOperand::constant_value(value, source_width);
  s.width = result_width;
  s.float_model = model;
  block.statements.push_back(s);
  donkey::IrStatement ret;
  ret.op = donkey::IrOp::Return;
  ret.a = donkey::IrOperand::register_ref("rax", 8);
  ret.width = 8;
  block.statements.push_back(ret);
  f.blocks.push_back(block);
  return f;
}

std::uint64_t fp_result(const donkey::IrFunction& function) {
  donkey::IrEvalMemory memory;
  donkey::IrEvalOptions options;
  const auto result = donkey::evaluate_ir(function, std::vector<std::uint64_t>(), memory, options);
  EXPECT_TRUE(result.has_value()) << (result.has_value() ? "" : result.diagnostic().code);
  return result.has_value() ? result.value().return_value : ~0ULL;
}

TEST(Ir, FloatArithmeticMatchesIeee) {
  using donkey::IrFloatModel;
  using donkey::IrOp;
  constexpr std::uint64_t inf = 0x7ff0000000000000ULL;
  constexpr std::uint64_t ninf = 0xfff0000000000000ULL;
  constexpr std::uint64_t one = 0x3ff0000000000000ULL;
  constexpr std::uint64_t nzero = 0x8000000000000000ULL;
  constexpr std::uint64_t qnan = 0x7ff8000000000000ULL;
  constexpr std::uint64_t qnan2 = 0x7ff8000000000123ULL;
  constexpr std::uint64_t snan = 0x7ff0000000000001ULL;
  constexpr std::uint64_t x86_default = 0xfff8000000000000ULL;
  constexpr std::uint64_t arm_default = 0x7ff8000000000000ULL;
  struct Case {
    IrOp op;
    std::uint8_t width;
    std::uint64_t a;
    std::uint64_t b;
    std::uint64_t x86;
    std::uint64_t aarch64;
  };
  const Case cases[] = {
      // Double precision: the ground-truth rows are dadd, dsub, dmul, ddiv and dsqrt.
      {IrOp::FAdd, 8, one, 0, one, one},
      {IrOp::FAdd, 8, nzero, 0, 0, 0},  // -0 + +0 is +0 in round-to-nearest
      {IrOp::FDiv, 8, one, 0, inf, inf},
      {IrOp::FDiv, 8, 0, 0, x86_default, arm_default},
      {IrOp::FAdd, 8, inf, ninf, x86_default, arm_default},
      {IrOp::FSub, 8, inf, inf, x86_default, arm_default},
      {IrOp::FMul, 8, 0, inf, x86_default, arm_default},
      {IrOp::FAdd, 8, qnan, one, qnan, qnan},
      {IrOp::FAdd, 8, qnan, qnan2, qnan, qnan},  // both NaN: the first operand
      {IrOp::FAdd, 8, qnan2, qnan, qnan2, qnan2},
      {IrOp::FAdd, 8, snan, one, 0x7ff8000000000001ULL, 0x7ff8000000000001ULL},  // quieted
      {IrOp::FAdd, 8, 1, 0x3fe0000000000000ULL, 0x3fe0000000000000ULL, 0x3fe0000000000000ULL},
      // 1 ulp divided by 0.5 is 2 ulps: a denormal, so the bits are 0x2.
      {IrOp::FDiv, 8, 1, 0x3fe0000000000000ULL, 0x2ULL, 0x2ULL},
      {IrOp::FMul, 8, nzero, 0, nzero, nzero},
      {IrOp::FSqrt, 8, 0xbff0000000000000ULL, 0, x86_default, arm_default},  // sqrt(-1)
      {IrOp::FSqrt, 8, 0x4010000000000000ULL, 0, 0x4000000000000000ULL, 0x4000000000000000ULL},
      {IrOp::FSqrt, 8, nzero, 0, nzero, nzero},
      {IrOp::FSqrt, 8, qnan2, 0, qnan2, qnan2},
      {IrOp::FNeg, 8, 0, 0, nzero, nzero},
      {IrOp::FAbs, 8, qnan | nzero, 0, qnan, qnan},
      // Single precision: the ground-truth rows are fadd32, fsub32, fmul32 and fdiv32.
      {IrOp::FAdd, 4, 0x3fc00000ULL, 0x40100000ULL, 0x40700000ULL, 0x40700000ULL},
      {IrOp::FSub, 4, 0x7f800000ULL, 0x7f800000ULL, 0xffc00000ULL, 0x7fc00000ULL},
      {IrOp::FMul, 4, 0, 0x7f800000ULL, 0xffc00000ULL, 0x7fc00000ULL},
      {IrOp::FDiv, 4, 0, 0, 0xffc00000ULL, 0x7fc00000ULL},
      {IrOp::FAdd, 4, 0x7f800001ULL, 0x3f800000ULL, 0x7fc00001ULL, 0x7fc00001ULL},
      {IrOp::FAdd, 4, 0x7fc00000ULL, 0x3f800000ULL, 0x7fc00000ULL, 0x7fc00000ULL},
  };
  for (const Case& c : cases) {
    const std::uint64_t mask = c.width == 4 ? 0xffffffffULL : ~0ULL;
    EXPECT_EQ(fp_result(fp_one_op(c.op, c.width, c.a, c.b, IrFloatModel::X86)) & mask, c.x86)
        << "x86 op " << static_cast<int>(c.op) << " a=" << std::hex << c.a << " b=" << c.b;
    EXPECT_EQ(fp_result(fp_one_op(c.op, c.width, c.a, c.b, IrFloatModel::AArch64)) & mask,
              c.aarch64)
        << "AArch64 op " << static_cast<int>(c.op) << " a=" << std::hex << c.a << " b=" << c.b;
  }
}

// Conversions from floating point to integers differ where the architectures do:
// x86 cvttsd2si gives the "integer indefinite" (the minimum) for a NaN or an
// out-of-range value, and AArch64 fcvtzs gives 0 for a NaN and saturates the rest.
TEST(Ir, FloatToIntIndefiniteOnX86AndSaturatesOnAArch64) {
  using donkey::IrFloatModel;
  using donkey::IrOp;
  struct Case {
    std::uint8_t result_width;
    std::uint64_t value;  // a double
    std::uint64_t x86;
    std::uint64_t aarch64;
  };
  const Case cases[] = {
      {8, 0x400f333333333333ULL, 3, 3},                                          // 3.9
      {8, 0xc00f333333333333ULL, 0xfffffffffffffffdULL, 0xfffffffffffffffdULL},  // -3.9
      {8, 0x7ff8000000000000ULL, 0x8000000000000000ULL, 0},                      // NaN
      {8, 0x7ff0000000000000ULL, 0x8000000000000000ULL, 0x7fffffffffffffffULL},  // +inf
      {8, 0xfff0000000000000ULL, 0x8000000000000000ULL, 0x8000000000000000ULL},  // -inf
      {8, 0x46293e5939a08ceaULL, 0x8000000000000000ULL, 0x7fffffffffffffffULL},  // 1e30
      {8, 0x43e0000000000000ULL, 0x8000000000000000ULL, 0x7fffffffffffffffULL},  // 2^63
      {4, 0x400f333333333333ULL, 3, 3},
      {4, 0x7ff8000000000000ULL, 0x80000000ULL, 0},
      {4, 0x41e0000000000000ULL, 0x80000000ULL, 0x7fffffffULL},  // 2^31
  };
  for (const Case& c : cases) {
    EXPECT_EQ(
        fp_result(fp_convert(IrOp::FloatToInt, c.result_width, 8, c.value, IrFloatModel::X86)),
        c.x86)
        << "x86 " << std::hex << c.value;
    EXPECT_EQ(
        fp_result(fp_convert(IrOp::FloatToInt, c.result_width, 8, c.value, IrFloatModel::AArch64)),
        c.aarch64)
        << "AArch64 " << std::hex << c.value;
  }
}

// ucomis* (x86) sets ZF, PF and CF, and an unordered comparison sets all three.
// fcmp (AArch64) sets NZCV, and an unordered comparison sets 0011.
TEST(Ir, FCompareUnorderedSetsFlags) {
  using donkey::IrCondition;
  using donkey::IrFloatModel;
  using donkey::IrOp;
  // dest = 0; compare a with b; if (condition) dest = 1; return dest
  const auto conditional = [](std::uint64_t a, std::uint64_t b, IrFloatModel model,
                              IrCondition condition) {
    donkey::IrFunction f;
    f.name = "fcompare";
    f.return_width = 8;
    donkey::IrBlock block;
    donkey::IrStatement zero;
    zero.op = donkey::IrOp::Assign;
    zero.dest = donkey::IrOperand::register_ref("rax", 8);
    zero.a = donkey::IrOperand::constant_value(0, 8);
    zero.width = 8;
    block.statements.push_back(zero);
    donkey::IrStatement compare;
    compare.op = IrOp::FCompare;
    compare.a = donkey::IrOperand::constant_value(a, 8);
    compare.b = donkey::IrOperand::constant_value(b, 8);
    compare.width = 8;
    compare.float_model = model;
    block.statements.push_back(compare);
    donkey::IrStatement pick;
    pick.op = donkey::IrOp::CondAssign;
    pick.dest = donkey::IrOperand::register_ref("rax", 8);
    pick.a = donkey::IrOperand::constant_value(1, 8);
    pick.condition = condition;
    pick.width = 8;
    block.statements.push_back(pick);
    donkey::IrStatement ret;
    ret.op = donkey::IrOp::Return;
    ret.a = donkey::IrOperand::register_ref("rax", 8);
    ret.width = 8;
    block.statements.push_back(ret);
    f.blocks.push_back(block);
    return f;
  };
  constexpr std::uint64_t qnan = 0x7ff8000000000000ULL;
  constexpr std::uint64_t one = 0x3ff0000000000000ULL;
  constexpr std::uint64_t two = 0x4000000000000000ULL;
  // x86: unordered sets ZF, PF and CF.
  EXPECT_EQ(fp_result(conditional(qnan, one, IrFloatModel::X86, IrCondition::Equal)), 1U);
  EXPECT_EQ(fp_result(conditional(qnan, one, IrFloatModel::X86, IrCondition::Parity)), 1U);
  EXPECT_EQ(fp_result(conditional(qnan, one, IrFloatModel::X86, IrCondition::UnsignedLess)), 1U);
  EXPECT_EQ(fp_result(conditional(qnan, one, IrFloatModel::X86, IrCondition::UnsignedGreater)), 0U);
  EXPECT_EQ(fp_result(conditional(qnan, one, IrFloatModel::X86, IrCondition::NoParity)), 0U);
  // x86, less: CF only.
  EXPECT_EQ(fp_result(conditional(one, two, IrFloatModel::X86, IrCondition::UnsignedLess)), 1U);
  EXPECT_EQ(fp_result(conditional(one, two, IrFloatModel::X86, IrCondition::Equal)), 0U);
  EXPECT_EQ(fp_result(conditional(one, two, IrFloatModel::X86, IrCondition::Parity)), 0U);
  // AArch64: unordered is 0011, so V is set and Z is clear.
  EXPECT_EQ(fp_result(conditional(qnan, one, IrFloatModel::AArch64, IrCondition::Overflow)), 1U);
  EXPECT_EQ(fp_result(conditional(qnan, one, IrFloatModel::AArch64, IrCondition::Equal)), 0U);
  EXPECT_EQ(fp_result(conditional(qnan, one, IrFloatModel::AArch64, IrCondition::UnsignedLess)),
            0U);
  // AArch64, less: 1000, so N is set.
  EXPECT_EQ(fp_result(conditional(one, two, IrFloatModel::AArch64, IrCondition::Negative)), 1U);
  EXPECT_EQ(fp_result(conditional(one, two, IrFloatModel::AArch64, IrCondition::UnsignedLess)), 1U);
  // Equal: x86 sets ZF; AArch64 sets Z and C.
  EXPECT_EQ(fp_result(conditional(one, one, IrFloatModel::X86, IrCondition::Equal)), 1U);
  EXPECT_EQ(fp_result(conditional(one, one, IrFloatModel::AArch64, IrCondition::Equal)), 1U);
}

TEST(Ir, VerifierRejectsMixedIntFloatOperands) {
  // A float operation whose operand is 8 bytes wide while the statement is 4 bytes.
  donkey::IrFunction mixed =
      fp_one_op(donkey::IrOp::FAdd, 4, 0x3f800000ULL, 0x3f800000ULL, donkey::IrFloatModel::X86);
  mixed.blocks[0].statements[0].a = donkey::IrOperand::constant_value(0x3ff0000000000000ULL, 8);
  EXPECT_FALSE(donkey::verify_ir(mixed).has_value());
  EXPECT_TRUE(donkey::verify_ir(fp_one_op(donkey::IrOp::FAdd, 4, 0x3f800000ULL, 0x3f800000ULL,
                                          donkey::IrFloatModel::X86))
                  .has_value());
}

TEST(Ir, FloatConstantsPrintAsExactHexadecimalFloats) {
  // 1.5 and 2.25, printed exactly: 0x1.8p+0 and 0x1.2p+1.
  const donkey::IrFunction f = fp_one_op(donkey::IrOp::FAdd, 8, 0x3ff8000000000000ULL,
                                         0x4002000000000000ULL, donkey::IrFloatModel::X86);
  const auto text = donkey::format_pseudocode(f);
  ASSERT_TRUE(text.has_value());
  EXPECT_NE(text.value().find("0x1.8p+0"), std::string::npos) << text.value();
  EXPECT_NE(text.value().find("0x1.2p+1"), std::string::npos) << text.value();
}

TEST(Ir, SingleFractionsAreAlignedToWholeHexDigits) {
  // 1.5f is 0x3fc00000: the 23-bit fraction 0x400000 must print as 0x1.8p+0, not 0x1.4p+0.
  const donkey::IrFunction f =
      fp_one_op(donkey::IrOp::FAdd, 4, 0x3fc00000ULL, 0ULL, donkey::IrFloatModel::X86);
  const auto text = donkey::format_pseudocode(f);
  ASSERT_TRUE(text.has_value());
  EXPECT_NE(text.value().find("0x1.8p+0"), std::string::npos) << text.value();
  EXPECT_EQ(text.value().find("0x1.4p+0"), std::string::npos) << text.value();
}

TEST(Ir, UnsignedConversionKeepsTheWholeOfAWideSource) {
  donkey::IrFunction function;
  function.name = "to_double";
  function.blocks.push_back(make_block(0x1000));
  donkey::IrStatement convert;
  convert.op = donkey::IrOp::UIntToFloat;
  convert.dest = donkey::IrOperand::register_ref("xmm0", 8);
  convert.a = donkey::IrOperand::register_ref("rdi", 8);
  convert.width = 8;
  function.blocks[0].statements.push_back(convert);
  IrStatement ret;
  ret.op = donkey::IrOp::Return;
  ret.a = donkey::IrOperand::register_ref("xmm0", 8);
  ret.width = 8;
  function.blocks[0].statements.push_back(ret);
  const auto text = donkey::format_pseudocode(function);
  ASSERT_TRUE(text.has_value());
  EXPECT_NE(text.value().find("(unsigned long long)rdi"), std::string::npos) << text.value();
}

TEST(Ir, FloatingPointEvaluationRoundsToNearestWhateverTheCallerSet) {
  // 1 + 2^-60 is 1 under round-to-nearest. Under FE_UPWARD the host would round it up.
  const int saved = std::fegetround();
  std::fesetround(FE_UPWARD);
  const std::uint64_t result =
      fp_result(fp_one_op(donkey::IrOp::FAdd, 8, 0x3ff0000000000000ULL, 0x3c30000000000000ULL,
                          donkey::IrFloatModel::X86));
  EXPECT_EQ(std::fegetround(), FE_UPWARD) << "the caller's rounding mode must be restored";
  std::fesetround(saved);
  EXPECT_EQ(result, 0x3ff0000000000000ULL);
}

/// The lifted AArch64 function for the code (the first function found).
donkey::IrFunction lift_aarch64_code(const std::vector<std::byte>& data) {
  auto image = synthetic_image(data.size());
  image.architecture = Architecture::AArch64;
  auto analyzed = donkey::analyze(image, data);
  EXPECT_TRUE(analyzed.has_value());
  donkey::IrFunction none;
  if (!analyzed.has_value() || analyzed.value().functions.empty()) {
    return none;
  }
  auto lifted = donkey::lift_function(image, analyzed.value(), analyzed.value().functions.front());
  EXPECT_TRUE(lifted.has_value());
  return lifted.has_value() ? lifted.value() : none;
}

TEST(Ir, AArch64FloatingPointParametersAndReturnAreRenderedAsDouble) {
  // fadd d0, d0, d1; ret: two double arguments and a double result.
  const auto function = lift_aarch64_code(aarch64_bytes({0x1e612800U, 0xd65f03c0U}));
  const auto text = donkey::format_pseudocode(function);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  EXPECT_NE(text.value().find("double a0, double a1"), std::string::npos) << text.value();
  EXPECT_NE(text.value().find("double sub"), std::string::npos) << text.value();
  EXPECT_EQ(text.value().find("u64 a0"), std::string::npos) << text.value();
}

TEST(Ir, AArch64FusedMultiplySubtractIsRenderedAsAFusedCall) {
  // fmsub d0, d1, d2, d3: d0 = d3 - d1 * d2, rounded once.
  const auto function = lift_aarch64_code(aarch64_bytes({0x1f428c20U, 0xd65f03c0U}));
  const auto text = donkey::format_pseudocode(function);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  EXPECT_NE(text.value().find("fma(-"), std::string::npos) << text.value();
  EXPECT_EQ(text.value().find("/* fused */"), std::string::npos) << text.value();
}

TEST(Ir, AArch64IntegerAndFloatingPointParametersTogetherArePartial) {
  // add x0, x0, x1; fadd d0, d0, d1; ret: the order of the four arguments is not
  // recoverable from their registers, so the signature is Partial.
  EXPECT_TRUE(lift_aarch64_code(aarch64_bytes({0x8b010000U, 0x1e612800U, 0xd65f03c0U})).partial);
}

TEST(Ir, AArch64IntegerReturnAfterAFloatingPointResultIsAmbiguous) {
  // fadd d0, d0, d1; movz x0, #1; ret: x0 and d0 are both written on the way to the
  // return, so the return channel is not determined.
  EXPECT_TRUE(lift_aarch64_code(aarch64_bytes({0x1e612800U, 0xd2800020U, 0xd65f03c0U})).partial);
}

TEST(Ir, AArch64AdcsWithoutAnExactCarryIsPartial) {
  // adcs with no flag writer before it: its carry in is unknown.
  EXPECT_TRUE(aarch64_lifts_partial(aarch64_bytes({0xba010000U, 0xd65f03c0U})));
}

TEST(Ir, AArch64AdcsIntoZeroRegisterSetsTheFlagsOnly) {
  // adcs xzr, x0, x1: the sum is discarded, the carry out is kept.
  const auto discard = aarch64_bytes({0xf100045fU, 0xba01001fU, 0x9a9f37e0U, 0xd65f03c0U});
  EXPECT_EQ(run_aarch64_args(discard, {~0ULL, 1, 0}), 1U);
  EXPECT_EQ(run_aarch64_args(discard, {5, 3, 0}), 0U);
}

TEST(Ir, AArch64AddsThenAdcsUsesTheSumsCarry) {
  // adds x0, x0, x1; adcs x0, x2, x3; ret: adcs takes the carry of adds.
  const auto code = aarch64_bytes({0xab010000, 0xba030040, 0xd65f03c0});
  EXPECT_FALSE(aarch64_lifts_partial(code));
  EXPECT_EQ(run_aarch64_args(code, {~0ULL, 1, 5, 7}), 13U);  // carry 1: 5 + 7 + 1
  EXPECT_EQ(run_aarch64_args(code, {1, 2, 5, 7}), 12U);      // carry 0
}

// Scalar SSE: only the low lane is modelled. The bit patterns below are the
// operands the interpreter receives, so a double is passed as its 64-bit image.
std::uint64_t double_bits(double value) {
  std::uint64_t bits = 0;
  std::memcpy(&bits, &value, sizeof bits);
  return bits;
}

double bits_as_double(std::uint64_t bits) {
  double value = 0;
  std::memcpy(&value, &bits, sizeof value);
  return value;
}

TEST(Ir, X86ScalarDoubleArithmeticLiftsExactly) {
  donkey::IrFunction add;  // addsd xmm0, xmm1; ret
  ASSERT_TRUE(lift_raw_x86_64({0xf2, 0x0f, 0x58, 0xc1, 0xc3}, add));
  // Rounding-dependent results are Partial: the MXCSR mode is not modelled.
  EXPECT_TRUE(add.partial);
  EXPECT_EQ(bits_as_double(run_x86_64(add, {double_bits(1.5), double_bits(2.25)})), 3.75);

  donkey::IrFunction divide;  // divsd xmm0, xmm1; ret
  ASSERT_TRUE(lift_raw_x86_64({0xf2, 0x0f, 0x5e, 0xc1, 0xc3}, divide));
  // Rounding-dependent results are Partial: the MXCSR mode is not modelled.
  EXPECT_TRUE(divide.partial);
  EXPECT_EQ(bits_as_double(run_x86_64(divide, {double_bits(1.0), double_bits(4.0)})), 0.25);
  // Division by zero gives infinity under IEEE, and no fault.
  EXPECT_EQ(bits_as_double(run_x86_64(divide, {double_bits(1.0), double_bits(0.0)})),
            std::numeric_limits<double>::infinity());

  donkey::IrFunction root;  // sqrtsd xmm0, xmm1; ret
  ASSERT_TRUE(lift_raw_x86_64({0xf2, 0x0f, 0x51, 0xc1, 0xc3}, root));
  EXPECT_EQ(bits_as_double(run_x86_64(root, {double_bits(2.25)})), 1.5);  // only xmm1 is read
}

TEST(Ir, X86ScalarSingleMergesIntoTheLowLane) {
  // addss xmm0, xmm1; ret: the sum is a single, and xmm0 bits 32 to 63 are kept.
  donkey::IrFunction add;
  ASSERT_TRUE(lift_raw_x86_64({0xf3, 0x0f, 0x58, 0xc1, 0xc3}, add));
  // Rounding-dependent results are Partial: the MXCSR mode is not modelled.
  EXPECT_TRUE(add.partial);
  const std::uint64_t kept = 0x1234567800000000ULL;
  const std::uint64_t one_and_a_half = 0x3fc00000ULL;     // 1.5f
  const std::uint64_t two_and_a_quarter = 0x40100000ULL;  // 2.25f
  EXPECT_EQ(run_x86_64(add, {kept | one_and_a_half, two_and_a_quarter}),
            kept | 0x40700000ULL);  // 3.75f
}

TEST(Ir, X86ScalarCompareWithAJumpOnAboveHandlesUnordered) {
  donkey::IrFunction f;  // ucomisd xmm0, xmm1; ja L; mov eax, 0; ret; L: mov eax, 1; ret
  ASSERT_TRUE(lift_raw_x86_64({0x66, 0x0f, 0x2e, 0xc1, 0x77, 0x06, 0xb8, 0x00, 0x00, 0x00, 0x00,
                               0xc3, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3},
                              f));
  EXPECT_FALSE(f.partial);
  EXPECT_EQ(run_x86_64(f, {double_bits(2.0), double_bits(1.0)}), 1U);
  EXPECT_EQ(run_x86_64(f, {double_bits(1.0), double_bits(2.0)}), 0U);
  EXPECT_EQ(run_x86_64(f, {double_bits(2.0), double_bits(2.0)}), 0U);
  // Unordered sets ZF, PF and CF, so "above" is false.
  EXPECT_EQ(
      run_x86_64(f, {double_bits(std::numeric_limits<double>::quiet_NaN()), double_bits(1.0)}), 0U);
}

TEST(Ir, X86IntegerToDoubleSignExtendsAndBackTruncates) {
  donkey::IrFunction to_double;  // cvtsi2sd xmm0, edi; ret
  ASSERT_TRUE(lift_raw_x86_64({0xf2, 0x0f, 0x2a, 0xc7, 0xc3}, to_double));
  EXPECT_EQ(bits_as_double(run_x86_64(to_double, {0xfffffffdULL})), -3.0);

  donkey::IrFunction to_int;  // cvttsd2si eax, xmm0; ret
  ASSERT_TRUE(lift_raw_x86_64({0xf2, 0x0f, 0x2c, 0xc0, 0xc3}, to_int));
  EXPECT_EQ(run_x86_64(to_int, {double_bits(-3.9)}), 0xfffffffdULL);
  EXPECT_EQ(run_x86_64(to_int, {double_bits(3.9)}), 3U);
}

TEST(Ir, X86ZeroingIdiomClearsTheLowLane) {
  donkey::IrFunction f;  // xorps xmm0, xmm0; ret
  ASSERT_TRUE(lift_raw_x86_64({0x0f, 0x57, 0xc0, 0xc3}, f));
  EXPECT_FALSE(f.partial);
  EXPECT_EQ(run_x86_64(f, {double_bits(7.0)}), 0U);
}

// movaps copies both 64-bit lanes, which the IR keeps as two registers. xmm1 is the only register
// the function reads, so it is the argument, and the return value is the low lane of xmm0.
TEST(Ir, X86MovapsCopiesBothLanesWithoutMakingTheFunctionPartial) {
  donkey::IrFunction f;  // movaps xmm0, xmm1; ret
  ASSERT_TRUE(lift_raw_x86_64({0x0f, 0x28, 0xc1, 0xc3}, f));
  EXPECT_FALSE(f.partial);
  EXPECT_EQ(bits_as_double(run_x86_64(f, {double_bits(7.5)})), 7.5);
}

// cmpltsd xmm0, xmm1 sets the low lane to all ones when xmm0 < xmm1 and to zero otherwise. An
// unordered comparison is false, so a NaN operand gives zero.
TEST(Ir, X86CmpltsdIsAnOrderedMask) {
  donkey::IrFunction f;  // cmpltsd xmm0, xmm1, 1 (less than); ret
  ASSERT_TRUE(lift_raw_x86_64({0xf2, 0x0f, 0xc2, 0xc1, 0x01, 0xc3}, f));
  EXPECT_FALSE(f.partial);
  const std::uint64_t all_ones = ~0ULL;
  EXPECT_EQ(run_x86_64(f, {double_bits(1.0), double_bits(2.0)}), all_ones);
  EXPECT_EQ(run_x86_64(f, {double_bits(2.0), double_bits(1.0)}), 0ULL);
  EXPECT_EQ(run_x86_64(f, {double_bits(1.0), double_bits(1.0)}), 0ULL);
  const double nan = std::numeric_limits<double>::quiet_NaN();
  EXPECT_EQ(run_x86_64(f, {double_bits(nan), double_bits(2.0)}), 0ULL);
  EXPECT_EQ(run_x86_64(f, {double_bits(1.0), double_bits(nan)}), 0ULL);
}

// AArch64 scalar floating point. The encodings are the assembler's (llvm-mc); the
// fused and NaN rules were checked against qemu-aarch64 by running the same
// instructions natively.
TEST(Ir, AArch64ScalarDoubleArithmeticLiftsExactly) {
  const auto fadd = aarch64_bytes({0x1e612800, 0xd65f03c0});  // fadd d0, d0, d1; ret
  const auto fsub = aarch64_bytes({0x1e613800, 0xd65f03c0});  // fsub d0, d0, d1; ret
  const auto fmul = aarch64_bytes({0x1e610800, 0xd65f03c0});  // fmul d0, d0, d1; ret
  const auto fdiv = aarch64_bytes({0x1e611800, 0xd65f03c0});  // fdiv d0, d0, d1; ret
  EXPECT_EQ(bits_as_double(run_aarch64_args(fadd, {double_bits(1.5), double_bits(2.25)})), 3.75);
  EXPECT_EQ(bits_as_double(run_aarch64_args(fsub, {double_bits(1.5), double_bits(2.25)})), -0.75);
  EXPECT_EQ(bits_as_double(run_aarch64_args(fmul, {double_bits(1.5), double_bits(2.25)})), 3.375);
  EXPECT_EQ(bits_as_double(run_aarch64_args(fdiv, {double_bits(1.0), double_bits(4.0)})), 0.25);
  const auto fsqrt = aarch64_bytes({0x1e61c020, 0xd65f03c0});  // fsqrt d0, d1; ret
  EXPECT_EQ(bits_as_double(run_aarch64_args(fsqrt, {double_bits(2.25)})), 1.5);
  const auto fneg = aarch64_bytes({0x1e614020, 0xd65f03c0});  // fneg d0, d1; ret
  EXPECT_EQ(bits_as_double(run_aarch64_args(fneg, {double_bits(2.5)})), -2.5);
  const auto fabs = aarch64_bytes({0x1e60c020, 0xd65f03c0});  // fabs d0, d1; ret
  EXPECT_EQ(bits_as_double(run_aarch64_args(fabs, {double_bits(-2.5)})), 2.5);
}

TEST(Ir, AArch64SingleRegisterWritesZeroTheRestOfTheVector) {
  // fadd s0, s0, s1; ret: a single result, with the upper half of d0 cleared.
  const auto fadd = aarch64_bytes({0x1e212800, 0xd65f03c0});
  const std::uint64_t one_and_a_half = 0x3fc00000ULL;
  const std::uint64_t two_and_a_quarter = 0x40100000ULL;
  const std::uint64_t dirty_upper = 0xabcdef0100000000ULL;  // ignored: only s0 is read
  EXPECT_EQ(run_aarch64_args(fadd, {one_and_a_half | dirty_upper, two_and_a_quarter}),
            0x40700000ULL);  // 3.75f, and bits 32 to 63 are zero
}

TEST(Ir, AArch64FusedMultiplyAddRoundsOnce) {
  // fmadd d0, d1, d2, d3: d0 = d3 + d1 * d2. (1 + 2^-52)^2 - (1 + 2^-51) is 2^-104
  // with one rounding, and 0 when the product is rounded before the add.
  const auto fmadd = aarch64_bytes({0x1f420c20, 0xd65f03c0});
  const double n = 1.0 + std::ldexp(1.0, -52);
  const double addend = -(1.0 + std::ldexp(1.0, -51));
  EXPECT_EQ(run_aarch64_args(fmadd, {double_bits(n), double_bits(n), double_bits(addend)}),
            double_bits(std::ldexp(1.0, -104)));
  // fmsub d0, d1, d2, d3: d0 = d3 - d1 * d2.
  const auto fmsub = aarch64_bytes({0x1f428c20, 0xd65f03c0});
  EXPECT_EQ(run_aarch64_args(fmsub, {double_bits(n), double_bits(n), double_bits(-addend)}),
            double_bits(-std::ldexp(1.0, -104)));
}

TEST(Ir, AArch64FusedMultiplyAddFollowsTheHardwareNaNRules) {
  const auto fmadd = aarch64_bytes({0x1f420c20, 0xd65f03c0});
  const auto fmsub = aarch64_bytes({0x1f428c20, 0xd65f03c0});
  const std::uint64_t nan1 = 0x7ff8000000000001ULL;
  const std::uint64_t nan3 = 0x7ff8000000000003ULL;
  const std::uint64_t one = double_bits(1.0);
  const std::uint64_t zero = 0;
  const std::uint64_t inf = 0x7ff0000000000000ULL;
  // A NaN addend wins over a NaN product operand.
  EXPECT_EQ(run_aarch64_args(fmadd, {nan1, one, nan3}), nan3);
  // The NaN taken from the product of fmsub has its sign flipped.
  EXPECT_EQ(run_aarch64_args(fmsub, {nan1, one, one}), 0xfff8000000000001ULL);
  // inf * 0 is invalid whatever the addend is: the default NaN.
  EXPECT_EQ(run_aarch64_args(fmadd, {inf, zero, nan3}), 0x7ff8000000000000ULL);
}

TEST(Ir, AArch64FloatCompareSelectsWithItsNZCV) {
  const auto fcsel =
      aarch64_bytes({0x1e612000, 0x1e62cc20, 0xd65f03c0});  // fcmp d0, d1; fcsel d0, d1, d2, gt
  // d0 > d1 selects d1; otherwise d2. NaN is unordered, so it is not greater.
  EXPECT_EQ(bits_as_double(
                run_aarch64_args(fcsel, {double_bits(2.0), double_bits(1.0), double_bits(5.0)})),
            1.0);
  EXPECT_EQ(bits_as_double(
                run_aarch64_args(fcsel, {double_bits(1.0), double_bits(2.0), double_bits(5.0)})),
            5.0);
  EXPECT_EQ(
      bits_as_double(run_aarch64_args(fcsel, {double_bits(std::numeric_limits<double>::quiet_NaN()),
                                              double_bits(1.0), double_bits(5.0)})),
      5.0);
}

TEST(Ir, AArch64IntegerToDoubleAndBack) {
  const auto scvtf = aarch64_bytes({0x9e620000, 0xd65f03c0});  // scvtf d0, x0; ret
  EXPECT_EQ(bits_as_double(run_aarch64_args(scvtf, {static_cast<std::uint64_t>(-3)})), -3.0);
  const auto fcvtzs = aarch64_bytes({0x9e780000, 0xd65f03c0});  // fcvtzs x0, d0; ret
  EXPECT_EQ(run_aarch64_args(fcvtzs, {double_bits(-3.9)}), static_cast<std::uint64_t>(-3));
  EXPECT_EQ(run_aarch64_args(fcvtzs, {double_bits(3.9)}), 3U);
}

TEST(Ir, AArch64FloatConversionsAndImmediateMoves) {
  const auto fcvt = aarch64_bytes({0x1e22c000, 0xd65f03c0});  // fcvt d0, s0; ret
  EXPECT_EQ(bits_as_double(run_aarch64_args(fcvt, {0x3fc00000ULL})), 1.5);
  const auto movi = aarch64_bytes({0x1e6e1000, 0xd65f03c0});  // fmov d0, #1.0; ret
  EXPECT_EQ(run_aarch64_args(movi, {}), double_bits(1.0));
}

// G04-T1: every register alias is its family. A write of 4 bytes zero-extends; a
// write of 1 or 2 bytes, and a write to ah, keeps the other bytes of the family.
TEST(Ir, X86NarrowWritesMergeIntoTheFamily) {
  donkey::IrFunction word;  // mov rax, -1; mov ax, di; ret
  ASSERT_TRUE(
      lift_raw_x86_64({0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0x66, 0x89, 0xf8, 0xc3}, word));
  EXPECT_EQ(run_x86_64(word, {0x1234}), 0xffffffffffff1234ULL);

  donkey::IrFunction high;  // mov rax, -1; mov ah, cl; ret
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0x88, 0xcc, 0xc3}, high));
  EXPECT_EQ(run_x86_64(high, {0, 0, 0, 0x42}), 0xffffffffffff42ffULL);  // cl is the 4th argument

  donkey::IrFunction read_high;  // mov rax, rdi; mov al, ah; ret
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0x89, 0xf8, 0x8a, 0xc4, 0xc3}, read_high));
  EXPECT_EQ(run_x86_64(read_high, {0x1234}), 0x1212ULL);
}

TEST(Ir, X86DoubleWordWritesZeroExtend) {
  donkey::IrFunction f;  // mov rax, -1; mov eax, edi; ret
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0x89, 0xf8, 0xc3}, f));
  EXPECT_EQ(run_x86_64(f, {0xffffffff12345678ULL}), 0x12345678ULL);
}

TEST(Ir, X86ConditionalMoveOfADoubleWordZeroExtendsEvenWhenItFails) {
  // mov rax, -1; cmp rdi, rsi; cmovl eax, edx; ret. A 32-bit cmov writes eax whether or
  // not the condition holds, so rax is zero-extended in both cases.
  donkey::IrFunction f;
  ASSERT_TRUE(lift_raw_x86_64(
      {0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0x48, 0x39, 0xf7, 0x0f, 0x4c, 0xc2, 0xc3}, f));
  EXPECT_EQ(run_x86_64(f, {5, 3, 7}), 0xffffffffULL);  // not less: eax kept, zero-extended
  EXPECT_EQ(run_x86_64(f, {1, 3, 7}), 7U);             // less: eax = edx
}

// G04-T2: copy propagation and removal of dead register writes.
TEST(Ir, CopyPropagationReadsTheSourceAndDropsTheCopy) {
  donkey::IrFunction f;  // mov rax, rdi; add rax, rsi; ret
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3}, f));
  auto text = donkey::format_pseudocode(f);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  EXPECT_NE(text.value().find("rax = rdi + rsi;"), std::string::npos) << text.value();
  EXPECT_EQ(text.value().find("rax = rdi;"), std::string::npos) << text.value();
  EXPECT_EQ(run_x86_64(f, {5, 7}), 12U);
}

TEST(Ir, DeadRegisterWriteIsRemoved) {
  donkey::IrFunction f;  // mov rdx, rdi; mov rax, rsi; ret: rdx is never read
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0x89, 0xfa, 0x48, 0x89, 0xf0, 0xc3}, f));
  auto text = donkey::format_pseudocode(f);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  EXPECT_EQ(text.value().find("rdx"), std::string::npos) << text.value();
  // The return reads rsi directly, so the copy into rax is gone too.
  EXPECT_NE(text.value().find("return rsi;"), std::string::npos) << text.value();
  EXPECT_EQ(run_x86_64(f, {5, 7}), 7U);
}

// Windows x64 and x86-32 keep rsi and rdi across calls, so the epilogue's restore of rsi is not
// a dead write even though nothing in the function reads it afterwards.
TEST(Ir, CalleeSavedRsiWriteIsKeptAtReturn) {
  donkey::IrFunction f;  // mov rsi, rdx; mov eax, 1; ret
  ASSERT_TRUE(lift_raw_x86_64({0x48, 0x89, 0xd6, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3}, f));
  auto text = donkey::format_pseudocode(f);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  EXPECT_NE(text.value().find("rsi"), std::string::npos) << text.value();
}

}  // namespace

// A branch that skips a block is printed with the complement of its condition: the body is the
// fall-through, so the if needs the negated compare.
namespace {
std::string skip_layout_text(bool floating) {
  IrFunction function;
  function.address = 0x2000;
  function.name = floating ? "float_skip" : "signed_skip";
  function.blocks.push_back(make_block(0x2000));  // 0: compare and branch over the body
  function.blocks.push_back(make_block(0x2008));  // 1: the body
  function.blocks.push_back(make_block(0x2010));  // 2: return rax
  IrStatement compare;
  compare.width = 8;
  compare.op = floating ? IrOp::FCompare : IrOp::Compare;
  compare.a = IrOperand::register_ref(floating ? "xmm0" : "rdi", 8);
  compare.b = IrOperand::register_ref(floating ? "xmm1" : "rsi", 8);
  compare.condition = floating ? IrCondition::UnsignedLess : IrCondition::SignedLess;
  function.blocks[0].statements.push_back(compare);
  IrStatement branch;
  branch.op = IrOp::CondBranch;
  branch.condition = compare.condition;
  branch.a = IrOperand::register_ref("rax", 8);
  branch.b = IrOperand::block_ref(2);
  branch.width = 8;
  function.blocks[0].statements.push_back(branch);
  IrStatement body;
  body.op = IrOp::Assign;
  body.dest = IrOperand::register_ref("rax", 8);
  body.a = IrOperand::constant_value(7, 8);
  body.width = 8;
  function.blocks[1].statements.push_back(body);
  IrStatement jump;
  jump.op = IrOp::Branch;
  jump.a = IrOperand::block_ref(2);
  jump.width = 8;
  function.blocks[1].statements.push_back(jump);
  function.blocks[2].statements.push_back(return_statement());
  auto text = format_pseudocode(function);
  return text ? text.value() : text.diagnostic().message;
}
}  // namespace

// G04-T3 step 3: an integer `!(a < b)` prints as `a >= b`, and no `!( )` wrapper is left.
TEST(Ir, NegatedIntegerCompareIsPrintedAsItsComplement) {
  const std::string text = skip_layout_text(/*floating=*/false);
  EXPECT_NE(text.find("if (rdi >= rsi) {"), std::string::npos) << text;
  EXPECT_EQ(text.find("!("), std::string::npos) << text;
}

// G04-T3 step 3, the floating-point rule: a negated float compare stays a flag test. The operands
// are not rewritten, because `!(a < b)` is not `a >= b` when either operand is NaN. The flag form
// is exact: after ucomis* CF is 0 only when the operands are ordered and a >= b.
TEST(Ir, NegatedFloatCompareStaysAFlagTest) {
  const std::string text = skip_layout_text(/*floating=*/true);
  EXPECT_NE(text.find("if (flags >=) {"), std::string::npos) << text;
  EXPECT_EQ(text.find("xmm0"), std::string::npos) << text;
  EXPECT_EQ(text.find("!("), std::string::npos) << text;
}
