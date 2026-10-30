#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/ir/abi.h"
#include "donkey/ir/ir.h"
#include "donkey/ir/lift.h"

namespace {

using donkey::Architecture;
using donkey::BasicBlock;
using donkey::BinaryImage;
using donkey::IrBlock;
using donkey::IrCondition;
using donkey::IrFunction;
using donkey::IrOp;
using donkey::IrOperand;
using donkey::IrOperandKind;
using donkey::IrParameter;
using donkey::IrStatement;
using donkey::Section;

std::string fixture_path(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/binaries/" + name;
}

std::vector<std::byte> read_bytes(const std::string& path) {
  std::ifstream file(path, std::ios::binary);
  const std::vector<char> chars((std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());
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

TEST(Ir, VerifierRejectsBadSignatureWidth) {
  IrFunction function = single_block_function();
  function.parameters.push_back(IrParameter{"a0", 3, "rdi"});
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
  EXPECT_NE(code.find("eax = (u32)al;"), std::string::npos) << code;
  EXPECT_NE(code.find("rcx = (u64)al;"), std::string::npos) << code;
  EXPECT_NE(code.find("edx = (s32)al;"), std::string::npos) << code;
  EXPECT_NE(code.find("rax = (s64)eax;"), std::string::npos) << code;
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
  EXPECT_NE(code.find("eax = 0x1;"), std::string::npos) << code;
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

  auto lifted = donkey::lift_function(image, analyzed.value(), analyzed.value().functions.front());
  ASSERT_TRUE(lifted.has_value()) << lifted.diagnostic().message;
  auto verified = donkey::verify_ir(lifted.value());
  ASSERT_TRUE(verified.has_value())
      << verified.diagnostic().code << ": " << verified.diagnostic().message;

  auto text = donkey::format_pseudocode(lifted.value());
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  const std::string& code = text.value();
  // Pre-index stp: store at [sp, #-0x10]!, then sp -= 0x10. Capstone reports
  // x29/x30 by their ABI aliases fp/lr.
  EXPECT_NE(code.find("*(u64 *)(sp - 0x10) = fp;"), std::string::npos) << code;
  EXPECT_NE(code.find("*(u64 *)(sp - 0x8) = lr;"), std::string::npos) << code;
  EXPECT_NE(code.find("sp = sp - 0x10;"), std::string::npos) << code;
  // mov x29, sp
  EXPECT_NE(code.find("fp = sp;"), std::string::npos) << code;
  // movz/movk: movz sets 0x1234, movk clears then merges 0xabcd into bits 16..31.
  EXPECT_NE(code.find("x0 = 0x1234;"), std::string::npos) << code;
  EXPECT_NE(code.find("x0 = x0 | 0xabcd0000;"), std::string::npos) << code;
  // Post-index ldp: access [sp] and [sp + 0x8], then sp += 0x10.
  EXPECT_NE(code.find("fp = *(u64 *)(sp);"), std::string::npos) << code;
  EXPECT_NE(code.find("lr = *(u64 *)(sp + 0x8);"), std::string::npos) << code;
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
  auto lifted = donkey::lift_function(loaded.value().image, analyzed.value(), *entry);
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

}  // namespace
