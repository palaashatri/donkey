// libFuzzer entry point for the IR verifier and pseudocode printer. Bytes are
// deterministically shaped into an IR function; the harness asserts that the
// verifier never accepts malformed IR and the printer never renders anything
// the verifier rejects.
//
// Build: cmake --preset fuzz-macos
// Run:   build/fuzz-macos/fuzz/fuzz_ir tests/fuzz/corpus/ir

#include <cstddef>
#include <cstdint>
#include <string>

#include "donkey/ir/ir.h"

namespace {

constexpr std::uint8_t kWidths[] = {1, 2, 4, 8};
constexpr const char* kRegisters[] = {"rax", "rbx", "rcx", "rdx", "r8", "rsp"};

std::uint8_t next_byte(const std::uint8_t* data, std::size_t size, std::size_t& cursor) {
  if (size == 0) {
    return 0;
  }
  const std::uint8_t value = data[cursor % size];
  ++cursor;
  return value;
}

donkey::IrOperand operand(const std::uint8_t* data, std::size_t size, std::size_t& cursor,
                          std::uint8_t width, std::uint64_t constant, bool allow_block,
                          std::uint32_t blocks) {
  const std::uint8_t tag = next_byte(data, size, cursor) % (allow_block ? 5 : 4);
  switch (tag) {
    case 0:
      return donkey::IrOperand::constant_value(constant, width);
    case 1:
      return donkey::IrOperand::register_ref(
          kRegisters[next_byte(data, size, cursor) % (sizeof(kRegisters) / sizeof(kRegisters[0]))],
          width);
    case 2: {
      donkey::IrOperand memory;
      memory.kind = donkey::IrOperandKind::Memory;
      memory.reg =
          kRegisters[next_byte(data, size, cursor) % (sizeof(kRegisters) / sizeof(kRegisters[0]))];
      memory.index =
          kRegisters[next_byte(data, size, cursor) % (sizeof(kRegisters) / sizeof(kRegisters[0]))];
      memory.scale = static_cast<std::int32_t>(1U << (next_byte(data, size, cursor) % 4));
      memory.constant = constant;
      memory.width = width;
      return memory;
    }
    case 3:
      return donkey::IrOperand::none();
    default:
      return donkey::IrOperand::block_ref(blocks == 0 ? 0 : next_byte(data, size, cursor) % blocks);
  }
}

donkey::IrCondition condition(const std::uint8_t* data, std::size_t size, std::size_t& cursor) {
  constexpr donkey::IrCondition kConditions[] = {
      donkey::IrCondition::Equal,        donkey::IrCondition::NotEqual,
      donkey::IrCondition::UnsignedLess, donkey::IrCondition::SignedGreater,
      donkey::IrCondition::Zero,         donkey::IrCondition::NonZero,
  };
  return kConditions[next_byte(data, size, cursor) %
                     (sizeof(kConditions) / sizeof(kConditions[0]))];
}

donkey::IrStatement statement(const std::uint8_t* data, std::size_t size, std::size_t& cursor,
                              std::uint32_t blocks) {
  donkey::IrStatement out;
  const std::uint8_t width = kWidths[next_byte(data, size, cursor) % 4];
  const std::uint64_t constant = next_byte(data, size, cursor);
  const std::uint8_t op_tag = next_byte(data, size, cursor) % 9;
  out.width = width;
  switch (op_tag) {
    case 0:
      out.op = donkey::IrOp::Assign;
      out.dest = donkey::IrOperand::register_ref("rax", width);
      out.a = operand(data, size, cursor, width, constant, false, blocks);
      break;
    case 1:
      out.op = donkey::IrOp::Add;
      out.dest = donkey::IrOperand::register_ref("rax", width);
      out.a = operand(data, size, cursor, width, constant, false, blocks);
      out.b = operand(data, size, cursor, width, constant, false, blocks);
      break;
    case 2:
      out.op = donkey::IrOp::ZeroExtend;
      out.dest = donkey::IrOperand::register_ref("rax", width);
      out.a = donkey::IrOperand::register_ref("al", 1);
      out.width = 8;
      break;
    case 3:
      out.op = donkey::IrOp::Load;
      out.dest = donkey::IrOperand::register_ref("rax", width);
      out.a = operand(data, size, cursor, width, constant, false, blocks);
      break;
    case 4:
      out.op = donkey::IrOp::Store;
      out.a = donkey::IrOperand::register_ref("rsp", width);
      out.b = operand(data, size, cursor, width, constant, false, blocks);
      break;
    case 5:
      out.op = donkey::IrOp::Compare;
      out.condition = condition(data, size, cursor);
      out.a = donkey::IrOperand::register_ref("rax", width);
      out.b = operand(data, size, cursor, width, constant, false, blocks);
      break;
    case 6:
      out.op = donkey::IrOp::Test;
      out.a = donkey::IrOperand::register_ref("rax", width);
      out.b = donkey::IrOperand::register_ref("rbx", width);
      break;
    case 7:
      out.op = donkey::IrOp::Call;
      out.a = donkey::IrOperand::constant_value(constant, 8);
      break;
    default:
      out.op = donkey::IrOp::Nop;
      break;
  }
  return out;
}

void terminator(donkey::IrBlock& block, const std::uint8_t* data, std::size_t size,
                std::size_t& cursor, std::uint32_t blocks, std::uint32_t block_index) {
  const std::uint8_t tag = next_byte(data, size, cursor) % 4;
  donkey::IrStatement out;
  out.width = 8;
  switch (tag) {
    case 0:
      out.op = donkey::IrOp::Branch;
      out.a =
          donkey::IrOperand::block_ref(blocks == 0 ? 0 : next_byte(data, size, cursor) % blocks);
      break;
    case 1:
      out.op = donkey::IrOp::CondBranch;
      out.condition = condition(data, size, cursor);
      out.a = donkey::IrOperand::register_ref("rax", 8);
      out.b =
          donkey::IrOperand::block_ref(blocks == 0 ? 0 : next_byte(data, size, cursor) % blocks);
      break;
    case 2:
      out.op = donkey::IrOp::Unsupported;
      out.text = "fuzz";
      break;
    default:
      out.op = donkey::IrOp::Return;
      out.a = donkey::IrOperand::register_ref("rax", 8);
      break;
  }
  (void)block_index;
  block.statements.push_back(std::move(out));
}

donkey::IrFunction build(const std::uint8_t* data, std::size_t size) {
  donkey::IrFunction function;
  function.address = 0x1000;
  function.name = "fuzz";
  std::size_t cursor = 0;
  const std::uint32_t blocks = 1 + next_byte(data, size, cursor) % 4;
  for (std::uint32_t block_index = 0; block_index < blocks; ++block_index) {
    donkey::IrBlock block;
    block.address = 0x1000 + block_index * 0x100;
    const std::uint32_t count = next_byte(data, size, cursor) % 6;
    for (std::uint32_t i = 0; i < count; ++i) {
      block.statements.push_back(statement(data, size, cursor, blocks));
    }
    terminator(block, data, size, cursor, blocks, block_index);
    function.blocks.push_back(std::move(block));
  }
  return function;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  donkey::IrFunction function = build(data, size);
  auto verified = donkey::verify_ir(function);
  auto text = donkey::format_pseudocode(function);
  if (verified.has_value() != text.has_value()) {
    // The printer must agree with the verifier, in both directions.
    __builtin_trap();
  }
  return 0;
}
