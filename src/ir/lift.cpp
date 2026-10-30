#include "donkey/ir/lift.h"

#include "donkey/ir/abi.h"

#include <algorithm>
#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>

#include "donkey/analysis/cfg.h"
#include "lift_internal.h"

namespace donkey {
namespace {

using namespace donkey;

constexpr std::uint8_t kPointerWidth = 8;

std::uint8_t register_width(const std::string& name) {
  static const std::unordered_map<std::string, std::uint8_t> kWidths = {
      {"rax", 8},  {"rbx", 8},  {"rcx", 8},  {"rdx", 8},  {"rsi", 8}, {"rdi", 8},  {"rbp", 8},
      {"rsp", 8},  {"r8", 8},   {"r9", 8},   {"r10", 8},  {"r11", 8}, {"r12", 8},  {"r13", 8},
      {"r14", 8},  {"r15", 8},  {"eax", 4},  {"ebx", 4},  {"ecx", 4}, {"edx", 4},  {"esi", 4},
      {"edi", 4},  {"ebp", 4},  {"esp", 4},  {"r8d", 4},  {"r9d", 4}, {"r10d", 4}, {"r11d", 4},
      {"r12d", 4}, {"r13d", 4}, {"r14d", 4}, {"r15d", 4}, {"ax", 2},  {"bx", 2},   {"cx", 2},
      {"dx", 2},   {"si", 2},   {"di", 2},   {"bp", 2},   {"sp", 2},  {"al", 1},   {"bl", 1},
      {"cl", 1},   {"dl", 1},   {"ah", 1},   {"bh", 1},   {"ch", 1},  {"dh", 1},   {"sil", 1},
      {"dil", 1},  {"bpl", 1},  {"spl", 1},  {"r8b", 1},  {"r9b", 1}, {"r10b", 1}, {"r11b", 1},
      {"r12b", 1}, {"r13b", 1}, {"r14b", 1}, {"r15b", 1}, {"x0", 8},  {"x1", 8},   {"x2", 8},
      {"x3", 8},   {"x4", 8},   {"x5", 8},   {"x6", 8},   {"x7", 8},  {"x8", 8},   {"x9", 8},
      {"x10", 8},  {"x11", 8},  {"x12", 8},  {"x13", 8},  {"x14", 8}, {"x15", 8},  {"x16", 8},
      {"x17", 8},  {"x18", 8},  {"x19", 8},  {"x20", 8},  {"x21", 8}, {"x22", 8},  {"x23", 8},
      {"x24", 8},  {"x25", 8},  {"x26", 8},  {"x27", 8},  {"x28", 8}, {"x29", 8},  {"x30", 8},
      {"w0", 4},   {"w1", 4},   {"w2", 4},   {"w3", 4},   {"w4", 4},  {"w5", 4},   {"w6", 4},
      {"w7", 4},   {"w8", 4},   {"w9", 4},   {"w10", 4},  {"w11", 4}, {"w12", 4},  {"w13", 4},
      {"w14", 4},  {"w15", 4},  {"w16", 4},  {"w17", 4},  {"w18", 4}, {"w19", 4},  {"w20", 4},
      {"w21", 4},  {"w22", 4},  {"w23", 4},  {"w24", 4},  {"w25", 4}, {"w26", 4},  {"w27", 4},
      {"w28", 4},  {"w29", 4},  {"w30", 4},  {"sp", 8},   {"wsp", 4}, {"fp", 8},   {"lr", 8},
      {"pc", 8},   {"xzr", 8},  {"wzr", 4},
  };
  const auto found = kWidths.find(name);
  return found == kWidths.end() ? 0 : found->second;
}

std::uint8_t operand_width(const Operand& operand) {
  if (operand.size != 0) {
    return operand.size;
  }
  if (operand.kind == OperandKind::Register) {
    return register_width(operand.reg);
  }
  return 0;
}

IrOperand memory_operand(const Operand& operand, const Instruction& instruction) {
  IrOperand result;
  result.kind = IrOperandKind::Memory;
  result.width = operand_width(operand);
  result.reg = operand.memory.base;
  result.index = operand.memory.index;
  result.scale = operand.memory.scale == 0 ? 1 : operand.memory.scale;
  if (result.reg == "rip") {
    result.reg.clear();
    const std::uint64_t resolved = instruction.address + instruction.length +
                                   static_cast<std::uint64_t>(operand.memory.displacement);
    result.constant = resolved;
  } else {
    result.constant = static_cast<std::uint64_t>(operand.memory.displacement);
  }
  return result;
}

IrOperand to_ir_operand(const Operand& operand, const Instruction& instruction) {
  switch (operand.kind) {
    case OperandKind::Register:
      return IrOperand::register_ref(operand.reg, register_width(operand.reg));
    case OperandKind::Immediate:
      return IrOperand::constant_value(
          static_cast<std::uint64_t>(operand.immediate),
          operand_width(operand) == 0 ? kPointerWidth : operand_width(operand));
    case OperandKind::Memory:
      return memory_operand(operand, instruction);
    case OperandKind::Unknown:
      break;
  }
  return IrOperand::none();
}

IrCondition branch_condition(const std::string& mnemonic) {
  if (mnemonic == "jz" || mnemonic == "je") {
    return IrCondition::Zero;
  }
  if (mnemonic == "jnz" || mnemonic == "jne") {
    return IrCondition::NonZero;
  }
  if (mnemonic == "jb" || mnemonic == "jc" || mnemonic == "jnae") {
    return IrCondition::UnsignedLess;
  }
  if (mnemonic == "jae" || mnemonic == "jnb" || mnemonic == "jnc") {
    return IrCondition::UnsignedGreaterEqual;
  }
  if (mnemonic == "ja" || mnemonic == "jnbe") {
    return IrCondition::UnsignedGreater;
  }
  if (mnemonic == "jbe" || mnemonic == "jna") {
    return IrCondition::UnsignedLessEqual;
  }
  if (mnemonic == "jl" || mnemonic == "jnge") {
    return IrCondition::SignedLess;
  }
  if (mnemonic == "jge" || mnemonic == "jnl") {
    return IrCondition::SignedGreaterEqual;
  }
  if (mnemonic == "jg" || mnemonic == "jnle") {
    return IrCondition::SignedGreater;
  }
  if (mnemonic == "jle" || mnemonic == "jng") {
    return IrCondition::SignedLessEqual;
  }
  return IrCondition::None;
}

bool is_bitwise_or_arithmetic(const std::string& mnemonic) {
  return mnemonic == "add" || mnemonic == "sub" || mnemonic == "and" || mnemonic == "or" ||
         mnemonic == "xor" || mnemonic == "shl" || mnemonic == "sal" || mnemonic == "shr" ||
         mnemonic == "sar" || mnemonic == "imul";
}

IrOp arithmetic_op(const std::string& mnemonic) {
  if (mnemonic == "add" || mnemonic == "inc") {
    return IrOp::Add;
  }
  if (mnemonic == "sub" || mnemonic == "dec") {
    return IrOp::Sub;
  }
  if (mnemonic == "and") {
    return IrOp::And;
  }
  if (mnemonic == "or") {
    return IrOp::Or;
  }
  if (mnemonic == "xor") {
    return IrOp::Xor;
  }
  if (mnemonic == "shl" || mnemonic == "sal") {
    return IrOp::Shl;
  }
  if (mnemonic == "shr") {
    return IrOp::Shr;
  }
  if (mnemonic == "sar") {
    return IrOp::Sar;
  }
  if (mnemonic == "imul") {
    return IrOp::Mul;
  }
  return IrOp::Nop;
}

struct Lifter {
  const BinaryImage& image;
  const AnalysisResult& analysis;
  const Function& function;
  const LiftOptions& options;

  std::vector<const BasicBlock*> blocks;
  std::unordered_map<std::uint64_t, std::uint32_t> block_by_address;
  IrFunction out;
  std::size_t statement_count = 0;
  std::uint32_t temporary = 0;

  Lifter(const BinaryImage& image_in, const AnalysisResult& analysis_in,
         const Function& function_in, const LiftOptions& options_in)
      : image(image_in), analysis(analysis_in), function(function_in), options(options_in) {}

  std::uint32_t temporary_id() { return temporary++; }

  IrOperand temp_operand(std::uint32_t id, std::uint8_t width) {
    return IrOperand::register_ref("var_" + std::to_string(id), width);
  }

  bool limit_reached() const { return statement_count >= options.max_statements; }

  void push(IrBlock& block, IrStatement statement) {
    if (limit_reached()) {
      return;
    }
    if (statement.width == 0) {
      statement.width = kPointerWidth;
    }
    // Never emit an operand the verifier would reject. An unknown register
    // width is a modelling gap, so the statement becomes an explicit opaque
    // effect instead of malformed IR.
    auto bad_width = [](const IrOperand& operand) {
      if (operand.kind == IrOperandKind::None || operand.kind == IrOperandKind::Block) {
        return false;
      }
      return operand.width != 1 && operand.width != 2 && operand.width != 4 && operand.width != 8;
    };
    if (bad_width(statement.dest) || bad_width(statement.a) || bad_width(statement.b)) {
      const std::uint64_t address = statement.source_address;
      statement = IrStatement{};
      statement.op = IrOp::Unsupported;
      statement.width = kPointerWidth;
      statement.source_address = address;
      statement.text = "operand width is not modelled";
      out.partial = true;
    }
    block.statements.push_back(std::move(statement));
    ++statement_count;
  }

  void note(std::string text) { out.notes.push_back(std::move(text)); }

  void mark_partial(std::string text) {
    out.notes.push_back(std::move(text));
    out.partial = true;
  }

  void unsupported(IrBlock& block, const Instruction& instruction) {
    IrStatement statement;
    statement.op = IrOp::Unsupported;
    statement.source_address = instruction.address;
    statement.width = kPointerWidth;
    statement.text = instruction.mnemonic;
    if (!instruction.operands.empty()) {
      statement.text += " " + instruction.operands;
    }
    push(block, std::move(statement));
    out.partial = true;
  }

  void lift_mov(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() != 2) {
      unsupported(block, instruction);
      return;
    }
    const IrOperand source = to_ir_operand(operands[1], instruction);
    const IrOperand destination = to_ir_operand(operands[0], instruction);

    if (destination.kind == IrOperandKind::Register) {
      IrStatement statement;
      statement.op = IrOp::Assign;
      statement.dest = destination;
      statement.a = source;
      statement.width = destination.width;
      statement.source_address = instruction.address;
      push(block, std::move(statement));
      return;
    }
    if (destination.kind == IrOperandKind::Memory) {
      IrStatement statement;
      statement.op = IrOp::Store;
      statement.a = destination;
      statement.b = source;
      statement.width = destination.width;
      statement.source_address = instruction.address;
      push(block, std::move(statement));
      return;
    }
    unsupported(block, instruction);
  }

  void lift_extend(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() != 2 || operands[0].kind != OperandKind::Register) {
      unsupported(block, instruction);
      return;
    }
    const IrOperand destination = to_ir_operand(operands[0], instruction);
    const IrOperand source = to_ir_operand(operands[1], instruction);
    if (destination.kind != IrOperandKind::Register || destination.width < source.width ||
        source.width == 0) {
      // movsxd from a 64-bit source is a plain copy; anything else that does
      // not widen is not modelled rather than silently mis-typed.
      unsupported(block, instruction);
      return;
    }
    IrStatement statement;
    statement.op = instruction.mnemonic == "movzx" ? IrOp::ZeroExtend : IrOp::SignExtend;
    statement.dest = destination;
    statement.a = source;
    statement.width = destination.width;
    statement.source_address = instruction.address;
    push(block, std::move(statement));
  }

  void lift_lea(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() != 2 || operands[1].kind != OperandKind::Memory) {
      unsupported(block, instruction);
      return;
    }
    IrStatement statement;
    statement.op = IrOp::Lea;
    statement.dest = to_ir_operand(operands[0], instruction);
    statement.a = memory_operand(operands[1], instruction);
    statement.width = statement.dest.width;
    statement.source_address = instruction.address;
    push(block, std::move(statement));
  }

  void lift_arithmetic(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    const IrOp op = arithmetic_op(instruction.mnemonic);
    if (op == IrOp::Nop || operands.empty()) {
      unsupported(block, instruction);
      return;
    }

    IrOperand destination = to_ir_operand(operands[0], instruction);
    IrOperand source;
    if (operands.size() >= 2) {
      source = to_ir_operand(operands[1], instruction);
    } else {
      source = IrOperand::constant_value(1, destination.width);
    }

    if (destination.kind == IrOperandKind::Register) {
      IrStatement statement;
      statement.op = op;
      statement.dest = destination;
      statement.a = destination;
      statement.b = source;
      statement.width = destination.width;
      statement.source_address = instruction.address;
      push(block, std::move(statement));
      return;
    }

    if (destination.kind == IrOperandKind::Memory) {
      // Read-modify-write through a temporary: the IR has no memory-to-memory
      // forms and must not pretend the destination is a register.
      const std::uint32_t id = temporary_id();
      IrStatement load;
      load.op = IrOp::Assign;
      load.dest = temp_operand(id, destination.width);
      load.a = destination;
      load.width = destination.width;
      load.source_address = instruction.address;
      push(block, std::move(load));

      IrStatement compute;
      compute.op = op;
      compute.dest = temp_operand(id, destination.width);
      compute.a = temp_operand(id, destination.width);
      compute.b = source;
      compute.width = destination.width;
      compute.source_address = instruction.address;
      push(block, std::move(compute));

      IrStatement store;
      store.op = IrOp::Store;
      store.a = destination;
      store.b = temp_operand(id, destination.width);
      store.width = destination.width;
      store.source_address = instruction.address;
      push(block, std::move(store));
      return;
    }
    unsupported(block, instruction);
  }

  void lift_compare(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() != 2) {
      unsupported(block, instruction);
      return;
    }
    IrStatement statement;
    statement.op = IrOp::Compare;
    statement.a = to_ir_operand(operands[0], instruction);
    statement.b = to_ir_operand(operands[1], instruction);
    statement.condition = IrCondition::Equal;
    statement.width = statement.a.width;
    statement.source_address = instruction.address;
    push(block, std::move(statement));
  }

  void lift_test(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() != 2) {
      unsupported(block, instruction);
      return;
    }
    IrStatement statement;
    statement.op = IrOp::Test;
    statement.a = to_ir_operand(operands[0], instruction);
    statement.b = to_ir_operand(operands[1], instruction);
    statement.width = statement.a.width;
    statement.source_address = instruction.address;
    push(block, std::move(statement));
  }

  void lift_push(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() != 1) {
      unsupported(block, instruction);
      return;
    }
    const IrOperand source = to_ir_operand(operands[0], instruction);
    if (source.kind == IrOperandKind::None) {
      // An operand this lifter cannot model would produce malformed IR.
      unsupported(block, instruction);
      return;
    }
    IrStatement decrement;
    decrement.op = IrOp::Sub;
    decrement.dest = IrOperand::register_ref("rsp", kPointerWidth);
    decrement.a = IrOperand::register_ref("rsp", kPointerWidth);
    decrement.b = IrOperand::constant_value(8, kPointerWidth);
    decrement.width = kPointerWidth;
    decrement.source_address = instruction.address;
    push(block, std::move(decrement));

    IrOperand slot;
    slot.kind = IrOperandKind::Memory;
    slot.reg = "rsp";
    slot.width = kPointerWidth;
    IrStatement store;
    store.op = IrOp::Store;
    store.a = slot;
    store.b = source;
    store.width = kPointerWidth;
    store.source_address = instruction.address;
    push(block, std::move(store));
  }

  void lift_pop(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() != 1) {
      unsupported(block, instruction);
      return;
    }
    const IrOperand destination = to_ir_operand(operands[0], instruction);
    if (destination.kind != IrOperandKind::Register) {
      // pop with a memory destination would need a load/store pair; model it
      // as unsupported rather than emitting a Load with no register result.
      unsupported(block, instruction);
      return;
    }
    IrOperand slot;
    slot.kind = IrOperandKind::Memory;
    slot.reg = "rsp";
    slot.width = kPointerWidth;
    IrStatement load;
    load.op = IrOp::Load;
    load.dest = destination;
    load.a = slot;
    load.width = kPointerWidth;
    load.source_address = instruction.address;
    push(block, std::move(load));

    IrStatement increment;
    increment.op = IrOp::Add;
    increment.dest = IrOperand::register_ref("rsp", kPointerWidth);
    increment.a = IrOperand::register_ref("rsp", kPointerWidth);
    increment.b = IrOperand::constant_value(8, kPointerWidth);
    increment.width = kPointerWidth;
    increment.source_address = instruction.address;
    push(block, std::move(increment));
  }

  void lift_leave(IrBlock& block, const Instruction& instruction) {
    IrStatement restore_stack;
    restore_stack.op = IrOp::Assign;
    restore_stack.dest = IrOperand::register_ref("rsp", kPointerWidth);
    restore_stack.a = IrOperand::register_ref("rbp", kPointerWidth);
    restore_stack.width = kPointerWidth;
    restore_stack.source_address = instruction.address;
    push(block, std::move(restore_stack));

    IrOperand slot;
    slot.kind = IrOperandKind::Memory;
    slot.reg = "rsp";
    slot.width = kPointerWidth;
    IrStatement load;
    load.op = IrOp::Load;
    load.dest = IrOperand::register_ref("rbp", kPointerWidth);
    load.a = slot;
    load.width = kPointerWidth;
    load.source_address = instruction.address;
    push(block, std::move(load));

    IrStatement increment;
    increment.op = IrOp::Add;
    increment.dest = IrOperand::register_ref("rsp", kPointerWidth);
    increment.a = IrOperand::register_ref("rsp", kPointerWidth);
    increment.b = IrOperand::constant_value(8, kPointerWidth);
    increment.width = kPointerWidth;
    increment.source_address = instruction.address;
    push(block, std::move(increment));
  }

  void lift_call(IrBlock& block, const Instruction& instruction) {
    IrStatement statement;
    statement.op = IrOp::Call;
    statement.width = kPointerWidth;
    statement.source_address = instruction.address;
    if (instruction.direct_target.has_value()) {
      statement.a = IrOperand::constant_value(instruction.direct_target.value(), kPointerWidth);
    } else if (!instruction.structured_operands.empty()) {
      statement.a = to_ir_operand(instruction.structured_operands.front(), instruction);
    } else {
      statement.a = IrOperand::constant_value(0, kPointerWidth);
    }
    push(block, std::move(statement));
    note("outgoing call arguments and return values follow no modelled ABI");
  }
};

}  // namespace

Result<IrFunction> lift_function(const BinaryImage& image, const AnalysisResult& analysis,
                                 const Function& function, const LiftOptions& options) {
  if (image.architecture == Architecture::AArch64) {
    auto lifted = internal::lift_aarch64(image, analysis, function, options);
    if (lifted) {
      infer_signature(lifted.value(), image.architecture);
    }
    return lifted;
  }
  if (image.architecture != Architecture::X86_64) {
    return make_error<IrFunction>(
        Status::Unsupported, "lift.unsupported_architecture",
        "the lifter models x86-64 and AArch64 only; no pseudocode is produced for other "
        "architectures",
        function.address);
  }

  Lifter lifter(image, analysis, function, options);

  for (const BasicBlock& block : analysis.cfg.blocks) {
    if (block.function == function.id) {
      lifter.blocks.push_back(&block);
    }
  }
  std::sort(lifter.blocks.begin(), lifter.blocks.end(),
            [](const BasicBlock* a, const BasicBlock* b) { return a->address < b->address; });

  if (lifter.blocks.size() > options.max_blocks) {
    return make_error<IrFunction>(Status::ResourceLimit, "lift.block_limit",
                                  "function exceeds the configured block limit", function.address);
  }
  if (lifter.blocks.empty()) {
    return make_error<IrFunction>(Status::Unsupported, "lift.no_blocks",
                                  "function has no decoded basic blocks", function.address);
  }

  for (std::size_t index = 0; index < lifter.blocks.size(); ++index) {
    lifter.block_by_address.emplace(lifter.blocks[index]->address,
                                    static_cast<std::uint32_t>(index));
  }

  lifter.out.address = function.address;
  lifter.out.name = function.name.empty() ? "sub" : function.name;
  lifter.out.partial = function.estimated;
  lifter.out.notes.push_back(
      "x86-64 subset; register aliases are not canonicalised and locals are not recovered");

  bool previous_sets_flags = false;
  for (const BasicBlock* block : lifter.blocks) {
    IrBlock out_block;
    out_block.address = block->address;
    previous_sets_flags = false;

    for (std::uint32_t i = 0; i < block->instruction_count; ++i) {
      const std::size_t index = static_cast<std::size_t>(block->first_instruction) + i;
      if (index >= analysis.instructions.size()) {
        lifter.out.partial = true;
        break;
      }
      const Instruction& instruction = analysis.instructions[index];
      const std::string& mnemonic = instruction.mnemonic;

      if (instruction.classification == InstructionClass::ConditionalJump) {
        IrCondition condition = branch_condition(mnemonic);
        IrStatement statement;
        statement.op = IrOp::CondBranch;
        statement.source_address = instruction.address;
        statement.width = kPointerWidth;
        statement.condition = condition;
        statement.a = previous_sets_flags ? IrOperand::register_ref("flags", kPointerWidth)
                                          : IrOperand::register_ref("flags", kPointerWidth);
        if (!previous_sets_flags) {
          lifter.mark_partial("conditional branch depends on flags this lifter does not model");
        }
        if (condition == IrCondition::None) {
          lifter.mark_partial("unsupported condition code '" + mnemonic + "'");
          condition = IrCondition::NonZero;
          statement.condition = condition;
        }
        const auto target = instruction.direct_target.has_value()
                                ? lifter.block_by_address.find(instruction.direct_target.value())
                                : lifter.block_by_address.end();
        if (target == lifter.block_by_address.end()) {
          lifter.mark_partial("conditional branch target is outside this function");
          statement.b = IrOperand::block_ref(0);
        } else {
          statement.b = IrOperand::block_ref(target->second);
        }
        lifter.push(out_block, std::move(statement));
        previous_sets_flags = false;
        continue;
      }

      if (instruction.classification == InstructionClass::Jump) {
        IrStatement statement;
        statement.op = IrOp::Branch;
        statement.source_address = instruction.address;
        statement.width = kPointerWidth;
        const auto target = instruction.direct_target.has_value()
                                ? lifter.block_by_address.find(instruction.direct_target.value())
                                : lifter.block_by_address.end();
        if (target == lifter.block_by_address.end()) {
          // Tail call or an unmodelled target: stop here instead of inventing
          // a block. Calling the target is the honest reading.
          IrStatement call;
          call.op = IrOp::Call;
          call.source_address = instruction.address;
          call.width = kPointerWidth;
          call.a = instruction.direct_target.has_value()
                       ? IrOperand::constant_value(instruction.direct_target.value(), kPointerWidth)
                       : IrOperand::constant_value(0, kPointerWidth);
          lifter.push(out_block, std::move(call));
          lifter.mark_partial("jump leaves the function; treated as a tail call");
          IrStatement tail;
          tail.op = IrOp::Return;
          tail.source_address = instruction.address;
          tail.width = kPointerWidth;
          tail.a = IrOperand::register_ref("rax", kPointerWidth);
          lifter.push(out_block, std::move(tail));
        } else {
          statement.a = IrOperand::block_ref(target->second);
          lifter.push(out_block, std::move(statement));
        }
        previous_sets_flags = false;
        continue;
      }

      if (instruction.classification == InstructionClass::Return) {
        IrStatement statement;
        statement.op = IrOp::Return;
        statement.source_address = instruction.address;
        statement.width = kPointerWidth;
        if (image.architecture == Architecture::X86_64) {
          statement.a = IrOperand::register_ref("rax", kPointerWidth);
        }
        lifter.push(out_block, std::move(statement));
        previous_sets_flags = false;
        continue;
      }

      if (instruction.classification == InstructionClass::Interrupt) {
        lifter.unsupported(out_block, instruction);
        IrStatement statement;
        statement.op = IrOp::Return;
        statement.source_address = instruction.address;
        statement.width = kPointerWidth;
        lifter.push(out_block, std::move(statement));
        previous_sets_flags = false;
        continue;
      }

      const bool sets_flags = mnemonic == "cmp" || mnemonic == "test";
      if (mnemonic == "mov" || mnemonic == "movabs") {
        lifter.lift_mov(out_block, instruction);
      } else if (mnemonic == "movzx" || mnemonic == "movsx" || mnemonic == "movsxd") {
        lifter.lift_extend(out_block, instruction);
      } else if (mnemonic == "lea") {
        lifter.lift_lea(out_block, instruction);
      } else if (mnemonic == "cmp") {
        lifter.lift_compare(out_block, instruction);
      } else if (mnemonic == "test") {
        lifter.lift_test(out_block, instruction);
      } else if (is_bitwise_or_arithmetic(mnemonic) || mnemonic == "inc" || mnemonic == "dec") {
        lifter.lift_arithmetic(out_block, instruction);
      } else if (mnemonic == "push") {
        lifter.lift_push(out_block, instruction);
      } else if (mnemonic == "pop") {
        lifter.lift_pop(out_block, instruction);
      } else if (mnemonic == "leave") {
        lifter.lift_leave(out_block, instruction);
      } else if (instruction.classification == InstructionClass::Call) {
        lifter.lift_call(out_block, instruction);
      } else if (mnemonic == "nop" || mnemonic == "endbr64" || mnemonic == "endbr32") {
        // No semantic effect in the IR.
      } else if (mnemonic == "cdqe" || mnemonic == "cqo" || mnemonic == "cdq" ||
                 mnemonic == "cwd") {
        lifter.unsupported(out_block, instruction);
      } else {
        lifter.unsupported(out_block, instruction);
      }
      previous_sets_flags = sets_flags;
      if (lifter.limit_reached()) {
        lifter.mark_partial("statement limit reached");
        break;
      }
    }

    if (out_block.statements.empty() || (out_block.statements.back().op != IrOp::Branch &&
                                         out_block.statements.back().op != IrOp::CondBranch &&
                                         out_block.statements.back().op != IrOp::Return)) {
      const auto next = lifter.block_by_address.find(block->end_address);
      if (next != lifter.block_by_address.end()) {
        IrStatement statement;
        statement.op = IrOp::Branch;
        statement.a = IrOperand::block_ref(next->second);
        statement.width = kPointerWidth;
        statement.source_address = block->end_address;
        lifter.push(out_block, std::move(statement));
      } else {
        IrStatement statement;
        statement.op = IrOp::Return;
        statement.width = kPointerWidth;
        statement.source_address = block->end_address;
        if (image.architecture == Architecture::X86_64) {
          statement.a = IrOperand::register_ref("rax", kPointerWidth);
        }
        lifter.push(out_block, std::move(statement));
        lifter.out.partial = true;
      }
    }

    lifter.out.blocks.push_back(std::move(out_block));
    if (lifter.limit_reached()) {
      lifter.out.partial = true;
      break;
    }
  }

  if (lifter.out.blocks.empty()) {
    return make_error<IrFunction>(Status::Unsupported, "lift.empty",
                                  "nothing was lifted for this function", function.address);
  }

  // A conditional branch falls through to the next block. When the branch is in
  // the last block there is no fallthrough block, so add an explicit exit block
  // for the unknown path instead of emitting IR that cannot be rendered.
  if (lifter.out.blocks.back().statements.back().op == IrOp::CondBranch) {
    IrBlock exit_block;
    exit_block.address = lifter.blocks.back()->end_address;
    IrStatement statement;
    statement.op = IrOp::Return;
    statement.width = kPointerWidth;
    statement.source_address = exit_block.address;
    if (image.architecture == Architecture::X86_64) {
      statement.a = IrOperand::register_ref("rax", kPointerWidth);
    }
    exit_block.statements.push_back(std::move(statement));
    lifter.out.blocks.push_back(std::move(exit_block));
    lifter.out.partial = true;
    lifter.note("conditional fallthrough leaves the function; exit path is unmodelled");
  }
  infer_signature(lifter.out, image.architecture);
  return lifter.out;
}

}  // namespace donkey
