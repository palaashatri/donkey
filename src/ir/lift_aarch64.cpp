#include "lift_internal.h"

#include <algorithm>
#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>

#include "donkey/analysis/cfg.h"

namespace donkey::internal {
namespace {

constexpr std::uint8_t kPointerWidth = 8;

bool all_digits(const std::string& text) {
  if (text.empty()) {
    return false;
  }
  return std::all_of(text.begin(), text.end(), [](char c) { return c >= '0' && c <= '9'; });
}

std::uint8_t register_width(const std::string& name) {
  if (name == "sp" || name == "fp" || name == "lr" || name == "pc" || name == "xzr") {
    return kPointerWidth;
  }
  if (name == "wsp" || name == "wzr") {
    return 4;
  }
  if (name.size() >= 2 && name[0] == 'x' && all_digits(name.substr(1))) {
    return kPointerWidth;
  }
  if (name.size() >= 2 && name[0] == 'w' && all_digits(name.substr(1))) {
    return 4;
  }
  return 0;
}

std::uint64_t width_mask(std::uint8_t width) {
  if (width >= 8) {
    return ~std::uint64_t{0};
  }
  return (std::uint64_t{1} << (width * 8)) - 1;
}

/// Condition encoded in a `b.<cond>` mnemonic. Returns None for `al` and for
/// conditions this lifter does not model.
IrCondition branch_condition(const std::string& mnemonic) {
  if (mnemonic == "b.eq") {
    return IrCondition::Zero;
  }
  if (mnemonic == "b.ne") {
    return IrCondition::NonZero;
  }
  if (mnemonic == "b.cs" || mnemonic == "b.hs") {
    return IrCondition::Carry;
  }
  if (mnemonic == "b.cc" || mnemonic == "b.lo") {
    return IrCondition::NoCarry;
  }
  if (mnemonic == "b.mi") {
    return IrCondition::Negative;
  }
  if (mnemonic == "b.pl") {
    return IrCondition::Positive;
  }
  if (mnemonic == "b.vs") {
    return IrCondition::Overflow;
  }
  if (mnemonic == "b.vc") {
    return IrCondition::NoOverflow;
  }
  if (mnemonic == "b.hi") {
    return IrCondition::UnsignedGreater;
  }
  if (mnemonic == "b.ls") {
    return IrCondition::UnsignedLessEqual;
  }
  if (mnemonic == "b.ge") {
    return IrCondition::SignedGreaterEqual;
  }
  if (mnemonic == "b.lt") {
    return IrCondition::SignedLess;
  }
  if (mnemonic == "b.gt") {
    return IrCondition::SignedGreater;
  }
  if (mnemonic == "b.le") {
    return IrCondition::SignedLessEqual;
  }
  return IrCondition::None;
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

  void note(std::string text) { out.notes.push_back(std::move(text)); }

  void mark_partial(std::string text) {
    out.notes.push_back(std::move(text));
    out.partial = true;
  }

  void push(IrBlock& block, IrStatement statement) {
    if (limit_reached()) {
      return;
    }
    if (statement.width == 0) {
      statement.width = kPointerWidth;
    }
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

  /// Convert one structured operand. `immediate_width` decides the width of an
  /// immediate, which the decoder does not record for AArch64.
  IrOperand to_ir_operand(const Operand& operand, std::uint8_t immediate_width) const {
    switch (operand.kind) {
      case OperandKind::Register: {
        const std::uint8_t width = register_width(operand.reg);
        if (operand.reg == "xzr" || operand.reg == "wzr") {
          return IrOperand::constant_value(0, width == 0 ? immediate_width : width);
        }
        return IrOperand::register_ref(operand.reg, width);
      }
      case OperandKind::Immediate:
        return IrOperand::constant_value(static_cast<std::uint64_t>(operand.immediate),
                                         immediate_width);
      case OperandKind::Memory: {
        IrOperand memory;
        memory.kind = IrOperandKind::Memory;
        memory.width = operand.memory.size != 0 ? operand.memory.size : immediate_width;
        memory.reg = operand.memory.base;
        memory.index = operand.memory.index;
        memory.scale = operand.memory.scale == 0 ? 1 : operand.memory.scale;
        memory.constant = static_cast<std::uint64_t>(operand.memory.displacement);
        return memory;
      }
      case OperandKind::Unknown:
        break;
    }
    return IrOperand::none();
  }

  /// A memory access at `base + displacement`. `extra_displacement` is added
  /// on top of the operand's own displacement (used for the second half of a
  /// load/store pair). Callers must reject indexed forms first: the index
  /// shift is captured but not modelled here.
  IrOperand memory_at(const Operand& operand, std::uint8_t width,
                      std::int64_t extra_displacement) const {
    IrOperand memory;
    memory.kind = IrOperandKind::Memory;
    memory.width = width;
    memory.reg = operand.memory.base;
    memory.constant = static_cast<std::uint64_t>(operand.memory.displacement + extra_displacement);
    return memory;
  }

  bool indexed_memory(const Operand& operand) const {
    return operand.kind == OperandKind::Memory && !operand.memory.index.empty();
  }

  /// Resolved addressing for one instruction. Capstone encodes the access
  /// displacement in the memory operand and, for post-index, the writeback
  /// amount as a trailing immediate operand (`[sp], #16`). Pre-index carries
  /// both in the memory operand (`[sp, #-16]!`).
  struct MemoryAccess {
    const Operand* memory = nullptr;
    std::int64_t access_displacement = 0;
    bool has_writeback = false;
    std::int64_t writeback_amount = 0;
    bool valid = false;
  };

  MemoryAccess resolve_memory(const std::vector<Operand>& operands,
                              std::size_t memory_index) const {
    MemoryAccess result;
    if (memory_index >= operands.size() || operands[memory_index].kind != OperandKind::Memory) {
      return result;
    }
    const Operand& memory = operands[memory_index];
    if (indexed_memory(memory) || memory.memory.base.empty()) {
      return result;
    }
    result.memory = &memory;
    result.access_displacement = memory.memory.displacement;
    if (memory.memory.writeback) {
      if (memory.memory.post_index) {
        // `[base], #imm`: the writeback amount is the trailing immediate.
        if (memory_index + 1 >= operands.size() ||
            operands[memory_index + 1].kind != OperandKind::Immediate) {
          return result;
        }
        result.writeback_amount = operands[memory_index + 1].immediate;
      } else {
        // `[base, #disp]!`: the memory displacement is the writeback amount.
        result.writeback_amount = memory.memory.displacement;
      }
      result.has_writeback = true;
    }
    result.valid = true;
    return result;
  }

  void lift_move(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() != 2 || operands[0].kind != OperandKind::Register) {
      unsupported(block, instruction);
      return;
    }
    const std::uint8_t destination_width = register_width(operands[0].reg);
    if (destination_width == 0) {
      unsupported(block, instruction);
      return;
    }
    const std::string& mnemonic = instruction.mnemonic;
    IrOperand source = to_ir_operand(operands[1], destination_width);
    if (source.kind == IrOperandKind::None) {
      unsupported(block, instruction);
      return;
    }

    if (mnemonic == "movz" || mnemonic == "movn" || mnemonic == "movk") {
      const std::uint8_t shift = operands[1].shift == ShiftKind::Lsl ? operands[1].shift_amount : 0;
      const std::uint64_t value = (source.constant & 0xFFFFU) << shift;
      if (mnemonic == "movn") {
        source.constant = ~value & width_mask(destination_width);
      } else if (mnemonic == "movk") {
        // Keep every other 16-bit lane, replace this one.
        IrStatement clear;
        clear.op = IrOp::And;
        clear.dest = to_ir_operand(operands[0], destination_width);
        clear.a = to_ir_operand(operands[0], destination_width);
        clear.b = IrOperand::constant_value(~(std::uint64_t{0xFFFF} << shift), destination_width);
        clear.width = destination_width;
        clear.source_address = instruction.address;
        push(block, std::move(clear));

        IrStatement merge;
        merge.op = IrOp::Or;
        merge.dest = to_ir_operand(operands[0], destination_width);
        merge.a = to_ir_operand(operands[0], destination_width);
        merge.b = IrOperand::constant_value(value, destination_width);
        merge.width = destination_width;
        merge.source_address = instruction.address;
        push(block, std::move(merge));
        return;
      }
      source.constant &= width_mask(destination_width);
    }

    IrStatement statement;
    statement.op = IrOp::Assign;
    statement.dest = to_ir_operand(operands[0], destination_width);
    statement.a = source;
    statement.width = destination_width;
    statement.source_address = instruction.address;
    push(block, std::move(statement));
  }

  /// Emit `value` shifted by the operand's shift metadata into a temporary.
  /// Returns a Source operand and whether a temporary was introduced.
  IrOperand shifted_operand(IrBlock& block, const Instruction& instruction, const Operand& operand,
                            std::uint8_t width, bool& failed) {
    const IrOperand value = to_ir_operand(operand, width);
    if (value.kind == IrOperandKind::None) {
      failed = true;
      return value;
    }
    if (operand.shift == ShiftKind::None || operand.shift_amount == 0) {
      return value;
    }
    IrOp op = IrOp::Shl;
    if (operand.shift == ShiftKind::Lsr) {
      op = IrOp::Shr;
    } else if (operand.shift == ShiftKind::Asr) {
      op = IrOp::Sar;
    } else if (operand.shift == ShiftKind::Ror) {
      failed = true;
      return value;
    }
    const std::uint32_t id = temporary_id();
    IrStatement statement;
    statement.op = op;
    statement.dest = temp_operand(id, width);
    statement.a = value;
    statement.b = IrOperand::constant_value(operand.shift_amount, width);
    statement.width = width;
    statement.source_address = instruction.address;
    push(block, std::move(statement));
    return temp_operand(id, width);
  }

  void lift_arithmetic(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    const std::string& mnemonic = instruction.mnemonic;

    if (operands.size() == 2) {
      const IrOperand source = to_ir_operand(operands[1], kPointerWidth);
      if (source.kind == IrOperandKind::None) {
        unsupported(block, instruction);
        return;
      }
      if (mnemonic == "cmp") {
        IrStatement statement;
        statement.op = IrOp::Compare;
        statement.a = to_ir_operand(operands[0], kPointerWidth);
        statement.b = source;
        statement.condition = IrCondition::Equal;
        statement.width = statement.a.width;
        statement.source_address = instruction.address;
        push(block, std::move(statement));
        return;
      }
      if (mnemonic == "tst") {
        IrStatement statement;
        statement.op = IrOp::Test;
        statement.a = to_ir_operand(operands[0], kPointerWidth);
        statement.b = source;
        statement.width = statement.a.width;
        statement.source_address = instruction.address;
        push(block, std::move(statement));
        return;
      }
      if (mnemonic == "neg" || mnemonic == "negs") {
        if (operands[0].kind != OperandKind::Register) {
          unsupported(block, instruction);
          return;
        }
        const std::uint8_t width = register_width(operands[0].reg);
        IrStatement statement;
        statement.op = IrOp::Sub;
        statement.dest = to_ir_operand(operands[0], width);
        statement.a = IrOperand::constant_value(0, width);
        statement.b = to_ir_operand(operands[1], width);
        statement.width = width;
        statement.source_address = instruction.address;
        push(block, std::move(statement));
        return;
      }
      unsupported(block, instruction);
      return;
    }

    if (operands.size() != 3 || operands[0].kind != OperandKind::Register) {
      unsupported(block, instruction);
      return;
    }
    const std::uint8_t width = register_width(operands[0].reg);
    if (width == 0) {
      unsupported(block, instruction);
      return;
    }

    IrOp op = IrOp::Nop;
    if (mnemonic == "add" || mnemonic == "adds") {
      op = IrOp::Add;
    } else if (mnemonic == "sub" || mnemonic == "subs") {
      op = IrOp::Sub;
    } else if (mnemonic == "and" || mnemonic == "ands") {
      op = IrOp::And;
    } else if (mnemonic == "orr") {
      op = IrOp::Or;
    } else if (mnemonic == "eor") {
      op = IrOp::Xor;
    } else if (mnemonic == "lsl") {
      op = IrOp::Shl;
    } else if (mnemonic == "lsr") {
      op = IrOp::Shr;
    } else if (mnemonic == "asr") {
      op = IrOp::Sar;
    }
    if (op == IrOp::Nop) {
      unsupported(block, instruction);
      return;
    }

    bool failed = false;
    const IrOperand left = to_ir_operand(operands[1], width);
    const IrOperand right = shifted_operand(block, instruction, operands[2], width, failed);
    if (failed || left.kind == IrOperandKind::None || right.kind == IrOperandKind::None) {
      unsupported(block, instruction);
      return;
    }

    IrStatement statement;
    statement.op = op;
    statement.dest = to_ir_operand(operands[0], width);
    statement.a = left;
    statement.b = right;
    statement.width = width;
    statement.source_address = instruction.address;
    push(block, std::move(statement));
  }

  void lift_multiply(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    const std::string& mnemonic = instruction.mnemonic;
    if (operands.empty() || operands[0].kind != OperandKind::Register) {
      unsupported(block, instruction);
      return;
    }
    const std::uint8_t width = register_width(operands[0].reg);
    if (width == 0) {
      unsupported(block, instruction);
      return;
    }
    if (mnemonic == "mul" && operands.size() == 3) {
      IrStatement statement;
      statement.op = IrOp::Mul;
      statement.dest = to_ir_operand(operands[0], width);
      statement.a = to_ir_operand(operands[1], width);
      statement.b = to_ir_operand(operands[2], width);
      statement.width = width;
      statement.source_address = instruction.address;
      push(block, std::move(statement));
      return;
    }
    if ((mnemonic == "madd" || mnemonic == "msub") && operands.size() == 4) {
      const std::uint32_t id = temporary_id();
      IrStatement product;
      product.op = IrOp::Mul;
      product.dest = temp_operand(id, width);
      product.a = to_ir_operand(operands[1], width);
      product.b = to_ir_operand(operands[2], width);
      product.width = width;
      product.source_address = instruction.address;
      push(block, std::move(product));

      IrStatement combine;
      combine.op = mnemonic == "madd" ? IrOp::Add : IrOp::Sub;
      combine.dest = to_ir_operand(operands[0], width);
      combine.a = mnemonic == "madd" ? temp_operand(id, width) : to_ir_operand(operands[3], width);
      combine.b = mnemonic == "madd" ? to_ir_operand(operands[3], width) : temp_operand(id, width);
      combine.width = width;
      combine.source_address = instruction.address;
      push(block, std::move(combine));
      return;
    }
    unsupported(block, instruction);
  }

  void lift_extend(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() != 2 || operands[0].kind != OperandKind::Register ||
        operands[1].kind != OperandKind::Register) {
      unsupported(block, instruction);
      return;
    }
    const std::uint8_t destination_width = register_width(operands[0].reg);
    const std::string& mnemonic = instruction.mnemonic;
    std::uint8_t source_width = 0;
    bool sign = false;
    if (mnemonic == "sxtb" || mnemonic == "uxtb") {
      source_width = 1;
      sign = mnemonic == "sxtb";
    } else if (mnemonic == "sxth" || mnemonic == "uxth") {
      source_width = 2;
      sign = mnemonic == "sxth";
    } else if (mnemonic == "sxtw" || mnemonic == "uxtw") {
      source_width = 4;
      sign = mnemonic == "sxtw";
    }
    if (source_width == 0 || destination_width < source_width) {
      unsupported(block, instruction);
      return;
    }
    IrStatement statement;
    statement.op = sign ? IrOp::SignExtend : IrOp::ZeroExtend;
    statement.dest = to_ir_operand(operands[0], destination_width);
    statement.a = to_ir_operand(operands[1], source_width);
    statement.width = destination_width;
    statement.source_address = instruction.address;
    push(block, std::move(statement));
  }

  void lift_address(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() != 2 || operands[0].kind != OperandKind::Register ||
        operands[1].kind != OperandKind::Immediate) {
      unsupported(block, instruction);
      return;
    }
    IrStatement statement;
    statement.op = IrOp::Assign;
    statement.dest = to_ir_operand(operands[0], kPointerWidth);
    statement.a =
        IrOperand::constant_value(static_cast<std::uint64_t>(operands[1].immediate), kPointerWidth);
    statement.width = kPointerWidth;
    statement.source_address = instruction.address;
    push(block, std::move(statement));
  }

  /// Emit the base-register update for a writeback access, using the amount
  /// Capstone reports for pre-index (`[sp, #-16]!`) or post-index (`[sp], #16`).
  /// Negative pre-index offsets become a subtraction so the pseudocode reads
  /// `sp = sp - 0x10` rather than an unsigned wrap constant.
  void lift_writeback(IrBlock& block, const Instruction& instruction, const MemoryAccess& access) {
    if (!access.has_writeback || access.memory == nullptr) {
      return;
    }
    const std::string& base = access.memory->memory.base;
    if (base.empty()) {
      unsupported(block, instruction);
      return;
    }
    const std::int64_t amount = access.writeback_amount;
    IrStatement statement;
    statement.op = amount < 0 ? IrOp::Sub : IrOp::Add;
    statement.dest = IrOperand::register_ref(base, kPointerWidth);
    statement.a = IrOperand::register_ref(base, kPointerWidth);
    statement.b = IrOperand::constant_value(
        static_cast<std::uint64_t>(amount < 0 ? -amount : amount), kPointerWidth);
    statement.width = kPointerWidth;
    statement.source_address = instruction.address;
    push(block, std::move(statement));
  }

  std::uint8_t access_width(const Instruction& instruction, const Operand& register_operand) const {
    const std::string& mnemonic = instruction.mnemonic;
    if (mnemonic == "ldrb" || mnemonic == "strb" || mnemonic == "ldrsb") {
      return 1;
    }
    if (mnemonic == "ldrh" || mnemonic == "strh" || mnemonic == "ldrsh") {
      return 2;
    }
    if (mnemonic == "ldrsw") {
      return 4;
    }
    if (register_operand.kind == OperandKind::Register) {
      return register_width(register_operand.reg);
    }
    return 0;
  }

  void lift_load_store(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() < 2 || operands[0].kind != OperandKind::Register) {
      unsupported(block, instruction);
      return;
    }
    const MemoryAccess access = resolve_memory(operands, 1);
    if (!access.valid) {
      unsupported(block, instruction);
      return;
    }
    const std::uint8_t width = access_width(instruction, operands[0]);
    if (width == 0) {
      unsupported(block, instruction);
      return;
    }
    // The access uses the memory operand's own displacement. For pre-index
    // that is the pre-adjusted address; for post-index it is the base itself.
    const IrOperand location = memory_at(*access.memory, width, 0);

    const bool is_load = instruction.mnemonic.rfind("ld", 0) == 0;
    const std::string& mnemonic = instruction.mnemonic;
    const bool extends = mnemonic == "ldrsb" || mnemonic == "ldrsh" || mnemonic == "ldrsw";

    if (is_load) {
      const std::uint8_t destination_width = register_width(operands[0].reg);
      if (destination_width == 0 || destination_width < width) {
        unsupported(block, instruction);
        return;
      }
      if (extends) {
        const std::uint32_t id = temporary_id();
        IrStatement load;
        load.op = IrOp::Load;
        load.dest = temp_operand(id, width);
        load.a = location;
        load.width = width;
        load.source_address = instruction.address;
        push(block, std::move(load));

        IrStatement extend;
        extend.op = IrOp::SignExtend;
        extend.dest = to_ir_operand(operands[0], destination_width);
        extend.a = temp_operand(id, width);
        extend.width = destination_width;
        extend.source_address = instruction.address;
        push(block, std::move(extend));
      } else {
        IrStatement load;
        load.op = IrOp::Load;
        load.dest = to_ir_operand(operands[0], destination_width);
        load.a = location;
        load.width = width;
        load.source_address = instruction.address;
        push(block, std::move(load));
      }
    } else {
      const IrOperand source = to_ir_operand(operands[0], width);
      if (source.kind == IrOperandKind::None) {
        unsupported(block, instruction);
        return;
      }
      IrStatement store;
      store.op = IrOp::Store;
      store.a = location;
      store.b = source;
      store.width = width;
      store.source_address = instruction.address;
      push(block, std::move(store));
    }
    lift_writeback(block, instruction, access);
  }

  void lift_pair(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() < 3 || operands[0].kind != OperandKind::Register ||
        operands[1].kind != OperandKind::Register) {
      unsupported(block, instruction);
      return;
    }
    const MemoryAccess access = resolve_memory(operands, 2);
    if (!access.valid) {
      unsupported(block, instruction);
      return;
    }
    const std::uint8_t width = register_width(operands[0].reg);
    if (width == 0) {
      unsupported(block, instruction);
      return;
    }
    const bool is_load = instruction.mnemonic == "ldp";
    if (is_load) {
      IrStatement first;
      first.op = IrOp::Load;
      first.dest = to_ir_operand(operands[0], width);
      first.a = memory_at(*access.memory, width, 0);
      first.width = width;
      first.source_address = instruction.address;
      push(block, std::move(first));

      IrStatement second;
      second.op = IrOp::Load;
      second.dest = to_ir_operand(operands[1], width);
      second.a = memory_at(*access.memory, width, static_cast<std::int64_t>(width));
      second.width = width;
      second.source_address = instruction.address;
      push(block, std::move(second));
    } else if (instruction.mnemonic == "stp") {
      IrStatement first;
      first.op = IrOp::Store;
      first.a = memory_at(*access.memory, width, 0);
      first.b = to_ir_operand(operands[0], width);
      first.width = width;
      first.source_address = instruction.address;
      push(block, std::move(first));

      IrStatement second;
      second.op = IrOp::Store;
      second.a = memory_at(*access.memory, width, static_cast<std::int64_t>(width));
      second.b = to_ir_operand(operands[1], width);
      second.width = width;
      second.source_address = instruction.address;
      push(block, std::move(second));
    } else {
      unsupported(block, instruction);
      return;
    }
    lift_writeback(block, instruction, access);
  }

  /// cbz/cbnz compare a register against zero and branch on the result.
  void lift_compare_zero(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.empty() || operands[0].kind != OperandKind::Register) {
      unsupported(block, instruction);
      return;
    }
    const std::uint8_t width = register_width(operands[0].reg);
    IrStatement compare;
    compare.op = IrOp::Compare;
    compare.a = to_ir_operand(operands[0], width);
    compare.b = IrOperand::constant_value(0, width);
    compare.condition = IrCondition::Equal;
    compare.width = width;
    compare.source_address = instruction.address;
    push(block, std::move(compare));
  }

  /// tbz/tbnz test one bit and branch on the result.
  void lift_test_bit(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() < 2 || operands[0].kind != OperandKind::Register ||
        operands[1].kind != OperandKind::Immediate) {
      unsupported(block, instruction);
      return;
    }
    const std::uint8_t width = register_width(operands[0].reg);
    const std::uint64_t mask = std::uint64_t{1} << (operands[1].immediate & 0x3F);
    IrStatement test;
    test.op = IrOp::Test;
    test.a = to_ir_operand(operands[0], width);
    test.b = IrOperand::constant_value(mask, width);
    test.width = width;
    test.source_address = instruction.address;
    push(block, std::move(test));
  }
};

}  // namespace

Result<IrFunction> lift_aarch64(const BinaryImage& image, const AnalysisResult& analysis,
                                const Function& function, const LiftOptions& options) {
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
      "AArch64 subset; register aliases are not canonicalised and locals are not recovered");

  for (const BasicBlock* block : lifter.blocks) {
    IrBlock out_block;
    out_block.address = block->address;

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
        if (mnemonic == "cbz" || mnemonic == "cbnz") {
          lifter.lift_compare_zero(out_block, instruction);
          condition = mnemonic == "cbz" ? IrCondition::Zero : IrCondition::NonZero;
          lifter.mark_partial(
              "conditional branch depends on flags; only cmp/tst set modelled flags");
        } else if (mnemonic == "tbz" || mnemonic == "tbnz") {
          lifter.lift_test_bit(out_block, instruction);
          condition = mnemonic == "tbz" ? IrCondition::Zero : IrCondition::NonZero;
        } else {
          lifter.mark_partial(
              "conditional branch depends on flags; only cmp/tst set modelled flags");
        }
        if (condition == IrCondition::None) {
          condition = IrCondition::NonZero;
          lifter.mark_partial("unsupported condition code '" + mnemonic + "'");
        }
        IrStatement statement;
        statement.op = IrOp::CondBranch;
        statement.source_address = instruction.address;
        statement.width = kPointerWidth;
        statement.condition = condition;
        statement.a = IrOperand::register_ref("flags", kPointerWidth);
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
        continue;
      }

      if (instruction.classification == InstructionClass::Jump) {
        const auto target = instruction.direct_target.has_value()
                                ? lifter.block_by_address.find(instruction.direct_target.value())
                                : lifter.block_by_address.end();
        if (target == lifter.block_by_address.end()) {
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
          tail.a = IrOperand::register_ref("x0", kPointerWidth);
          lifter.push(out_block, std::move(tail));
        } else {
          IrStatement statement;
          statement.op = IrOp::Branch;
          statement.source_address = instruction.address;
          statement.width = kPointerWidth;
          statement.a = IrOperand::block_ref(target->second);
          lifter.push(out_block, std::move(statement));
        }
        continue;
      }

      if (instruction.classification == InstructionClass::Call) {
        IrStatement statement;
        statement.op = IrOp::Call;
        statement.source_address = instruction.address;
        statement.width = kPointerWidth;
        if (instruction.direct_target.has_value()) {
          statement.a = IrOperand::constant_value(instruction.direct_target.value(), kPointerWidth);
        } else if (!instruction.structured_operands.empty()) {
          statement.a =
              lifter.to_ir_operand(instruction.structured_operands.front(), kPointerWidth);
        } else {
          statement.a = IrOperand::constant_value(0, kPointerWidth);
        }
        lifter.push(out_block, std::move(statement));
        lifter.note("call arguments and return values follow no modelled ABI");
        continue;
      }

      if (instruction.classification == InstructionClass::Return) {
        IrStatement statement;
        statement.op = IrOp::Return;
        statement.source_address = instruction.address;
        statement.width = kPointerWidth;
        statement.a = IrOperand::register_ref("x0", kPointerWidth);
        lifter.push(out_block, std::move(statement));
        continue;
      }

      if (mnemonic == "mov" || mnemonic == "movz" || mnemonic == "movn" || mnemonic == "movk") {
        lifter.lift_move(out_block, instruction);
      } else if (mnemonic == "add" || mnemonic == "adds" || mnemonic == "sub" ||
                 mnemonic == "subs" || mnemonic == "and" || mnemonic == "ands" ||
                 mnemonic == "orr" || mnemonic == "eor" || mnemonic == "cmp" || mnemonic == "tst" ||
                 mnemonic == "neg" || mnemonic == "negs" || mnemonic == "lsl" ||
                 mnemonic == "lsr" || mnemonic == "asr") {
        lifter.lift_arithmetic(out_block, instruction);
      } else if (mnemonic == "mul" || mnemonic == "madd" || mnemonic == "msub") {
        lifter.lift_multiply(out_block, instruction);
      } else if (mnemonic == "sxtb" || mnemonic == "sxth" || mnemonic == "sxtw" ||
                 mnemonic == "uxtb" || mnemonic == "uxth" || mnemonic == "uxtw") {
        lifter.lift_extend(out_block, instruction);
      } else if (mnemonic == "adr" || mnemonic == "adrp") {
        lifter.lift_address(out_block, instruction);
      } else if (mnemonic == "ldp" || mnemonic == "stp") {
        lifter.lift_pair(out_block, instruction);
      } else if (mnemonic == "ldr" || mnemonic == "str" || mnemonic == "ldur" ||
                 mnemonic == "stur" || mnemonic == "ldrb" || mnemonic == "strb" ||
                 mnemonic == "ldrh" || mnemonic == "strh" || mnemonic == "ldrsb" ||
                 mnemonic == "ldrsh" || mnemonic == "ldrsw") {
        lifter.lift_load_store(out_block, instruction);
      } else if (mnemonic == "nop" || mnemonic == "bti" || mnemonic == "hint") {
        // No semantic effect in the IR.
      } else {
        lifter.unsupported(out_block, instruction);
      }
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
        statement.a = IrOperand::register_ref("x0", kPointerWidth);
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

  if (lifter.out.blocks.back().statements.back().op == IrOp::CondBranch) {
    IrBlock exit_block;
    exit_block.address = lifter.blocks.back()->end_address;
    IrStatement statement;
    statement.op = IrOp::Return;
    statement.width = kPointerWidth;
    statement.source_address = exit_block.address;
    statement.a = IrOperand::register_ref("x0", kPointerWidth);
    exit_block.statements.push_back(std::move(statement));
    lifter.out.blocks.push_back(std::move(exit_block));
    lifter.out.partial = true;
    lifter.note("conditional fallthrough leaves the function; exit path is unmodelled");
  }
  return lifter.out;
}

}  // namespace donkey::internal
