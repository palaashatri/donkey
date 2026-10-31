#include "donkey/ir/lift.h"

#include "donkey/ir/abi.h"

#include <algorithm>
#include <cstddef>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "donkey/analysis/cfg.h"
#include "lift_internal.h"

namespace donkey {
namespace {

using namespace donkey;

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

IrOperand to_ir_operand(const Operand& operand, const Instruction& instruction,
                        std::uint8_t default_width) {
  switch (operand.kind) {
    case OperandKind::Register:
      return IrOperand::register_ref(operand.reg, register_width(operand.reg));
    case OperandKind::Immediate:
      return IrOperand::constant_value(
          static_cast<std::uint64_t>(operand.immediate),
          operand_width(operand) == 0 ? default_width : operand_width(operand));
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
  if (mnemonic == "js") {
    return IrCondition::Negative;
  }
  if (mnemonic == "jns") {
    return IrCondition::Positive;
  }
  if (mnemonic == "jo") {
    return IrCondition::Overflow;
  }
  if (mnemonic == "jno") {
    return IrCondition::NoOverflow;
  }
  return IrCondition::None;
}

/// Condition of a cmovcc / setcc mnemonic, through the jcc table.
IrCondition suffix_condition(const std::string& mnemonic, std::size_t prefix) {
  if (mnemonic.size() <= prefix) {
    return IrCondition::None;
  }
  return branch_condition("j" + mnemonic.substr(prefix));
}

bool is_cmov(const std::string& mnemonic) {
  return mnemonic.rfind("cmov", 0) == 0 && suffix_condition(mnemonic, 4) != IrCondition::None;
}

bool is_setcc(const std::string& mnemonic) {
  return mnemonic.rfind("set", 0) == 0 && suffix_condition(mnemonic, 3) != IrCondition::None;
}

/// Instructions that leave the flags exactly as they were.
bool preserves_flags(const std::string& mnemonic) {
  return mnemonic == "mov" || mnemonic == "movabs" || mnemonic == "movzx" || mnemonic == "movsx" ||
         mnemonic == "movsxd" || mnemonic == "lea" || mnemonic == "push" || mnemonic == "pop" ||
         mnemonic == "nop" || mnemonic == "endbr64" || mnemonic == "endbr32" ||
         mnemonic == "cdqe" || mnemonic == "cdq" || mnemonic == "cqo" || mnemonic == "cwde" ||
         mnemonic == "cbw" || mnemonic == "cwd" || mnemonic == "not" || is_cmov(mnemonic) ||
         is_setcc(mnemonic);
}

/// Conditions that read only ZF and SF, which every flag-setting arithmetic
/// instruction derives from its result alone.
bool zero_sign_condition(IrCondition condition) {
  return condition == IrCondition::Zero || condition == IrCondition::NonZero ||
         condition == IrCondition::Equal || condition == IrCondition::NotEqual ||
         condition == IrCondition::Negative || condition == IrCondition::Positive;
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
  std::uint8_t pointer_width = 8;
  const char* stack_pointer = "rsp";
  const char* frame_pointer = "rbp";
  const char* return_register = "rax";

  Lifter(const BinaryImage& image_in, const AnalysisResult& analysis_in,
         const Function& function_in, const LiftOptions& options_in)
      : image(image_in),
        analysis(analysis_in),
        function(function_in),
        options(options_in),
        pointer_width(image_in.architecture == Architecture::X86 ? 4 : 8),
        stack_pointer(image_in.architecture == Architecture::X86 ? "esp" : "rsp"),
        frame_pointer(image_in.architecture == Architecture::X86 ? "ebp" : "rbp"),
        return_register(image_in.architecture == Architecture::X86 ? "eax" : "rax") {}

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
      statement.width = pointer_width;
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
      statement.width = pointer_width;
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
    statement.width = pointer_width;
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
    const IrOperand source = to_ir_operand(operands[1], instruction, pointer_width);
    const IrOperand destination = to_ir_operand(operands[0], instruction, pointer_width);

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
    const IrOperand destination = to_ir_operand(operands[0], instruction, pointer_width);
    const IrOperand source = to_ir_operand(operands[1], instruction, pointer_width);
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
    statement.dest = to_ir_operand(operands[0], instruction, pointer_width);
    statement.a = memory_operand(operands[1], instruction);
    statement.width = statement.dest.width;
    statement.source_address = instruction.address;
    push(block, std::move(statement));
  }

  /// What the IR knows about the flags a later jcc / cmovcc / setcc reads.
  enum class FlagsState { Unknown, Exact, ZeroSign };
  FlagsState flags_state = FlagsState::Unknown;

  IrStatement flags_test_of(const IrOperand& value, std::uint64_t address) const {
    IrStatement test;
    test.op = IrOp::Test;
    test.a = value;
    test.b = value;
    test.width = value.width;
    test.source_address = address;
    return test;
  }

  /// `consumer` is the condition the next flag reader in this block uses (if
  /// any reads these flags before they are overwritten). Flags are modelled
  /// only where the IR can state them exactly: logic operations clear CF/OF
  /// so a test of the result is exact; a subtraction keeps its operands in a
  /// comparison; other arithmetic gives exact ZF/SF only.
  void lift_arithmetic(IrBlock& block, const Instruction& instruction,
                       std::optional<IrCondition> consumer) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    const std::string& mnemonic = instruction.mnemonic;
    const IrOp op = arithmetic_op(mnemonic);
    flags_state = FlagsState::Unknown;
    if (op == IrOp::Nop || operands.empty()) {
      unsupported(block, instruction);
      return;
    }
    if (mnemonic == "imul" && operands.size() == 1) {
      unsupported(block, instruction);  // rdx:rax = rax * src: no double-width result in the IR
      return;
    }

    IrOperand destination = to_ir_operand(operands[0], instruction, pointer_width);
    IrOperand left = destination;
    IrOperand source;
    if (mnemonic == "imul" && operands.size() == 3) {
      // imul dst, src, imm: dst = src * imm (the destination is not an input).
      left = to_ir_operand(operands[1], instruction, pointer_width);
      source = to_ir_operand(operands[2], instruction, pointer_width);
    } else if (operands.size() >= 2) {
      source = to_ir_operand(operands[1], instruction, pointer_width);
    } else {
      source = IrOperand::constant_value(1, destination.width);  // inc / dec
    }
    const bool shift = op == IrOp::Shl || op == IrOp::Shr || op == IrOp::Sar;
    const bool logic = op == IrOp::And || op == IrOp::Or || op == IrOp::Xor;
    const bool subtract = mnemonic == "sub";
    // A shift by a register may be by zero, which leaves the flags alone.
    const bool flags_defined =
        mnemonic != "imul" &&
        (!shift || (source.kind == IrOperandKind::Constant && (source.constant & 0x3F) != 0));

    if (destination.kind == IrOperandKind::Register) {
      std::optional<IrOperand> saved;
      if (consumer && subtract && !zero_sign_condition(*consumer)) {
        // Keep the minuend: the condition compares it with the subtrahend.
        saved = temp_operand(temporary_id(), destination.width);
        IrStatement copy;
        copy.op = IrOp::Assign;
        copy.dest = *saved;
        copy.a = destination;
        copy.width = destination.width;
        copy.source_address = instruction.address;
        push(block, std::move(copy));
      }
      IrStatement statement;
      statement.op = op;
      statement.dest = destination;
      statement.a = left;
      statement.b = source;
      statement.width = destination.width;
      statement.source_address = instruction.address;
      push(block, std::move(statement));
      if (consumer && flags_defined) {
        if (saved) {
          IrStatement compare;
          compare.op = IrOp::Compare;
          compare.a = *saved;
          compare.b = source;
          compare.condition = IrCondition::Equal;
          compare.width = saved->width;
          compare.source_address = instruction.address;
          push(block, std::move(compare));
          flags_state = FlagsState::Exact;
        } else {
          push(block, flags_test_of(destination, instruction.address));
          flags_state = logic ? FlagsState::Exact : FlagsState::ZeroSign;
        }
      }
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
      if (consumer && flags_defined) {
        push(block, flags_test_of(temp_operand(id, destination.width), instruction.address));
        flags_state = logic ? FlagsState::Exact : FlagsState::ZeroSign;
      }
      return;
    }
    unsupported(block, instruction);
  }

  /// neg / not.
  void lift_unary(IrBlock& block, const Instruction& instruction,
                  std::optional<IrCondition> consumer) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    const bool negate = instruction.mnemonic == "neg";
    if (operands.size() != 1 || operands[0].kind != OperandKind::Register) {
      unsupported(block, instruction);
      return;
    }
    const IrOperand destination = to_ir_operand(operands[0], instruction, pointer_width);
    IrStatement statement;
    statement.op = negate ? IrOp::Sub : IrOp::Xor;
    statement.dest = destination;
    statement.a = negate ? IrOperand::constant_value(0, destination.width) : destination;
    statement.b = negate ? destination : IrOperand::constant_value(~0ULL, destination.width);
    statement.width = destination.width;
    statement.source_address = instruction.address;
    if (negate) {
      // 0 - x: operand `a` must have the destination's width.
      statement.a.width = destination.width;
    }
    push(block, std::move(statement));
    if (negate) {  // not leaves the flags alone
      flags_state = FlagsState::Unknown;
      if (consumer) {
        push(block, flags_test_of(destination, instruction.address));
        flags_state = FlagsState::ZeroSign;
      }
    }
  }

  /// cdqe / cwde / cbw (sign-extend in place) and cdq / cqo / cwd (fill the
  /// high register with the sign of the low one).
  void lift_sign_widen(IrBlock& block, const Instruction& instruction) {
    struct Form {
      const char* mnemonic;
      const char* dest;
      std::uint8_t dest_width;
      const char* source;
      std::uint8_t source_width;
      bool fill;
    };
    static const Form kForms[] = {
        {"cdqe", "rax", 8, "eax", 4, false}, {"cwde", "eax", 4, "ax", 2, false},
        {"cbw", "ax", 2, "al", 1, false},    {"cqo", "rdx", 8, "rax", 8, true},
        {"cdq", "edx", 4, "eax", 4, true},   {"cwd", "dx", 2, "ax", 2, true},
    };
    for (const Form& form : kForms) {
      if (instruction.mnemonic != form.mnemonic) {
        continue;
      }
      IrStatement statement;
      statement.dest = IrOperand::register_ref(form.dest, form.dest_width);
      statement.width = form.dest_width;
      statement.source_address = instruction.address;
      if (form.fill) {
        statement.op = IrOp::Sar;
        statement.a = IrOperand::register_ref(form.source, form.source_width);
        statement.b = IrOperand::constant_value(form.source_width * 8U - 1U, 1);
      } else {
        statement.op = IrOp::SignExtend;
        statement.a = IrOperand::register_ref(form.source, form.source_width);
      }
      push(block, std::move(statement));
      return;
    }
    unsupported(block, instruction);
  }

  /// rol / ror by an immediate: two shifts and an or through temporaries.
  void lift_rotate(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() != 2 || operands[0].kind != OperandKind::Register ||
        operands[1].kind != OperandKind::Immediate) {
      unsupported(block, instruction);
      return;
    }
    const IrOperand value = to_ir_operand(operands[0], instruction, pointer_width);
    const unsigned bits = value.width * 8U;
    const unsigned count = static_cast<unsigned>(operands[1].immediate) % bits;
    flags_state = FlagsState::Unknown;  // CF/OF change, ZF does not: not modelled
    if (count == 0) {
      return;
    }
    const bool left = instruction.mnemonic == "rol";
    const IrOperand high = temp_operand(temporary_id(), value.width);
    const IrOperand low = temp_operand(temporary_id(), value.width);
    IrStatement first;
    first.op = left ? IrOp::Shl : IrOp::Shr;
    first.dest = high;
    first.a = value;
    first.b = IrOperand::constant_value(count, 1);
    first.width = value.width;
    first.source_address = instruction.address;
    push(block, std::move(first));
    IrStatement second;
    second.op = left ? IrOp::Shr : IrOp::Shl;
    second.dest = low;
    second.a = value;
    second.b = IrOperand::constant_value(bits - count, 1);
    second.width = value.width;
    second.source_address = instruction.address;
    push(block, std::move(second));
    IrStatement combine;
    combine.op = IrOp::Or;
    combine.dest = value;
    combine.a = high;
    combine.b = low;
    combine.width = value.width;
    combine.source_address = instruction.address;
    push(block, std::move(combine));
  }

  /// cmovcc (dest = src if cond) and setcc (dest = cond ? 1 : 0).
  void lift_conditional(IrBlock& block, const Instruction& instruction, bool set) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    const IrCondition condition = suffix_condition(instruction.mnemonic, set ? 3U : 4U);
    if (flags_state == FlagsState::Unknown ||
        (flags_state == FlagsState::ZeroSign && !zero_sign_condition(condition))) {
      mark_partial("'" + instruction.mnemonic + "' reads flags this lifter does not model");
    }
    if ((set && operands.size() != 1) || (!set && operands.size() != 2) ||
        operands[0].kind != OperandKind::Register) {
      unsupported(block, instruction);
      return;
    }
    const IrOperand destination = to_ir_operand(operands[0], instruction, pointer_width);
    if (set) {
      IrStatement clear;
      clear.op = IrOp::Assign;
      clear.dest = destination;
      clear.a = IrOperand::constant_value(0, destination.width);
      clear.width = destination.width;
      clear.source_address = instruction.address;
      push(block, std::move(clear));
    } else if (destination.width == 4) {
      // A 32-bit cmov zero-extends its destination even when it does not
      // move: model that before the conditional part.
      IrStatement widen;
      widen.op = IrOp::Assign;
      widen.dest = destination;
      widen.a = destination;
      widen.width = destination.width;
      widen.source_address = instruction.address;
      push(block, std::move(widen));
    }
    IrStatement statement;
    statement.op = IrOp::CondAssign;
    statement.condition = condition;
    statement.dest = destination;
    statement.a = set ? IrOperand::constant_value(1, destination.width)
                      : to_ir_operand(operands[1], instruction, pointer_width);
    statement.width = destination.width;
    statement.source_address = instruction.address;
    push(block, std::move(statement));
  }

  void lift_compare(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() != 2) {
      unsupported(block, instruction);
      return;
    }
    IrStatement statement;
    statement.op = IrOp::Compare;
    statement.a = to_ir_operand(operands[0], instruction, pointer_width);
    statement.b = to_ir_operand(operands[1], instruction, pointer_width);
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
    statement.a = to_ir_operand(operands[0], instruction, pointer_width);
    statement.b = to_ir_operand(operands[1], instruction, pointer_width);
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
    const IrOperand source = to_ir_operand(operands[0], instruction, pointer_width);
    if (source.kind == IrOperandKind::None) {
      // An operand this lifter cannot model would produce malformed IR.
      unsupported(block, instruction);
      return;
    }
    IrStatement decrement;
    decrement.op = IrOp::Sub;
    decrement.dest = IrOperand::register_ref(stack_pointer, pointer_width);
    decrement.a = IrOperand::register_ref(stack_pointer, pointer_width);
    decrement.b = IrOperand::constant_value(pointer_width, pointer_width);
    decrement.width = pointer_width;
    decrement.source_address = instruction.address;
    push(block, std::move(decrement));

    IrOperand slot;
    slot.kind = IrOperandKind::Memory;
    slot.reg = stack_pointer;
    slot.width = pointer_width;
    IrStatement store;
    store.op = IrOp::Store;
    store.a = slot;
    store.b = source;
    store.width = pointer_width;
    store.source_address = instruction.address;
    push(block, std::move(store));
  }

  void lift_pop(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() != 1) {
      unsupported(block, instruction);
      return;
    }
    const IrOperand destination = to_ir_operand(operands[0], instruction, pointer_width);
    if (destination.kind != IrOperandKind::Register) {
      // pop with a memory destination would need a load/store pair; model it
      // as unsupported rather than emitting a Load with no register result.
      unsupported(block, instruction);
      return;
    }
    IrOperand slot;
    slot.kind = IrOperandKind::Memory;
    slot.reg = stack_pointer;
    slot.width = pointer_width;
    IrStatement load;
    load.op = IrOp::Load;
    load.dest = destination;
    load.a = slot;
    load.width = pointer_width;
    load.source_address = instruction.address;
    push(block, std::move(load));

    IrStatement increment;
    increment.op = IrOp::Add;
    increment.dest = IrOperand::register_ref(stack_pointer, pointer_width);
    increment.a = IrOperand::register_ref(stack_pointer, pointer_width);
    increment.b = IrOperand::constant_value(pointer_width, pointer_width);
    increment.width = pointer_width;
    increment.source_address = instruction.address;
    push(block, std::move(increment));
  }

  void lift_leave(IrBlock& block, const Instruction& instruction) {
    IrStatement restore_stack;
    restore_stack.op = IrOp::Assign;
    restore_stack.dest = IrOperand::register_ref(stack_pointer, pointer_width);
    restore_stack.a = IrOperand::register_ref(frame_pointer, pointer_width);
    restore_stack.width = pointer_width;
    restore_stack.source_address = instruction.address;
    push(block, std::move(restore_stack));

    IrOperand slot;
    slot.kind = IrOperandKind::Memory;
    slot.reg = stack_pointer;
    slot.width = pointer_width;
    IrStatement load;
    load.op = IrOp::Load;
    load.dest = IrOperand::register_ref(frame_pointer, pointer_width);
    load.a = slot;
    load.width = pointer_width;
    load.source_address = instruction.address;
    push(block, std::move(load));

    IrStatement increment;
    increment.op = IrOp::Add;
    increment.dest = IrOperand::register_ref(stack_pointer, pointer_width);
    increment.a = IrOperand::register_ref(stack_pointer, pointer_width);
    increment.b = IrOperand::constant_value(pointer_width, pointer_width);
    increment.width = pointer_width;
    increment.source_address = instruction.address;
    push(block, std::move(increment));
  }

  void lift_call(IrBlock& block, const Instruction& instruction) {
    IrStatement statement;
    statement.op = IrOp::Call;
    statement.width = pointer_width;
    statement.source_address = instruction.address;
    if (instruction.direct_target.has_value()) {
      statement.a = IrOperand::constant_value(instruction.direct_target.value(), pointer_width);
    } else if (!instruction.structured_operands.empty()) {
      statement.a =
          to_ir_operand(instruction.structured_operands.front(), instruction, pointer_width);
    } else {
      statement.a = IrOperand::constant_value(0, pointer_width);
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
      infer_signature(lifted.value(), image.architecture, image.format);
    }
    return lifted;
  }
  if (image.architecture != Architecture::X86_64 && image.architecture != Architecture::X86) {
    return make_error<IrFunction>(
        Status::Unsupported, "lift.unsupported_architecture",
        "the lifter models x86, x86-64 and AArch64 only; no pseudocode is produced for other "
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
      image.architecture == Architecture::X86
          ? "x86-32 subset; register aliases are not canonicalised, cdecl stack arguments are "
            "not recovered and locals are not recovered"
          : "x86-64 subset; register aliases are not canonicalised and locals are not recovered");

  for (const BasicBlock* block : lifter.blocks) {
    IrBlock out_block;
    out_block.address = block->address;
    // Flags are only followed within a block.
    lifter.flags_state = Lifter::FlagsState::Unknown;

    // The condition the next flag reader in this block uses, if one reads the
    // flags written by instruction `i` before anything else writes them.
    auto next_consumer = [&](std::uint32_t i) -> std::optional<IrCondition> {
      for (std::uint32_t j = i + 1; j < block->instruction_count; ++j) {
        const std::size_t at = static_cast<std::size_t>(block->first_instruction) + j;
        if (at >= analysis.instructions.size()) {
          break;
        }
        const Instruction& next = analysis.instructions[at];
        if (next.classification == InstructionClass::ConditionalJump) {
          return branch_condition(next.mnemonic);
        }
        if (is_cmov(next.mnemonic)) {
          return suffix_condition(next.mnemonic, 4);
        }
        if (is_setcc(next.mnemonic)) {
          return suffix_condition(next.mnemonic, 3);
        }
        if (!preserves_flags(next.mnemonic) || next.classification != InstructionClass::Other) {
          break;  // overwritten, or control leaves the block
        }
      }
      return std::nullopt;
    };

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
        statement.width = lifter.pointer_width;
        statement.condition = condition;
        statement.a = IrOperand::register_ref("flags", lifter.pointer_width);
        if (lifter.flags_state == Lifter::FlagsState::Unknown ||
            (lifter.flags_state == Lifter::FlagsState::ZeroSign &&
             !zero_sign_condition(condition))) {
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
        continue;
      }

      if (instruction.classification == InstructionClass::Jump) {
        IrStatement statement;
        statement.op = IrOp::Branch;
        statement.source_address = instruction.address;
        statement.width = lifter.pointer_width;
        const auto target = instruction.direct_target.has_value()
                                ? lifter.block_by_address.find(instruction.direct_target.value())
                                : lifter.block_by_address.end();
        const JumpTable* table = nullptr;
        if (!instruction.direct_target.has_value()) {
          for (const JumpTable& candidate : analysis.cfg.jump_tables) {
            if (candidate.jump_address == instruction.address) {
              table = &candidate;
            }
          }
        }
        if (table != nullptr) {
          // A jump table the analysis recovered from the bounds check and the
          // table bytes: a switch over the compared operand.
          const auto check =
              std::find_if(analysis.instructions.begin(), analysis.instructions.end(),
                           [&](const Instruction& candidate_instruction) {
                             return candidate_instruction.address == table->check_address;
                           });
          bool cases_in_function = check != analysis.instructions.end();
          IrStatement sw;
          sw.op = IrOp::Switch;
          sw.source_address = instruction.address;
          sw.width = lifter.pointer_width;
          if (cases_in_function) {
            sw.dest = to_ir_operand(table->selector, *check, lifter.pointer_width);
          }
          for (std::size_t value = 0; value < table->targets.size() && cases_in_function; ++value) {
            const auto block_it = lifter.block_by_address.find(table->targets[value]);
            if (block_it == lifter.block_by_address.end()) {
              cases_in_function = false;
              break;
            }
            sw.switch_cases.push_back(IrSwitchCase{value, block_it->second});
          }
          const auto fallback = lifter.block_by_address.find(table->default_target);
          if (cases_in_function && sw.dest.kind != IrOperandKind::None) {
            if (fallback != lifter.block_by_address.end()) {
              sw.a = IrOperand::block_ref(fallback->second);
            } else {
              // Out-of-range selectors were sent elsewhere by the bounds check
              // before this jump, so the default is unreachable here.
              sw.a = IrOperand::block_ref(sw.switch_cases.front().target_block);
            }
            lifter.push(out_block, std::move(sw));
            continue;
          }
          lifter.mark_partial("jump table cases lie outside this function");
        }
        if (target == lifter.block_by_address.end()) {
          // Tail call or an unmodelled target: stop here instead of inventing
          // a block. Calling the target is the honest reading.
          IrStatement call;
          call.op = IrOp::Call;
          call.source_address = instruction.address;
          call.width = lifter.pointer_width;
          call.a = instruction.direct_target.has_value()
                       ? IrOperand::constant_value(instruction.direct_target.value(),
                                                   lifter.pointer_width)
                       : IrOperand::constant_value(0, lifter.pointer_width);
          lifter.push(out_block, std::move(call));
          lifter.mark_partial("jump leaves the function; treated as a tail call");
          IrStatement tail;
          tail.op = IrOp::Return;
          tail.source_address = instruction.address;
          tail.width = lifter.pointer_width;
          tail.a = IrOperand::register_ref(lifter.return_register, lifter.pointer_width);
          lifter.push(out_block, std::move(tail));
        } else {
          statement.a = IrOperand::block_ref(target->second);
          lifter.push(out_block, std::move(statement));
        }
        continue;
      }

      if (instruction.classification == InstructionClass::Return) {
        IrStatement statement;
        statement.op = IrOp::Return;
        statement.source_address = instruction.address;
        statement.width = lifter.pointer_width;
        statement.a = IrOperand::register_ref(lifter.return_register, lifter.pointer_width);
        lifter.push(out_block, std::move(statement));
        continue;
      }

      if (instruction.classification == InstructionClass::Interrupt) {
        lifter.unsupported(out_block, instruction);
        IrStatement statement;
        statement.op = IrOp::Return;
        statement.source_address = instruction.address;
        statement.width = lifter.pointer_width;
        lifter.push(out_block, std::move(statement));
        continue;
      }

      const auto flags_before = lifter.flags_state;
      bool keeps_flags = preserves_flags(mnemonic);
      if (mnemonic == "mov" || mnemonic == "movabs") {
        lifter.lift_mov(out_block, instruction);
      } else if (mnemonic == "movzx" || mnemonic == "movsx" || mnemonic == "movsxd") {
        lifter.lift_extend(out_block, instruction);
      } else if (mnemonic == "lea") {
        lifter.lift_lea(out_block, instruction);
      } else if (mnemonic == "cmp") {
        lifter.lift_compare(out_block, instruction);
        lifter.flags_state = Lifter::FlagsState::Exact;
        keeps_flags = true;  // state set above
      } else if (mnemonic == "test") {
        lifter.lift_test(out_block, instruction);
        lifter.flags_state = Lifter::FlagsState::Exact;
        keeps_flags = true;
      } else if (is_bitwise_or_arithmetic(mnemonic) || mnemonic == "inc" || mnemonic == "dec") {
        lifter.lift_arithmetic(out_block, instruction, next_consumer(i));
        keeps_flags = true;  // lift_arithmetic set the state
      } else if (mnemonic == "neg" || mnemonic == "not") {
        lifter.lift_unary(out_block, instruction, next_consumer(i));
        keeps_flags = true;  // lift_unary set the state
      } else if (mnemonic == "rol" || mnemonic == "ror") {
        lifter.lift_rotate(out_block, instruction);
        keeps_flags = true;
      } else if (is_cmov(mnemonic)) {
        lifter.lift_conditional(out_block, instruction, false);
      } else if (is_setcc(mnemonic)) {
        lifter.lift_conditional(out_block, instruction, true);
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
                 mnemonic == "cwd" || mnemonic == "cwde" || mnemonic == "cbw") {
        lifter.lift_sign_widen(out_block, instruction);
      } else {
        lifter.unsupported(out_block, instruction);
        keeps_flags = false;
      }
      if (!keeps_flags) {
        lifter.flags_state = Lifter::FlagsState::Unknown;
      } else if (preserves_flags(mnemonic)) {
        lifter.flags_state = flags_before;
      }
      if (lifter.limit_reached()) {
        lifter.mark_partial("statement limit reached");
        break;
      }
    }

    if (out_block.statements.empty() || (out_block.statements.back().op != IrOp::Branch &&
                                         out_block.statements.back().op != IrOp::CondBranch &&
                                         out_block.statements.back().op != IrOp::Switch &&
                                         out_block.statements.back().op != IrOp::Return)) {
      const auto next = lifter.block_by_address.find(block->end_address);
      if (next != lifter.block_by_address.end()) {
        IrStatement statement;
        statement.op = IrOp::Branch;
        statement.a = IrOperand::block_ref(next->second);
        statement.width = lifter.pointer_width;
        statement.source_address = block->end_address;
        lifter.push(out_block, std::move(statement));
      } else {
        IrStatement statement;
        statement.op = IrOp::Return;
        statement.width = lifter.pointer_width;
        statement.source_address = block->end_address;
        statement.a = IrOperand::register_ref(lifter.return_register, lifter.pointer_width);
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
    statement.width = lifter.pointer_width;
    statement.source_address = exit_block.address;
    statement.a = IrOperand::register_ref(lifter.return_register, lifter.pointer_width);
    exit_block.statements.push_back(std::move(statement));
    lifter.out.blocks.push_back(std::move(exit_block));
    lifter.out.partial = true;
    lifter.note("conditional fallthrough leaves the function; exit path is unmodelled");
  }
  infer_signature(lifter.out, image.architecture, image.format);
  return lifter.out;
}

}  // namespace donkey
