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
#include "registers.h"

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
  if (found != kWidths.end()) {
    return found->second;
  }
  // An XMM register is modelled by its low 8 bytes (the scalar lane).
  return name.rfind("xmm", 0) == 0 ? 8 : 0;
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
  if (mnemonic == "jp" || mnemonic == "jpe") {
    return IrCondition::Parity;  // unordered after an FP comparison
  }
  if (mnemonic == "jnp" || mnemonic == "jpo") {
    return IrCondition::NoParity;
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

/// Scalar single and double SSE instructions that the lifter models. Only the low
/// lane of an XMM register is modelled, so an instruction that needs the upper
/// lanes is not in this list.
bool is_scalar_sse(const std::string& mnemonic) {
  static const char* const kNames[] = {
      "addss",    "addsd",    "subss",     "subsd",     "mulss",    "mulsd",    "divss",
      "divsd",    "sqrtss",   "sqrtsd",    "movss",     "movsd",    "movaps",   "movapd",
      "cvtsi2ss", "cvtsi2sd", "cvttss2si", "cvttsd2si", "cvtss2sd", "cvtsd2ss", "ucomiss",
      "ucomisd",  "comiss",   "comisd",    "xorps",     "xorpd",    "pxor",
  };
  return std::find(std::begin(kNames), std::end(kNames), mnemonic) != std::end(kNames);
}

/// The comparisons that set the flags from an FP comparison.
bool is_sse_compare(const std::string& mnemonic) {
  return mnemonic == "ucomiss" || mnemonic == "ucomisd" || mnemonic == "comiss" ||
         mnemonic == "comisd";
}

/// Instructions that leave the flags exactly as they were.
bool preserves_flags(const std::string& mnemonic) {
  return mnemonic == "mov" || mnemonic == "movabs" || mnemonic == "movzx" || mnemonic == "movsx" ||
         mnemonic == "movsxd" || mnemonic == "lea" || mnemonic == "push" || mnemonic == "pop" ||
         mnemonic == "nop" || mnemonic == "endbr64" || mnemonic == "endbr32" ||
         mnemonic == "cdqe" || mnemonic == "cdq" || mnemonic == "cqo" || mnemonic == "cwde" ||
         mnemonic == "cbw" || mnemonic == "cwd" || mnemonic == "not" || is_cmov(mnemonic) ||
         is_setcc(mnemonic) || (is_scalar_sse(mnemonic) && !is_sse_compare(mnemonic));
}

/// xchg of two registers: a swap that leaves the flags alone. The memory forms
/// need a load and a store, so they are not register exchanges.
bool is_register_exchange(const Instruction& instruction) {
  const std::vector<Operand>& operands = instruction.structured_operands;
  return instruction.mnemonic == "xchg" && operands.size() == 2 &&
         operands[0].kind == OperandKind::Register && operands[1].kind == OperandKind::Register;
}

/// Conditions that read only ZF and SF, which every flag-setting arithmetic
/// instruction derives from its result alone.
bool zero_sign_condition(IrCondition condition) {
  return condition == IrCondition::Zero || condition == IrCondition::NonZero ||
         condition == IrCondition::Equal || condition == IrCondition::NotEqual ||
         condition == IrCondition::Negative || condition == IrCondition::Positive;
}

/// Conditions that read only CF (jb, jae, setb, cmovae, ...), and adc/sbb. A
/// Compare's unsigned conditions are exactly the carry: `a <u b` is CF after
/// `cmp a, b`, and the lifter writes jb / setb as UnsignedLess.
bool carry_condition(IrCondition condition) {
  return condition == IrCondition::Carry || condition == IrCondition::NoCarry ||
         condition == IrCondition::UnsignedLess || condition == IrCondition::UnsignedGreaterEqual;
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

  /// What the IR knows about the flags a later jcc / cmovcc / setcc / adc reads.
  /// Exact: every flag. ZeroSign: ZF and SF only. CarryOnly: CF only (the last
  /// Compare holds the operands that give CF exactly, but not ZF or SF).
  enum class FlagsState { Unknown, Exact, ZeroSign, CarryOnly };
  FlagsState flags_state = FlagsState::Unknown;

  /// True when the modelled flags give `condition` exactly.
  bool flags_readable(IrCondition condition) const {
    switch (flags_state) {
      case FlagsState::Unknown:
        return false;
      case FlagsState::Exact:
        return true;
      case FlagsState::ZeroSign:
        return zero_sign_condition(condition);
      case FlagsState::CarryOnly:
        return carry_condition(condition);
    }
    return false;
  }

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
    const FlagsState prior_flags = flags_state;
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
    if (shift && source.kind == IrOperandKind::Constant) {
      // x86 masks the count to 5 bits (6 for 64-bit operands): `shl eax, 32`
      // shifts by 0. Emit the effective count.
      source.constant &= destination.width >= 8 ? 0x3FU : 0x1FU;
    }
    // A shift by an effective count of zero (a register may hold one) changes
    // neither the destination nor the flags, so its flags are not defined here.
    const bool flags_defined =
        mnemonic != "imul" &&
        (!shift || (source.kind == IrOperandKind::Constant && source.constant != 0));
    if (shift && source.kind == IrOperandKind::Constant && source.constant == 0) {
      // Known not to touch the flags: the previous flag writer's Compare/Test
      // is still the last one in the block, so whatever it modelled holds.
      flags_state = prior_flags;
    }

    if (destination.kind == IrOperandKind::Register) {
      std::optional<IrOperand> saved;
      // The flags are derived from the operands the operation read. An operand
      // that is also the destination is overwritten by the operation, so it is
      // copied first: `sub x, x` and `add x, x` need the original value.
      const bool carry_add = mnemonic == "add" && consumer && carry_condition(*consumer);
      const bool needs_operands =
          consumer && flags_defined && (subtract ? !zero_sign_condition(*consumer) : carry_add);
      auto copy_before = [&](const IrOperand& value) {
        const IrOperand copy_of = temp_operand(temporary_id(), value.width);
        IrStatement copy;
        copy.op = IrOp::Assign;
        copy.dest = copy_of;
        copy.a = value;
        copy.width = value.width;
        copy.source_address = instruction.address;
        push(block, std::move(copy));
        return copy_of;
      };
      if (needs_operands && subtract) {
        // Keep the minuend: the condition compares it with the subtrahend.
        saved = copy_before(destination);
      }
      // The Compare reads the source again after the destination is written. A
      // source that the destination is part of (a register, or a memory address
      // formed from it, as in `add rax, [rax]`) must be copied before the write.
      std::optional<IrOperand> saved_source;
      const std::string destination_family = internal::register_family(destination.reg);
      const bool source_uses_destination =
          source.kind == IrOperandKind::Register
              ? internal::register_family(source.reg) == destination_family
              : source.kind == IrOperandKind::Memory &&
                    (internal::register_family(source.reg) == destination_family ||
                     internal::register_family(source.index) == destination_family);
      if (needs_operands && source_uses_destination) {
        saved_source = copy_before(source);
      }
      IrStatement statement;
      statement.op = op;
      statement.dest = destination;
      statement.a = left;
      statement.b = source;
      statement.width = destination.width;
      statement.source_address = instruction.address;
      push(block, std::move(statement));
      if (needs_operands) {
        const IrOperand compared = saved_source ? *saved_source : source;
        IrStatement compare;
        compare.op = IrOp::Compare;
        compare.b = compared;
        compare.width = destination.width;
        compare.source_address = instruction.address;
        if (saved) {
          compare.a = *saved;
          compare.condition = IrCondition::Equal;
          push(block, std::move(compare));
          flags_state = FlagsState::Exact;
        } else {
          // add: the carry out is set exactly when the sum is below the addend.
          compare.a = destination;
          compare.condition = IrCondition::UnsignedLess;
          push(block, std::move(compare));
          flags_state = FlagsState::CarryOnly;
        }
      } else if (consumer && flags_defined) {
        push(block, flags_test_of(destination, instruction.address));
        flags_state = logic ? FlagsState::Exact : FlagsState::ZeroSign;
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

  /// popcnt, tzcnt, lzcnt and bswap (register destination; popcnt, tzcnt and
  /// lzcnt take a register or memory source). popcnt, tzcnt and lzcnt write
  /// flags that are not modelled. bswap leaves the flags alone. Memory
  /// destinations and the 8- and 16-bit forms are Unsupported.
  void lift_bit_operation(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    const std::string& mnemonic = instruction.mnemonic;
    if (mnemonic == "bt" || mnemonic == "bts" || mnemonic == "btr" || mnemonic == "btc") {
      lift_bit_test(block, instruction);
      return;
    }
    const bool swap = mnemonic == "bswap";
    if (!swap) {
      flags_state = FlagsState::Unknown;
    }
    if (operands.size() != (swap ? 1U : 2U) || operands[0].kind != OperandKind::Register ||
        (!swap && operands[1].kind != OperandKind::Register &&
         operands[1].kind != OperandKind::Memory)) {
      unsupported(block, instruction);
      return;
    }
    const IrOperand destination = to_ir_operand(operands[0], instruction, pointer_width);
    if (destination.width != 4 && destination.width != 8) {
      unsupported(block, instruction);
      return;
    }
    IrOperand source = destination;
    if (!swap) {
      source = to_ir_operand(operands[1], instruction, pointer_width);
      if (source.kind == IrOperandKind::Memory) {
        // The memory operand is read first, into a temporary of the operation's width.
        const IrOperand value = temp_operand(temporary_id(), destination.width);
        IrStatement load;
        load.op = IrOp::Load;
        load.dest = value;
        load.a = source;
        load.width = destination.width;
        load.source_address = instruction.address;
        push(block, std::move(load));
        source = value;
      }
    }
    IrStatement statement;
    if (mnemonic == "popcnt") {
      statement.op = IrOp::PopCount;
    } else if (mnemonic == "tzcnt") {
      statement.op = IrOp::CountTrailingZeros;
    } else if (mnemonic == "lzcnt") {
      statement.op = IrOp::CountLeadingZeros;
    } else {
      statement.op = IrOp::ByteSwap;
    }
    statement.dest = destination;
    statement.a = source;
    statement.width = destination.width;
    statement.source_address = instruction.address;
    push(block, std::move(statement));
  }

  /// bt, bts, btr and btc with a register destination and a register or immediate
  /// bit index. CF becomes the selected bit, and the other flags are undefined.
  /// The IR states CF as `0 <u bit`, which is the CarryOnly state. bts, btr and
  /// btc then set, clear or flip that bit. A memory destination, whose bit can
  /// lie outside the operand, is Unsupported.
  void lift_bit_test(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    flags_state = FlagsState::Unknown;
    if (operands.size() != 2 || operands[0].kind != OperandKind::Register ||
        (operands[1].kind != OperandKind::Register && operands[1].kind != OperandKind::Immediate)) {
      unsupported(block, instruction);
      return;
    }
    const IrOperand value = to_ir_operand(operands[0], instruction, pointer_width);
    if (value.width != 4 && value.width != 8) {
      unsupported(block, instruction);
      return;
    }
    const std::uint8_t width = value.width;
    const std::uint64_t mask_bits = static_cast<std::uint64_t>(width) * 8U - 1U;
    const auto emit = [&](IrOp op, const IrOperand& dest, const IrOperand& a, const IrOperand& b,
                          IrCondition condition) {
      IrStatement statement;
      statement.op = op;
      statement.dest = dest;
      statement.a = a;
      statement.b = b;
      statement.condition = condition;
      statement.width = width;
      statement.source_address = instruction.address;
      push(block, std::move(statement));
    };
    IrOperand index = IrOperand::constant_value(0, width);
    if (operands[1].kind == OperandKind::Immediate) {
      index = IrOperand::constant_value(
          static_cast<std::uint64_t>(operands[1].immediate) & mask_bits, width);
    } else {
      // A register index is taken modulo the operand width.
      const IrOperand selector = to_ir_operand(operands[1], instruction, pointer_width);
      if (selector.width != width) {
        unsupported(block, instruction);
        return;
      }
      const IrOperand masked = temp_operand(temporary_id(), width);
      emit(IrOp::And, masked, selector, IrOperand::constant_value(mask_bits, width),
           IrCondition::None);
      index = masked;
    }
    const IrOperand shifted = temp_operand(temporary_id(), width);
    emit(IrOp::Shr, shifted, value, index, IrCondition::None);
    const IrOperand bit = temp_operand(temporary_id(), width);
    emit(IrOp::And, bit, shifted, IrOperand::constant_value(1, width), IrCondition::None);
    // CF = bit, which is `0 <u bit`.
    emit(IrOp::Compare, IrOperand::none(), IrOperand::constant_value(0, width), bit,
         IrCondition::UnsignedLess);
    flags_state = FlagsState::CarryOnly;
    if (instruction.mnemonic == "bt") {
      return;
    }
    // bts sets the selected bit, btr clears it and btc flips it. CF was read into
    // `bit` above, so the write does not change it.
    const IrOperand mask = temp_operand(temporary_id(), width);
    emit(IrOp::Shl, mask, IrOperand::constant_value(1, width), index, IrCondition::None);
    if (instruction.mnemonic == "bts") {
      emit(IrOp::Or, value, value, mask, IrCondition::None);
    } else if (instruction.mnemonic == "btc") {
      emit(IrOp::Xor, value, value, mask, IrCondition::None);
    } else {
      // btr: AND with the complement of the mask.
      const std::uint64_t all_ones = width == 8 ? ~0ULL : 0xFFFF'FFFFULL;
      const IrOperand clear = temp_operand(temporary_id(), width);
      emit(IrOp::Xor, clear, mask, IrOperand::constant_value(all_ones, width), IrCondition::None);
      emit(IrOp::And, value, value, clear, IrCondition::None);
    }
  }

  /// movbe with a register and a memory operand: a load of the memory operand
  /// with its bytes reversed (`movbe reg, mem`), or the reverse, a store
  /// (`movbe mem, reg`). Only 32- and 64-bit forms are lifted; movbe leaves the
  /// flags alone.
  void lift_movbe(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (operands.size() != 2 ||
        !((operands[0].kind == OperandKind::Register && operands[1].kind == OperandKind::Memory) ||
          (operands[0].kind == OperandKind::Memory && operands[1].kind == OperandKind::Register))) {
      unsupported(block, instruction);
      return;
    }
    const bool load = operands[0].kind == OperandKind::Register;
    const IrOperand register_operand =
        to_ir_operand(operands[load ? 0 : 1], instruction, pointer_width);
    const IrOperand memory_operand =
        to_ir_operand(operands[load ? 1 : 0], instruction, pointer_width);
    const std::uint8_t width = register_operand.width;
    if (width != 4 && width != 8) {
      unsupported(block, instruction);
      return;
    }
    if (load) {
      // reg = bswap(load(mem)).
      const IrOperand value = temp_operand(temporary_id(), width);
      IrStatement fetch;
      fetch.op = IrOp::Load;
      fetch.dest = value;
      fetch.a = memory_operand;
      fetch.width = width;
      fetch.source_address = instruction.address;
      push(block, std::move(fetch));
      IrStatement swap;
      swap.op = IrOp::ByteSwap;
      swap.dest = register_operand;
      swap.a = value;
      swap.width = width;
      swap.source_address = instruction.address;
      push(block, std::move(swap));
      return;
    }
    // store(mem, bswap(reg)).
    const IrOperand value = temp_operand(temporary_id(), width);
    IrStatement swap;
    swap.op = IrOp::ByteSwap;
    swap.dest = value;
    swap.a = register_operand;
    swap.width = width;
    swap.source_address = instruction.address;
    push(block, std::move(swap));
    IrStatement store;
    store.op = IrOp::Store;
    store.a = memory_operand;
    store.b = value;
    store.width = width;
    store.source_address = instruction.address;
    push(block, std::move(store));
  }

  /// mul / imul with one operand, and div / idiv, which use the implicit rax and
  /// rdx operands: rdx:rax = rax * source, or rax = rdx:rax / source and
  /// rdx = rdx:rax % source. The 8- and 16-bit forms use other registers and are
  /// Unsupported. The flags after these are not modelled.
  void lift_multiply_divide(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    const std::string& mnemonic = instruction.mnemonic;
    flags_state = FlagsState::Unknown;
    if (operands.size() != 1 ||
        (operands[0].kind != OperandKind::Register && operands[0].kind != OperandKind::Memory)) {
      unsupported(block, instruction);
      return;
    }
    IrOperand source = to_ir_operand(operands[0], instruction, pointer_width);
    const std::uint8_t width = source.width;
    if (width != 4 && width != 8) {
      unsupported(block, instruction);
      return;
    }
    if (source.kind == IrOperandKind::Memory) {
      // The memory operand is read first, into a temporary of the operation's width.
      const IrOperand value = temp_operand(temporary_id(), width);
      IrStatement load;
      load.op = IrOp::Load;
      load.dest = value;
      load.a = source;
      load.width = width;
      load.source_address = instruction.address;
      push(block, std::move(load));
      source = value;
    }
    const IrOperand accumulator = IrOperand::register_ref(width == 8 ? "rax" : "eax", width);
    const IrOperand high = IrOperand::register_ref(width == 8 ? "rdx" : "edx", width);
    const auto emit = [&](IrOp op, const IrOperand& dest, const IrOperand& a, const IrOperand& b,
                          const IrOperand& c) {
      IrStatement statement;
      statement.op = op;
      statement.dest = dest;
      statement.a = a;
      statement.b = b;
      statement.c = c;
      statement.width = width;
      statement.source_address = instruction.address;
      push(block, std::move(statement));
    };
    if (mnemonic == "mul" || mnemonic == "imul") {
      // Both halves are computed before either register is written.
      const bool is_signed = mnemonic == "imul";
      const IrOperand high_part = temp_operand(temporary_id(), width);
      const IrOperand low_part = temp_operand(temporary_id(), width);
      emit(is_signed ? IrOp::MulHighSigned : IrOp::MulHighUnsigned, high_part, accumulator, source,
           IrOperand::none());
      emit(IrOp::Mul, low_part, accumulator, source, IrOperand::none());
      emit(IrOp::Assign, high, high_part, IrOperand::none(), IrOperand::none());
      emit(IrOp::Assign, accumulator, low_part, IrOperand::none(), IrOperand::none());
      return;
    }
    const bool is_signed = mnemonic == "idiv";
    const IrOperand quotient = temp_operand(temporary_id(), width);
    const IrOperand remainder = temp_operand(temporary_id(), width);
    emit(is_signed ? IrOp::DivSigned : IrOp::DivUnsigned, quotient, high, accumulator, source);
    emit(is_signed ? IrOp::RemSigned : IrOp::RemUnsigned, remainder, high, accumulator, source);
    emit(IrOp::Assign, accumulator, quotient, IrOperand::none(), IrOperand::none());
    emit(IrOp::Assign, high, remainder, IrOperand::none(), IrOperand::none());
  }

  /// xchg reg, reg: a swap through a temporary. An exchange leaves the flags alone.
  /// Returns false when the exchange is Unsupported, which invalidates the flags.
  bool lift_exchange(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    if (!is_register_exchange(instruction)) {
      unsupported(block, instruction);  // with memory it needs a load and a store
      return false;
    }
    const IrOperand first = to_ir_operand(operands[0], instruction, pointer_width);
    const IrOperand second = to_ir_operand(operands[1], instruction, pointer_width);
    if (first.width != second.width) {
      unsupported(block, instruction);
      return false;
    }
    const IrOperand saved = temp_operand(temporary_id(), first.width);
    const auto assign = [&](const IrOperand& dest, const IrOperand& source) {
      IrStatement statement;
      statement.op = IrOp::Assign;
      statement.dest = dest;
      statement.a = source;
      statement.width = dest.width;
      statement.source_address = instruction.address;
      push(block, std::move(statement));
    };
    assign(saved, first);
    assign(first, second);
    assign(second, saved);
    return true;
  }

  /// adc / sbb with a register destination: dest = dest +/- source +/- CF. The
  /// carry is read through the flag model, so it must be exact there: the last
  /// flag writer must have set CF (a compare, a test, or an add whose consumer
  /// reads CF). Otherwise the instruction is Unsupported, which makes the
  /// function Partial.
  void lift_add_with_carry(IrBlock& block, const Instruction& instruction,
                           std::optional<IrCondition> consumer) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    const bool subtract = instruction.mnemonic == "sbb";
    if (operands.size() != 2 || operands[0].kind != OperandKind::Register ||
        (operands[1].kind != OperandKind::Register && operands[1].kind != OperandKind::Immediate &&
         operands[1].kind != OperandKind::Memory) ||
        !flags_readable(IrCondition::Carry)) {
      flags_state = FlagsState::Unknown;
      unsupported(block, instruction);
      return;
    }
    const IrOperand destination = to_ir_operand(operands[0], instruction, pointer_width);
    IrStatement statement;
    statement.op = subtract ? IrOp::SubBorrow : IrOp::AddCarry;
    statement.dest = destination;
    statement.a = destination;
    if (operands[1].kind == OperandKind::Memory) {
      // The memory operand is loaded first. A load leaves the flags alone.
      const IrOperand value = temp_operand(temporary_id(), destination.width);
      IrStatement load;
      load.op = IrOp::Load;
      load.dest = value;
      load.a = memory_operand(operands[1], instruction);
      load.width = destination.width;
      load.source_address = instruction.address;
      push(block, std::move(load));
      statement.b = value;
    } else {
      statement.b = to_ir_operand(operands[1], instruction, pointer_width);
    }
    statement.width = destination.width;
    statement.source_address = instruction.address;
    push(block, std::move(statement));
    flags_state = FlagsState::Unknown;  // the carry out is not modelled
    if (consumer) {
      push(block, flags_test_of(destination, instruction.address));
      flags_state = FlagsState::ZeroSign;
    }
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
    if (!flags_readable(condition)) {
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

  static bool is_xmm(const Operand& operand) {
    return operand.kind == OperandKind::Register && operand.reg.rfind("xmm", 0) == 0;
  }

  IrStatement statement_of(IrOp op, IrOperand dest, IrOperand a, IrOperand b, std::uint8_t width,
                           const Instruction& instruction) const {
    IrStatement statement;
    statement.op = op;
    statement.dest = std::move(dest);
    statement.a = std::move(a);
    statement.b = std::move(b);
    statement.width = width;
    statement.source_address = instruction.address;
    return statement;
  }

  /// A source operand of `width` bytes: an XMM register, or a memory operand loaded
  /// into a temporary. Returns nullopt for anything else.
  std::optional<IrOperand> sse_source(IrBlock& block, const Instruction& instruction,
                                      const Operand& operand, std::uint8_t width) {
    if (is_xmm(operand)) {
      return IrOperand::register_ref(operand.reg, width);
    }
    if (operand.kind != OperandKind::Memory) {
      return std::nullopt;
    }
    const std::uint32_t id = temporary_id();
    IrOperand address = memory_operand(operand, instruction);
    address.width = width;
    push(block, statement_of(IrOp::Load, temp_operand(id, width), address, IrOperand::none(), width,
                             instruction));
    return temp_operand(id, width);
  }

  /// Writes a 4-byte value held in temporary `value` into bits 0 to 31 of `destination`.
  /// Bits 32 to 63 keep their old value, as the scalar single forms require.
  void merge_low_single(IrBlock& block, const Instruction& instruction, std::uint32_t value,
                        const std::string& destination) {
    const std::uint32_t widened = temporary_id();
    push(block, statement_of(IrOp::ZeroExtend, temp_operand(widened, 8), temp_operand(value, 4),
                             IrOperand::none(), 8, instruction));
    const std::uint32_t kept = temporary_id();
    push(block,
         statement_of(IrOp::And, temp_operand(kept, 8), IrOperand::register_ref(destination, 8),
                      IrOperand::constant_value(0xffffffff00000000ULL, 8), 8, instruction));
    IrStatement merge =
        statement_of(IrOp::Or, IrOperand::register_ref(destination, 8), temp_operand(kept, 8),
                     temp_operand(widened, 8), 8, instruction);
    merge.merged_width = 4;
    push(block, std::move(merge));
  }

  /// Writes a result of `width` bytes into the XMM register `destination`: a double
  /// replaces the low lane, and a single goes through the merge above.
  void write_xmm_scalar(IrBlock& block, const Instruction& instruction, IrStatement statement,
                        std::uint8_t width, const std::string& destination) {
    if (width == 8) {
      statement.dest = IrOperand::register_ref(destination, 8);
      push(block, std::move(statement));
      return;
    }
    const std::uint32_t id = temporary_id();
    statement.dest = temp_operand(id, 4);
    push(block, std::move(statement));
    merge_low_single(block, instruction, id, destination);
  }

  /// Lowers one of the scalar SSE instructions in is_scalar_sse. Returns false if
  /// the operands are not a form it models; the caller then marks the instruction
  /// Unsupported.
  bool lift_scalar_sse(IrBlock& block, const Instruction& instruction) {
    const std::string& m = instruction.mnemonic;
    const std::vector<Operand>& ops = instruction.structured_operands;
    if (ops.size() != 2) {
      return false;
    }
    const bool single = m.size() >= 2 && m.compare(m.size() - 2, 2, "ss") == 0;

    // Arithmetic and square root: dest = dest OP source (sqrt: dest = sqrt(source)).
    static const char* const kBinary[] = {"addss", "addsd", "subss", "subsd",
                                          "mulss", "mulsd", "divss", "divsd"};
    const bool binary = std::find(std::begin(kBinary), std::end(kBinary), m) != std::end(kBinary);
    if (binary || m == "sqrtss" || m == "sqrtsd") {
      const std::uint8_t width = single ? 4 : 8;
      if (!is_xmm(ops[0])) {
        return false;
      }
      const auto source = sse_source(block, instruction, ops[1], width);
      if (!source) {
        return false;
      }
      IrOp op = IrOp::FSqrt;
      if (m.rfind("add", 0) == 0) op = IrOp::FAdd;
      if (m.rfind("sub", 0) == 0) op = IrOp::FSub;
      if (m.rfind("mul", 0) == 0) op = IrOp::FMul;
      if (m.rfind("div", 0) == 0) op = IrOp::FDiv;
      IrStatement statement =
          statement_of(op, IrOperand::none(), IrOperand::register_ref(ops[0].reg, width),
                       binary ? *source : IrOperand::none(), width, instruction);
      if (op == IrOp::FSqrt) {
        statement.a = *source;
      }
      statement.float_model = IrFloatModel::X86;
      // The operations round in the MXCSR mode the caller left. The ABI sets round to
      // nearest on entry, which is what the IR models; ldmxcsr is not modelled, so a
      // function that changes the mode is Partial through its Unsupported statement.
      static const std::string kMxcsrNote =
          "scalar floating-point operations assume the ABI's default MXCSR (round to nearest, "
          "no exceptions unmasked) on entry";
      if (std::find(out.notes.begin(), out.notes.end(), kMxcsrNote) == out.notes.end()) {
        note(kMxcsrNote);
      }
      write_xmm_scalar(block, instruction, std::move(statement), width, ops[0].reg);
      return true;
    }

    // Scalar moves. The register form keeps the bits the instruction does not write.
    if (m == "movss" || m == "movsd") {
      const std::uint8_t width = single ? 4 : 8;
      if (is_xmm(ops[0]) && is_xmm(ops[1])) {
        if (width == 8) {
          push(block, statement_of(IrOp::Assign, IrOperand::register_ref(ops[0].reg, 8),
                                   IrOperand::register_ref(ops[1].reg, 8), IrOperand::none(), 8,
                                   instruction));
        } else {
          const std::uint32_t id = temporary_id();
          push(block, statement_of(IrOp::Assign, temp_operand(id, 4),
                                   IrOperand::register_ref(ops[1].reg, 4), IrOperand::none(), 4,
                                   instruction));
          merge_low_single(block, instruction, id, ops[0].reg);
        }
        return true;
      }
      if (is_xmm(ops[0]) && ops[1].kind == OperandKind::Memory) {
        // A load zeroes the rest of the register, as the architecture does.
        IrOperand address = memory_operand(ops[1], instruction);
        address.width = width;
        push(block, statement_of(IrOp::Load, IrOperand::register_ref(ops[0].reg, width), address,
                                 IrOperand::none(), width, instruction));
        return true;
      }
      if (ops[0].kind == OperandKind::Memory && is_xmm(ops[1])) {
        IrOperand address = memory_operand(ops[0], instruction);
        address.width = width;
        push(block, statement_of(IrOp::Store, IrOperand::none(), address,
                                 IrOperand::register_ref(ops[1].reg, width), width, instruction));
        return true;
      }
      return false;
    }
    if ((m == "movaps" || m == "movapd") && is_xmm(ops[0]) && is_xmm(ops[1])) {
      // Copies all 128 bits; the upper lanes are not modelled, so the function is Partial.
      push(block,
           statement_of(IrOp::Assign, IrOperand::register_ref(ops[0].reg, 8),
                        IrOperand::register_ref(ops[1].reg, 8), IrOperand::none(), 8, instruction));
      mark_partial("movaps and movapd copy the upper lanes, which are not modelled");
      return true;
    }

    // Conversions between integers and floats.
    if (m == "cvtsi2ss" || m == "cvtsi2sd") {
      if (!is_xmm(ops[0])) {
        return false;
      }
      const std::uint8_t width = single ? 4 : 8;
      std::uint8_t integer_width = 0;
      std::optional<IrOperand> source;
      if (ops[1].kind == OperandKind::Register) {
        integer_width = register_width(ops[1].reg);
        source = IrOperand::register_ref(ops[1].reg, integer_width);
      } else if (ops[1].kind == OperandKind::Memory) {
        integer_width = ops[1].size;
        if (integer_width == 4 || integer_width == 8) {
          source = sse_source(block, instruction, ops[1], integer_width);
        }
      }
      if (!source || (integer_width != 4 && integer_width != 8)) {
        return false;
      }
      write_xmm_scalar(block, instruction,
                       statement_of(IrOp::IntToFloat, IrOperand::none(), *source, IrOperand::none(),
                                    width, instruction),
                       width, ops[0].reg);
      return true;
    }
    if (m == "cvttss2si" || m == "cvttsd2si") {
      if (ops[0].kind != OperandKind::Register) {
        return false;
      }
      const std::uint8_t integer_width = register_width(ops[0].reg);
      const std::uint8_t width = m == "cvttss2si" ? 4 : 8;
      if (integer_width != 4 && integer_width != 8) {
        return false;
      }
      const auto source = sse_source(block, instruction, ops[1], width);
      if (!source) {
        return false;
      }
      IrStatement statement =
          statement_of(IrOp::FloatToInt, IrOperand::register_ref(ops[0].reg, integer_width),
                       *source, IrOperand::none(), integer_width, instruction);
      statement.float_model = IrFloatModel::X86;
      push(block, std::move(statement));
      return true;
    }
    if (m == "cvtss2sd" || m == "cvtsd2ss") {
      if (!is_xmm(ops[0])) {
        return false;
      }
      const bool widen = m == "cvtss2sd";
      const auto source = sse_source(block, instruction, ops[1], widen ? 4 : 8);
      if (!source) {
        return false;
      }
      write_xmm_scalar(
          block, instruction,
          statement_of(widen ? IrOp::FloatExtend : IrOp::FloatTruncate, IrOperand::none(), *source,
                       IrOperand::none(), widen ? 8 : 4, instruction),
          widen ? 8 : 4, ops[0].reg);
      return true;
    }

    // Comparisons set the flags as ucomis* and comis* do.
    if (is_sse_compare(m)) {
      if (!is_xmm(ops[0])) {
        return false;
      }
      const std::uint8_t width = single ? 4 : 8;
      const auto source = sse_source(block, instruction, ops[1], width);
      if (!source) {
        return false;
      }
      IrStatement statement =
          statement_of(IrOp::FCompare, IrOperand::none(),
                       IrOperand::register_ref(ops[0].reg, width), *source, width, instruction);
      statement.float_model = IrFloatModel::X86;
      push(block, std::move(statement));
      return true;
    }

    // Zeroing idioms: xorps x, x and pxor x, x set the register to zero.
    if ((m == "xorps" || m == "xorpd" || m == "pxor") && is_xmm(ops[0]) && is_xmm(ops[1]) &&
        ops[0].reg == ops[1].reg) {
      push(block, statement_of(IrOp::Assign, IrOperand::register_ref(ops[0].reg, 8),
                               IrOperand::constant_value(0, 8), IrOperand::none(), 8, instruction));
      return true;
    }
    return false;
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
    // The callee's effects on registers and memory are not modelled, so the
    // function cannot be Complete. The call itself stays in the IR.
    mark_partial("outgoing call arguments and return values follow no modelled ABI");
  }
};

/// What a returned value is, as the last definition before a return says.
struct ReturnDefinition {
  bool found = false;    // some path defined the return value
  bool unknown = false;  // a path reaches a call, an unmodelled write or the entry
  bool float_value = false;
  std::uint8_t width = 0;
};

ReturnDefinition join(const ReturnDefinition& a, const ReturnDefinition& b) {
  if (!a.found) {
    return b;
  }
  if (!b.found) {
    return a;
  }
  ReturnDefinition out = a;
  if (a.unknown || b.unknown || a.float_value != b.float_value || a.width != b.width) {
    out.unknown = true;
  }
  return out;
}

/// The registers a function returns values in: the integer register and the
/// floating-point register, as register families (rax and xmm0, or x0 and v0).
struct ReturnRegisters {
  std::string integer_family;
  std::string float_family;
  bool aarch64 = false;
};

/// The name the IR uses for the floating-point return register at `width` bytes.
std::string float_return_name(const ReturnRegisters& regs, std::uint8_t width) {
  if (!regs.aarch64) {
    return "xmm0";
  }
  return width == 4 ? "s0" : "d0";
}

ReturnDefinition unknown_definition() {
  ReturnDefinition out;
  out.found = true;
  out.unknown = true;
  return out;
}

/// Successor blocks of block `index`, from its terminator and fall-through.
std::vector<std::size_t> successors_of(const IrFunction& function, std::size_t index) {
  std::vector<std::size_t> out;
  const IrBlock& block = function.blocks[index];
  bool falls_through = true;
  if (!block.statements.empty()) {
    const IrStatement& last = block.statements.back();
    if (last.op == IrOp::Branch) {
      out.push_back(last.a.block);
      falls_through = false;
    } else if (last.op == IrOp::CondBranch) {
      out.push_back(last.b.block);
    } else if (last.op == IrOp::Switch) {
      out.push_back(last.a.block);
      for (const IrSwitchCase& switch_case : last.switch_cases) {
        out.push_back(switch_case.target_block);
      }
      falls_through = false;
    } else if (last.op == IrOp::Return) {
      falls_through = false;
    }
  }
  if (falls_through && index + 1 < function.blocks.size()) {
    out.push_back(index + 1);
  }
  return out;
}

/// The last definition of rax (any width) or xmm0 among statements [0, end) of
/// `block`. A call or an unmodelled statement may define either, so it is unknown.
std::optional<ReturnDefinition> definition_in_block(const IrBlock& block, std::size_t end,
                                                    const ReturnRegisters& regs) {
  for (std::size_t s = end; s-- > 0;) {
    const IrStatement& statement = block.statements[s];
    if (statement.op == IrOp::Call || statement.op == IrOp::Unsupported) {
      return unknown_definition();
    }
    if (statement.dest.kind != IrOperandKind::Register || statement.dest.reg.empty()) {
      continue;
    }
    const std::string family = internal::register_family(statement.dest.reg);
    const bool integer = family == regs.integer_family;
    if (!integer && family != regs.float_family) {
      continue;
    }
    ReturnDefinition out;
    out.found = true;
    out.float_value = !integer;
    out.width = statement.dest.width != 0 ? statement.dest.width : statement.width;
    return out;
  }
  return std::nullopt;
}

/// The definition that reaches the start of block `index`, over every path back
/// through its predecessors. A path that reaches the function entry without a
/// definition carries an incoming value, which is unknown here. `visited` stops a
/// loop: a block searched already adds nothing, because the search that began there
/// covers its paths.
ReturnDefinition reaching_block_start(const IrFunction& function, std::size_t index,
                                      std::vector<bool>& visited, const ReturnRegisters& regs) {
  if (visited[index]) {
    return {};
  }
  visited[index] = true;
  ReturnDefinition joined;
  if (index == 0) {
    joined = join(joined, unknown_definition());  // the entry itself
  }
  bool has_predecessor = false;
  for (std::size_t p = 0; p < function.blocks.size(); ++p) {
    const auto successors = successors_of(function, p);
    if (std::find(successors.begin(), successors.end(), index) == successors.end()) {
      continue;
    }
    has_predecessor = true;
    const IrBlock& pred = function.blocks[p];
    if (const auto defined = definition_in_block(pred, pred.statements.size(), regs)) {
      joined = join(joined, *defined);
    } else {
      joined = join(joined, reaching_block_start(function, p, visited, regs));
    }
  }
  if (!has_predecessor && index != 0) {
    joined = join(joined, unknown_definition());  // unreachable from the entry
  }
  return joined;
}

/// Which return registers are written along some path to a return. A write is not killed
/// by a later one, so a write to rax and a write to xmm0 on one path make the return
/// channel ambiguous, whichever was written last. Walks back from statement `end` of block
/// `start` over every predecessor, once per block.
struct ReturnClasses {
  bool integer = false;
  bool floating = false;
};

ReturnClasses classes_reaching_return(const IrFunction& function, std::size_t start,
                                      std::size_t end, const ReturnRegisters& regs) {
  ReturnClasses out;
  std::vector<bool> visited(function.blocks.size(), false);
  std::vector<std::pair<std::size_t, std::size_t>> pending{{start, end}};
  while (!pending.empty()) {
    const auto [index, limit] = pending.back();
    pending.pop_back();
    const IrBlock& block = function.blocks[index];
    for (std::size_t s = 0; s < limit && s < block.statements.size(); ++s) {
      const IrStatement& statement = block.statements[s];
      if (statement.dest.kind != IrOperandKind::Register || statement.dest.reg.empty()) {
        continue;
      }
      const std::string family = internal::register_family(statement.dest.reg);
      if (family == regs.integer_family) {
        out.integer = true;
      } else if (family == regs.float_family) {
        out.floating = true;
      }
    }
    for (std::size_t p = 0; p < function.blocks.size(); ++p) {
      if (visited[p]) {
        continue;
      }
      const auto successors = successors_of(function, p);
      if (std::find(successors.begin(), successors.end(), index) == successors.end()) {
        continue;
      }
      visited[p] = true;
      pending.emplace_back(p, function.blocks[p].statements.size());
    }
  }
  return out;
}

/// Returns that carry a floating-point value leave it in xmm0, not rax. The lifter
/// emits rax for every return, so each return is resolved from the definitions that
/// reach it. When they disagree, or a path has no definition, the return stays rax
/// and the function is marked Partial.
void resolve_return_registers(IrFunction& function, const ReturnRegisters& regs) {
  for (std::size_t b = 0; b < function.blocks.size(); ++b) {
    IrBlock& block = function.blocks[b];
    for (std::size_t s = 0; s < block.statements.size(); ++s) {
      IrStatement& statement = block.statements[s];
      if (statement.op != IrOp::Return || statement.a.kind != IrOperandKind::Register ||
          internal::register_family(statement.a.reg) != regs.integer_family) {
        continue;
      }
      const ReturnClasses classes = classes_reaching_return(function, b, s, regs);
      if (classes.integer && classes.floating) {
        function.partial = true;
        function.notes.push_back("both " + regs.integer_family + " and " + regs.float_family +
                                 " are written on a path to this return; which one carries the "
                                 "return value is not determined, so " +
                                 regs.integer_family + " is assumed");
        continue;
      }
      ReturnDefinition found;
      if (const auto defined = definition_in_block(block, s, regs)) {
        found = *defined;
      } else {
        std::vector<bool> visited(function.blocks.size(), false);
        found = reaching_block_start(function, b, visited, regs);
      }
      if (!found.found || found.unknown) {
        function.partial = true;
        function.notes.push_back(
            "the returned register is not determined by the definitions that reach the return; rax "
            "is assumed");
      } else if (found.float_value) {
        statement.a = IrOperand::register_ref(float_return_name(regs, found.width), found.width);
      }
    }
  }
}

}  // namespace

/// Integer and floating-point parameters are placed by their own registers, so the order
/// the source gives them is not recoverable from the registers they arrive in. The
/// evaluator places parameters in the order it has, so a function with both kinds is
/// Partial rather than Complete with an order that may be wrong.
void mark_mixed_parameters(IrFunction& function) {
  bool integer = false;
  bool floating = false;
  for (const IrParameter& parameter : function.parameters) {
    (parameter.floating_point ? floating : integer) = true;
  }
  if (integer && floating) {
    function.partial = true;
    function.notes.push_back(
        "integer and floating-point parameters are both present; their order in the source is "
        "not recoverable from the registers, so the signature is Partial");
  }
}

Result<IrFunction> lift_function(const BinaryImage& image, const AnalysisResult& analysis,
                                 const Function& function, const LiftOptions& options) {
  if (image.architecture == Architecture::AArch64) {
    auto lifted = internal::lift_aarch64(image, analysis, function, options);
    if (lifted) {
      resolve_return_registers(lifted.value(), ReturnRegisters{"x0", "v0", true});
      internal::canonicalise_registers(lifted.value(), image.architecture);
      if (options.run_passes) {
        run_ir_passes(lifted.value(), PassOptions{image.architecture, image.format, {}});
        mark_mixed_parameters(lifted.value());
      }
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
          : "x86-64 subset; locals are not recovered");

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
        if (next.mnemonic == "adc" || next.mnemonic == "sbb") {
          return IrCondition::Carry;  // reads CF only
        }
        if (is_register_exchange(next)) {
          continue;  // swaps two registers; the flags pass through
        }
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
        if (!lifter.flags_readable(condition)) {
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
      if (is_scalar_sse(mnemonic)) {
        if (!lifter.lift_scalar_sse(out_block, instruction)) {
          lifter.unsupported(out_block, instruction);
        }
        if (is_sse_compare(mnemonic)) {
          lifter.flags_state = Lifter::FlagsState::Exact;
          keeps_flags = true;  // the comparison sets the flags it reads
        }
      } else if (mnemonic == "mov" || mnemonic == "movabs") {
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
      } else if (mnemonic == "popcnt" || mnemonic == "tzcnt" || mnemonic == "lzcnt" ||
                 mnemonic == "bswap" || mnemonic == "bt" || mnemonic == "bts" ||
                 mnemonic == "btr" || mnemonic == "btc") {
        lifter.lift_bit_operation(out_block, instruction);
        // bswap leaves the flags alone; the bit tests set CF, so their state is kept.
        keeps_flags = mnemonic == "bswap" || mnemonic == "bt" || mnemonic == "bts" ||
                      mnemonic == "btr" || mnemonic == "btc";
      } else if (mnemonic == "movbe") {
        lifter.lift_movbe(out_block, instruction);
        keeps_flags = true;  // movbe leaves the flags alone
      } else if (mnemonic == "mul" || mnemonic == "div" || mnemonic == "idiv" ||
                 (mnemonic == "imul" && instruction.structured_operands.size() == 1)) {
        lifter.lift_multiply_divide(out_block, instruction);
      } else if (is_bitwise_or_arithmetic(mnemonic) || mnemonic == "inc" || mnemonic == "dec") {
        lifter.lift_arithmetic(out_block, instruction, next_consumer(i));
        keeps_flags = true;  // lift_arithmetic set the state
      } else if (mnemonic == "xchg") {
        // A register exchange does not write the flags; an unsupported one may
        // have, so the flag state is dropped.
        keeps_flags = lifter.lift_exchange(out_block, instruction);
      } else if (mnemonic == "adc" || mnemonic == "sbb") {
        lifter.lift_add_with_carry(out_block, instruction, next_consumer(i));
        keeps_flags = true;  // lift_add_with_carry set the state
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
  const ReturnRegisters return_registers = image.architecture == Architecture::AArch64
                                               ? ReturnRegisters{"x0", "v0", true}
                                               : ReturnRegisters{"rax", "xmm0", false};
  resolve_return_registers(lifter.out, return_registers);
  internal::canonicalise_registers(lifter.out, image.architecture);
  if (options.run_passes) {
    run_ir_passes(lifter.out, PassOptions{image.architecture, image.format, {}});
    mark_mixed_parameters(lifter.out);
  }
  return lifter.out;
}

}  // namespace donkey
