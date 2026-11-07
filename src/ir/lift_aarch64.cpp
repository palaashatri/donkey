#include "lift_internal.h"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <initializer_list>
#include <iterator>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "donkey/analysis/cfg.h"
#include "registers.h"

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
  if (internal::scalar_fp_width(name) != 0) {
    return internal::scalar_fp_width(name);
  }
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

/// Condition code written as the last operand of a conditional select
/// (`csel w0, w1, w2, gt`, `cset w8, ne`). Returns None when there is none.
IrCondition trailing_condition(const std::string& operands) {
  const std::size_t comma = operands.rfind(',');
  if (comma == std::string::npos) {
    return IrCondition::None;
  }
  std::size_t begin = comma + 1;
  while (begin < operands.size() && operands[begin] == ' ') {
    ++begin;
  }
  const std::string code = operands.substr(begin);
  if (code == "al" || code == "nv") {
    return IrCondition::None;
  }
  return branch_condition("b." + code);
}

/// The scalar floating-point mnemonics lift_scalar_fp models. fcsel is in the select
/// lowering. fcvtzu and the negated fused forms are not modelled.
bool is_scalar_fp_mnemonic(const std::string& mnemonic) {
  static const char* const kNames[] = {"fmov",  "fadd",  "fsub",   "fmul",  "fdiv", "fsqrt",
                                       "fneg",  "fabs",  "fmadd",  "fmsub", "fcmp", "fcmpe",
                                       "scvtf", "ucvtf", "fcvtzs", "fcvt",  "movi"};
  return std::find(std::begin(kNames), std::end(kNames), mnemonic) != std::end(kNames);
}

/// Instructions that write NZCV. The lifter models the flags of cmp, tst,
/// subs and ands exactly; any other writer leaves them unknown.
bool sets_flags(const std::string& mnemonic) {
  static const char* const kWriters[] = {"cmp",   "cmn",    "tst",   "ccmp",  "ccmn",   "adds",
                                         "subs",  "ands",   "bics",  "negs",  "ngcs",   "adcs",
                                         "sbcs",  "fcmp",   "fcmpe", "fccmp", "fccmpe", "msr",
                                         "setf8", "setf16", "rmif",  "cfinv", "axflag", "xaflag"};
  for (const char* writer : kWriters) {
    if (mnemonic == writer) {
      return true;
    }
  }
  return false;
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

  /// The most recent NZCV writer in the current block was modelled by a
  /// Compare/Test (cmp, tst, subs, ands). Reset at each block start.
  bool flags_exact = false;
  /// Set by a lift function that emitted the Compare/Test for its flags.
  bool modelled_flags = false;

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

  /// A rounded result depends on FPCR's rounding mode, which the caller may set, and this lifter
  /// does not model FPCR. The function is Partial, with the assumption written in its notes once.
  void mark_rounding_dependent() {
    static const std::string kNote =
        "floating-point results assume the FPCR rounding mode is round to nearest; a caller may "
        "set another mode, which is not modelled";
    if (std::find(out.notes.begin(), out.notes.end(), kNote) == out.notes.end()) {
      mark_partial(kNote);
    } else {
      out.partial = true;
    }
  }

  void push(IrBlock& block, IrStatement statement) {
    if (limit_reached()) {
      return;
    }
    if (statement.width == 0) {
      statement.width = kPointerWidth;
    }
    // A W register or an immediate used at a narrower width means its low
    // bits: `cmp w0, #0` compares 32 bits, `strb w1` stores one byte.
    auto narrow = [](IrOperand& operand, std::uint8_t width) {
      if ((operand.kind == IrOperandKind::Constant || operand.kind == IrOperandKind::Register) &&
          operand.width > width && width != 0) {
        if (operand.kind == IrOperandKind::Constant) {
          operand.constant &= width >= 8 ? ~0ULL : ((1ULL << (width * 8U)) - 1U);
        }
        operand.width = width;
      }
    };
    if (statement.op == IrOp::Compare || statement.op == IrOp::Test) {
      narrow(statement.b, statement.a.width);
    } else if (statement.op == IrOp::Store) {
      narrow(statement.b, statement.width);
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

  /// The location of a load/store: `base + displacement`, or for a register
  /// offset `base + (extend(index) << shift)`. A 32-bit index is widened
  /// into a temporary first (uxtw/sxtw); anything else unmodelled fails.
  IrOperand access_location(IrBlock& block, const Instruction& instruction, const Operand& operand,
                            std::uint8_t width, bool& failed) {
    if (!indexed_memory(operand)) {
      return memory_at(operand, width, 0);
    }
    const std::string& index = operand.memory.index;
    const std::uint8_t index_width = register_width(index);
    if (operand.shift != ShiftKind::None && operand.shift != ShiftKind::Lsl) {
      failed = true;
      return IrOperand::none();
    }
    if (operand.shift_amount > 4 || operand.memory.displacement != 0) {
      failed = true;
      return IrOperand::none();
    }
    std::string index_name = index;
    if (index_width == 4) {
      if (operand.extend != ExtendKind::Uxtw && operand.extend != ExtendKind::Sxtw) {
        failed = true;
        return IrOperand::none();
      }
      const std::uint32_t id = temporary_id();
      IrStatement widen;
      widen.op = operand.extend == ExtendKind::Sxtw ? IrOp::SignExtend : IrOp::ZeroExtend;
      widen.dest = temp_operand(id, kPointerWidth);
      widen.a = IrOperand::register_ref(index, 4);
      widen.width = kPointerWidth;
      widen.source_address = instruction.address;
      push(block, std::move(widen));
      index_name = "var_" + std::to_string(id);
    } else if (index_width != 8 ||
               (operand.extend != ExtendKind::None && operand.extend != ExtendKind::Uxtx &&
                operand.extend != ExtendKind::Sxtx)) {
      failed = true;
      return IrOperand::none();
    }
    IrOperand memory = IrOperand::memory_reference(operand.memory.base, index_name,
                                                   1 << operand.shift_amount, 0, width);
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
    if (memory.memory.base.empty() || (indexed_memory(memory) && memory.memory.writeback)) {
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
    IrOperand value = to_ir_operand(operand, width);
    if (value.kind == IrOperandKind::None) {
      failed = true;
      return value;
    }
    if (operand.kind == OperandKind::Register && operand.extend != ExtendKind::None) {
      // Extended register: take the low byte/half/word, extend it to the
      // operation width, then shift.
      std::uint8_t from = 8;
      bool sign = false;
      switch (operand.extend) {
        case ExtendKind::Uxtb:
          from = 1;
          break;
        case ExtendKind::Uxth:
          from = 2;
          break;
        case ExtendKind::Uxtw:
          from = 4;
          break;
        case ExtendKind::Uxtx:
          from = 8;
          break;
        case ExtendKind::Sxtb:
          from = 1;
          sign = true;
          break;
        case ExtendKind::Sxth:
          from = 2;
          sign = true;
          break;
        case ExtendKind::Sxtw:
          from = 4;
          sign = true;
          break;
        case ExtendKind::Sxtx:
          from = 8;
          sign = true;
          break;
        case ExtendKind::None:
          break;
      }
      if (from < width) {
        value.width = from;
        const std::uint32_t id = temporary_id();
        IrStatement extend;
        extend.op = sign ? IrOp::SignExtend : IrOp::ZeroExtend;
        extend.dest = temp_operand(id, width);
        extend.a = value;
        extend.width = width;
        extend.source_address = instruction.address;
        push(block, std::move(extend));
        value = temp_operand(id, width);
      }
      if (operand.shift_amount == 0) {
        return value;
      }
      const std::uint32_t shifted = temporary_id();
      IrStatement shift;
      shift.op = IrOp::Shl;  // extended operands only take LSL
      shift.dest = temp_operand(shifted, width);
      shift.a = value;
      shift.b = IrOperand::constant_value(operand.shift_amount, width);
      shift.width = width;
      shift.source_address = instruction.address;
      push(block, std::move(shift));
      return temp_operand(shifted, width);
    }
    if (value.width != width) {
      failed = true;  // a narrower register without an extend is not modelled
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
      if (operands[0].kind != OperandKind::Register || register_width(operands[0].reg) == 0) {
        unsupported(block, instruction);
        return;
      }
      // The second operand may be shifted or extended (cmp w8, w9, lsl #2).
      bool failed = false;
      const IrOperand source =
          shifted_operand(block, instruction, operands[1], register_width(operands[0].reg), failed);
      if (failed || source.kind == IrOperandKind::None) {
        unsupported(block, instruction);
        return;
      }
      if (mnemonic == "cmp") {
        modelled_flags = true;
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
      if (mnemonic == "cmn") {
        // cmn is adds into the zero register: the flags of a + b, set unconditionally.
        modelled_flags = true;
        IrStatement statement;
        statement.op = IrOp::CondCompareAdd;
        statement.a = to_ir_operand(operands[0], kPointerWidth);
        statement.b = source;
        statement.c = IrOperand::constant_value(0, 1);
        statement.condition = IrCondition::None;
        statement.width = statement.a.width;
        statement.source_address = instruction.address;
        push(block, std::move(statement));
        return;
      }
      if (mnemonic == "tst") {
        modelled_flags = true;
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
        statement.b = source;
        statement.width = width;
        statement.source_address = instruction.address;
        push(block, std::move(statement));
        return;
      }
      if (mnemonic == "mvn") {
        const std::uint8_t width = register_width(operands[0].reg);
        IrStatement statement;
        statement.op = IrOp::Xor;
        statement.dest = to_ir_operand(operands[0], width);
        statement.a = source;
        statement.b = IrOperand::constant_value(width_mask(width), width);
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

    // adds sets the flags of a + b, unconditionally, from the operands before the
    // destination is written.
    if (mnemonic == "adds") {
      modelled_flags = true;
      IrStatement flags;
      flags.op = IrOp::CondCompareAdd;
      flags.a = left;
      flags.b = right;
      flags.c = IrOperand::constant_value(0, 1);
      flags.condition = IrCondition::None;
      flags.width = width;
      flags.source_address = instruction.address;
      push(block, std::move(flags));
    }
    // subs and ands set NZCV exactly as cmp and tst of the same operands.
    // The Compare/Test reads the operands before the destination is written.
    if (mnemonic == "subs" || mnemonic == "ands") {
      modelled_flags = true;
      IrStatement flags;
      flags.op = mnemonic == "subs" ? IrOp::Compare : IrOp::Test;
      flags.a = left;
      flags.b = right;
      flags.condition = IrCondition::Equal;
      flags.width = width;
      flags.source_address = instruction.address;
      push(block, std::move(flags));
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

  /// csel/csinc/csinv/csneg and their aliases cset, csetm, cinc, cinv, cneg:
  /// dest = condition ? a : f(b). Exact only when the block's flags are.
  /// Scalar floating-point instructions on the s and d registers. A float is its bits
  /// in the IR, so moves and selects do not depend on the type. Returns false when the
  /// form is not modelled; the caller then marks the instruction Unsupported.
  bool lift_scalar_fp(IrBlock& block, const Instruction& instruction) {
    const std::string& m = instruction.mnemonic;
    const std::vector<Operand>& ops = instruction.structured_operands;
    const auto is_fp = [](const Operand& o) {
      return o.kind == OperandKind::Register && internal::scalar_fp_width(o.reg) != 0;
    };
    const auto is_gp = [](const Operand& o) {
      return o.kind == OperandKind::Register && internal::scalar_fp_width(o.reg) == 0 &&
             (register_width(o.reg) == 4 || register_width(o.reg) == 8);
    };
    const auto width_of_fp = [](const Operand& o) { return internal::scalar_fp_width(o.reg); };
    const auto reg = [](const Operand& o, std::uint8_t width) {
      return IrOperand::register_ref(o.reg, width);
    };
    const auto emit = [&](IrOp op, IrOperand dest, IrOperand a, IrOperand b, IrOperand c,
                          std::uint8_t width) {
      IrStatement statement;
      statement.op = op;
      statement.dest = std::move(dest);
      statement.a = std::move(a);
      statement.b = std::move(b);
      statement.c = std::move(c);
      statement.width = width;
      statement.float_model = IrFloatModel::AArch64;
      statement.source_address = instruction.address;
      push(block, std::move(statement));
    };
    const auto all_fp = [&](std::initializer_list<std::size_t> indices, std::uint8_t width) {
      for (const std::size_t index : indices) {
        if (index >= ops.size() || !is_fp(ops[index]) || width_of_fp(ops[index]) != width) {
          return false;
        }
      }
      return true;
    };

    if (m == "movi" && ops.size() == 2 && is_fp(ops[0]) && ops[1].kind == OperandKind::Immediate &&
        ops[1].immediate == 0) {
      // movi d0, #0 clears the scalar register, as a zeroing idiom does.
      const std::uint8_t width = width_of_fp(ops[0]);
      emit(IrOp::Assign, reg(ops[0], width), IrOperand::constant_value(0, width), IrOperand::none(),
           IrOperand::none(), width);
      return true;
    }
    if (m == "fmov" && ops.size() == 2) {
      if (is_fp(ops[0])) {
        const std::uint8_t width = width_of_fp(ops[0]);
        if (ops[1].kind == OperandKind::Immediate) {
          // The immediate is the bits of the double it encodes. A single is that
          // value rounded, which is exact for every value fmov can encode.
          const double value = std::bit_cast<double>(static_cast<std::uint64_t>(ops[1].immediate));
          const std::uint64_t bits = width == 8
                                         ? std::bit_cast<std::uint64_t>(value)
                                         : std::bit_cast<std::uint32_t>(static_cast<float>(value));
          emit(IrOp::Assign, reg(ops[0], width), IrOperand::constant_value(bits, width),
               IrOperand::none(), IrOperand::none(), width);
          return true;
        }
        const bool same_fp = is_fp(ops[1]) && width_of_fp(ops[1]) == width;
        const bool from_gp = is_gp(ops[1]) && register_width(ops[1].reg) == width;
        if (!same_fp && !from_gp) {
          return false;
        }
        emit(IrOp::Assign, reg(ops[0], width), reg(ops[1], width), IrOperand::none(),
             IrOperand::none(), width);
        return true;
      }
      if (is_gp(ops[0]) && is_fp(ops[1]) && register_width(ops[0].reg) == width_of_fp(ops[1])) {
        const std::uint8_t width = register_width(ops[0].reg);
        emit(IrOp::Assign, reg(ops[0], width), reg(ops[1], width), IrOperand::none(),
             IrOperand::none(), width);
        return true;
      }
      return false;
    }

    static const char* const kBinary[] = {"fadd", "fsub", "fmul", "fdiv"};
    if (std::find(std::begin(kBinary), std::end(kBinary), m) != std::end(kBinary) &&
        ops.size() == 3 && is_fp(ops[0])) {
      const std::uint8_t width = width_of_fp(ops[0]);
      if (!all_fp({0, 1, 2}, width)) {
        return false;
      }
      const IrOp op = m == "fadd"   ? IrOp::FAdd
                      : m == "fsub" ? IrOp::FSub
                      : m == "fmul" ? IrOp::FMul
                                    : IrOp::FDiv;
      mark_rounding_dependent();
      emit(op, reg(ops[0], width), reg(ops[1], width), reg(ops[2], width), IrOperand::none(),
           width);
      return true;
    }
    if ((m == "fsqrt" || m == "fneg" || m == "fabs") && ops.size() == 2 && is_fp(ops[0])) {
      const std::uint8_t width = width_of_fp(ops[0]);
      if (!all_fp({0, 1}, width)) {
        return false;
      }
      const IrOp op = m == "fsqrt" ? IrOp::FSqrt : m == "fneg" ? IrOp::FNeg : IrOp::FAbs;
      if (m == "fsqrt") {
        mark_rounding_dependent();
      }
      emit(op, reg(ops[0], width), reg(ops[1], width), IrOperand::none(), IrOperand::none(), width);
      return true;
    }
    if ((m == "fmadd" || m == "fmsub") && ops.size() == 4 && is_fp(ops[0])) {
      const std::uint8_t width = width_of_fp(ops[0]);
      if (!all_fp({0, 1, 2, 3}, width)) {
        return false;
      }
      // Dd = Da + Dn * Dm (fmadd) or Da - Dn * Dm (fmsub), rounded once.
      mark_rounding_dependent();
      emit(m == "fmadd" ? IrOp::FMulAdd : IrOp::FMulSub, reg(ops[0], width), reg(ops[1], width),
           reg(ops[2], width), reg(ops[3], width), width);
      return true;
    }
    if ((m == "fcmp" || m == "fcmpe") && ops.size() == 2 && is_fp(ops[0])) {
      const std::uint8_t width = width_of_fp(ops[0]);
      IrOperand other;
      if (is_fp(ops[1]) && width_of_fp(ops[1]) == width) {
        other = reg(ops[1], width);
      } else if (ops[1].kind == OperandKind::Immediate && ops[1].immediate == 0) {
        other = IrOperand::constant_value(0, width);  // fcmp with #0.0
      } else {
        return false;
      }
      emit(IrOp::FCompare, IrOperand::none(), reg(ops[0], width), other, IrOperand::none(), width);
      modelled_flags = true;  // NZCV as fcmp sets them
      return true;
    }
    if ((m == "scvtf" || m == "ucvtf") && ops.size() == 2 && is_fp(ops[0]) && is_gp(ops[1])) {
      const std::uint8_t width = width_of_fp(ops[0]);
      const std::uint8_t integer = register_width(ops[1].reg);
      mark_rounding_dependent();
      emit(m == "scvtf" ? IrOp::IntToFloat : IrOp::UIntToFloat, reg(ops[0], width),
           reg(ops[1], integer), IrOperand::none(), IrOperand::none(), width);
      return true;
    }
    if (m == "fcvtzs" && ops.size() == 2 && is_gp(ops[0]) && is_fp(ops[1])) {
      const std::uint8_t integer = register_width(ops[0].reg);
      const std::uint8_t width = width_of_fp(ops[1]);
      emit(IrOp::FloatToInt, reg(ops[0], integer), reg(ops[1], width), IrOperand::none(),
           IrOperand::none(), integer);
      return true;
    }
    if (m == "fcvt" && ops.size() == 2 && is_fp(ops[0]) && is_fp(ops[1])) {
      const std::uint8_t to = width_of_fp(ops[0]);
      const std::uint8_t from = width_of_fp(ops[1]);
      if (to == 8 && from == 4) {
        emit(IrOp::FloatExtend, reg(ops[0], 8), reg(ops[1], 4), IrOperand::none(),
             IrOperand::none(), 8);
        return true;
      }
      if (to == 4 && from == 8) {
        mark_rounding_dependent();  // narrowing rounds; widening is exact
        emit(IrOp::FloatTruncate, reg(ops[0], 4), reg(ops[1], 8), IrOperand::none(),
             IrOperand::none(), 4);
        return true;
      }
    }
    return false;
  }

  void lift_conditional_select(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    const std::string& mnemonic = instruction.mnemonic;
    const IrCondition condition = trailing_condition(instruction.operands);
    if (operands.empty() || operands[0].kind != OperandKind::Register ||
        condition == IrCondition::None) {
      unsupported(block, instruction);
      return;
    }
    const std::uint8_t width = register_width(operands[0].reg);
    if (width == 0) {
      unsupported(block, instruction);
      return;
    }
    if (!flags_exact) {
      mark_partial(
          "conditional select depends on flags not set by a modelled cmp/tst/subs/ands "
          "in the same block");
    }
    const auto operand_at = [&](std::size_t index) {
      return index < operands.size() ? to_ir_operand(operands[index], width) : IrOperand::none();
    };
    // `taken` is the value when the condition holds; `otherwise` is built
    // from `base` by `transform` (Assign, +1, ~, negate).
    IrOperand taken;
    IrOperand base;
    IrOp transform = IrOp::Assign;
    bool invert_input = false;  // cinc/cinv/cneg: transform applies to the taken value
    if (mnemonic == "csel" || mnemonic == "fcsel" || mnemonic == "csinc" || mnemonic == "csinv" ||
        mnemonic == "csneg") {
      if (operands.size() < 3) {
        unsupported(block, instruction);
        return;
      }
      taken = operand_at(1);
      base = operand_at(2);
      transform = mnemonic == "csel" || mnemonic == "fcsel" ? IrOp::Assign
                  : mnemonic == "csinc"                     ? IrOp::Add
                  : mnemonic == "csinv"                     ? IrOp::Xor
                                                            : IrOp::Sub;
    } else if (mnemonic == "cset" || mnemonic == "csetm") {
      taken = IrOperand::constant_value(mnemonic == "cset" ? 1 : width_mask(width), width);
      base = IrOperand::constant_value(0, width);
    } else if (mnemonic == "cinc" || mnemonic == "cinv" || mnemonic == "cneg") {
      if (operands.size() < 2) {
        unsupported(block, instruction);
        return;
      }
      base = operand_at(1);
      taken = base;
      transform = mnemonic == "cinc" ? IrOp::Add : mnemonic == "cinv" ? IrOp::Xor : IrOp::Sub;
      invert_input = true;
    } else {
      unsupported(block, instruction);
      return;
    }
    if (taken.kind == IrOperandKind::None || base.kind == IrOperandKind::None) {
      unsupported(block, instruction);
      return;
    }
    const auto transformed = [&](const IrOperand& value) {
      if (transform == IrOp::Assign) {
        return value;
      }
      const std::uint32_t id = temporary_id();
      IrStatement statement;
      statement.op = transform;
      statement.dest = temp_operand(id, width);
      if (transform == IrOp::Sub) {
        statement.a = IrOperand::constant_value(0, width);
        statement.b = value;
      } else {
        statement.a = value;
        statement.b =
            IrOperand::constant_value(transform == IrOp::Add ? 1 : width_mask(width), width);
      }
      statement.width = width;
      statement.source_address = instruction.address;
      push(block, std::move(statement));
      return temp_operand(id, width);
    };
    if (invert_input) {
      taken = transformed(base);
    } else {
      base = transformed(base);
    }
    const std::uint32_t result = temporary_id();
    IrStatement start;
    start.op = IrOp::Assign;
    start.dest = temp_operand(result, width);
    start.a = base;
    start.width = width;
    start.source_address = instruction.address;
    push(block, std::move(start));

    IrStatement select;
    select.op = IrOp::CondAssign;
    select.dest = temp_operand(result, width);
    select.a = taken;
    select.condition = condition;
    select.width = width;
    select.source_address = instruction.address;
    push(block, std::move(select));

    IrStatement finish;
    finish.op = IrOp::Assign;
    finish.dest = to_ir_operand(operands[0], width);
    finish.a = temp_operand(result, width);
    finish.width = width;
    finish.source_address = instruction.address;
    push(block, std::move(finish));
  }

  /// ror by an immediate, and the bitfield moves ubfiz/sbfiz/ubfx/sbfx, as
  /// shifts and masks of the operation width.
  void lift_bitfield(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    const std::string& mnemonic = instruction.mnemonic;
    const bool rotate = mnemonic == "ror";
    if (operands.size() != (rotate ? 3U : 4U) || operands[0].kind != OperandKind::Register ||
        operands[1].kind != OperandKind::Register) {
      unsupported(block, instruction);
      return;
    }
    for (std::size_t i = 2; i < operands.size(); ++i) {
      if (operands[i].kind != OperandKind::Immediate) {
        unsupported(block, instruction);  // ror by a register is not modelled
        return;
      }
    }
    const std::uint8_t width = register_width(operands[0].reg);
    const std::uint64_t bits = std::uint64_t{width} * 8;
    const IrOperand source = to_ir_operand(operands[1], width);
    if (width == 0 || source.kind == IrOperandKind::None || source.width != width) {
      unsupported(block, instruction);
      return;
    }
    const auto shift_value = [&](IrOp op, const IrOperand& value, std::uint64_t amount) {
      if (amount == 0) {
        return value;
      }
      const std::uint32_t id = temporary_id();
      IrStatement statement;
      statement.op = op;
      statement.dest = temp_operand(id, width);
      statement.a = value;
      statement.b = IrOperand::constant_value(amount, width);
      statement.width = width;
      statement.source_address = instruction.address;
      push(block, std::move(statement));
      return temp_operand(id, width);
    };
    const auto finish = [&](IrOp op, const IrOperand& a, const IrOperand& b) {
      IrStatement statement;
      statement.op = op;
      statement.dest = to_ir_operand(operands[0], width);
      statement.a = a;
      statement.b = b;
      statement.width = width;
      statement.source_address = instruction.address;
      push(block, std::move(statement));
    };
    const std::uint64_t first = static_cast<std::uint64_t>(operands[2].immediate);
    if (rotate) {
      const std::uint64_t amount = first % bits;
      if (amount == 0) {
        finish(IrOp::Or, source, IrOperand::constant_value(0, width));
        return;
      }
      const IrOperand low = shift_value(IrOp::Shr, source, amount);
      const IrOperand high = shift_value(IrOp::Shl, source, bits - amount);
      finish(IrOp::Or, low, high);
      return;
    }
    const std::uint64_t field = static_cast<std::uint64_t>(operands[3].immediate);
    if (field == 0 || first >= bits || field > bits - (mnemonic.ends_with("fiz") ? first : 0) ||
        (mnemonic.ends_with("fx") && first + field > bits)) {
      unsupported(block, instruction);
      return;
    }
    if (mnemonic == "ubfiz" || mnemonic == "sbfiz") {
      // dest = extend(source[field-1:0]) << lsb
      const IrOperand high = shift_value(IrOp::Shl, source, bits - field);
      const IrOperand low =
          shift_value(mnemonic == "sbfiz" ? IrOp::Sar : IrOp::Shr, high, bits - field);
      if (first == 0) {
        finish(IrOp::Or, low, IrOperand::constant_value(0, width));
      } else {
        finish(IrOp::Shl, low, IrOperand::constant_value(first, width));
      }
      return;
    }
    if (mnemonic == "ubfx" || mnemonic == "sbfx") {
      // dest = extend(source[lsb+field-1:lsb])
      const IrOperand high = shift_value(IrOp::Shl, source, bits - first - field);
      const std::uint64_t down = bits - field;
      finish(mnemonic == "sbfx" ? IrOp::Sar : IrOp::Shr, high,
             IrOperand::constant_value(down, width));
      return;
    }
    unsupported(block, instruction);
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

  /// umull, smull, umaddl, smaddl, umsubl, smsubl, umnegl and smnegl: a 32-bit
  /// product widened to 64 bits, which is added to or subtracted from Xa, or
  /// negated. Each W source is zero- or sign-extended to 64 bits first, so the
  /// 64-bit product is exact (|product| < 2^63 for signed sources) and its low
  /// 64 bits are the architectural result.
  void lift_widening_multiply(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    const std::string& mnemonic = instruction.mnemonic;
    enum class Combine { None, Add, Sub, Negate };
    Combine combine = Combine::None;
    if (mnemonic == "umaddl" || mnemonic == "smaddl") {
      combine = Combine::Add;
    } else if (mnemonic == "umsubl" || mnemonic == "smsubl") {
      combine = Combine::Sub;
    } else if (mnemonic == "umnegl" || mnemonic == "smnegl") {
      combine = Combine::Negate;
    } else if (mnemonic != "umull" && mnemonic != "smull") {
      unsupported(block, instruction);
      return;
    }
    const std::size_t expected = combine == Combine::Add || combine == Combine::Sub ? 4 : 3;
    if (operands.size() != expected || operands[0].kind != OperandKind::Register ||
        register_width(operands[0].reg) != kPointerWidth ||
        operands[1].kind != OperandKind::Register || operands[2].kind != OperandKind::Register ||
        register_width(operands[1].reg) != 4 || register_width(operands[2].reg) != 4 ||
        (expected == 4 && (operands[3].kind != OperandKind::Register ||
                           register_width(operands[3].reg) != kPointerWidth))) {
      unsupported(block, instruction);
      return;
    }
    if (operands[0].reg == "xzr") {
      // The result is discarded and no flags are written, so there is nothing to lift.
      return;
    }
    const bool sign = mnemonic[0] == 's';
    auto widen = [&](const Operand& source, std::uint32_t id) {
      IrStatement extend;
      extend.op = sign ? IrOp::SignExtend : IrOp::ZeroExtend;
      extend.dest = temp_operand(id, kPointerWidth);
      extend.a = to_ir_operand(source, 4);
      extend.a.width = 4;
      extend.width = kPointerWidth;
      extend.source_address = instruction.address;
      push(block, std::move(extend));
    };
    const std::uint32_t left = temporary_id();
    const std::uint32_t right = temporary_id();
    widen(operands[1], left);
    widen(operands[2], right);

    IrStatement product;
    product.op = IrOp::Mul;
    product.dest = combine == Combine::None ? to_ir_operand(operands[0], kPointerWidth)
                                            : temp_operand(temporary_id(), kPointerWidth);
    product.a = temp_operand(left, kPointerWidth);
    product.b = temp_operand(right, kPointerWidth);
    product.width = kPointerWidth;
    product.source_address = instruction.address;
    const IrOperand product_value = product.dest;
    push(block, std::move(product));
    if (combine == Combine::None) {
      return;
    }

    IrStatement combined;
    combined.dest = to_ir_operand(operands[0], kPointerWidth);
    combined.width = kPointerWidth;
    combined.source_address = instruction.address;
    if (combine == Combine::Add) {
      combined.op = IrOp::Add;
      combined.a = to_ir_operand(operands[3], kPointerWidth);
      combined.b = product_value;
    } else if (combine == Combine::Sub) {
      combined.op = IrOp::Sub;
      combined.a = to_ir_operand(operands[3], kPointerWidth);
      combined.b = product_value;
    } else {
      combined.op = IrOp::Sub;
      combined.a = IrOperand::constant_value(0, kPointerWidth);
      combined.b = product_value;
    }
    push(block, std::move(combined));
  }

  /// The cmp or tst whose flags are still current at the end of `previous`, a block
  /// that falls through into the next one. Scanning back from its end, the first
  /// instruction that sets flags must be a cmp or tst of registers and immediates
  /// with no shift. Nothing after it may set flags, write a register it reads, or
  /// write back an address. Returns its index in analysis.instructions.
  std::optional<std::uint32_t> carried_flag_writer(const BasicBlock& previous) const {
    const std::uint32_t first = previous.first_instruction;
    const std::uint32_t end = previous.first_instruction + previous.instruction_count;
    if (previous.instruction_count == 0 || end > analysis.instructions.size()) {
      return std::nullopt;
    }
    std::optional<std::uint32_t> writer;
    for (std::uint32_t i = end; i-- > first;) {
      const Instruction& candidate = analysis.instructions[i];
      if (candidate.classification == InstructionClass::ConditionalJump) {
        continue;  // reads the flags and writes none; it can only end the block
      }
      if (candidate.classification != InstructionClass::Other) {
        return std::nullopt;
      }
      if (sets_flags(candidate.mnemonic)) {
        writer = i;
        break;
      }
    }
    if (!writer) {
      return std::nullopt;
    }
    const Instruction& compare = analysis.instructions[*writer];
    if ((compare.mnemonic != "cmp" && compare.mnemonic != "tst") ||
        compare.structured_operands.size() != 2) {
      return std::nullopt;
    }
    std::vector<std::string> read;
    for (const Operand& operand : compare.structured_operands) {
      if (operand.kind == OperandKind::Register && operand.shift == ShiftKind::None &&
          operand.extend == ExtendKind::None) {
        read.push_back(internal::register_family(operand.reg));
      } else if (operand.kind != OperandKind::Immediate || operand.shift != ShiftKind::None) {
        return std::nullopt;
      }
    }
    const auto reads = [&read](const std::string& family) {
      return std::find(read.begin(), read.end(), family) != read.end();
    };
    for (std::uint32_t i = *writer + 1; i < end; ++i) {
      const Instruction& later = analysis.instructions[i];
      if (later.classification == InstructionClass::ConditionalJump && i + 1 == end) {
        continue;  // the block's terminator
      }
      if (later.classification != InstructionClass::Other || sets_flags(later.mnemonic)) {
        return std::nullopt;
      }
      const bool store = later.mnemonic.rfind("st", 0) == 0;
      for (const Operand& operand : later.structured_operands) {
        if (operand.kind == OperandKind::Memory && operand.memory.writeback) {
          return std::nullopt;
        }
        if (!store && operand.kind == OperandKind::Register &&
            reads(internal::register_family(operand.reg))) {
          return std::nullopt;
        }
      }
    }
    return writer;
  }

  /// True when `block` has no predecessor but `previous`, the block just before it
  /// in address order, which reaches it by falling through: either `previous` does
  /// not end in a branch, or it ends in a conditional branch whose not-taken edge is
  /// `block`. An unresolved indirect branch in the function could reach any block,
  /// so it rules this out. Calls and jumps from elsewhere count as predecessors.
  bool single_fallthrough_predecessor(const BasicBlock& previous, const BasicBlock& block) const {
    if (function.estimated) {
      return false;
    }
    const Instruction& last =
        analysis.instructions[previous.first_instruction + previous.instruction_count - 1];
    std::size_t predecessors = 0;
    bool from_previous = false;
    for (const CfgEdge& edge : analysis.cfg.edges) {
      if (edge.to != block.address) {
        continue;
      }
      ++predecessors;
      if (edge.from == last.address && edge.kind == CfgEdgeKind::ConditionalFalse) {
        from_previous = true;
      }
    }
    if (last.classification == InstructionClass::Other) {
      ++predecessors;  // a fall-through has no CFG edge
      from_previous = true;
    } else if (last.classification != InstructionClass::ConditionalJump) {
      return false;
    }
    return from_previous && predecessors == 1;
  }

  /// adc, sbc, adcs and sbcs. adc is a + b + C, and sbc is a - b - borrow, with the
  /// borrow the inverse of C. The carry comes from the flags before, so they must be
  /// exact. adc and sbc without S do not write NZCV, so every carry reader in the block
  /// reads the same carry. adcs and sbcs set NZCV from the addition (C is the carry out,
  /// V the signed overflow), which the IR states exactly. sbcs is the addition of
  /// NOT(b), as the architecture defines it.
  void lift_add_with_carry(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    const std::string& mnemonic = instruction.mnemonic;
    const bool sets_nzcv = mnemonic == "adcs" || mnemonic == "sbcs";
    const bool discard =
        operands.size() == 3 && (operands[0].reg == "xzr" || operands[0].reg == "wzr");
    if (!flags_exact || operands.size() != 3 || operands[0].kind != OperandKind::Register ||
        operands[1].kind != OperandKind::Register || operands[2].kind != OperandKind::Register ||
        (discard && !sets_nzcv)) {
      unsupported(block, instruction);
      return;
    }
    const std::uint8_t width = register_width(operands[0].reg);
    if (width == 0 || register_width(operands[1].reg) != width ||
        register_width(operands[2].reg) != width) {
      unsupported(block, instruction);
      return;
    }
    IrOperand addend = to_ir_operand(operands[2], width);
    if (mnemonic == "sbcs") {
      // sbcs: a + NOT(b) + C, as the architecture defines it.
      const std::uint32_t inverted = temporary_id();
      IrStatement invert;
      invert.op = IrOp::Xor;
      invert.dest = temp_operand(inverted, width);
      invert.a = addend;
      invert.b = IrOperand::constant_value(width_mask(width), width);
      invert.width = width;
      invert.source_address = instruction.address;
      push(block, std::move(invert));
      addend = temp_operand(inverted, width);
    }
    IrStatement statement;
    if (mnemonic == "sbc") {
      statement.op = IrOp::SubBorrow;
    } else if (sets_nzcv) {
      statement.op = IrOp::AddCarryFlags;
    } else {
      statement.op = IrOp::AddCarry;
    }
    statement.dest =
        discard ? temp_operand(temporary_id(), width) : to_ir_operand(operands[0], width);
    statement.a = to_ir_operand(operands[1], width);
    statement.b = addend;
    statement.width = width;
    statement.source_address = instruction.address;
    statement.writes_flags = false;
    push(block, std::move(statement));
    if (sets_nzcv) {
      modelled_flags = true;  // the flags after are NZCV of this addition
    }
  }

  /// ccmp and ccmn. If the condition holds over the current flags, NZCV becomes
  /// the flags of a compare (ccmp: a - b) or an addition (ccmn: a + b); otherwise
  /// NZCV becomes the immediate #nzcv. The condition is read from the flags before,
  /// so they must be exact: when they are not, the instruction is Unsupported.
  void lift_conditional_compare(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    const IrCondition condition = trailing_condition(instruction.operands);
    if (!flags_exact || condition == IrCondition::None || operands.size() < 3 ||
        operands[0].kind != OperandKind::Register || register_width(operands[0].reg) == 0 ||
        (operands[1].kind != OperandKind::Register && operands[1].kind != OperandKind::Immediate) ||
        operands[2].kind != OperandKind::Immediate) {
      unsupported(block, instruction);
      return;
    }
    const std::uint8_t width = register_width(operands[0].reg);
    IrStatement statement;
    statement.op = instruction.mnemonic == "ccmn" ? IrOp::CondCompareAdd : IrOp::CondCompare;
    statement.a = to_ir_operand(operands[0], kPointerWidth);
    statement.b = to_ir_operand(operands[1], width);
    statement.c =
        IrOperand::constant_value(static_cast<std::uint64_t>(operands[2].immediate) & 0xFU, 1);
    statement.condition = condition;
    statement.width = width;
    statement.source_address = instruction.address;
    push(block, std::move(statement));
    modelled_flags = true;
  }

  /// udiv, sdiv, umulh, smulh, clz, cls, rbit, rev, rev16, rev32, extr, bfi and
  /// bfxil. AArch64 division by zero yields 0 and never faults, and INT_MIN / -1
  /// yields INT_MIN, while the IR divide faults in both cases. So the divisor is
  /// replaced by one where the IR would fault, and the result is then selected by
  /// 0/1 coefficients computed arithmetically. No flags are written, so the guard
  /// does not disturb the NZCV state the block's later instructions read.
  void lift_bit_and_division(IrBlock& block, const Instruction& instruction) {
    const std::vector<Operand>& operands = instruction.structured_operands;
    const std::string& mnemonic = instruction.mnemonic;
    if (operands.empty() || operands[0].kind != OperandKind::Register) {
      unsupported(block, instruction);
      return;
    }
    const std::uint8_t width = register_width(operands[0].reg);
    if (width != 4 && width != 8) {
      unsupported(block, instruction);
      return;
    }
    const std::uint64_t bits = static_cast<std::uint64_t>(width) * 8U;
    const std::uint64_t all_ones = width == 8 ? ~0ULL : 0xFFFF'FFFFULL;
    const auto constant = [&](std::uint64_t value) {
      return IrOperand::constant_value(value & all_ones, width);
    };
    const auto fresh = [&]() { return temp_operand(temporary_id(), width); };
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
    const IrOperand none = IrOperand::none();
    if (operands[0].kind == OperandKind::Register &&
        (operands[0].reg == "xzr" || operands[0].reg == "wzr")) {
      // The result is discarded, and none of these instructions sets flags or
      // has another effect, so there is nothing to lift.
      return;
    }
    const IrOperand destination = to_ir_operand(operands[0], width);
    const auto is_register = [&](std::size_t index) {
      return index < operands.size() && operands[index].kind == OperandKind::Register;
    };
    const auto is_immediate = [&](std::size_t index) {
      return index < operands.size() && operands[index].kind == OperandKind::Immediate;
    };

    if (mnemonic == "udiv" || mnemonic == "sdiv") {
      if (operands.size() != 3 || !is_register(1) || !is_register(2)) {
        unsupported(block, instruction);
        return;
      }
      const IrOperand n = to_ir_operand(operands[1], width);
      const IrOperand m = to_ir_operand(operands[2], width);
      // nz = 1 when m != 0: the top bit of m | -m is set exactly when m is non-zero.
      const IrOperand negm = fresh();
      emit(IrOp::Sub, negm, constant(0), m, none);
      const IrOperand orm = fresh();
      emit(IrOp::Or, orm, m, negm, none);
      const IrOperand nz = fresh();
      emit(IrOp::Shr, nz, orm, constant(bits - 1), none);
      // zero_flag = 1 when m == 0, where the result is 0.
      const IrOperand zero_flag = fresh();
      emit(IrOp::Sub, zero_flag, constant(1), nz, none);
      if (mnemonic == "udiv") {
        // The divisor is m, or 1 when m == 0 (the quotient is then n, and it is
        // multiplied by nz = 0).
        const IrOperand safe = fresh();
        emit(IrOp::Add, safe, m, zero_flag, none);
        const IrOperand quotient = fresh();
        emit(IrOp::DivUnsigned, quotient, constant(0), n, safe);
        emit(IrOp::Mul, destination, quotient, nz, none);
        return;
      }
      // is_minus_one = 1 when m == -1, where the result is -n. m + 1 == 0 exactly then.
      const IrOperand m1 = fresh();
      emit(IrOp::Add, m1, m, constant(1), none);
      const IrOperand negm1 = fresh();
      emit(IrOp::Sub, negm1, constant(0), m1, none);
      const IrOperand orm1 = fresh();
      emit(IrOp::Or, orm1, m1, negm1, none);
      const IrOperand nz1 = fresh();
      emit(IrOp::Shr, nz1, orm1, constant(bits - 1), none);
      const IrOperand is_minus_one = fresh();
      emit(IrOp::Sub, is_minus_one, constant(1), nz1, none);
      // The divisor is 1 where m is 0 or -1: m + zero_flag + 2 * is_minus_one.
      const IrOperand twice = fresh();
      emit(IrOp::Add, twice, is_minus_one, is_minus_one, none);
      const IrOperand shifted = fresh();
      emit(IrOp::Add, shifted, m, zero_flag, none);
      const IrOperand safe = fresh();
      emit(IrOp::Add, safe, shifted, twice, none);
      // The dividend is n sign-extended to 2 * width bits.
      const IrOperand high = fresh();
      emit(IrOp::Sar, high, n, constant(bits - 1), none);
      const IrOperand quotient = fresh();
      emit(IrOp::DivSigned, quotient, high, n, safe);
      // Quotient coefficient: nz - is_minus_one, which is 1 for a normal divisor.
      const IrOperand quotient_coefficient = fresh();
      emit(IrOp::Sub, quotient_coefficient, nz, is_minus_one, none);
      const IrOperand negn = fresh();
      emit(IrOp::Sub, negn, constant(0), n, none);
      const IrOperand from_quotient = fresh();
      emit(IrOp::Mul, from_quotient, quotient, quotient_coefficient, none);
      const IrOperand from_negation = fresh();
      emit(IrOp::Mul, from_negation, negn, is_minus_one, none);
      emit(IrOp::Add, destination, from_quotient, from_negation, none);
      return;
    }

    if (mnemonic == "umulh" || mnemonic == "smulh") {
      if (width != 8 || operands.size() != 3 || !is_register(1) || !is_register(2)) {
        unsupported(block, instruction);  // only the 64-bit forms exist
        return;
      }
      emit(mnemonic == "umulh" ? IrOp::MulHighUnsigned : IrOp::MulHighSigned, destination,
           to_ir_operand(operands[1], width), to_ir_operand(operands[2], width), none);
      return;
    }

    if (mnemonic == "clz" || mnemonic == "cls") {
      if (operands.size() != 2 || !is_register(1)) {
        unsupported(block, instruction);
        return;
      }
      const IrOperand n = to_ir_operand(operands[1], width);
      if (mnemonic == "clz") {
        emit(IrOp::CountLeadingZeros, destination, n, none, none);
        return;
      }
      // cls counts the leading bits equal to the sign bit: clz(n ^ sign) - 1.
      const IrOperand sign = fresh();
      emit(IrOp::Sar, sign, n, constant(bits - 1), none);
      const IrOperand differs = fresh();
      emit(IrOp::Xor, differs, n, sign, none);
      const IrOperand count = fresh();
      emit(IrOp::CountLeadingZeros, count, differs, none, none);
      emit(IrOp::Sub, destination, count, constant(1), none);
      return;
    }

    if (mnemonic == "rbit") {
      if (operands.size() != 2 || !is_register(1)) {
        unsupported(block, instruction);
        return;
      }
      // Swap adjacent groups of 1, 2, 4, ... bits. mask selects the bit positions
      // whose index has the group bit clear.
      IrOperand value = to_ir_operand(operands[1], width);
      for (std::uint64_t group = 1; group < bits; group <<= 1) {
        std::uint64_t mask = 0;
        for (std::uint64_t index = 0; index < bits; ++index) {
          if ((index & group) == 0) {
            mask |= 1ULL << index;
          }
        }
        const IrOperand low = fresh();
        emit(IrOp::And, low, value, constant(mask), none);
        const IrOperand low_up = fresh();
        emit(IrOp::Shl, low_up, low, constant(group), none);
        const IrOperand high = fresh();
        emit(IrOp::Shr, high, value, constant(group), none);
        const IrOperand high_down = fresh();
        emit(IrOp::And, high_down, high, constant(mask), none);
        const IrOperand swapped = fresh();
        emit(IrOp::Or, swapped, low_up, high_down, none);
        value = swapped;
      }
      emit(IrOp::Assign, destination, value, none, none);
      return;
    }

    if (mnemonic == "rev") {
      if (operands.size() != 2 || !is_register(1)) {
        unsupported(block, instruction);
        return;
      }
      emit(IrOp::ByteSwap, destination, to_ir_operand(operands[1], width), none, none);
      return;
    }

    if (mnemonic == "rev16") {
      // Swap the bytes of each 16-bit half.
      if (operands.size() != 2 || !is_register(1)) {
        unsupported(block, instruction);
        return;
      }
      const IrOperand n = to_ir_operand(operands[1], width);
      const std::uint64_t mask = 0x00FF'00FF'00FF'00FFULL;
      const IrOperand low = fresh();
      emit(IrOp::And, low, n, constant(mask), none);
      const IrOperand low_up = fresh();
      emit(IrOp::Shl, low_up, low, constant(8), none);
      const IrOperand high = fresh();
      emit(IrOp::Shr, high, n, constant(8), none);
      const IrOperand high_down = fresh();
      emit(IrOp::And, high_down, high, constant(mask), none);
      emit(IrOp::Or, destination, low_up, high_down, none);
      return;
    }

    if (mnemonic == "rev32") {
      // Swap the bytes of each 32-bit half: the full byte swap with its halves exchanged.
      if (width != 8 || operands.size() != 2 || !is_register(1)) {
        unsupported(block, instruction);
        return;
      }
      const IrOperand swapped = fresh();
      emit(IrOp::ByteSwap, swapped, to_ir_operand(operands[1], width), none, none);
      const IrOperand high = fresh();
      emit(IrOp::Shl, high, swapped, constant(32), none);
      const IrOperand low = fresh();
      emit(IrOp::Shr, low, swapped, constant(32), none);
      emit(IrOp::Or, destination, high, low, none);
      return;
    }

    if (mnemonic == "extr") {
      // extr Rd, Rn, Rm, #lsb: the low width bits of (Rn:Rm) >> lsb.
      if (operands.size() != 4 || !is_register(1) || !is_register(2) || !is_immediate(3)) {
        unsupported(block, instruction);
        return;
      }
      const std::uint64_t lsb = static_cast<std::uint64_t>(operands[3].immediate);
      if (lsb >= bits) {
        unsupported(block, instruction);
        return;
      }
      const IrOperand n = to_ir_operand(operands[1], width);
      const IrOperand m = to_ir_operand(operands[2], width);
      if (lsb == 0) {
        emit(IrOp::Assign, destination, m, none, none);
        return;
      }
      const IrOperand low = fresh();
      emit(IrOp::Shr, low, m, constant(lsb), none);
      const IrOperand high = fresh();
      emit(IrOp::Shl, high, n, constant(bits - lsb), none);
      emit(IrOp::Or, destination, low, high, none);
      return;
    }

    if (mnemonic == "bfi" || mnemonic == "bfxil") {
      // bfi Rd, Rn, #lsb, #width: insert the low width bits of Rn at lsb.
      // bfxil Rd, Rn, #lsb, #width: copy the bits [lsb, lsb + width) of Rn to the low end.
      if (operands.size() != 4 || !is_register(1) || !is_immediate(2) || !is_immediate(3)) {
        unsupported(block, instruction);
        return;
      }
      const std::uint64_t lsb = static_cast<std::uint64_t>(operands[2].immediate);
      const std::uint64_t field_width = static_cast<std::uint64_t>(operands[3].immediate);
      if (field_width == 0 || lsb >= bits || lsb + field_width > bits) {
        unsupported(block, instruction);
        return;
      }
      const std::uint64_t field = field_width >= 64 ? ~0ULL : (1ULL << field_width) - 1;
      const IrOperand n = to_ir_operand(operands[1], width);
      if (mnemonic == "bfi") {
        const std::uint64_t placed = (field << lsb) & all_ones;
        const IrOperand kept = fresh();
        emit(IrOp::And, kept, destination, constant(~placed), none);
        const IrOperand shifted = fresh();
        emit(IrOp::Shl, shifted, n, constant(lsb), none);
        const IrOperand inserted = fresh();
        emit(IrOp::And, inserted, shifted, constant(placed), none);
        emit(IrOp::Or, destination, kept, inserted, none);
        return;
      }
      const IrOperand kept = fresh();
      emit(IrOp::And, kept, destination, constant(~field), none);
      const IrOperand shifted = fresh();
      emit(IrOp::Shr, shifted, n, constant(lsb), none);
      const IrOperand extracted = fresh();
      emit(IrOp::And, extracted, shifted, constant(field), none);
      emit(IrOp::Or, destination, kept, extracted, none);
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
    // sxtb/uxtb/sxth/uxth read only the low byte or halfword of the source.
    statement.a.width = source_width;
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
    bool location_failed = false;
    const IrOperand location =
        access_location(block, instruction, *access.memory, width, location_failed);
    if (location_failed) {
      unsupported(block, instruction);
      return;
    }

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
    if (!access.valid || indexed_memory(*access.memory)) {
      unsupported(block, instruction);
      return;
    }
    const std::uint8_t width = register_width(operands[0].reg);
    if (width == 0) {
      unsupported(block, instruction);
      return;
    }
    const bool is_load = instruction.mnemonic == "ldp" || instruction.mnemonic == "ldpsw";
    if (is_load) {
      // ldpsw loads two signed 32-bit words into 64-bit registers.
      const bool sign_words = instruction.mnemonic == "ldpsw";
      const std::uint8_t element = sign_words ? std::uint8_t{4} : width;
      if (sign_words && width != 8) {
        unsupported(block, instruction);
        return;
      }
      // Both addresses use the base as it was before the instruction:
      // when the first destination is the base (ldp x0, x1, [x0]), load the
      // second register first so its address is not computed from the
      // value just loaded.
      const std::string base_family = internal::register_family(access.memory->memory.base);
      const bool first_is_base = internal::register_family(operands[0].reg) == base_family;
      const auto load_one = [&](std::size_t index) {
        const std::int64_t offset = static_cast<std::int64_t>(index) * element;
        if (!sign_words) {
          IrStatement load;
          load.op = IrOp::Load;
          load.dest = to_ir_operand(operands[index], width);
          load.a = memory_at(*access.memory, width, offset);
          load.width = width;
          load.source_address = instruction.address;
          push(block, std::move(load));
          return;
        }
        const std::uint32_t id = temporary_id();
        IrStatement load;
        load.op = IrOp::Load;
        load.dest = temp_operand(id, element);
        load.a = memory_at(*access.memory, element, offset);
        load.width = element;
        load.source_address = instruction.address;
        push(block, std::move(load));
        IrStatement extend;
        extend.op = IrOp::SignExtend;
        extend.dest = to_ir_operand(operands[index], width);
        extend.a = temp_operand(id, element);
        extend.width = width;
        extend.source_address = instruction.address;
        push(block, std::move(extend));
      };
      if (first_is_base) {
        load_one(1);
        load_one(0);
      } else {
        load_one(0);
        load_one(1);
      }
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

/// The synthetic register that holds a jump table's selector from its compare
/// to its jump. Not an architectural name, so it cannot collide with one.
constexpr const char* kJumpSelectorRegister = "jump_selector";

/// A jump table the analysis recovered (G03-T3), lowered as the x86 lifter
/// lowers one: a switch over the selector copy, with one case per table entry.
/// Returns false, with a note, when the cases are not all blocks of this
/// function; the jump then stays a tail call.
bool lift_jump_table_switch(Lifter& lifter, IrBlock& out_block, const AnalysisResult& analysis,
                            const JumpTable& table, std::uint64_t jump_address) {
  const bool check_found = std::any_of(
      analysis.instructions.begin(), analysis.instructions.end(),
      [&](const Instruction& candidate) { return candidate.address == table.check_address; });
  std::vector<IrSwitchCase> cases;
  for (std::size_t value = 0; check_found && value < table.targets.size(); ++value) {
    const auto block_it = lifter.block_by_address.find(table.targets[value]);
    if (block_it == lifter.block_by_address.end()) {
      break;
    }
    cases.push_back(IrSwitchCase{value, block_it->second});
  }
  IrOperand selector;
  if (check_found && cases.size() == table.targets.size() && !cases.empty()) {
    selector = IrOperand::register_ref(kJumpSelectorRegister, register_width(table.selector.reg));
  }
  if (selector.kind == IrOperandKind::None) {
    lifter.mark_partial("jump table cases lie outside this function");
    return false;
  }
  IrStatement sw;
  sw.op = IrOp::Switch;
  sw.source_address = jump_address;
  sw.width = kPointerWidth;
  sw.dest = selector;
  sw.switch_cases = std::move(cases);
  // Out-of-range selectors were sent elsewhere by the bounds check before this
  // jump, so the default is unreachable here when it is not a block of this
  // function.
  const auto fallback = lifter.block_by_address.find(table.default_target);
  sw.a = IrOperand::block_ref(fallback != lifter.block_by_address.end()
                                  ? fallback->second
                                  : sw.switch_cases.front().target_block);
  lifter.push(out_block, std::move(sw));
  return true;
}

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
  lifter.out.notes.push_back("AArch64 subset; locals are not recovered");

  for (const BasicBlock* block : lifter.blocks) {
    IrBlock out_block;
    out_block.address = block->address;
    // The flags exact at the end of the previous block carry into this one when this
    // block has no other predecessor: the cmp or tst that set them is repeated here,
    // from the same operands, before anything else in the block.
    const bool entering = lifter.flags_exact;
    lifter.flags_exact = false;
    const std::uint32_t block_index = lifter.block_by_address.at(block->address);
    if (block_index > 0 && entering && lifter.out.blocks.size() == block_index) {
      const BasicBlock& previous = *lifter.blocks[block_index - 1];
      if (previous.end_address == block->address) {
        const auto writer = lifter.carried_flag_writer(previous);
        if (writer && lifter.single_fallthrough_predecessor(previous, *block)) {
          lifter.modelled_flags = false;
          lifter.lift_arithmetic(out_block, analysis.instructions[*writer]);
          bool unsupported_statement = false;
          for (const IrStatement& statement : out_block.statements) {
            unsupported_statement = unsupported_statement || statement.op == IrOp::Unsupported;
          }
          lifter.flags_exact = lifter.modelled_flags && !unsupported_statement;
        }
      }
    }

    for (std::uint32_t i = 0; i < block->instruction_count; ++i) {
      const std::size_t index = static_cast<std::size_t>(block->first_instruction) + i;
      if (index >= analysis.instructions.size()) {
        lifter.out.partial = true;
        break;
      }
      const Instruction& instruction = analysis.instructions[index];
      const std::string& mnemonic = instruction.mnemonic;

      if (instruction.classification == InstructionClass::ConditionalJump) {
        // A jump table behind this branch switches on the value the compare
        // tested. Its table code may overwrite that register (GCC keeps the
        // table base in x0), so the value is copied here, after the compare
        // and before the branch.
        for (const JumpTable& table : analysis.cfg.jump_tables) {
          // The recogniser only accepts a compare directly before the branch,
          // and AArch64 instructions are four bytes.
          if (table.check_address + 4 == instruction.address) {
            IrStatement copy;
            copy.op = IrOp::Assign;
            copy.source_address = instruction.address;
            copy.width = register_width(table.selector.reg);
            copy.dest = IrOperand::register_ref(kJumpSelectorRegister, copy.width);
            copy.a = lifter.to_ir_operand(table.selector, copy.width);
            lifter.push(out_block, std::move(copy));
          }
        }
        IrCondition condition = branch_condition(mnemonic);
        if (mnemonic == "cbz" || mnemonic == "cbnz") {
          // cbz/cbnz test a register, not the flags: exact.
          lifter.lift_compare_zero(out_block, instruction);
          condition = mnemonic == "cbz" ? IrCondition::Zero : IrCondition::NonZero;
        } else if (mnemonic == "tbz" || mnemonic == "tbnz") {
          lifter.lift_test_bit(out_block, instruction);
          condition = mnemonic == "tbz" ? IrCondition::Zero : IrCondition::NonZero;
        } else if (!lifter.flags_exact) {
          lifter.mark_partial(
              "conditional branch depends on flags not set by a modelled cmp/tst/subs/ands in "
              "the same block");
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
        const JumpTable* table = nullptr;
        if (!instruction.direct_target.has_value()) {
          for (const JumpTable& candidate : analysis.cfg.jump_tables) {
            if (candidate.jump_address == instruction.address) {
              table = &candidate;
            }
          }
        }
        if (table != nullptr &&
            lift_jump_table_switch(lifter, out_block, analysis, *table, instruction.address)) {
          continue;
        }
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
        // The callee's effects on registers, memory and NZCV are not modelled.
        lifter.mark_partial("outgoing call arguments and return values follow no modelled ABI");
        lifter.flags_exact = false;  // the callee may change NZCV
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

      lifter.modelled_flags = false;
      const std::size_t statements_before = out_block.statements.size();
      if (mnemonic == "mov" || mnemonic == "movz" || mnemonic == "movn" || mnemonic == "movk") {
        lifter.lift_move(out_block, instruction);
      } else if (mnemonic == "add" || mnemonic == "adds" || mnemonic == "sub" ||
                 mnemonic == "subs" || mnemonic == "and" || mnemonic == "ands" ||
                 mnemonic == "orr" || mnemonic == "eor" || mnemonic == "cmp" || mnemonic == "tst" ||
                 mnemonic == "neg" || mnemonic == "negs" || mnemonic == "lsl" ||
                 mnemonic == "lsr" || mnemonic == "asr" || mnemonic == "mvn" || mnemonic == "cmn") {
        lifter.lift_arithmetic(out_block, instruction);
      } else if (mnemonic == "ror" || mnemonic == "ubfiz" || mnemonic == "sbfiz" ||
                 mnemonic == "ubfx" || mnemonic == "sbfx") {
        lifter.lift_bitfield(out_block, instruction);
      } else if (mnemonic == "csel" || mnemonic == "fcsel" || mnemonic == "csinc" ||
                 mnemonic == "csinv" || mnemonic == "csneg" || mnemonic == "cset" ||
                 mnemonic == "csetm" || mnemonic == "cinc" || mnemonic == "cinv" ||
                 mnemonic == "cneg") {
        lifter.lift_conditional_select(out_block, instruction);
      } else if (mnemonic == "mul" || mnemonic == "madd" || mnemonic == "msub") {
        lifter.lift_multiply(out_block, instruction);
      } else if (mnemonic == "umull" || mnemonic == "smull" || mnemonic == "umaddl" ||
                 mnemonic == "smaddl" || mnemonic == "umsubl" || mnemonic == "smsubl" ||
                 mnemonic == "umnegl" || mnemonic == "smnegl") {
        lifter.lift_widening_multiply(out_block, instruction);
      } else if (mnemonic == "adc" || mnemonic == "sbc" || mnemonic == "adcs" ||
                 mnemonic == "sbcs") {
        lifter.lift_add_with_carry(out_block, instruction);
      } else if (mnemonic == "ccmp" || mnemonic == "ccmn") {
        lifter.lift_conditional_compare(out_block, instruction);
      } else if (mnemonic == "udiv" || mnemonic == "sdiv" || mnemonic == "umulh" ||
                 mnemonic == "smulh" || mnemonic == "clz" || mnemonic == "cls" ||
                 mnemonic == "rbit" || mnemonic == "rev" || mnemonic == "rev16" ||
                 mnemonic == "rev32" || mnemonic == "extr" || mnemonic == "bfi" ||
                 mnemonic == "bfxil") {
        lifter.lift_bit_and_division(out_block, instruction);
      } else if (mnemonic == "sxtb" || mnemonic == "sxth" || mnemonic == "sxtw" ||
                 mnemonic == "uxtb" || mnemonic == "uxth" || mnemonic == "uxtw") {
        lifter.lift_extend(out_block, instruction);
      } else if (mnemonic == "adr" || mnemonic == "adrp") {
        lifter.lift_address(out_block, instruction);
      } else if (mnemonic == "ldp" || mnemonic == "ldpsw" || mnemonic == "stp") {
        lifter.lift_pair(out_block, instruction);
      } else if (mnemonic == "ldr" || mnemonic == "str" || mnemonic == "ldur" ||
                 mnemonic == "stur" || mnemonic == "ldrb" || mnemonic == "strb" ||
                 mnemonic == "ldrh" || mnemonic == "strh" || mnemonic == "ldrsb" ||
                 mnemonic == "ldrsh" || mnemonic == "ldrsw") {
        lifter.lift_load_store(out_block, instruction);
      } else if (mnemonic == "nop" || mnemonic == "bti" || mnemonic == "hint") {
        // No semantic effect in the IR.
      } else if (is_scalar_fp_mnemonic(mnemonic)) {
        if (!lifter.lift_scalar_fp(out_block, instruction)) {
          lifter.unsupported(out_block, instruction);
        }
      } else {
        lifter.unsupported(out_block, instruction);
      }
      if (sets_flags(mnemonic)) {
        lifter.flags_exact = lifter.modelled_flags;
      }
      // An unsupported statement may have written the flags, so no later flag reader
      // is exact. This also keeps an adc from reading a carry through an unsupported one.
      for (std::size_t s = statements_before; s < out_block.statements.size(); ++s) {
        if (out_block.statements[s].op == IrOp::Unsupported) {
          lifter.flags_exact = false;
        }
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
