#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "donkey/core/result.h"
#include "donkey/core/status.h"

namespace donkey {

/// A deliberately small, verifiable IR. It is produced only by the x86-64
/// lifter today; no pseudocode is ever synthesised from strings or a model.
enum class IrOp : std::uint8_t {
  Nop = 0,
  Assign,       ///< dest = a
  Add,          ///< dest = a + b
  Sub,          ///< dest = a - b
  Mul,          ///< dest = a * b
  And,          ///< dest = a & b
  Or,           ///< dest = a | b
  Xor,          ///< dest = a ^ b
  Shl,          ///< dest = a << b
  Shr,          ///< dest = a >> b (logical)
  Sar,          ///< dest = a >> b (arithmetic)
  ZeroExtend,   ///< dest = (dest.width)a, zero-extended
  SignExtend,   ///< dest = (dest.width)a, sign-extended
  Lea,          ///< dest = address of a     (a is a memory operand)
  Load,         ///< dest = *(width*)a        (a is a memory operand)
  Store,        ///< *(width*)a = b           (a is a memory operand)
  Call,         ///< dest = call(a)           (a is a constant address, 0 = indirect)
  Return,       ///< return a (a may be None)
  Branch,       ///< goto block a.block
  CondBranch,   ///< if (condition over a) goto block b.block
  Compare,      ///< flags = a <condition> b
  Test,         ///< flags = a & b
  Unsupported,  ///< an instruction the lifter does not model; `text` is raw
};

const char* ir_op_name(IrOp op) noexcept;

enum class IrCondition : std::uint8_t {
  None = 0,
  Equal,
  NotEqual,
  UnsignedLess,
  UnsignedGreaterEqual,
  UnsignedGreater,
  UnsignedLessEqual,
  SignedLess,
  SignedGreaterEqual,
  SignedGreater,
  SignedLessEqual,
  Zero,
  NonZero,
  Negative,
  Positive,
  Overflow,
  NoOverflow,
  Carry,
  NoCarry,
};

const char* ir_condition_name(IrCondition condition) noexcept;
/// Textual form of a condition for a comparison between two operands.
const char* ir_condition_operator(IrCondition condition) noexcept;

enum class IrOperandKind : std::uint8_t {
  None = 0,
  Constant,
  Register,
  Memory,
  Block,
};

struct IrOperand {
  IrOperandKind kind = IrOperandKind::None;
  /// Constant value or displacement.
  std::uint64_t constant = 0;
  /// Register name, or base register for a memory operand.
  std::string reg;
  /// Index register for a memory operand.
  std::string index;
  std::int32_t scale = 1;
  /// Target block index for Block operands.
  std::uint32_t block = 0;
  /// Access/operation width in bytes.
  std::uint8_t width = 0;

  [[nodiscard]] static IrOperand none() { return {}; }
  [[nodiscard]] static IrOperand constant_value(std::uint64_t value, std::uint8_t width);
  [[nodiscard]] static IrOperand register_ref(std::string name, std::uint8_t width);
  [[nodiscard]] static IrOperand block_ref(std::uint32_t index);
};

struct IrStatement {
  IrOp op = IrOp::Nop;
  IrOperand dest;
  IrOperand a;
  IrOperand b;
  IrCondition condition = IrCondition::None;
  std::uint8_t width = 0;
  /// Address of the machine instruction this statement came from (0 for
  /// synthesized statements).
  std::uint64_t source_address = 0;
  /// Raw text for Unsupported statements only.
  std::string text;
};

struct IrBlock {
  std::uint64_t address = 0;
  std::vector<IrStatement> statements;
};

struct IrFunction {
  std::uint64_t address = 0;
  std::string name;
  std::vector<IrBlock> blocks;
  bool partial = false;
  std::vector<std::string> notes;
};

/// Check structural invariants: operand widths, block indices, def-use order
/// within each block, and required block terminators. Returns InvalidData with
/// a precise message; never throws.
[[nodiscard]] Result<bool> verify_ir(const IrFunction& function);

/// Verified C-like rendering of an IR function. Returns the verifier's
/// diagnostic if the IR is malformed; it never prints partial garbage.
[[nodiscard]] Result<std::string> format_pseudocode(const IrFunction& function);

}  // namespace donkey
