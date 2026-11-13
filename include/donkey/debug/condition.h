#pragma once

// Breakpoint conditions (G14-T5). A condition is `<operand> <op> <value>`. The operand is a
// register of the host (`rax`, `x0`, `pc`) or the 8-byte little-endian word at an address
// (`*0x4010` or `*(0x4010)`). The operator is one of `==`, `!=`, `<`, `<=`, `>`, `>=`. The value is
// a decimal or `0x` hexadecimal number. Comparisons are unsigned. Examples: `*0x4010 == 2`, `rdi !=
// 0`.
//
// Parsing reads only the text. The debugger checks that a register exists on its host, and reads
// the operand when the breakpoint is hit.

#include <cstdint>
#include <string>
#include <string_view>

#include "donkey/core/result.h"

namespace donkey::debug {

enum class ConditionOp : std::uint8_t { Equal, NotEqual, Less, LessEqual, Greater, GreaterEqual };

struct BreakCondition {
  bool memory = false;        ///< the operand is the 8-byte word at `address`
  std::string register_name;  ///< the operand when `memory` is false
  std::uint64_t address = 0;  ///< the operand's address when `memory` is true (runtime address)
  ConditionOp op = ConditionOp::Equal;
  std::uint64_t value = 0;  ///< the right-hand side
  std::string text;         ///< the condition as it was written
};

/// Parses a condition. A malformed one is an InvalidInput diagnostic that says what was expected.
[[nodiscard]] Result<BreakCondition> parse_break_condition(std::string_view text);

/// Whether `operand` (the register or memory value, read when the breakpoint hit) satisfies the
/// condition.
[[nodiscard]] bool condition_holds(const BreakCondition& condition, std::uint64_t operand) noexcept;

/// The operator as it is written in a condition: "==", "!=", "<", "<=", ">" or ">=".
[[nodiscard]] const char* condition_op_text(ConditionOp op) noexcept;

}  // namespace donkey::debug
