#pragma once

// Display names for the parameters of a recovered function, taken from the debug
// information of the same binary (G04-T4). A name is for display only: the registers,
// statements, types and layouts of the IR do not change.

#include "donkey/binary/debug_info.h"
#include "donkey/core/result.h"
#include "donkey/ir/ir.h"

namespace donkey {

/// Names the parameters of `function` after the parameters of `debug`, in order. The
/// names are applied only when every check holds: the parameter counts are equal; each
/// debug parameter has a scalar type (an integer, pointer, enum or float; a structure or
/// array passed by value is not matched by position) whose size and class are those of
/// the register the function reads; and the names are distinct C identifiers. Otherwise
/// the function is left as it was.
///
/// Errors are `InvalidInput` with a code under `ir.debug_names_`.
[[nodiscard]] Result<bool> apply_debug_parameter_names(IrFunction& function,
                                                       const DebugFunction& debug,
                                                       const DebugInfo& info);

/// Names the memory operands that are frame slots of `function` after the parameters and
/// locals of `debug` (G04-T4). The stack pointer's movement is tracked from the entry: the
/// slot of an access at `rsp + k` is the one whose CFA offset is `-8 + delta + k`. A
/// function whose stack pointer moves in any other way, or whose frame does not balance, is
/// left unnamed. Only the operands' display names change. Returns whether any name was set.
[[nodiscard]] Result<bool> apply_debug_stack_names(IrFunction& function, const DebugFunction& debug,
                                                   const DebugInfo& info);

}  // namespace donkey
