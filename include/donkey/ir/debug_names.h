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

}  // namespace donkey
