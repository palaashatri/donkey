#pragma once

#include "donkey/ir/lift.h"

namespace donkey::internal {

/// Lift one AArch64 function. Declared here so the architecture dispatcher in
/// lift.cpp stays a single entry point and the verifier/printer contract is
/// shared by every lifter.
[[nodiscard]] Result<IrFunction> lift_aarch64(const BinaryImage& image,
                                              const AnalysisResult& analysis,
                                              const Function& function, const LiftOptions& options);

/// Rewrites every register operand to its family (eax, ax, al and rax become rax) and
/// makes the width rules explicit: a 4-byte write zero-extends, and a 1- or 2-byte
/// write, or a high-byte write, is an explicit merge. x86-64 and AArch64 only.
void canonicalise_registers(IrFunction& function, Architecture architecture);

/// Keeps the blocks reachable from the function's entry, puts a trampoline in front of an entry
/// that is not block 0, and notes the blocks left out. Returns false when nothing changed. See
/// lift.cpp for the rules. `function_id` is the CFG function the blocks came from.
[[nodiscard]] Result<bool> keep_reachable_blocks(IrFunction& function,
                                                 const AnalysisResult& analysis,
                                                 FunctionId function_id,
                                                 std::uint8_t pointer_width);

}  // namespace donkey::internal
