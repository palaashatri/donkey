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

/// Checks that no caller-saved register is read after a call without the call defining it (G21-T1),
/// and marks the function partial when one is (see lift.cpp). The lifter runs it after the passes
/// on x86-64 functions; the corpus test runs it on its replayed passes, so both see the same IR.
void check_call_clobbers(IrFunction& function);

/// Keeps the blocks reachable from the function's entry, puts a trampoline in front of an entry
/// that is not block 0, and notes the blocks left out. Returns false when nothing changed. See
/// lift.cpp for the rules. `function_id` is the CFG function the blocks came from.
[[nodiscard]] Result<bool> keep_reachable_blocks(IrFunction& function,
                                                 const AnalysisResult& analysis,
                                                 FunctionId function_id,
                                                 std::uint8_t pointer_width);

/// G24-T3: when `block` ends in a call to an address the analysis marks as not returning (a
/// direct target, or the GOT or IAT slot an indirect call reads), marks the call `no_return` and
/// ends the block with an unreachable Return, and returns true. The lifters call it where a block
/// would otherwise fall through or get a synthetic return.
bool end_block_at_no_return_call(const AnalysisResult& analysis, IrBlock& block,
                                 std::uint8_t pointer_width);

}  // namespace donkey::internal
