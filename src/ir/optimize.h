#pragma once

// Passes that make the IR smaller without changing what it computes (G04-T2). Each one
// is checked by DecompilerCorpus.EveryPassPreservesSemantics: the interpreter runs the
// function before and after the pass on the corpus inputs, and any difference fails.
//
// What is not done yet: the passes work within one block, so there is no SSA form and
// no liveness across blocks. A register written in one block and read in another is
// kept as it is.

#include "donkey/ir/ir.h"

namespace donkey::internal {

/// Replaces a read of a register that holds a copy of another 8-byte register, or of a
/// constant, by that register or constant, until either register is written again.
/// Calls and unsupported statements forget every copy.
void propagate_copies(IrFunction& function);

/// Removes assignments to temporaries that nothing reads. Only statements that cannot
/// fault or set flags are removed, so a removed statement had no other effect.
void remove_dead_temporaries(IrFunction& function);

/// Removes a pure write to a register whose value no later statement reads. Liveness is
/// computed over the blocks: a return reads its value, and a call or an unsupported
/// statement may read any register. Loads, stores and calls are never removed.
void remove_dead_register_writes(IrFunction& function);

}  // namespace donkey::internal
