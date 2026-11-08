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

/// Replaces a load from a frame slot by a copy of the register that was stored to the slot, while
/// neither the slot nor the register has changed (G05-T3). Only 8-byte accesses are forwarded.
void forward_slot_copies(IrFunction& function);

/// Reads a register that was loaded from memory and compared on the next statement straight from
/// the memory, and removes the load, when the register is dead after the compare (G04-T3). The
/// compare sees the same value at the same point, so the change is exact.
void forward_compare_loads(IrFunction& function);

/// Lays a bottom-tested loop out with its test first, so the structurer sees a while loop
/// (G04-T3). The change swaps two adjacent blocks, negates the test and renumbers every block
/// reference. It is exact: the same blocks run in the same order. The G04-T0 checker runs it
/// like the other passes.
void arrange_loop_tests(IrFunction& function);

}  // namespace donkey::internal
