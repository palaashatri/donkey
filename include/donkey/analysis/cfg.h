#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "donkey/core/ids.h"
#include "donkey/core/status.h"
#include "donkey/decode/decode.h"

namespace donkey {

/// A seeded function. Extents are derived from reachable basic blocks, so they
/// are estimates: unresolved indirect jumps, overlapping code and analysis
/// limits make a function's true end unknowable without runtime information.
struct Function {
  FunctionId id;
  std::string name;
  std::uint64_t address = 0;
  /// Exclusive end address of the last reachable block. Only meaningful when
  /// `has_extent` is true.
  std::uint64_t end_address = 0;
  std::uint32_t block_count = 0;
  bool has_extent = false;
  bool exported = false;
  bool from_symbol = false;
  /// The start is an FDE of the image's `.eh_frame` (G23-T1): the compiler's unwind table names it.
  bool from_unwind = false;
  bool estimated = true;
  /// The function is an import stub (G24-T4): a PLT entry (`.plt`, `.plt.sec`, `.plt.got`) whose
  /// relocation names the import it jumps to. `name` is then `<import>@plt`, and this field holds
  /// the import's own name, which the pseudocode prints as the call target.
  std::string import_name;
  /// For any PLT stub, the name its relocation names (G24-T4): the import, or, for a stub of an
  /// interposable function the image defines itself (libc's `free@plt`), that function's name.
  /// The pseudocode prints a call to the stub by it. Only `import_name` marks an import.
  std::string stub_target;
  /// For a stub that jumps through an import's slot (a PE IAT slot, or an ELF GOT slot named by a
  /// relocation), that slot's address; 0 for a PLT stub found by its relocation.
  std::uint64_t import_slot = 0;
  /// The function is a thunk (G24-T4): its only instruction is an unconditional direct jump to
  /// another function's start. `name` is then `j_` and the target's name, unless a symbol names it.
  bool thunk = false;
  std::uint64_t thunk_target = 0;
  /// A call to this function does not return (G24-T3): an import on the fixed list bound to a
  /// runtime library, or a function of the image whose every path ends in such a call or in an
  /// instruction that never falls through. `no_return_reason` is the evidence, for example
  /// `known-name:abort version:GLIBC_2.2.5 file:libc.so.6` or `propagated:every path calls abort`.
  bool no_return = false;
  std::string no_return_reason;
};

struct BasicBlock {
  BasicBlockId id;
  FunctionId function;
  std::uint64_t address = 0;
  /// Exclusive end address.
  std::uint64_t end_address = 0;
  /// Index into AnalysisResult::instructions of the first instruction.
  std::uint32_t first_instruction = 0;
  std::uint32_t instruction_count = 0;
};

enum class CfgEdgeKind : std::uint8_t {
  Unknown = 0,
  Jump,
  ConditionalTrue,
  ConditionalFalse,
  Indirect,
  Call,
  JumpTable,  ///< one recovered target of a jump table
  /// An unconditional direct jump to another function's start or to an import stub (G24-T4): the
  /// target is not followed, because its code belongs to that function.
  TailCall,
};

const char* cfg_edge_kind_name(CfgEdgeKind kind) noexcept;

struct CfgEdge {
  /// Address of the instruction that creates the edge.
  std::uint64_t from = 0;
  /// Target address, or 0 when the target is unknown (indirect branch).
  std::uint64_t to = 0;
  CfgEdgeKind kind = CfgEdgeKind::Unknown;
};

/// A jump table recovered from the code that indexes it: the bounds check
/// `cmp selector, N` + `ja/jae default`, then straight-line code that loads
/// a target from a table in the image and jumps to it. Every target was
/// computed by evaluating that code for each index with the table's bytes and
/// lands on a decoded instruction in executable code.
struct JumpTable {
  std::uint64_t jump_address = 0;    ///< the indirect jmp
  std::uint64_t check_address = 0;   ///< the cmp that bounds the selector
  std::uint64_t default_target = 0;  ///< where an out-of-range selector goes
  /// The compared operand (register or memory) as the decoder reported it;
  /// nothing between the check and the jump writes it.
  Operand selector;
  std::vector<std::uint64_t> targets;  ///< targets[i] for selector == i
};

struct ControlFlowGraph {
  /// Seeded functions with estimated extents, in the order they were seeded.
  std::vector<Function> functions;
  std::vector<BasicBlock> blocks;
  std::vector<CfgEdge> edges;
  std::vector<JumpTable> jump_tables;
  /// True when a limit was hit, code overlapped, or an indirect branch left
  /// successors unknown. Extents are then lower bounds, never exact.
  bool partial = false;
  std::vector<Diagnostic> diagnostics;
};

}  // namespace donkey
