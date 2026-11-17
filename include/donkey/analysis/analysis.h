#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "donkey/analysis/cfg.h"
#include "donkey/binary/image.h"
#include "donkey/core/cancellation.h"
#include "donkey/core/ids.h"
#include "donkey/core/result.h"
#include "donkey/decode/decode.h"

namespace donkey {

enum class XrefKind : std::uint8_t { Unknown = 0, Call, Jump, Data };
const char* xref_kind_name(XrefKind kind) noexcept;

struct Xref {
  std::uint64_t from = 0;
  std::uint64_t to = 0;
  XrefKind kind = XrefKind::Unknown;
};

struct StringLiteral {
  std::uint64_t file_offset = 0;
  std::uint64_t address = 0;
  bool mapped = false;
  std::string text;
  std::string encoding;
};

/// One call site: the function containing it calls `callee`.
struct CallGraphEdge {
  std::uint64_t caller = 0;  ///< entry of the calling function
  std::uint64_t callee = 0;  ///< direct call target
  std::uint64_t site = 0;    ///< address of the call instruction
};

/// Direct calls between functions. Indirect calls are listed as unresolved
/// sites instead of being given guessed targets.
struct CallGraph {
  std::vector<CallGraphEdge> edges;  ///< sorted by caller, then site
  struct Unresolved {
    std::uint64_t caller = 0;
    std::uint64_t site = 0;
  };
  std::vector<Unresolved> unresolved;
  /// Call sites in functions the CFG did not cover (caller unknown).
  std::size_t orphan_sites = 0;

  [[nodiscard]] std::vector<CallGraphEdge> callers_of(std::uint64_t function) const;
  [[nodiscard]] std::vector<CallGraphEdge> callees_of(std::uint64_t function) const;
};

/// Bytes the user declared to be data (G12-T1): `count` elements of `element_size` bytes at
/// `address`, or `count` undefined bytes when `element_size` is 0. The sweep never decodes
/// them, and no function starts inside them. A range that would run past the top of the
/// address space is ignored.
struct UserDataRange {
  std::uint64_t address = 0;
  std::uint64_t element_size = 0;
  std::uint64_t count = 0;

  /// Byte length of the range: count, or element size times count.
  [[nodiscard]] std::uint64_t byte_length() const noexcept {
    return element_size == 0 ? count : element_size * count;
  }
};

struct AnalysisOptions {
  std::size_t max_instructions = 1'000'000;
  std::size_t max_strings = 100'000;
  std::size_t min_string_length = 4;
  std::size_t max_string_length = 256;
  /// Build basic blocks, CFG edges and per-function extents. Off gives the M2
  /// linear behaviour: decoded instructions and seeds only.
  bool build_control_flow = true;
  /// Optional token to abort analysis cooperatively on request.
  CancellationToken cancellation_token = CancellationToken::none();
  /// Configured limits and budget.
  ResourceBudget budget;
  /// Function starts the user defined (seeded in addition to discovered ones)
  /// and discovered starts the user removed. Both come from the project.
  std::vector<std::uint64_t> user_function_starts;
  std::vector<std::uint64_t> removed_function_starts;
  /// Code starts the user declared (G12-T1). Each is seeded like a function start when it
  /// lies in an executable section and outside every user data range.
  std::vector<std::uint64_t> user_code_starts;
  /// Byte ranges the user declared to be data (G12-T1). See UserDataRange.
  std::vector<UserDataRange> user_data_ranges;
  /// Mark calls that do not return (G24-T3): calls to the no-return imports bound to a runtime
  /// library, then, propagated, to the image's functions whose every path ends in one.
  bool no_return_analysis = true;
  /// Addresses a call does not return from (G24-T3): function starts, and GOT or IAT slots that
  /// a `call *slot` reads. analyze() fills it from the analysis; a direct caller of
  /// build_control_flow_graph may set it. The walk does not continue after such a call.
  std::set<std::uint64_t> no_return_targets;
};

struct AnalysisResult {
  Architecture architecture = Architecture::Unknown;
  std::vector<Instruction> instructions;
  /// Seeded functions with estimated extents and block counts when
  /// `build_control_flow` is enabled.
  std::vector<Function> functions;
  ControlFlowGraph cfg;
  CallGraph call_graph;
  std::vector<Xref> xrefs;
  std::vector<StringLiteral> strings;
  /// GOT slots that a GLOB_DAT relocation for an import names (G24-T4), keyed by slot address:
  /// a `-fno-plt` call reads its target from one of them.
  std::map<std::uint64_t, std::string> import_slots;
  /// Every address a call does not return from (G24-T3), with its evidence: the stub and slot
  /// addresses of bound no-return imports, and the starts of functions propagated from them.
  std::map<std::uint64_t, std::string> no_return;
  bool partial = false;
  std::vector<Diagnostic> diagnostics;
};

/// The name a call to `function` prints: its import, its stub's target, or its own name; empty
/// when that is the synthetic `sub_<hex>` name or not a C identifier.
[[nodiscard]] std::string function_call_name(const Function& function);

/// The name a call to `address` prints as in pseudocode (G24-T4): the import's own name for an
/// import stub (`abort`, not `abort@plt`, so the output stays C), the function's name for a
/// function with a symbol or a thunk name, and empty when the name is synthetic (`sub_<hex>`) or
/// is not a C identifier. An address that is not a function start gives empty.
[[nodiscard]] std::string call_target_name(const AnalysisResult& analysis, std::uint64_t address);

/// True for a C identifier: a letter or `_`, then letters, digits and `_`.
[[nodiscard]] bool is_c_identifier(std::string_view text) noexcept;

/// Bounded printable-ASCII and UTF-16LE string extraction. Scans only
/// non-executable, file-backed sections when present, otherwise the whole file.
[[nodiscard]] Result<std::vector<StringLiteral>> extract_strings(
    const BinaryImage& image, std::span<const std::byte> file, const AnalysisOptions& options = {});

/// Bounded, deterministic control-flow reconstruction over an existing
/// instruction stream. Follows direct branches from every seed and never runs
/// code. x86 jump tables are recovered when their bounds check and table load
/// can be evaluated exactly (`file` holds the table bytes); every other
/// indirect jump ends a path and marks the result partial/estimated.
[[nodiscard]] Result<ControlFlowGraph> build_control_flow_graph(
    const BinaryImage& image, std::span<const Instruction> instructions,
    std::span<const Function> seeds, const AnalysisOptions& options = {},
    std::span<const std::byte> file = {});

/// Call graph from the CFG's blocks and the decoded call instructions.
[[nodiscard]] CallGraph build_call_graph(const ControlFlowGraph& cfg,
                                         std::span<const Instruction> instructions);

/// Linear disassembly of executable sections plus seeded function discovery.
/// When `build_control_flow` is set, basic blocks, CFG edges and estimated
/// function extents are derived from the decoded instructions.
[[nodiscard]] Result<AnalysisResult> analyze(const BinaryImage& image,
                                             std::span<const std::byte> file,
                                             const AnalysisOptions& options = {});

}  // namespace donkey
