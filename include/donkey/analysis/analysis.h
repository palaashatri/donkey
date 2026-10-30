#pragma once

#include <cstdint>
#include <span>
#include <string>
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
};

struct AnalysisResult {
  Architecture architecture = Architecture::Unknown;
  std::vector<Instruction> instructions;
  /// Seeded functions with estimated extents and block counts when
  /// `build_control_flow` is enabled.
  std::vector<Function> functions;
  ControlFlowGraph cfg;
  std::vector<Xref> xrefs;
  std::vector<StringLiteral> strings;
  bool partial = false;
  std::vector<Diagnostic> diagnostics;
};

/// Bounded printable-ASCII and UTF-16LE string extraction. Scans only
/// non-executable, file-backed sections when present, otherwise the whole file.
[[nodiscard]] Result<std::vector<StringLiteral>> extract_strings(
    const BinaryImage& image, std::span<const std::byte> file, const AnalysisOptions& options = {});

/// Bounded, deterministic control-flow reconstruction over an existing
/// instruction stream. Follows direct branches from every seed and never runs
/// code. Indirect jumps end a path and mark the result partial/estimated.
[[nodiscard]] Result<ControlFlowGraph> build_control_flow_graph(
    const BinaryImage& image, std::span<const Instruction> instructions,
    std::span<const Function> seeds, const AnalysisOptions& options = {});

/// Linear disassembly of executable sections plus seeded function discovery.
/// When `build_control_flow` is set, basic blocks, CFG edges and estimated
/// function extents are derived from the decoded instructions.
[[nodiscard]] Result<AnalysisResult> analyze(const BinaryImage& image,
                                             std::span<const std::byte> file,
                                             const AnalysisOptions& options = {});

}  // namespace donkey
