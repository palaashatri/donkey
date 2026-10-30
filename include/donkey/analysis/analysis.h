#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "donkey/binary/image.h"
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

struct FunctionSeed {
  FunctionId id;
  std::string name;
  std::uint64_t address = 0;
  bool exported = false;
  bool from_symbol = false;
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
};

struct AnalysisResult {
  Architecture architecture = Architecture::Unknown;
  std::vector<Instruction> instructions;
  std::vector<FunctionSeed> functions;
  std::vector<Xref> xrefs;
  std::vector<StringLiteral> strings;
  bool partial = false;
  std::vector<Diagnostic> diagnostics;
};

/// Bounded printable-ASCII and UTF-16LE string extraction. Scans only
/// non-executable, file-backed sections when present, otherwise the whole file.
[[nodiscard]] Result<std::vector<StringLiteral>> extract_strings(
    const BinaryImage& image, std::span<const std::byte> file, const AnalysisOptions& options = {});

/// Linear, deterministic analysis for M2: disassembles executable sections,
/// records branch/data references, and builds function seeds from entry points,
/// exported symbols and call targets. It does not build a CFG or claim
/// function extents.
[[nodiscard]] Result<AnalysisResult> analyze(const BinaryImage& image,
                                             std::span<const std::byte> file,
                                             const AnalysisOptions& options = {});

}  // namespace donkey
