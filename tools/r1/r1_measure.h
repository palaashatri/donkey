#pragma once

// The R1 measurement (G20-T2): read what `tools/r1/build.cmake` built (`binaries.json`) and what
// `donkey-cli decompile --json --no-pseudocode` printed for each binary, and count, for every
// binary, the functions by status, the reasons of the Partial ones, and, for a stripped binary, the
// function starts found against the symbols of its unstripped twin. Nothing here runs a binary.

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/core/result.h"

namespace donkey::r1 {

/// One entry of `binaries.json`.
struct Binary {
  std::string file;
  std::string build;
  std::string source;
  std::string toolchain;
  std::string architecture;
  std::string level;
  std::string variant;     ///< "unstripped" or "stripped"
  std::string unstripped;  ///< a stripped copy's twin; empty for an unstripped binary
  std::string compiler;
  std::string sha256;
};

/// The entries of `binaries.json`. Refused (`r1.bad_binaries`) when it is not the schema-1 list.
[[nodiscard]] Result<std::vector<Binary>> read_binaries(std::string_view json);

/// A Partial function that carries no specific note: its result does not say why it is Partial.
struct Unexplained {
  std::string address;
  std::string name;
};

struct Measure {
  std::string file;
  /// The decompile output could not be used: the process failed, timed out or wrote no readable
  /// JSON. Every other count is then zero.
  bool error = false;
  std::string error_reason;
  std::size_t functions = 0;
  std::size_t complete = 0;
  std::size_t partial = 0;
  std::size_t unsupported = 0;
  std::size_t invalid_ir = 0;
  /// The first specific note of each Partial function (see `specific_notes`), normalised.
  std::map<std::string, std::size_t> first_notes;
  /// Every specific note, counted once per Partial function, normalised.
  std::map<std::string, std::size_t> all_notes;
  std::vector<Unexplained> unexplained;
  /// Output from a CLI built before the notes array existed: no reasons are counted.
  bool has_notes = true;
  /// The function starts the decompile run found.
  std::set<std::uint64_t> starts;
  /// The analysis was Partial, and the codes of its diagnostics (none is a resource limit: such
  /// an output is refused).
  bool analysis_partial = false;
  std::vector<std::string> analysis_notes;
};

/// Counts one decompile output. A missing `notes` array is accepted (`has_notes` is false); a
/// malformed document, one without `functions`, one truncated by --max-functions, and one whose
/// analysis stopped at a resource limit (see `is_resource_limit`) are refused (`r1.bad_decompile`).
[[nodiscard]] Result<Measure> measure_decompile(std::string_view file, std::string_view json);

/// An analysis diagnostic that means the analysis stopped early, so functions may be missing:
/// `analysis.instruction_limit`, `analysis.block_limit` and `analysis.traversal_limit`.
[[nodiscard]] bool is_resource_limit(std::string_view code);

/// The notes that every function of an architecture carries, and so explain nothing: "x86-64
/// subset; locals are not recovered" and the like, and "signature inferred from ...".
[[nodiscard]] bool is_generic_note(std::string_view note);

/// A note with its addresses and numbers replaced, so notes that differ only in them group
/// together: `0x...` becomes `0xN`, `sub_...` becomes `sub_N`, other digit runs become `N`.
[[nodiscard]] std::string normalise_note(std::string_view note);

/// The defined function symbols of an image (`SymbolKind::Function`: ELF `STT_FUNC` and
/// `STT_GNU_IFUNC`, whose value is its resolver's start) that lie in an executable section.
[[nodiscard]] std::set<std::uint64_t> function_symbol_starts(const BinaryImage& image);

/// The starts of `found` that lie in an ELF import-stub section (`.plt`, `.plt.sec`, `.plt.got`):
/// stubs are functions with no symbol, so they are counted apart from the extra starts.
[[nodiscard]] std::set<std::uint64_t> starts_in_stub_sections(const BinaryImage& image,
                                                              const std::set<std::uint64_t>& found);

struct StartsComparison {
  std::size_t truth = 0;
  std::size_t found = 0;
  std::size_t matched = 0;
  std::size_t missed = 0;
  /// Found starts that are import stubs (see `starts_in_stub_sections`).
  std::size_t stubs = 0;
  /// Found starts that are neither a symbol's start nor a stub.
  std::size_t extra = 0;
};

[[nodiscard]] StartsComparison compare_starts(const std::set<std::uint64_t>& truth,
                                              const std::set<std::uint64_t>& found,
                                              const std::set<std::uint64_t>& stubs = {});

}  // namespace donkey::r1
