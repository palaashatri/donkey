#pragma once

// The R1 ratchet (G20-T3). `tools/r1/baseline.json` stores, for each R1 binary, the counts that may
// only get better: Complete may not drop, and Unsupported, InvalidIR, an error and the missed
// function starts of a stripped binary may not rise. Each entry also records the compiler and the
// SHA-256 of the binary it was measured on, because the counts describe those bytes only.
//
// The check compares a measurement (`r1-result.json` from `donkey-r1 measure`) with the baseline
// as it is at the base commit, never with the file a change brings, so a change cannot lower the
// bar it is checked against. A binary whose bytes differ from its baseline entry (a new compiler,
// a changed source, flag or manifest) is compared instead with the base commit's CLI measured on
// the same bytes; that measurement is the caller's to make, and the check says when it needs one.

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "donkey/core/result.h"

namespace donkey::r1 {

/// The ratcheted counts of one binary.
struct Counts {
  std::string file;
  std::string compiler;
  std::string sha256;
  std::size_t complete = 0;
  std::size_t unsupported = 0;
  std::size_t invalid_ir = 0;
  bool error = false;
  /// The function starts of the unstripped twin that a stripped binary's analysis missed; none for
  /// an unstripped binary, or for a stripped one whose measurement had an error.
  std::optional<std::size_t> missed_starts;

  friend bool operator==(const Counts&, const Counts&) = default;
};

/// The entries of a baseline file, sorted by file. Refused (`r1.bad_baseline`) unless it is the
/// schema 1 baseline with one entry per file.
[[nodiscard]] Result<std::vector<Counts>> read_baseline(std::string_view json);

/// The counts of every binary of an `r1-result.json`, sorted by file. Refused (`r1.bad_result`)
/// unless it is a schema 1 result with one entry per file.
[[nodiscard]] Result<std::vector<Counts>> read_result_counts(std::string_view json);

/// The baseline file for `counts`: deterministic, one entry per line, sorted by file.
[[nodiscard]] std::string write_baseline(std::vector<Counts> counts);

struct CheckOutcome {
  /// A count that got worse: the check fails.
  std::vector<std::string> regressions;
  /// A count that got better: printed, and recorded by the next `--update`.
  std::vector<std::string> improvements;
  /// The baseline no longer describes what was measured (other bytes, a new or removed binary),
  /// though nothing got worse.
  std::vector<std::string> warnings;
  /// Binaries whose bytes the baseline does not describe and for which no base measurement of the
  /// same bytes was given: the caller must measure them with the base commit's CLI and check again.
  std::vector<std::string> needs_base;
  /// Binaries in the baseline that were not measured: the manifest no longer builds them. Dropping
  /// a binary could hide its regression, so the caller accepts it only when the change re-records
  /// the baseline without it.
  std::vector<std::string> removed;

  [[nodiscard]] bool failed() const noexcept { return !regressions.empty(); }
};

/// Checks `head` against `baseline`, the baseline of the base commit. For a binary whose SHA-256
/// differs from its baseline entry, or that has none, the reference is its entry in
/// `base_measured` (the base commit's CLI on the same bytes) when that entry has the same SHA-256;
/// otherwise the binary is listed in `needs_base`.
[[nodiscard]] CheckOutcome check(const std::vector<Counts>& baseline,
                                 const std::vector<Counts>& head,
                                 const std::vector<Counts>* base_measured = nullptr);

}  // namespace donkey::r1
