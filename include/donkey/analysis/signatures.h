#pragma once

// Library function identification (G09-T1): an original signature format, the matcher, and the
// rules that decide when a match names a function. A signature set is JSON (`donkey.signatures.v1`,
// documented in docs/SIGNATURES.md). A function matches a signature when its length and its bytes
// agree with it, with the relocated bytes (the wildcards) left out of the comparison. A pattern
// that matches functions with different names names nothing. Matches never replace a user's name:
// the caller says which addresses the user has named, and those are skipped. Nothing is run; the
// signature file and the binary are only read.

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/core/json.h"
#include "donkey/core/result.h"

namespace donkey {

inline constexpr char kSignatureFormat[] = "donkey.signatures.v1";

/// Bytes a signature does not compare, as offsets from the start of the function. They are the
/// relocated bytes: an address that the linker or loader filled in, which differs between builds.
struct SignatureWildcard {
  std::uint32_t offset = 0;
  std::uint32_t length = 0;
};

/// One function's signature. The prefix is the first min(32, length) bytes, with the wildcard
/// positions zeroed; the CRC-32 covers the bytes after the prefix, with every wildcard byte zeroed.
struct Signature {
  std::string name;
  std::uint32_t length = 0;
  std::vector<std::byte> prefix;
  std::vector<SignatureWildcard> wildcards;  ///< sorted by offset, non-overlapping, within length
  std::uint32_t crc32 = 0;
};

/// A library's signatures for one architecture, with the provenance every match reports.
struct SignatureSet {
  std::string library;
  std::string version;
  std::string license;
  std::string architecture;  ///< as architecture_name() spells it, for example "x86_64"
  std::vector<Signature> signatures;
};

/// The signature of a function from its bytes. The wildcards are checked against the length.
[[nodiscard]] Result<Signature> make_signature(std::span<const std::byte> function_bytes,
                                               std::string name,
                                               std::vector<SignatureWildcard> wildcards = {});

/// Reads a signature set. Strict: the format must be `donkey.signatures.v1`, every field must be
/// present with the right type and range, and nothing is returned partially.
[[nodiscard]] Result<SignatureSet> parse_signature_set(std::string_view json,
                                                       const JsonLimits& limits = {});

/// The canonical JSON of a set: fixed key order, one signature per line. Reading it back gives the
/// same set.
[[nodiscard]] std::string write_signature_set(const SignatureSet& set);

/// A function to identify: its start address and the address just past its last byte.
struct SignatureFunction {
  std::uint64_t address = 0;
  std::uint64_t end = 0;
};

/// The outcome for one function that at least one signature matched.
struct SignatureMatch {
  std::uint64_t address = 0;
  std::string name;        ///< empty when the matching signatures name different functions
  std::string provenance;  ///< "signature <library> <version>"; empty when ambiguous
  bool ambiguous = false;
  std::size_t candidates = 0;  ///< the signatures that matched
  std::uint32_t length = 0;    ///< the matched length in bytes (the start mode only)
};

/// Matches each function against the set. A function whose bytes are unreadable, or that a user has
/// named (`user_named`), is skipped. The set's architecture must be the image's, or nothing is
/// matched.
[[nodiscard]] Result<std::vector<SignatureMatch>> identify_functions(
    const SignatureSet& set, const BinaryImage& image, std::span<const std::byte> file,
    std::span<const SignatureFunction> functions, std::span<const std::uint64_t> user_named);

/// Matches each candidate start address against every signature length, for a function whose
/// extent is not known (a stripped file, where the analysis may stop too early or too late). A
/// start matched by signatures of several lengths reports the longest; the matched length is
/// in `SignatureMatch::length`. Costs at most starts x distinct lengths comparisons, and a
/// start that a user named is skipped. The same architecture check as identify_functions.
[[nodiscard]] Result<std::vector<SignatureMatch>> identify_at_starts(
    const SignatureSet& set, const BinaryImage& image, std::span<const std::byte> file,
    std::span<const std::uint64_t> starts, std::span<const std::uint64_t> user_named);

}  // namespace donkey
