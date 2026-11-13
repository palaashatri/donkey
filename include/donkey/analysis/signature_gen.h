#pragma once

// Signature generation (G09-T2): makes a `donkey.signatures.v1` set from the global functions of
// x86-64 ELF relocatable objects (`.o`) and of the relocatable members of static archives (`.a`).
// The bytes a relocation patches become the function's wildcards, so a function that a build links
// at another address, or calls through another address, still matches (docs/SIGNATURES.md). The
// file is only read: the object is not laid out or relocated, and nothing is run. Shared objects
// and PE import libraries are not read yet.

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "donkey/analysis/signatures.h"
#include "donkey/core/result.h"

namespace donkey {

struct SignatureGenOptions {
  std::string library;  ///< required: the library's name, as the set's `library` field
  std::string version;  ///< required: the library's version
  std::string license;  ///< required: the licence of the library, as the set's `license` field
};

struct SignatureGenResult {
  SignatureSet set;                ///< the signatures, in member and then symbol order
  std::size_t functions = 0;       ///< global functions with a size that were examined
  std::size_t skipped = 0;         ///< functions, and members, left out; each has a note
  std::vector<std::string> notes;  ///< why each was left out, at most kMaxSignatureNotes of them
  bool partial = false;            ///< reading stopped early: a malformed or over-limit table
};

/// The most notes one generation keeps. Further skips are counted in `skipped` only.
inline constexpr std::size_t kMaxSignatureNotes = 64;

/// Signatures for the global functions in `file`, which is an ELF relocatable object or a static
/// archive. A function is named only when its symbol is a global or weak FUNC with a size, in an
/// executable section, and when every relocation in it has a width the generator knows. Local
/// functions are not named, because one name can be defined in several members. Errors:
/// `sig.options` (an empty or over-long library, version or licence), `sig.input` (the file is
/// neither an ELF object nor an archive), `sig.not_relocatable` (an ELF file of another type),
/// `sig.machine` (not a 64-bit little-endian x86-64 object), `sig.truncated` (a header or table
/// lies outside the file), and the archive reader's codes.
[[nodiscard]] Result<SignatureGenResult> generate_signatures(std::span<const std::byte> file,
                                                             const SignatureGenOptions& options);

}  // namespace donkey
