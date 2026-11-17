#pragma once

// ELF symbol versions of imports (G24-T3): which library each versioned import is bound to, from
// `.gnu.version` (one 16-bit version index per dynamic symbol) and `.gnu.version_r` (the version
// needs: for each needed file, the versions it must provide). `abort@GLIBC_2.2.5` is an import
// whose version need names `libc.so.6`. Reads the image's bytes only; nothing is run.

#include <cstddef>
#include <cstdint>
#include <map>
#include <span>
#include <string>

#include "donkey/binary/image.h"
#include "donkey/core/result.h"

namespace donkey {

/// One version a needed file must provide: `GLIBC_2.2.5` from `libc.so.6`.
struct ElfVersionNeed {
  std::string file;     ///< the needed file's name, as DT_NEEDED spells it
  std::string version;  ///< the version name
};

/// The version needs of `.gnu.version_r`, keyed by the version index that `.gnu.version` uses.
struct ElfVersionNeeds {
  std::map<std::uint16_t, ElfVersionNeed> by_index;
  std::size_t files = 0;    ///< Verneed entries read
  std::size_t entries = 0;  ///< Vernaux entries read
};

/// Entries read from `.gnu.version_r` before the reader refuses the table.
inline constexpr std::size_t kMaxVersionNeedEntries = 65'536;

/// Reads the little-endian `.gnu.version_r` bytes `section`, whose names are offsets into
/// `strings` (`.dynstr`). Each Verneed is 16 bytes (version, count, file, aux, next) and each
/// Vernaux 16 bytes (hash, flags, index, name, next); the chains follow the `next` offsets. A chain
/// that leaves the section, loops, or runs past `max_entries` is refused (`elf.version_needs.*`),
/// and so is a name that is not a terminated string inside `strings`, an index of 0 or 1 (the
/// reserved local and global indexes), and two entries with one index.
[[nodiscard]] Result<ElfVersionNeeds> read_version_needs(
    std::span<const std::byte> section, std::span<const std::byte> strings,
    std::size_t max_entries = kMaxVersionNeedEntries);

/// The version need of each versioned import of a 64-bit little-endian ELF image, keyed by the
/// import's name. An import whose `.gnu.version` index is 0 or 1 (unversioned), or whose index no
/// need names, is not listed. An image without the two sections gives an empty map; a malformed
/// table gives the reader's diagnostic. An import listed twice with two different needs is left
/// out, so its provider stays unknown.
[[nodiscard]] Result<std::map<std::string, ElfVersionNeed>> read_import_versions(
    const BinaryImage& image, std::span<const std::byte> data);

}  // namespace donkey
