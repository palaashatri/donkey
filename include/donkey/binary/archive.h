#pragma once

// Static archives (`ar` format, G15-T1): the members of a `.a` file, listed without
// extracting them. Reads the System V and GNU name table (`//`, and `/<offset>` names),
// the BSD `#1/<length>` names, and the symbol tables. Bounded: the member count, the
// name length and every offset and size are checked, and no allocation is sized from
// the file.

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "donkey/core/result.h"

namespace donkey {

enum class ArchiveMemberKind : std::uint8_t {
  Object,       ///< an ordinary member: an object file, or any other file
  SymbolTable,  ///< `/` (System V and GNU) or `/SYM64/`
  LongNames,    ///< `//`, the table that holds the long names of the other members
};

const char* archive_member_kind_name(ArchiveMemberKind kind) noexcept;

struct ArchiveMember {
  std::string name;  ///< sanitized; an unresolved GNU long name stays as `/<offset>`
  ArchiveMemberKind kind = ArchiveMemberKind::Object;
  std::uint64_t offset = 0;    ///< where the member's data starts, within the archive
  std::uint64_t size = 0;      ///< the data's size in bytes (BSD names are not counted)
  std::uint64_t modified = 0;  ///< seconds since the epoch, 0 when the field is blank
  std::uint32_t mode = 0;      ///< the octal mode field
};

struct ArchiveIndex {
  std::vector<ArchiveMember> members;
  /// Reading stopped early at a malformed or truncated header, or at the member limit.
  /// The members before that point are kept, and `note` says why.
  bool partial = false;
  std::string note;
};

struct ArchiveOptions {
  std::size_t max_members = 100'000;
};

/// The longest member name the reader accepts, in bytes (BSD names are read from the
/// member data, so this is also the longest of those).
inline constexpr std::uint64_t kMaxArchiveNameBytes = 4096;

/// Lists the members of the archive in `data`. A file that does not start with the
/// `!<arch>` magic is `InvalidInput` with the code `archive.bad_magic`. Any later
/// problem gives a partial index rather than an error.
[[nodiscard]] Result<ArchiveIndex> read_archive(std::span<const std::byte> data,
                                                const ArchiveOptions& options = {});

}  // namespace donkey
