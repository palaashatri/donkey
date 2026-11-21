#pragma once

// Mach-O compact unwind, `__TEXT,__unwind_info` version 1 (G23-T3). The section maps function
// offsets (from the image base, the start of __TEXT) to 32-bit unwind encodings through a
// first-level index and second-level pages, regular (kind 2) or compressed (kind 3). The linker
// folds a run of adjacent functions that share an encoding into one entry, so every entry names a
// function start, but not every function start has an entry. Reads bytes only; nothing is run.

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "donkey/binary/byte_reader.h"
#include "donkey/binary/image.h"
#include "donkey/core/result.h"

namespace donkey {

inline constexpr std::size_t kUnwindInfoMaxEntries = std::size_t{1} << 20;

struct UnwindInfoEntry {
  /// The function's address: the image base plus the entry's function offset.
  std::uint64_t start = 0;
  /// The compact unwind encoding (frameless, frame-based or DWARF), kept and not interpreted.
  std::uint32_t encoding = 0;
};

struct UnwindInfo {
  /// Every second-level entry, in ascending address order.
  std::vector<UnwindInfoEntry> entries;
  /// The end of the range the index covers (the address of its final sentinel entry), or 0 when
  /// the table has no index entries.
  std::uint64_t end = 0;
};

/// The entries of `section` (the bytes of `__TEXT,__unwind_info`), with function offsets taken
/// from `image_base`. Refused with a stable code:
/// - `unwind_info.bad_header`: too short for the header, or a version other than 1;
/// - `unwind_info.outside_section`: an array, page or entry that does not lie inside the section;
/// - `unwind_info.bad_index`: index offsets that decrease, or an index with no final sentinel;
/// - `unwind_info.bad_page`: a page kind other than 2 or 3, or an entry outside its index range;
/// - `unwind_info.bad_encoding_index`: a compressed entry whose encoding index names no encoding;
/// - `unwind_info.unsorted`: entries whose addresses do not increase;
/// - `unwind_info.too_many`: more than `max_entries` entries.
[[nodiscard]] Result<UnwindInfo> read_unwind_info(std::span<const std::byte> section,
                                                  std::uint64_t image_base, Endian endian,
                                                  std::size_t max_entries = kUnwindInfoMaxEntries);

/// The entries of a Mach-O image's `__TEXT,__unwind_info` section, or none when it has no such
/// section. An image with the section and no __TEXT segment is refused (`unwind_info.no_text`), as
/// is a section outside the file (`unwind_info.outside_file`).
[[nodiscard]] Result<UnwindInfo> read_unwind_info_of_image(
    const BinaryImage& image, std::span<const std::byte> file,
    std::size_t max_entries = kUnwindInfoMaxEntries);

}  // namespace donkey
