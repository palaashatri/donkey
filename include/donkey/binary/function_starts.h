#pragma once

// Mach-O LC_FUNCTION_STARTS (G23-T3): the linker's list of function starts, kept in a stripped
// image. The table is a run of ULEB128 deltas: the first from the start of the __TEXT segment, each
// later one from the previous start; a zero delta or the end of the data ends it (the linker pads
// with zeros). Reads bytes only; nothing is run.

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/core/result.h"

namespace donkey {

inline constexpr std::size_t kFunctionStartsMaxEntries = std::size_t{1} << 20;

/// The starts of `table`, in table order (ascending), each inside [text_address, text_address +
/// text_size). With `thumb` (32-bit ARM) the low bit of each start, which marks Thumb code, is
/// cleared. Refused with a stable code: a ULEB128 longer than 10 bytes or past 64 bits
/// (`function_starts.bad_uleb128`), a start outside __TEXT (`function_starts.outside_text`), more
/// than `max_entries` starts (`function_starts.too_many`).
[[nodiscard]] Result<std::vector<std::uint64_t>> read_function_starts(
    std::span<const std::byte> table, std::uint64_t text_address, std::uint64_t text_size,
    bool thumb, std::size_t max_entries = kFunctionStartsMaxEntries);

/// The starts of a Mach-O image's LC_FUNCTION_STARTS table (`BinaryImage::function_starts_*`), or
/// none when it has no table. An image with a table and no __TEXT segment is refused
/// (`function_starts.no_text`).
[[nodiscard]] Result<std::vector<std::uint64_t>> read_function_starts_of_image(
    const BinaryImage& image, std::span<const std::byte> file,
    std::size_t max_entries = kFunctionStartsMaxEntries);

}  // namespace donkey
