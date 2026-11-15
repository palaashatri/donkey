#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/core/result.h"

namespace donkey {

/// The code range one RUNTIME_FUNCTION entry describes, in virtual addresses.
struct PdataFunction {
  std::uint64_t start = 0;
  std::uint64_t size = 0;
};

struct PdataReadResult {
  /// Every entry that is a function's first unwind record (not a chained continuation) and has a
  /// non-empty range, in directory order.
  std::vector<PdataFunction> functions;
  /// RUNTIME_FUNCTION entries in the exception directory.
  std::size_t entries = 0;
  /// Entries that are chained (UNWIND_CHAININFO): they continue another function's unwind data,
  /// so they are not reported as a function start.
  std::size_t chained = 0;
  /// Entries whose range is empty or inverted, or whose unwind record is not readable.
  std::size_t malformed = 0;
  /// The directory held more entries than `max_entries`; the rest are not read.
  bool truncated = false;
};

/// The RUNTIME_FUNCTION entries of an x64 PE image's exception directory (data directory 3,
/// G23-T2). An image that is not PE32+ x86-64, or has no exception directory, yields an empty
/// result. The only error is a PE header that cannot be read.
inline constexpr std::size_t kPdataMaxEntries = std::size_t{1} << 20;
[[nodiscard]] Result<PdataReadResult> read_pdata_of_image(
    const BinaryImage& image, std::span<const std::byte> file,
    std::size_t max_entries = kPdataMaxEntries);

}  // namespace donkey
