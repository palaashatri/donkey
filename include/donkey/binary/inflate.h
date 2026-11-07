#pragma once

// Decompression of zlib streams (RFC 1950 over RFC 1951), for compressed debug sections
// (G07). Written from the RFC; no zlib code is used. Every read is bounded, the output is
// capped, and a stream whose checksum does not match is an error, never partial data.

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "donkey/core/result.h"

namespace donkey {

struct InflateOptions {
  /// The most output a stream may produce. A larger stream is `inflate.too_large`.
  std::size_t max_output_bytes = 256U * 1024U * 1024U;
};

/// Decompresses a zlib stream: the two-byte header, the deflate data and the Adler-32 trailer,
/// which must match the output. Errors are `InvalidInput` with a code under `inflate.`:
/// `header` (not a zlib stream, or a preset dictionary), `corrupt` (an invalid code, length
/// or distance), `truncated` (the stream ends early), `checksum` and `too_large`.
[[nodiscard]] Result<std::vector<std::byte>> inflate_zlib(std::span<const std::byte> stream,
                                                          const InflateOptions& options = {});

}  // namespace donkey
