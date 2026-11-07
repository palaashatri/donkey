#pragma once

// Decompression of Zstandard frames (RFC 8878), for compressed debug sections (G07). Written
// from the specification; no zstd code is used. Every read is bounded, the output is capped, and
// a frame whose checksum does not match is an error, never partial data.
//
// Supported: several concatenated frames, skippable frames, raw, RLE and compressed blocks,
// Huffman-coded literals (including treeless reuse), every sequence table mode, repeat offsets
// and the content checksum. Not supported: dictionaries (a frame that names one is an error).

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "donkey/core/result.h"

namespace donkey {

struct ZstdOptions {
  /// The most output the frames may produce. A larger result is `zstd.limit`.
  std::size_t max_output_bytes = 256U * 1024U * 1024U;
};

/// Decompresses one or more Zstandard frames. Errors are `InvalidInput` with a code under
/// `zstd.`: `magic`, `header`, `dictionary` (a frame names a dictionary, which is not supported),
/// `block`, `literals`, `huffman`, `fse`, `sequences`, `offset`, `size` (the frame's declared size
/// disagrees with its content), `checksum`, `truncated` and `limit`.
[[nodiscard]] Result<std::vector<std::byte>> zstd_decompress(std::span<const std::byte> input,
                                                             const ZstdOptions& options = {});

}  // namespace donkey
