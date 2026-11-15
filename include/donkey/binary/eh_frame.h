#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "donkey/binary/byte_reader.h"
#include "donkey/binary/image.h"
#include "donkey/core/result.h"

namespace donkey {

/// The code range one FDE describes: pc_begin and pc_range of a frame description entry.
struct EhFrameFunction {
  std::uint64_t start = 0;
  std::uint64_t size = 0;
};

struct EhFrameReadResult {
  /// Every FDE with a non-zero start and a non-zero range, in section order. A function start
  /// found here comes from the unwind tables the compiler wrote (G23-T1).
  std::vector<EhFrameFunction> functions;
  /// Records walked, CIEs and FDEs together.
  std::size_t records = 0;
  /// Records that could not be read (a bad CIE pointer, an encoding this reader does not follow,
  /// an operand past the record). Each is skipped and counted; none stops the walk.
  std::size_t malformed_records = 0;
  /// The walk stopped early: a record length ran past the section, or the record limit was
  /// reached. Everything before that point is in `functions`.
  bool truncated = false;
};

/// The record limit of one walk. A section holds at most this many records; a larger one is read
/// up to the limit and reported as truncated.
inline constexpr std::size_t kEhFrameMaxRecords = std::size_t{1} << 20;

/// Reads the FDE ranges of one `.eh_frame` section. `section_address` is the address the section
/// is mapped at (pc-relative pointers are relative to it), `pointer_size` is 4 or 8, and `endian`
/// is the byte order. Every read is bounds-checked against `section`; a malformed record is
/// counted, never a crash. The only errors are a bad `pointer_size`.
[[nodiscard]] Result<EhFrameReadResult> read_eh_frame(std::span<const std::byte> section,
                                                      std::uint64_t section_address,
                                                      unsigned pointer_size, Endian endian,
                                                      std::size_t max_records = kEhFrameMaxRecords);

/// Reads the `.eh_frame` section of an ELF image from the file bytes. An image without the section
/// yields an empty result, not an error.
[[nodiscard]] Result<EhFrameReadResult> read_eh_frame_of_image(const BinaryImage& image,
                                                               std::span<const std::byte> file);

}  // namespace donkey
