#pragma once

// Finding the separate debug file of a binary (G07): the Mach-O route (`<binary>.dSYM/Contents/
// Resources/DWARF/<name>`, whose LC_UUID must equal the executable's), the GNU build-id route
// (`<dir>/.build-id/xx/yyyy.debug`) and the debuglink route (`.gnu_debuglink`, a file name and a
// CRC-32 of the file). The file is validated before it is returned: its UUID or build-id must equal
// the binary's, or its CRC-32 must equal the link's. Nothing is loaded or executed here.

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/core/result.h"

namespace donkey {

struct SeparateDebugOptions {
  /// Directories searched for debug files, in order. The usual system location is
  /// /usr/lib/debug; an analysis session may add its own.
  std::vector<std::string> debug_directories = {"/usr/lib/debug"};
};

/// The IEEE CRC-32 that `.gnu_debuglink` stores (the same as zlib's crc32).
[[nodiscard]] std::uint32_t gnu_crc32(std::span<const std::byte> bytes) noexcept;

/// The build-id of an image as lowercase hex, or empty when it has none.
[[nodiscard]] std::string build_id_hex(const BinaryImage& image, std::span<const std::byte> data);

/// Finds and validates the separate debug file of the binary at `binary_path`. Returns the
/// path of the first candidate that exists and matches; a candidate that exists but names a
/// different file is skipped. Errors are `InvalidInput` diagnostics under `debug.`: `no_link`
/// (the binary names no separate file), `not_found` (no candidate exists), and `build_id` or
/// `crc` when a candidate exists but matches nothing, which is reported only when nothing else
/// matched.
[[nodiscard]] Result<std::string> find_separate_debug_file(
    const BinaryImage& image, std::span<const std::byte> data, const std::string& binary_path,
    const SeparateDebugOptions& options = {});

/// Checks a debug file the user names (`donkey-cli debuginfo --debug-file`), with the rules of the
/// search: the UUID for a Mach-O, else the build-id, else the debuglink CRC-32. It returns the path
/// when the file matches. A mismatch is a diagnostic (`debug.uuid`, `debug.build_id` or
/// `debug.crc`), and the file is never used.
[[nodiscard]] Result<std::string> check_separate_debug_file(const BinaryImage& image,
                                                            std::span<const std::byte> data,
                                                            const std::string& debug_path);

}  // namespace donkey
