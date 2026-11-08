#pragma once

// C string literals for the strings the user has defined (G12-T2). A DataRange "string:<bytes>" is
// a NUL-terminated string of the binary. This turns each such range into the literal the pseudocode
// prints, read from the file bytes; nothing is run and no range is changed.

#include <cstddef>
#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/project/project.h"

namespace donkey {

/// The C literal (quotes included) of each user-defined one-byte string, keyed by the range's
/// address. A range is used only when its bytes lie in the file and its terminator is one of its
/// own bytes: a UTF-16 range, a range with no terminator, or one that runs past the file gives no
/// literal. The literal escapes `"`, `\`, the newline and tab, and prints any other byte outside
/// 0x20 to 0x7e as a three-digit octal escape, so the text is valid C.
[[nodiscard]] std::map<std::uint64_t, std::string> string_literals(
    const std::vector<Annotation>& annotations, const BinaryImage& image,
    std::span<const std::byte> file);

}  // namespace donkey
