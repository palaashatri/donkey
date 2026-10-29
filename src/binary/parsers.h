#pragma once

#include "donkey/binary/byte_reader.h"
#include "donkey/binary/image.h"

namespace donkey::binary::detail {

// Parsers assume the magic bytes were already checked by parse_binary. They
// fill `image` completely or return a diagnostic; a failed parse must not be
// treated as a partial image.
[[nodiscard]] Result<void> parse_elf(ByteReader reader, BinaryImage& image);
[[nodiscard]] Result<void> parse_pe(ByteReader reader, BinaryImage& image);
[[nodiscard]] Result<void> parse_macho(ByteReader reader, BinaryImage& image);

// Helpers shared by format parsers.
[[nodiscard]] Result<std::uint64_t> rva_to_file_offset(const BinaryImage& image, std::uint64_t rva);

}  // namespace donkey::binary::detail
