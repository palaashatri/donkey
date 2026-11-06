#pragma once

// Intel HEX and Motorola S-record files (G15-T3): the records are decoded into one flat
// image at their lowest address, which is then analysed as a raw image. Bytes that no
// record writes are 0xFF, the value of erased flash. The formats carry no access rights,
// so the image is analysed as readable and executable, like any raw image.

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "donkey/core/result.h"

namespace donkey {

enum class RecordFormat : std::uint8_t {
  None,      ///< not a record file (the bytes are left to the container detection)
  IntelHex,  ///< Intel HEX: lines of the form `:LLAAAATT...CC`
  SRecord,   ///< Motorola S-records: lines of the form `STLLAAAA...CC`
};

const char* record_format_name(RecordFormat format) noexcept;

/// The format of `bytes` when its first line is a record. A file whose first line is a
/// record is taken to be a record file, and a malformed record later in it is an error
/// (see decode_records); it is never loaded as raw bytes.
[[nodiscard]] RecordFormat detect_record_format(std::span<const std::byte> bytes);

struct DecodedRecords {
  std::vector<std::byte> bytes;  ///< the flat image, starting at `base`
  std::uint64_t base = 0;        ///< the lowest address written by a data record
  bool has_entry_point = false;  ///< a start-address record was present
  std::uint64_t entry_point = 0;
};

/// Decodes every record of `bytes`, which must be in `format`. Errors are `InvalidInput`
/// with a code under `records.` and a message that names the line. A checksum or a
/// length that does not match, an unknown record type, and a record after the end of an
/// Intel HEX file are all errors. The flat image may not be larger than `max_bytes`, which
/// is `ResourceLimit`; a file with no data records is `InvalidInput`.
[[nodiscard]] Result<DecodedRecords> decode_records(std::span<const std::byte> bytes,
                                                    RecordFormat format, std::uint64_t max_bytes);

}  // namespace donkey
