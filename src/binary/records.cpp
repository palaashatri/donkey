#include "donkey/binary/records.h"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <string>
#include <string_view>
#include <utility>

namespace donkey {
namespace {

constexpr std::size_t kMinimumDetectHexDigits = 10;  // the shortest Intel HEX record
constexpr std::size_t kMinimumDetectSDigits = 4;     // count and at least one address byte

struct Segment {
  std::uint64_t address = 0;
  std::vector<std::byte> data;
};

int nibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

/// The bytes written as hex pairs in `text`, or false if `text` is not an even run of hex.
bool hex_bytes(std::string_view text, std::vector<std::uint8_t>& out) {
  out.clear();
  if (text.size() % 2 != 0) {
    return false;
  }
  out.reserve(text.size() / 2);
  for (std::size_t i = 0; i < text.size(); i += 2) {
    const int high = nibble(text[i]);
    const int low = nibble(text[i + 1]);
    if (high < 0 || low < 0) {
      return false;
    }
    out.push_back(static_cast<std::uint8_t>(high * 16 + low));
  }
  return true;
}

std::uint64_t big_endian(const std::vector<std::uint8_t>& bytes, std::size_t at,
                         std::size_t width) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < width; ++i) {
    value = (value << 8U) | bytes[at + i];
  }
  return value;
}

/// The lines of `bytes`, without their line endings and trailing blanks; empty lines are
/// kept so that the line numbers stay right.
std::vector<std::string_view> lines_of(std::span<const std::byte> bytes) {
  std::vector<std::string_view> lines;
  std::string_view text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  std::size_t start = 0;
  while (start <= text.size()) {
    std::size_t end = text.find('\n', start);
    if (end == std::string_view::npos) {
      end = text.size();
    }
    std::string_view line = text.substr(start, end - start);
    while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) {
      line.remove_suffix(1);
    }
    lines.push_back(line);
    if (end == text.size()) {
      break;
    }
    start = end + 1;
  }
  return lines;
}

Diagnostic record_error(std::size_t line, const char* code, const std::string& message) {
  return Diagnostic::make(Status::InvalidInput, code,
                          "line " + std::to_string(line) + ": " + message);
}

}  // namespace

const char* record_format_name(RecordFormat format) noexcept {
  switch (format) {
    case RecordFormat::None:
      return "none";
    case RecordFormat::IntelHex:
      return "Intel HEX";
    case RecordFormat::SRecord:
      return "Motorola S-record";
  }
  return "unknown";
}

RecordFormat detect_record_format(std::span<const std::byte> bytes) {
  std::size_t i = 0;
  while (i < bytes.size() && (bytes[i] == std::byte{' '} || bytes[i] == std::byte{'\t'} ||
                              bytes[i] == std::byte{'\r'} || bytes[i] == std::byte{'\n'})) {
    ++i;
  }
  if (i >= bytes.size()) {
    return RecordFormat::None;
  }
  const auto first = static_cast<char>(bytes[i]);
  std::size_t digits = 0;
  std::size_t j = i + 1;
  while (j < bytes.size() && nibble(static_cast<char>(bytes[j])) >= 0) {
    ++digits;
    ++j;
  }
  if (first == ':' && digits >= kMinimumDetectHexDigits) {
    return RecordFormat::IntelHex;
  }
  if (first == 'S' && i + 1 < bytes.size() && bytes[i + 1] >= std::byte{'0'} &&
      bytes[i + 1] <= std::byte{'9'} && digits >= kMinimumDetectSDigits) {
    return RecordFormat::SRecord;
  }
  return RecordFormat::None;
}

Result<DecodedRecords> decode_records(std::span<const std::byte> bytes, RecordFormat format,
                                      std::uint64_t max_bytes) {
  const auto fail = [](Diagnostic diagnostic) {
    return make_error<DecodedRecords>(diagnostic.status, diagnostic.code, diagnostic.message);
  };
  if (format == RecordFormat::None) {
    return make_error<DecodedRecords>(Status::InvalidInput, "records.not_records",
                                      "the bytes are not Intel HEX or S-records");
  }

  std::vector<Segment> segments;
  bool has_entry = false;
  std::uint64_t entry = 0;
  std::uint64_t upper = 0;  // Intel HEX: the address the 16-bit offsets are added to
  bool ended = false;
  std::vector<std::uint8_t> record;

  const std::vector<std::string_view> lines = lines_of(bytes);
  for (std::size_t index = 0; index < lines.size(); ++index) {
    const std::size_t number = index + 1;
    const std::string_view line = lines[index];
    if (line.empty()) {
      continue;
    }
    if (ended) {
      return fail(
          record_error(number, "records.after_end", "a record follows the end-of-file record"));
    }

    if (format == RecordFormat::IntelHex) {
      if (line.front() != ':' || !hex_bytes(line.substr(1), record) || record.size() < 5) {
        return fail(record_error(number, "records.syntax", "not an Intel HEX record"));
      }
      const std::size_t count = record[0];
      if (record.size() != count + 5) {
        return fail(record_error(number, "records.length",
                                 "the record's length does not match its byte count"));
      }
      std::uint8_t sum = 0;
      for (const std::uint8_t byte : record) {
        sum = static_cast<std::uint8_t>(sum + byte);
      }
      if (sum != 0) {
        return fail(record_error(number, "records.checksum", "the record's checksum is wrong"));
      }
      const std::uint64_t address = big_endian(record, 1, 2);
      const std::uint8_t type = record[3];
      switch (type) {
        case 0x00:  // data
          if (count > 0) {
            Segment segment;
            segment.address = upper + address;
            segment.data.reserve(count);
            for (std::size_t k = 0; k < count; ++k) {
              segment.data.push_back(static_cast<std::byte>(record[4 + k]));
            }
            segments.push_back(std::move(segment));
          }
          break;
        case 0x01:  // end of file
          if (count != 0) {
            return fail(record_error(number, "records.length", "an end-of-file record has data"));
          }
          ended = true;
          break;
        case 0x02:  // extended segment address
          if (count != 2) {
            return fail(
                record_error(number, "records.length", "the segment record is not 2 bytes"));
          }
          upper = big_endian(record, 4, 2) * 16U;
          break;
        case 0x03:  // start segment address (CS:IP)
          if (count != 4) {
            return fail(record_error(number, "records.length", "the start record is not 4 bytes"));
          }
          has_entry = true;
          entry = big_endian(record, 4, 2) * 16U + big_endian(record, 6, 2);
          break;
        case 0x04:  // extended linear address
          if (count != 2) {
            return fail(record_error(number, "records.length", "the linear record is not 2 bytes"));
          }
          upper = big_endian(record, 4, 2) << 16U;
          break;
        case 0x05:  // start linear address
          if (count != 4) {
            return fail(record_error(number, "records.length", "the start record is not 4 bytes"));
          }
          has_entry = true;
          entry = big_endian(record, 4, 4);
          break;
        default:
          return fail(record_error(number, "records.unknown_type",
                                   "unknown Intel HEX record type " + std::to_string(type)));
      }
      continue;
    }

    // Motorola S-record: S, a type digit, then hex bytes: count, address, data, checksum.
    if (line.size() < 4 || line.front() != 'S' || line[1] < '0' || line[1] > '9' ||
        !hex_bytes(line.substr(2), record) || record.empty()) {
      return fail(record_error(number, "records.syntax", "not a Motorola S-record"));
    }
    const int type = line[1] - '0';
    const std::size_t count = record[0];
    if (record.size() != count + 1 || count < 1) {
      return fail(record_error(number, "records.length",
                               "the record's length does not match its byte count"));
    }
    std::uint8_t sum = 0;
    for (const std::uint8_t byte : record) {
      sum = static_cast<std::uint8_t>(sum + byte);
    }
    if (sum != 0xFF) {
      return fail(record_error(number, "records.checksum", "the record's checksum is wrong"));
    }
    std::size_t address_width = 0;
    switch (type) {
      case 0:
      case 1:
      case 5:
      case 9:
        address_width = 2;
        break;
      case 2:
      case 6:
      case 8:
        address_width = 3;
        break;
      case 3:
      case 7:
        address_width = 4;
        break;
      default:
        return fail(record_error(number, "records.unknown_type",
                                 "unknown S-record type S" + std::to_string(type)));
    }
    if (count < address_width + 1) {
      return fail(
          record_error(number, "records.length", "the record is too short for its address"));
    }
    const std::uint64_t address = big_endian(record, 1, address_width);
    const std::size_t data_length = count - address_width - 1;
    if (type == 1 || type == 2 || type == 3) {
      if (data_length > 0) {
        Segment segment;
        segment.address = address;
        segment.data.reserve(data_length);
        for (std::size_t k = 0; k < data_length; ++k) {
          segment.data.push_back(static_cast<std::byte>(record[1 + address_width + k]));
        }
        segments.push_back(std::move(segment));
      }
    } else if (type == 7 || type == 8 || type == 9) {
      has_entry = true;
      entry = address;
    }
    // S0 (header) and S5/S6 (record counts) carry nothing the image needs.
  }

  if (segments.empty()) {
    return make_error<DecodedRecords>(Status::InvalidInput, "records.no_data",
                                      "the file has no data records");
  }
  std::uint64_t low = std::numeric_limits<std::uint64_t>::max();
  std::uint64_t high = 0;
  for (const Segment& segment : segments) {
    low = std::min(low, segment.address);
    const std::uint64_t end = segment.address + segment.data.size();
    if (end < segment.address) {
      return make_error<DecodedRecords>(Status::InvalidInput, "records.address_overflow",
                                        "a record's data runs past the 64-bit address space");
    }
    high = std::max(high, end);
  }
  const std::uint64_t span = high - low;
  if (span > max_bytes) {
    return make_error<DecodedRecords>(Status::ResourceLimit, "records.too_large",
                                      "the records cover more address space than the limit");
  }

  DecodedRecords decoded;
  decoded.base = low;
  decoded.has_entry_point = has_entry;
  decoded.entry_point = entry;
  // Gaps are 0xFF, the value of erased flash. Later records overwrite earlier ones.
  decoded.bytes.assign(static_cast<std::size_t>(span), std::byte{0xFF});
  for (const Segment& segment : segments) {
    std::copy(segment.data.begin(), segment.data.end(),
              decoded.bytes.begin() + static_cast<std::ptrdiff_t>(segment.address - low));
  }
  return decoded;
}

}  // namespace donkey
