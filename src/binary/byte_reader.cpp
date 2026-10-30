#include "donkey/binary/byte_reader.h"

#include "donkey/core/checked.h"

namespace donkey {

const char* endian_name(Endian endian) noexcept {
  return endian == Endian::Little ? "little" : "big";
}

Diagnostic ByteReader::out_of_bounds(std::uint64_t offset) const {
  return Diagnostic::make(Status::InvalidInput, "reader.out_of_bounds",
                          "read past the end of the buffer", offset);
}

Result<std::span<const std::byte>> ByteReader::slice(std::uint64_t offset,
                                                     std::uint64_t length) const {
  if (!checked::in_range(offset, length, size())) {
    return out_of_bounds(offset);
  }
  return data_.subspan(static_cast<std::size_t>(offset), static_cast<std::size_t>(length));
}

Result<std::uint8_t> ByteReader::u8(std::uint64_t offset) const {
  auto bytes = slice(offset, 1);
  if (!bytes) {
    return bytes.diagnostic();
  }
  return static_cast<std::uint8_t>(bytes.value()[0]);
}

std::uint16_t ByteReader::load_u16(const std::byte* data, Endian endian) noexcept {
  const auto b0 = static_cast<std::uint16_t>(static_cast<std::uint8_t>(data[0]));
  const auto b1 = static_cast<std::uint16_t>(static_cast<std::uint8_t>(data[1]));
  if (endian == Endian::Little) {
    return static_cast<std::uint16_t>(b0 | (b1 << 8U));
  }
  return static_cast<std::uint16_t>((b0 << 8U) | b1);
}

std::uint32_t ByteReader::load_u32(const std::byte* data, Endian endian) noexcept {
  std::uint32_t result = 0;
  if (endian == Endian::Little) {
    for (int i = 3; i >= 0; --i) {
      result = (result << 8U) | static_cast<std::uint8_t>(data[i]);
    }
  } else {
    for (int i = 0; i < 4; ++i) {
      result = (result << 8U) | static_cast<std::uint8_t>(data[i]);
    }
  }
  return result;
}

std::uint64_t ByteReader::load_u64(const std::byte* data, Endian endian) noexcept {
  std::uint64_t result = 0;
  if (endian == Endian::Little) {
    for (int i = 7; i >= 0; --i) {
      result = (result << 8U) | static_cast<std::uint8_t>(data[i]);
    }
  } else {
    for (int i = 0; i < 8; ++i) {
      result = (result << 8U) | static_cast<std::uint8_t>(data[i]);
    }
  }
  return result;
}

Result<std::uint16_t> ByteReader::u16(std::uint64_t offset, Endian endian) const {
  auto bytes = slice(offset, 2);
  if (!bytes) {
    return bytes.diagnostic();
  }
  return load_u16(bytes.value().data(), endian);
}

Result<std::uint32_t> ByteReader::u32(std::uint64_t offset, Endian endian) const {
  auto bytes = slice(offset, 4);
  if (!bytes) {
    return bytes.diagnostic();
  }
  return load_u32(bytes.value().data(), endian);
}

Result<std::uint64_t> ByteReader::u64(std::uint64_t offset, Endian endian) const {
  auto bytes = slice(offset, 8);
  if (!bytes) {
    return bytes.diagnostic();
  }
  return load_u64(bytes.value().data(), endian);
}

Result<std::string_view> ByteReader::c_string(std::uint64_t offset,
                                              std::uint64_t max_length) const {
  if (offset >= size()) {
    return out_of_bounds(offset);
  }
  const std::uint64_t available = size() - offset;
  const std::uint64_t limit = max_length < available ? max_length : available;
  auto bytes = slice(offset, limit);
  if (!bytes) {
    return bytes.diagnostic();
  }
  const auto* begin = reinterpret_cast<const char*>(bytes.value().data());
  for (std::uint64_t i = 0; i < limit; ++i) {
    if (begin[i] == '\0') {
      return std::string_view(begin, static_cast<std::size_t>(i));
    }
  }
  return Diagnostic::make(Status::InvalidInput, "reader.unterminated_string",
                          "string is not NUL-terminated within its bounded region", offset);
}

std::string sanitize_name(std::string_view raw) {
  std::string out;
  out.reserve(raw.size());
  for (const char ch : raw) {
    const auto byte = static_cast<unsigned char>(ch);
    out.push_back((byte >= 0x20U && byte <= 0x7EU) ? ch : '?');
  }
  // Trim trailing filler commonly used in fixed-width name fields.
  while (!out.empty() && (out.back() == ' ' || out.back() == '?')) {
    out.pop_back();
  }
  if (out.empty()) {
    return "<unnamed>";
  }
  return out;
}

}  // namespace donkey
