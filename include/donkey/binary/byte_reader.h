#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include "donkey/core/result.h"

namespace donkey {

enum class Endian : std::uint8_t { Little, Big };

const char* endian_name(Endian endian) noexcept;

/// A bounds-checked reader over an immutable byte range. Every accessor
/// returns a diagnostic instead of reading out of bounds; no accessor throws.
/// Callers keep the underlying buffer alive for as long as the reader exists.
class ByteReader {
 public:
  explicit ByteReader(std::span<const std::byte> data) noexcept : data_(data) {}

  [[nodiscard]] std::uint64_t size() const noexcept {
    return static_cast<std::uint64_t>(data_.size());
  }
  [[nodiscard]] bool empty() const noexcept { return data_.empty(); }

  [[nodiscard]] Result<std::uint8_t> u8(std::uint64_t offset) const;
  [[nodiscard]] Result<std::uint16_t> u16(std::uint64_t offset, Endian endian) const;
  [[nodiscard]] Result<std::uint32_t> u32(std::uint64_t offset, Endian endian) const;
  [[nodiscard]] Result<std::uint64_t> u64(std::uint64_t offset, Endian endian) const;

  [[nodiscard]] Result<std::span<const std::byte>> slice(std::uint64_t offset,
                                                         std::uint64_t length) const;

  /// Reads a NUL-terminated string. Fails if no terminator is found within
  /// `max_length` bytes or before the end of the buffer.
  [[nodiscard]] Result<std::string_view> c_string(std::uint64_t offset,
                                                  std::uint64_t max_length) const;

 private:
  [[nodiscard]] Diagnostic out_of_bounds(std::uint64_t offset) const;
  [[nodiscard]] static std::uint16_t load_u16(const std::byte* data, Endian endian) noexcept;
  [[nodiscard]] static std::uint32_t load_u32(const std::byte* data, Endian endian) noexcept;
  [[nodiscard]] static std::uint64_t load_u64(const std::byte* data, Endian endian) noexcept;

  std::span<const std::byte> data_;
};

/// Replace control and non-ASCII bytes in an untrusted name so it is safe to
/// print or embed in JSON. Empty or all-control names become "<unnamed>".
[[nodiscard]] std::string sanitize_name(std::string_view raw);

}  // namespace donkey
