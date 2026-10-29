#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace donkey {

/// Minimal, dependency-free SHA-256 used for stable file identity. It is not
/// used for any security decision; it exists so reopening a project can verify
/// that the underlying image has not changed.
class Sha256 {
 public:
  static constexpr std::size_t kDigestSize = 32;

  Sha256() noexcept;

  void update(std::span<const std::byte> data) noexcept;
  [[nodiscard]] std::array<std::uint8_t, kDigestSize> finish() noexcept;

  [[nodiscard]] static std::array<std::uint8_t, kDigestSize> digest(
      std::span<const std::byte> data) noexcept;
  [[nodiscard]] static std::string hex(std::span<const std::byte> data);
  [[nodiscard]] static std::string hex(const std::array<std::uint8_t, kDigestSize>& digest);

 private:
  void transform(const std::uint8_t* block) noexcept;

  std::array<std::uint32_t, 8> state_;
  std::array<std::uint8_t, 64> buffer_;
  std::size_t buffer_size_ = 0;
  std::uint64_t total_bytes_ = 0;
  bool finished_ = false;
};

}  // namespace donkey
