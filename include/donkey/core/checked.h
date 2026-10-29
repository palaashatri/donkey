#pragma once

#include <cstdint>
#include <optional>

namespace donkey::checked {

#if defined(__GNUC__) || defined(__clang__)
#define DONKEY_HAS_BUILTIN_OVERFLOW 1
#endif

/// Checked unsigned addition. Returns true on overflow and leaves `out`
/// unmodified.
[[nodiscard]] constexpr bool add_overflow(std::uint64_t a, std::uint64_t b,
                                          std::uint64_t& out) noexcept {
#if defined(DONKEY_HAS_BUILTIN_OVERFLOW)
  std::uint64_t tmp = 0;
  if (__builtin_add_overflow(a, b, &tmp)) {
    return true;
  }
  out = tmp;
  return false;
#else
  if (b > UINT64_MAX - a) {
    return true;
  }
  out = a + b;
  return false;
#endif
}

/// Checked unsigned subtraction. Returns true when `b > a` and leaves `out`
/// unmodified.
[[nodiscard]] constexpr bool sub_overflow(std::uint64_t a, std::uint64_t b,
                                          std::uint64_t& out) noexcept {
#if defined(DONKEY_HAS_BUILTIN_OVERFLOW)
  std::uint64_t tmp = 0;
  if (__builtin_sub_overflow(a, b, &tmp)) {
    return true;
  }
  out = tmp;
  return false;
#else
  if (b > a) {
    return true;
  }
  out = a - b;
  return false;
#endif
}

/// Checked unsigned multiplication. Returns true on overflow and leaves `out`
/// unmodified.
[[nodiscard]] constexpr bool mul_overflow(std::uint64_t a, std::uint64_t b,
                                          std::uint64_t& out) noexcept {
#if defined(DONKEY_HAS_BUILTIN_OVERFLOW)
  std::uint64_t tmp = 0;
  if (__builtin_mul_overflow(a, b, &tmp)) {
    return true;
  }
  out = tmp;
  return false;
#else
  if (a != 0 && b > UINT64_MAX / a) {
    return true;
  }
  out = a * b;
  return false;
#endif
}

/// Round `value` up to a multiple of `alignment`. `alignment` must be non-zero;
/// returns false on overflow.
[[nodiscard]] constexpr bool align_up(std::uint64_t value, std::uint64_t alignment,
                                      std::uint64_t& out) noexcept {
  if (alignment == 0) {
    return false;
  }
  const std::uint64_t remainder = value % alignment;
  if (remainder == 0) {
    out = value;
    return true;
  }
  return !add_overflow(value, alignment - remainder, out);
}

/// True when [offset, offset + length) lies entirely within [0, limit).
[[nodiscard]] constexpr bool in_range(std::uint64_t offset, std::uint64_t length,
                                      std::uint64_t limit) noexcept {
  if (offset > limit || length > limit - offset) {
    return false;
  }
  return true;
}

/// Convenience: overflow-checked offset + length, expressed as a pair.
[[nodiscard]] constexpr std::optional<std::uint64_t> add(std::uint64_t a,
                                                         std::uint64_t b) noexcept {
  std::uint64_t result = 0;
  if (add_overflow(a, b, result)) {
    return std::nullopt;
  }
  return result;
}

}  // namespace donkey::checked
