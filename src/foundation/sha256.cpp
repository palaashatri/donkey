#include "donkey/core/sha256.h"

#include <algorithm>
#include <cstring>

namespace donkey {
namespace {

constexpr std::array<std::uint32_t, 64> kRoundConstants = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
    0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
    0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
    0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
    0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
    0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
    0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
    0xc67178f2U,
};

constexpr std::uint32_t rotr(std::uint32_t value, unsigned bits) noexcept {
  return (value >> bits) | (value << (32U - bits));
}

}  // namespace

Sha256::Sha256() noexcept
    : state_{0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
             0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U},
      buffer_{} {}

void Sha256::update(std::span<const std::byte> data) noexcept {
  if (finished_) {
    return;
  }
  const auto* input = reinterpret_cast<const std::uint8_t*>(data.data());
  std::size_t remaining = data.size();
  total_bytes_ += remaining;

  if (buffer_size_ != 0) {
    const std::size_t take = std::min(remaining, buffer_.size() - buffer_size_);
    std::memcpy(buffer_.data() + buffer_size_, input, take);
    buffer_size_ += take;
    input += take;
    remaining -= take;
    if (buffer_size_ == buffer_.size()) {
      transform(buffer_.data());
      buffer_size_ = 0;
    }
  }

  while (remaining >= 64) {
    transform(input);
    input += 64;
    remaining -= 64;
  }

  if (remaining != 0) {
    std::memcpy(buffer_.data(), input, remaining);
    buffer_size_ = remaining;
  }
}

void Sha256::transform(const std::uint8_t* block) noexcept {
  std::array<std::uint32_t, 64> words{};
  for (std::size_t i = 0; i < 16; ++i) {
    words[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24U) |
               (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16U) |
               (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8U) |
               static_cast<std::uint32_t>(block[i * 4 + 3]);
  }
  for (std::size_t i = 16; i < 64; ++i) {
    const std::uint32_t s0 =
        rotr(words[i - 15], 7) ^ rotr(words[i - 15], 18) ^ (words[i - 15] >> 3U);
    const std::uint32_t s1 =
        rotr(words[i - 2], 17) ^ rotr(words[i - 2], 19) ^ (words[i - 2] >> 10U);
    words[i] = words[i - 16] + s0 + words[i - 7] + s1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t i = 0; i < 64; ++i) {
    const std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const std::uint32_t choose = (e & f) ^ (~e & g);
    const std::uint32_t temp1 = h + s1 + choose + kRoundConstants[i] + words[i];
    const std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + majority;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

std::array<std::uint8_t, Sha256::kDigestSize> Sha256::finish() noexcept {
  const std::uint64_t bit_length = total_bytes_ * 8U;

  std::array<std::uint8_t, 72> padding{};
  padding[0] = 0x80U;
  const std::size_t pad_length = (buffer_size_ < 56) ? (56 - buffer_size_) : (120 - buffer_size_);
  update(
      std::span<const std::byte>(reinterpret_cast<const std::byte*>(padding.data()), pad_length));

  std::array<std::uint8_t, 8> length_bytes{};
  for (std::size_t i = 0; i < 8; ++i) {
    length_bytes[i] = static_cast<std::uint8_t>(bit_length >> ((7 - i) * 8U));
  }
  update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(length_bytes.data()),
                                    length_bytes.size()));

  finished_ = true;

  std::array<std::uint8_t, kDigestSize> digest{};
  for (std::size_t i = 0; i < state_.size(); ++i) {
    digest[i * 4] = static_cast<std::uint8_t>(state_[i] >> 24U);
    digest[i * 4 + 1] = static_cast<std::uint8_t>(state_[i] >> 16U);
    digest[i * 4 + 2] = static_cast<std::uint8_t>(state_[i] >> 8U);
    digest[i * 4 + 3] = static_cast<std::uint8_t>(state_[i]);
  }
  return digest;
}

std::array<std::uint8_t, Sha256::kDigestSize> Sha256::digest(
    std::span<const std::byte> data) noexcept {
  Sha256 hasher;
  hasher.update(data);
  return hasher.finish();
}

std::string Sha256::hex(std::span<const std::byte> data) {
  return hex(digest(data));
}

std::string Sha256::hex(const std::array<std::uint8_t, kDigestSize>& bytes) {
  constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (const std::uint8_t byte : bytes) {
    out.push_back(kHex[byte >> 4U]);
    out.push_back(kHex[byte & 0x0FU]);
  }
  return out;
}

}  // namespace donkey
