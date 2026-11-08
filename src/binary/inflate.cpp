#include "donkey/binary/inflate.h"

#include <array>
#include <cstdint>
#include <string>
#include <utility>

namespace donkey {
namespace {

constexpr int kMaxBits = 15;           // the longest code in deflate
constexpr int kMaxLiteralCodes = 288;  // 286 used, 2 reserved
constexpr int kMaxDistanceCodes = 32;  // 30 used, 2 reserved
constexpr int kMaxCodeLengthCodes = 19;

constexpr std::array<std::uint16_t, 29> kLengthBase = {3,  4,  5,  6,   7,   8,   9,   10,  11, 13,
                                                       15, 17, 19, 23,  27,  31,  35,  43,  51, 59,
                                                       67, 83, 99, 115, 131, 163, 195, 227, 258};
constexpr std::array<std::uint8_t, 29> kLengthExtra = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
                                                       2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
constexpr std::array<std::uint16_t, 30> kDistanceBase = {
    1,   2,   3,   4,   5,   7,    9,    13,   17,   25,   33,   49,   65,    97,    129,
    193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
constexpr std::array<std::uint8_t, 30> kDistanceExtra = {0, 0, 0,  0,  1,  1,  2,  2,  3,  3,
                                                         4, 4, 5,  5,  6,  6,  7,  7,  8,  8,
                                                         9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
constexpr std::array<std::uint8_t, 19> kCodeLengthOrder = {16, 17, 18, 0, 8,  7, 9,  6, 10, 5,
                                                           11, 4,  12, 3, 13, 2, 14, 1, 15};

/// A canonical Huffman code, by the number of codes of each length and the symbols in order.
struct Huffman {
  std::array<std::uint16_t, kMaxBits + 1> count{};
  std::vector<std::uint16_t> symbol;
};

/// Builds the code for `lengths` (symbol i has length lengths[i]; 0 means unused). Returns
/// false for an over-subscribed set of lengths; an incomplete set is allowed, as deflate permits.
bool build(Huffman& code, const std::uint16_t* lengths, int count) {
  code.count.fill(0);
  for (int i = 0; i < count; ++i) {
    ++code.count[lengths[i]];
  }
  code.count[0] = 0;
  int left = 1;
  for (int len = 1; len <= kMaxBits; ++len) {
    left <<= 1;
    left -= code.count[len];
    if (left < 0) {
      return false;
    }
  }
  std::array<std::uint16_t, kMaxBits + 2> offsets{};
  for (int len = 1; len <= kMaxBits; ++len) {
    offsets[len + 1] = static_cast<std::uint16_t>(offsets[len] + code.count[len]);
  }
  code.symbol.assign(static_cast<std::size_t>(count), 0);
  for (int i = 0; i < count; ++i) {
    if (lengths[i] != 0) {
      code.symbol[offsets[lengths[i]]++] = static_cast<std::uint16_t>(i);
    }
  }
  return true;
}

class Inflater {
 public:
  Inflater(std::span<const std::byte> input, std::size_t max_output)
      : input_(input), max_output_(max_output) {}

  /// The deflate data; `position` is left after the last byte of the final block.
  Result<std::vector<std::byte>> run() {
    bool last = false;
    while (!last) {
      auto flag = bits(1);
      auto type = bits(2);
      if (!flag || !type) {
        return failure("truncated", "the stream ends inside a block header");
      }
      last = flag.value() != 0;
      const Result<bool> block = type.value() == 0   ? stored()
                                 : type.value() == 1 ? fixed()
                                 : type.value() == 2
                                     ? dynamic()
                                     : bad("corrupt", "a block has the reserved type 3");
      if (!block) {
        return Result<std::vector<std::byte>>(block.diagnostic());
      }
    }
    return std::move(out_);
  }

  std::size_t position() const { return position_; }

 private:
  Diagnostic diagnostic(const char* code, std::string message) const {
    return Diagnostic::make(Status::InvalidInput, std::string("inflate.") + code,
                            std::move(message), position_);
  }
  Result<std::vector<std::byte>> failure(const char* code, std::string message) const {
    return Result<std::vector<std::byte>>(diagnostic(code, std::move(message)));
  }
  Result<bool> bad(const char* code, std::string message) const {
    return Result<bool>(diagnostic(code, std::move(message)));
  }

  /// `count` bits, least significant first.
  Result<std::uint32_t> bits(int count) {
    std::uint32_t value = 0;
    for (int i = 0; i < count; ++i) {
      if (bit_ == 8) {
        if (position_ >= input_.size()) {
          return Result<std::uint32_t>(diagnostic("truncated", "the stream ends early"));
        }
        current_ = static_cast<std::uint8_t>(input_[position_++]);
        bit_ = 0;
      }
      value |= static_cast<std::uint32_t>((current_ >> bit_) & 1U) << i;
      ++bit_;
    }
    return value;
  }

  /// One symbol of `code`, read a bit at a time (the canonical code is built up from the
  /// first bit read).
  Result<int> decode(const Huffman& code) {
    int value = 0;
    int first = 0;
    int index = 0;
    for (int len = 1; len <= kMaxBits; ++len) {
      auto bit = bits(1);
      if (!bit) {
        return Result<int>(bit.diagnostic());
      }
      value |= static_cast<int>(bit.value());
      const int count = code.count[len];
      if (value - count < first) {
        return code.symbol[static_cast<std::size_t>(index + (value - first))];
      }
      index += count;
      first += count;
      first <<= 1;
      value <<= 1;
    }
    return Result<int>(diagnostic("corrupt", "a code matches no symbol"));
  }

  Result<bool> emit(std::uint8_t byte) {
    if (out_.size() >= max_output_) {
      return Result<bool>(Diagnostic::make(Status::ResourceLimit, "inflate.too_large",
                                           "the stream produces more output than the limit",
                                           position_));
    }
    out_.push_back(static_cast<std::byte>(byte));
    return true;
  }

  Result<bool> stored() {
    bit_ = 8;  // a stored block starts at a byte boundary
    if (position_ + 4 > input_.size()) {
      return bad("truncated", "a stored block has no length");
    }
    const auto length = static_cast<std::uint16_t>(
        static_cast<std::uint8_t>(input_[position_]) |
        (static_cast<std::uint16_t>(static_cast<std::uint8_t>(input_[position_ + 1])) << 8));
    const auto inverse = static_cast<std::uint16_t>(
        static_cast<std::uint8_t>(input_[position_ + 2]) |
        (static_cast<std::uint16_t>(static_cast<std::uint8_t>(input_[position_ + 3])) << 8));
    position_ += 4;
    if (static_cast<std::uint16_t>(~length) != inverse) {
      return bad("corrupt", "a stored block's length and its complement differ");
    }
    if (position_ + length > input_.size()) {
      return bad("truncated", "a stored block runs past the end of the stream");
    }
    for (std::uint16_t i = 0; i < length; ++i) {
      if (auto ok = emit(static_cast<std::uint8_t>(input_[position_++])); !ok) {
        return ok;
      }
    }
    return true;
  }

  Result<bool> codes(const Huffman& literals, const Huffman& distances) {
    while (true) {
      auto symbol = decode(literals);
      if (!symbol) {
        return Result<bool>(symbol.diagnostic());
      }
      if (symbol.value() < 256) {
        if (auto ok = emit(static_cast<std::uint8_t>(symbol.value())); !ok) {
          return ok;
        }
        continue;
      }
      if (symbol.value() == 256) {
        return true;  // end of block
      }
      const int code = symbol.value() - 257;
      if (code >= 29) {
        return bad("corrupt", "a length code is out of range");
      }
      auto extra = bits(kLengthExtra[code]);
      if (!extra) {
        return Result<bool>(extra.diagnostic());
      }
      const std::size_t length = kLengthBase[code] + extra.value();
      auto distance_symbol = decode(distances);
      if (!distance_symbol) {
        return Result<bool>(distance_symbol.diagnostic());
      }
      if (distance_symbol.value() >= 30) {
        return bad("corrupt", "a distance code is out of range");
      }
      auto distance_extra = bits(kDistanceExtra[distance_symbol.value()]);
      if (!distance_extra) {
        return Result<bool>(distance_extra.diagnostic());
      }
      const std::size_t distance = kDistanceBase[distance_symbol.value()] + distance_extra.value();
      if (distance > out_.size()) {
        return bad("corrupt", "a match reaches before the start of the output");
      }
      for (std::size_t i = 0; i < length; ++i) {
        const std::byte copied = out_[out_.size() - distance];
        if (out_.size() >= max_output_) {
          return Result<bool>(Diagnostic::make(Status::ResourceLimit, "inflate.too_large",
                                               "the stream produces more output than the limit",
                                               position_));
        }
        out_.push_back(copied);
      }
    }
  }

  Result<bool> fixed() {
    std::array<std::uint16_t, kMaxLiteralCodes> lengths{};
    for (int i = 0; i < 144; ++i) lengths[i] = 8;
    for (int i = 144; i < 256; ++i) lengths[i] = 9;
    for (int i = 256; i < 280; ++i) lengths[i] = 7;
    for (int i = 280; i < 288; ++i) lengths[i] = 8;
    std::array<std::uint16_t, kMaxDistanceCodes> distance_lengths{};
    distance_lengths.fill(5);
    Huffman literals;
    Huffman distances;
    build(literals, lengths.data(), kMaxLiteralCodes);
    build(distances, distance_lengths.data(), kMaxDistanceCodes);
    return codes(literals, distances);
  }

  Result<bool> dynamic() {
    auto counts = bits(14);
    if (!counts) {
      return bad("truncated", "a dynamic block has no code counts");
    }
    const int literal_count = static_cast<int>(counts.value() & 0x1f) + 257;
    const int distance_count = static_cast<int>((counts.value() >> 5) & 0x1f) + 1;
    const int code_length_count = static_cast<int>((counts.value() >> 10) & 0xf) + 4;
    if (literal_count > 286 || distance_count > 30) {
      return bad("corrupt", "a dynamic block has too many codes");
    }
    std::array<std::uint16_t, kMaxCodeLengthCodes> code_lengths{};
    for (int i = 0; i < code_length_count; ++i) {
      auto length = bits(3);
      if (!length) {
        return bad("truncated", "a dynamic block ends in its code lengths");
      }
      code_lengths[kCodeLengthOrder[i]] = static_cast<std::uint16_t>(length.value());
    }
    Huffman length_code;
    if (!build(length_code, code_lengths.data(), kMaxCodeLengthCodes)) {
      return bad("corrupt", "the code length code is over-subscribed");
    }
    std::array<std::uint16_t, kMaxLiteralCodes + kMaxDistanceCodes> lengths{};
    const int total = literal_count + distance_count;
    int index = 0;
    while (index < total) {
      auto symbol = decode(length_code);
      if (!symbol) {
        return Result<bool>(symbol.diagnostic());
      }
      if (symbol.value() < 16) {
        lengths[index++] = static_cast<std::uint16_t>(symbol.value());
        continue;
      }
      std::uint16_t value = 0;
      int repeat = 0;
      if (symbol.value() == 16) {
        if (index == 0) {
          return bad("corrupt", "a repeat has no previous length");
        }
        value = lengths[index - 1];
        auto extra = bits(2);
        if (!extra) return bad("truncated", "a dynamic block ends in its lengths");
        repeat = 3 + static_cast<int>(extra.value());
      } else if (symbol.value() == 17) {
        auto extra = bits(3);
        if (!extra) return bad("truncated", "a dynamic block ends in its lengths");
        repeat = 3 + static_cast<int>(extra.value());
      } else {
        auto extra = bits(7);
        if (!extra) return bad("truncated", "a dynamic block ends in its lengths");
        repeat = 11 + static_cast<int>(extra.value());
      }
      if (index + repeat > total) {
        return bad("corrupt", "a repeat runs past the code lengths");
      }
      while (repeat-- > 0) {
        lengths[index++] = value;
      }
    }
    if (lengths[256] == 0) {
      return bad("corrupt", "the block has no end-of-block code");
    }
    Huffman literals;
    Huffman distances;
    if (!build(literals, lengths.data(), literal_count)) {
      return bad("corrupt", "the literal code is over-subscribed");
    }
    if (!build(distances, lengths.data() + literal_count, distance_count)) {
      return bad("corrupt", "the distance code is over-subscribed");
    }
    return codes(literals, distances);
  }

  std::span<const std::byte> input_;
  std::size_t max_output_;
  std::size_t position_ = 0;
  std::uint8_t current_ = 0;
  int bit_ = 8;
  std::vector<std::byte> out_;
};

std::uint32_t adler32(std::span<const std::byte> bytes) {
  std::uint32_t a = 1;
  std::uint32_t b = 0;
  for (const std::byte value : bytes) {
    a = (a + static_cast<std::uint8_t>(value)) % 65521U;
    b = (b + a) % 65521U;
  }
  return (b << 16) | a;
}

}  // namespace

Result<std::vector<std::byte>> inflate_zlib(std::span<const std::byte> stream,
                                            const InflateOptions& options) {
  if (stream.size() < 6) {
    return make_error<std::vector<std::byte>>(Status::InvalidInput, "inflate.header",
                                              "the stream is too short for a zlib header");
  }
  const auto cmf = static_cast<std::uint8_t>(stream[0]);
  const auto flg = static_cast<std::uint8_t>(stream[1]);
  if ((cmf & 0x0f) != 8 || (cmf >> 4) > 7 || ((cmf << 8) | flg) % 31 != 0) {
    return make_error<std::vector<std::byte>>(Status::InvalidInput, "inflate.header",
                                              "the stream is not a zlib stream");
  }
  if ((flg & 0x20) != 0) {
    return make_error<std::vector<std::byte>>(Status::Unsupported, "inflate.header",
                                              "a preset dictionary is not supported");
  }
  Inflater inflater(stream.subspan(2), options.max_output_bytes);
  auto out = inflater.run();
  if (!out) {
    return out;
  }
  // The Adler-32 of the output follows the deflate data, big-endian.
  const std::size_t trailer = 2 + inflater.position();
  if (trailer + 4 > stream.size()) {
    return make_error<std::vector<std::byte>>(Status::InvalidInput, "inflate.truncated",
                                              "the stream ends before its checksum");
  }
  std::uint32_t expected = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    expected = (expected << 8) | static_cast<std::uint8_t>(stream[trailer + i]);
  }
  if (adler32(out.value()) != expected) {
    return make_error<std::vector<std::byte>>(Status::InvalidInput, "inflate.checksum",
                                              "the output does not match the stream's checksum");
  }
  return out;
}

}  // namespace donkey
