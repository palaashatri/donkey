#include "donkey/binary/zstd.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <optional>
#include <string>
#include <utility>

// Written from RFC 8878 (Zstandard Compression Format). The default distributions and the
// length-code tables are the specification's numbers; the decoder is this file's own code.

namespace donkey {
namespace {

constexpr std::uint32_t kMagic = 0xFD2F'B528U;
constexpr std::uint32_t kSkippableStart = 0x184D'2A50U;
constexpr std::uint32_t kSkippableMask = 0xFFFF'FFF0U;
constexpr std::size_t kMaxBlockSize = 128U * 1024U;
constexpr unsigned kMaxHuffmanLog = 11;

// The three sequence tables, in the order their modes and states appear in the stream.
enum Kind : std::size_t { kLiteralLength = 0, kOffset = 1, kMatchLength = 2 };
constexpr std::array<unsigned, 3> kMaxLog = {9, 8, 9};
constexpr std::array<unsigned, 3> kMaxSymbol = {35, 31, 52};

// The length codes (RFC 8878, sections 3.1.1.3.2.1.1 and 3.1.1.3.2.1.2): each code's base value
// and its number of extra bits. Taken from the specification's tables.
constexpr std::array<std::uint32_t, 36> kLiteralBase = {
    0,  1,  2,  3,  4,  5,  6,  7,  8,   9,   10,  11,   12,   13,   14,   15,    16,    18,
    20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
};
constexpr std::array<std::uint8_t, 36> kLiteralBits = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  1,  1,
    1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
};
constexpr std::array<std::uint32_t, 53> kMatchBase = {
    3,  4,  5,  6,  7,  8,  9,  10,  11,  12,  13,   14,   15,   16,   17,    18,    19,    20,
    21, 22, 23, 24, 25, 26, 27, 28,  29,  30,  31,   32,   33,   34,   35,    37,    39,    41,
    43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051, 4099, 8195, 16387, 32771, 65539,
};
constexpr std::array<std::uint8_t, 53> kMatchBits = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,
    0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
};

// The predefined distributions (RFC 8878, section 3.1.1.3.2.2): normalized counts, where -1 is a
// symbol of less than one slot.
constexpr std::array<int, 36> kLiteralDefault = {
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1,  1,  2,  2,
    2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1,
};
constexpr std::array<int, 53> kMatchDefault = {
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1,  1,  1,  1,  1,  1,  1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
};
constexpr std::array<int, 29> kOffsetDefault = {
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
};

// The first error of a decode. Functions return false after setting it.
struct Error {
  const char* code = "";
  const char* message = "";
};

bool fail(Error& error, const char* code, const char* message) {
  error = Error{code, message};
  return false;
}

unsigned high_bit(std::uint32_t value) {
  return static_cast<unsigned>(std::bit_width(value)) - 1U;
}

std::uint64_t mask(unsigned bits) {
  return bits >= 64 ? ~std::uint64_t{0} : (std::uint64_t{1} << bits) - 1U;
}

std::uint32_t read_le(std::span<const std::byte> bytes, std::size_t at, unsigned width) {
  std::uint32_t value = 0;
  for (unsigned i = 0; i < width; ++i) {
    value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[at + i])) << (8 * i);
  }
  return value;
}

std::uint8_t byte_at(std::span<const std::byte> bytes, std::size_t at) {
  return std::to_integer<std::uint8_t>(bytes[at]);
}

// A bit stream read from its end towards its start (RFC 8878, section 4.1). The last byte holds
// a sentinel bit: the data is the bits below its highest set bit. Bits are read most significant
// first, and a read past the start is an error.
class BackwardBits {
 public:
  bool open(std::span<const std::byte> bytes, Error& error) {
    if (bytes.empty()) {
      return fail(error, "zstd.truncated", "a bit stream is empty");
    }
    const std::uint8_t last = byte_at(bytes, bytes.size() - 1);
    if (last == 0) {
      return fail(error, "zstd.truncated", "a bit stream has no end marker");
    }
    const unsigned data_bits = high_bit(last);
    buffer_ = last & mask(data_bits);
    count_ = data_bits;
    next_ = bytes.size() - 1;
    bytes_ = bytes;
    return true;
  }

  /// The next `bits` bits (at most 32), without consuming them. Bits past the start read as zero,
  /// which lets the last Huffman symbols look ahead by a full table index.
  [[nodiscard]] std::uint32_t peek(unsigned bits) {
    fill(bits);
    if (count_ >= bits) {
      return static_cast<std::uint32_t>((buffer_ >> (count_ - bits)) & mask(bits));
    }
    return static_cast<std::uint32_t>((buffer_ << (bits - count_)) & mask(bits));
  }

  bool consume(unsigned bits, Error& error) {
    fill(bits);
    if (count_ < bits) {
      return fail(error, "zstd.truncated", "a bit stream ends before its last symbol");
    }
    count_ -= bits;
    return true;
  }

  bool read(unsigned bits, std::uint32_t& value, Error& error) {
    value = peek(bits);
    return consume(bits, error);
  }

  [[nodiscard]] std::size_t bits_left() const { return count_ + next_ * 8U; }

 private:
  void fill(unsigned bits) {
    while (count_ < bits && count_ <= 56 && next_ > 0) {
      --next_;
      buffer_ = (buffer_ << 8U) | byte_at(bytes_, next_);
      count_ += 8;
    }
  }

  std::span<const std::byte> bytes_;
  std::uint64_t buffer_ = 0;
  unsigned count_ = 0;
  std::size_t next_ = 0;
};

// A bit stream read forwards, least significant bit first (the table descriptions).
class ForwardBits {
 public:
  explicit ForwardBits(std::span<const std::byte> bytes) : bytes_(bytes) {}

  [[nodiscard]] std::uint32_t peek(unsigned bits) const {
    std::uint32_t value = 0;
    for (unsigned i = 0; i < bits; ++i) {
      const std::size_t at = position_ + i;
      if (at / 8 < bytes_.size() && ((byte_at(bytes_, at / 8) >> (at % 8)) & 1U) != 0) {
        value |= std::uint32_t{1} << i;
      }
    }
    return value;
  }

  bool skip(unsigned bits, Error& error) {
    if (position_ + bits > bytes_.size() * 8U) {
      return fail(error, "zstd.fse", "a table description ends early");
    }
    position_ += bits;
    return true;
  }

  [[nodiscard]] std::size_t bytes_used() const { return (position_ + 7U) / 8U; }

 private:
  std::span<const std::byte> bytes_;
  std::size_t position_ = 0;
};

// A finite-state decoding table (RFC 8878, section 4.1.1).
struct FseEntry {
  std::uint16_t symbol = 0;
  std::uint8_t bits = 0;
  std::uint16_t base = 0;
};

struct FseTable {
  unsigned log = 0;
  std::vector<FseEntry> entries{FseEntry{}};
};

// Builds the table from normalized counts (-1 marks a symbol of less than one slot).
bool build_fse(const std::vector<int>& counts, unsigned log, FseTable& table, Error& error) {
  const std::size_t size = std::size_t{1} << log;
  table.log = log;
  table.entries.assign(size, FseEntry{});
  std::size_t high = size - 1;
  std::vector<std::uint32_t> next(counts.size(), 0);
  for (std::size_t s = 0; s < counts.size(); ++s) {
    if (counts[s] == -1) {
      table.entries[high].symbol = static_cast<std::uint16_t>(s);
      if (high == 0) {
        return fail(error, "zstd.fse", "a table has too many symbols of less than one slot");
      }
      --high;
      next[s] = 1;
    } else {
      next[s] = static_cast<std::uint32_t>(std::max(counts[s], 0));
    }
  }
  // Spread the symbols over the table with a fixed step that skips the less-than-one slots.
  const std::size_t step = (size >> 1U) + (size >> 3U) + 3U;
  std::size_t position = 0;
  for (std::size_t s = 0; s < counts.size(); ++s) {
    if (counts[s] <= 0) {
      continue;
    }
    for (int i = 0; i < counts[s]; ++i) {
      table.entries[position].symbol = static_cast<std::uint16_t>(s);
      do {
        position = (position + step) & (size - 1);
      } while (position > high);
    }
  }
  if (position != 0) {
    return fail(error, "zstd.fse", "a table's symbols do not fill it");
  }
  for (FseEntry& entry : table.entries) {
    const std::uint32_t x = next[entry.symbol]++;
    if (x == 0) {
      return fail(error, "zstd.fse", "a table's counts are inconsistent");
    }
    const unsigned bits = log - high_bit(x);
    entry.bits = static_cast<std::uint8_t>(bits);
    entry.base = static_cast<std::uint16_t>((std::uint64_t{x} << bits) - size);
  }
  return true;
}

// Reads a table description from the forward bit stream (RFC 8878, section 4.1.1).
bool read_fse_description(std::span<const std::byte> bytes, unsigned max_symbol, unsigned max_log,
                          FseTable& table, std::size_t& used, Error& error) {
  if (bytes.empty()) {
    return fail(error, "zstd.fse", "a table description is missing");
  }
  ForwardBits in(bytes);
  const unsigned log = in.peek(4) + 5U;
  if (!in.skip(4, error)) {
    return false;
  }
  if (log > max_log) {
    return fail(error, "zstd.fse", "a table's accuracy is larger than allowed");
  }
  std::vector<int> counts(max_symbol + 1U, 0);
  std::int64_t remaining = (std::int64_t{1} << log) + 1;
  std::int64_t threshold = std::int64_t{1} << log;
  unsigned bits_needed = log + 1U;
  std::size_t symbol = 0;
  bool previous_zero = false;
  while (remaining > 1 && symbol <= max_symbol) {
    if (previous_zero) {
      // A run of symbols of probability zero: each 2-bit code is one, and 3 is three more.
      std::uint32_t code = in.peek(2);
      if (!in.skip(2, error)) {
        return false;
      }
      while (code == 3) {
        symbol += 3;
        code = in.peek(2);
        if (!in.skip(2, error)) {
          return false;
        }
      }
      symbol += code;
      if (symbol > max_symbol + 1U) {
        return fail(error, "zstd.fse", "a run of zero probabilities runs past the last symbol");
      }
      if (symbol == max_symbol + 1U) {
        break;
      }
    }
    const std::int64_t maximum = (2 * threshold - 1) - remaining;
    if (maximum < 0) {
      return fail(error, "zstd.fse", "a table description is inconsistent");
    }
    const std::uint32_t word = in.peek(bits_needed);
    std::int64_t count = 0;
    if ((static_cast<std::int64_t>(word) & (threshold - 1)) < maximum) {
      count = static_cast<std::int64_t>(word) & (threshold - 1);
      if (!in.skip(bits_needed - 1, error)) {
        return false;
      }
    } else {
      count = static_cast<std::int64_t>(word) & (2 * threshold - 1);
      if (count >= threshold) {
        count -= maximum;
      }
      if (!in.skip(bits_needed, error)) {
        return false;
      }
    }
    --count;  // the stored value is one more than the probability; zero stores less than one
    remaining -= count >= 0 ? count : 1;
    if (remaining < 0) {
      return fail(error, "zstd.fse", "a table's probabilities exceed its size");
    }
    counts[symbol++] = static_cast<int>(count);
    previous_zero = count == 0;
    if (remaining < threshold) {
      if (remaining <= 1) {
        break;
      }
      bits_needed = high_bit(static_cast<std::uint32_t>(remaining)) + 1U;
      threshold = std::int64_t{1} << (bits_needed - 1U);
    }
  }
  if (remaining != 1) {
    return fail(error, "zstd.fse", "a table's probabilities do not sum to its size");
  }
  used = in.bytes_used();
  return build_fse(counts, log, table, error);
}

// The table of a predefined distribution, built once.
const FseTable& default_table(Kind kind) {
  static const FseTable literal = [] {
    FseTable table;
    Error ignored;
    build_fse(std::vector<int>(kLiteralDefault.begin(), kLiteralDefault.end()), 6, table, ignored);
    return table;
  }();
  static const FseTable offset = [] {
    FseTable table;
    Error ignored;
    build_fse(std::vector<int>(kOffsetDefault.begin(), kOffsetDefault.end()), 5, table, ignored);
    return table;
  }();
  static const FseTable match = [] {
    FseTable table;
    Error ignored;
    build_fse(std::vector<int>(kMatchDefault.begin(), kMatchDefault.end()), 6, table, ignored);
    return table;
  }();
  switch (kind) {
    case kLiteralLength:
      return literal;
    case kOffset:
      return offset;
    case kMatchLength:
      break;
  }
  return match;
}

// Huffman weights and the code table built from them (RFC 8878, section 4.2.1).
struct HuffmanTable {
  unsigned log = 0;
  // Indexed by the next `log` bits: the symbol and its code length (zero length: no code).
  std::vector<std::pair<std::uint8_t, std::uint8_t>> lookup;
};

bool build_huffman(const std::vector<std::uint8_t>& weights, HuffmanTable& table, Error& error) {
  std::uint64_t sum = 0;
  for (const std::uint8_t weight : weights) {
    if (weight > kMaxHuffmanLog) {
      return fail(error, "zstd.huffman", "a literal weight is larger than the maximum");
    }
    if (weight > 0) {
      sum += std::uint64_t{1} << (weight - 1U);
    }
  }
  if (sum == 0 || sum >= (std::uint64_t{1} << 16)) {
    return fail(error, "zstd.huffman", "the literal weights are empty or too large");
  }
  // The last symbol's weight is implied: the remaining power of two it completes.
  const auto log = static_cast<unsigned>(std::bit_width(sum));
  const std::uint64_t rest = (std::uint64_t{1} << log) - sum;
  if ((rest & (rest - 1)) != 0) {
    return fail(error, "zstd.huffman", "the literal weights do not complete a power of two");
  }
  if (log > kMaxHuffmanLog) {
    return fail(error, "zstd.huffman", "the literal codes are longer than the maximum");
  }
  std::vector<std::uint8_t> all = weights;
  all.push_back(static_cast<std::uint8_t>(std::bit_width(rest)));
  // Code lengths: a weight w gives a length of log + 1 - w. Codes are canonical: shorter codes
  // first, and symbols of the same length in symbol order.
  std::vector<unsigned> lengths(all.size(), 0);
  std::array<unsigned, kMaxHuffmanLog + 2> per_length{};
  for (std::size_t s = 0; s < all.size(); ++s) {
    if (all[s] > 0) {
      lengths[s] = log + 1U - all[s];
      ++per_length[lengths[s]];
    }
  }
  std::array<std::uint32_t, kMaxHuffmanLog + 2> next_code{};
  std::uint32_t code = 0;
  for (unsigned length = 1; length <= log; ++length) {
    next_code[length] = code;
    code = (code + per_length[length]) << 1U;
  }
  table.log = log;
  table.lookup.assign(std::size_t{1} << log, {0, 0});
  // Within one length the symbols take their codes from the highest symbol down, and each code
  // is the complement of its canonical value (the stream reads the table's index from the top).
  // This is the layout the reference encoder writes; the differential tests check it.
  for (std::size_t s = all.size(); s-- > 0;) {
    const unsigned length = lengths[s];
    if (length == 0) {
      continue;
    }
    const std::uint32_t first = next_code[length]++;
    const std::uint32_t complement = ((std::uint32_t{1} << length) - 1U) - first;
    const std::size_t shift = log - length;
    for (std::size_t i = std::size_t{complement} << shift;
         i < (std::size_t{complement} + 1U) << shift; ++i) {
      table.lookup[i] = {static_cast<std::uint8_t>(s), static_cast<std::uint8_t>(length)};
    }
  }
  return true;
}

// Reads the Huffman tree of a compressed literals section. Returns the bytes it used.
bool read_huffman_tree(std::span<const std::byte> bytes, HuffmanTable& table, std::size_t& used,
                       Error& error) {
  if (bytes.empty()) {
    return fail(error, "zstd.huffman", "a literal tree is missing");
  }
  const std::uint8_t header = byte_at(bytes, 0);
  std::vector<std::uint8_t> weights;
  if (header >= 128) {
    // Direct: header - 127 weights of four bits each, two to a byte, high nibble first.
    const std::size_t count = header - 127U;
    used = 1 + (count + 1) / 2;
    if (used > bytes.size()) {
      return fail(error, "zstd.huffman", "a literal tree ends early");
    }
    for (std::size_t i = 0; i < count; ++i) {
      const std::uint8_t pair = byte_at(bytes, 1 + i / 2);
      weights.push_back(static_cast<std::uint8_t>(i % 2 == 0 ? pair >> 4U : pair & 0x0FU));
    }
  } else {
    // FSE-coded: the next `header` bytes hold a table and the weights, read by two interleaved
    // states from a backward bit stream.
    used = 1 + header;
    if (used > bytes.size()) {
      return fail(error, "zstd.huffman", "a literal tree ends early");
    }
    FseTable weight_table;
    std::size_t description = 0;
    if (!read_fse_description(bytes.subspan(1, header), 255, 6, weight_table, description, error)) {
      return false;
    }
    BackwardBits bits;
    if (!bits.open(bytes.subspan(1 + description, header - description), error)) {
      return false;
    }
    std::uint32_t state1 = 0;
    std::uint32_t state2 = 0;
    if (!bits.read(weight_table.log, state1, error) ||
        !bits.read(weight_table.log, state2, error)) {
      return false;
    }
    while (true) {
      const FseEntry& first = weight_table.entries[state1];
      weights.push_back(static_cast<std::uint8_t>(first.symbol));
      std::uint32_t value = 0;
      if (bits.bits_left() < first.bits) {
        weights.push_back(static_cast<std::uint8_t>(weight_table.entries[state2].symbol));
        break;
      }
      if (!bits.read(first.bits, value, error)) {
        return false;
      }
      state1 = first.base + value;
      const FseEntry& second = weight_table.entries[state2];
      weights.push_back(static_cast<std::uint8_t>(second.symbol));
      if (bits.bits_left() < second.bits) {
        weights.push_back(static_cast<std::uint8_t>(weight_table.entries[state1].symbol));
        break;
      }
      if (!bits.read(second.bits, value, error)) {
        return false;
      }
      state2 = second.base + value;
      if (weights.size() > 255) {
        return fail(error, "zstd.huffman", "a literal tree has too many weights");
      }
    }
  }
  return build_huffman(weights, table, error);
}

bool huffman_decode(const HuffmanTable& table, std::span<const std::byte> bytes, std::size_t count,
                    std::vector<std::byte>& out, Error& error) {
  BackwardBits bits;
  if (!bits.open(bytes, error)) {
    return false;
  }
  for (std::size_t i = 0; i < count; ++i) {
    const auto [symbol, length] = table.lookup[bits.peek(table.log)];
    if (length == 0) {
      return fail(error, "zstd.huffman", "a literal code is not in the table");
    }
    if (!bits.consume(length, error)) {
      return false;
    }
    out.push_back(static_cast<std::byte>(symbol));
  }
  return true;
}

// The literals of one block. `tree` is the last Huffman tree of the frame, reused by treeless
// sections.
bool decode_literals(std::span<const std::byte> block, std::size_t& pos,
                     std::optional<HuffmanTable>& tree, std::vector<std::byte>& literals,
                     Error& error) {
  if (pos >= block.size()) {
    return fail(error, "zstd.literals", "the literals header is missing");
  }
  const std::uint8_t b0 = byte_at(block, pos);
  const unsigned type = b0 & 3U;
  const unsigned format = (b0 >> 2U) & 3U;
  if (type == 0 || type == 1) {
    // Raw or run-length: the size is in one, two or three bytes.
    std::size_t header = 1;
    std::size_t size = b0 >> 3U;
    if (format == 1 || format == 3) {
      header = format == 1 ? 2 : 3;
      if (pos + header > block.size()) {
        return fail(error, "zstd.literals", "the literals header ends early");
      }
      size = (b0 >> 4U) | (std::size_t{byte_at(block, pos + 1)} << 4U);
      if (header == 3) {
        size |= std::size_t{byte_at(block, pos + 2)} << 12U;
      }
    }
    if (type == 0) {
      if (pos + header + size > block.size()) {
        return fail(error, "zstd.literals", "raw literals end early");
      }
      for (std::size_t i = 0; i < size; ++i) {
        literals.push_back(block[pos + header + i]);
      }
      pos += header + size;
    } else {
      if (pos + header + 1 > block.size()) {
        return fail(error, "zstd.literals", "a run-length literal is missing its byte");
      }
      literals.insert(literals.end(), size, block[pos + header]);
      pos += header + 1;
    }
    return true;
  }
  // Huffman-coded (type 2) or treeless (type 3): the sizes are in three to five bytes.
  std::size_t header = 3;
  std::size_t regenerated = 0;
  std::size_t compressed = 0;
  unsigned streams = 1;
  if (pos + 3 > block.size()) {
    return fail(error, "zstd.literals", "the literals header ends early");
  }
  const std::size_t b1 = byte_at(block, pos + 1);
  const std::size_t b2 = byte_at(block, pos + 2);
  if (format == 0 || format == 1) {
    regenerated = (b0 >> 4U) | ((b1 & 0x3FU) << 4U);
    compressed = (b1 >> 6U) | (b2 << 2U);
    streams = format == 0 ? 1U : 4U;
  } else {
    header = format == 2 ? 4 : 5;
    if (pos + header > block.size()) {
      return fail(error, "zstd.literals", "the literals header ends early");
    }
    const std::size_t b3 = byte_at(block, pos + 3);
    streams = 4;
    if (format == 2) {
      regenerated = (b0 >> 4U) | (b1 << 4U) | ((b2 & 3U) << 12U);
      compressed = (b2 >> 2U) | (b3 << 6U);
    } else {
      const std::size_t b4 = byte_at(block, pos + 4);
      regenerated = (b0 >> 4U) | (b1 << 4U) | ((b2 & 0x3FU) << 12U);
      compressed = (b2 >> 6U) | (b3 << 2U) | (b4 << 10U);
    }
  }
  if (regenerated > kMaxBlockSize) {
    return fail(error, "zstd.literals", "the literals are larger than a block");
  }
  if (pos + header + compressed > block.size()) {
    return fail(error, "zstd.literals", "compressed literals end early");
  }
  std::span<const std::byte> body = block.subspan(pos + header, compressed);
  if (type == 2) {
    HuffmanTable table;
    std::size_t tree_bytes = 0;
    if (!read_huffman_tree(body, table, tree_bytes, error)) {
      return false;
    }
    tree = std::move(table);
    body = body.subspan(tree_bytes);
  } else if (!tree.has_value()) {
    return fail(error, "zstd.literals", "treeless literals follow no Huffman tree");
  }
  if (streams == 1) {
    if (!huffman_decode(*tree, body, regenerated, literals, error)) {
      return false;
    }
  } else {
    // Four streams, sized by a jump table of three 16-bit lengths; the segments are equal but
    // the last, which takes the rest.
    if (body.size() < 6) {
      return fail(error, "zstd.literals", "the stream jump table is missing");
    }
    const std::size_t s1 = read_le(body, 0, 2);
    const std::size_t s2 = read_le(body, 2, 2);
    const std::size_t s3 = read_le(body, 4, 2);
    const std::size_t data = body.size() - 6;
    if (s1 + s2 + s3 > data) {
      return fail(error, "zstd.literals", "the stream sizes exceed the literals");
    }
    const std::size_t segment = (regenerated + 3) / 4;
    if (3 * segment > regenerated) {
      return fail(error, "zstd.literals", "the literal segments do not fit");
    }
    const std::span<const std::byte> payload = body.subspan(6);
    std::size_t at = 0;
    const std::array<std::size_t, 4> sizes = {s1, s2, s3, data - s1 - s2 - s3};
    const std::array<std::size_t, 4> counts = {segment, segment, segment,
                                               regenerated - 3 * segment};
    for (std::size_t i = 0; i < 4; ++i) {
      if (!huffman_decode(*tree, payload.subspan(at, sizes[i]), counts[i], literals, error)) {
        return false;
      }
      at += sizes[i];
    }
  }
  pos += header + compressed;
  return true;
}

// A decoded sequence: literal count, match length, and the raw offset value (before the repeat
// offset rules).
struct Sequence {
  std::uint32_t literals = 0;
  std::uint32_t match = 0;
  std::uint64_t offset_value = 0;
};

// The frame state that a sequence section may reuse: repeat offsets and the last tables.
struct SequenceState {
  std::array<std::uint64_t, 3> repeat{1, 4, 8};
  std::array<std::optional<FseTable>, 3> tables{};
};

bool decode_sequences(std::span<const std::byte> section, SequenceState& state,
                      std::vector<Sequence>& sequences, Error& error) {
  if (section.empty()) {
    return fail(error, "zstd.sequences", "the sequences section is missing");
  }
  std::size_t pos = 0;
  std::size_t count = 0;
  const std::uint8_t first = byte_at(section, 0);
  if (first == 0) {
    pos = 1;
  } else if (first < 128) {
    count = first;
    pos = 1;
  } else if (first < 255) {
    if (section.size() < 2) {
      return fail(error, "zstd.sequences", "the sequence count is cut short");
    }
    count = (std::size_t{first} - 128U) * 256U + byte_at(section, 1);
    pos = 2;
  } else {
    if (section.size() < 3) {
      return fail(error, "zstd.sequences", "the sequence count is cut short");
    }
    count = byte_at(section, 1) + (std::size_t{byte_at(section, 2)} << 8U) + 0x7F00U;
    pos = 3;
  }
  if (count == 0) {
    return true;
  }
  if (pos >= section.size()) {
    return fail(error, "zstd.sequences", "the compression modes are missing");
  }
  const std::uint8_t modes = byte_at(section, pos++);
  if ((modes & 3U) != 0) {
    return fail(error, "zstd.sequences", "a reserved bit of the compression modes is set");
  }
  std::array<const FseTable*, 3> tables{};
  std::array<FseTable, 3> fresh;
  for (std::size_t kind = 0; kind < 3; ++kind) {
    const unsigned mode = (modes >> (6U - 2U * kind)) & 3U;
    switch (mode) {
      case 0:  // predefined
        tables[kind] = &default_table(static_cast<Kind>(kind));
        break;
      case 1: {  // run-length: one symbol for every state
        if (pos >= section.size()) {
          return fail(error, "zstd.sequences", "a run-length table is missing its symbol");
        }
        const std::uint8_t symbol = byte_at(section, pos++);
        if (symbol > kMaxSymbol[kind]) {
          return fail(error, "zstd.sequences", "a run-length symbol is out of range");
        }
        fresh[kind].log = 0;
        fresh[kind].entries.assign(1, FseEntry{symbol, 0, 0});
        tables[kind] = &fresh[kind];
        break;
      }
      case 2: {  // compressed: a table description
        std::size_t used = 0;
        if (!read_fse_description(section.subspan(pos), kMaxSymbol[kind], kMaxLog[kind],
                                  fresh[kind], used, error)) {
          return false;
        }
        pos += used;
        tables[kind] = &fresh[kind];
        break;
      }
      default:  // repeat: the previous table of this kind
        if (!state.tables[kind].has_value()) {
          return fail(error, "zstd.sequences", "a repeated table has no earlier table");
        }
        tables[kind] = &*state.tables[kind];
        break;
    }
    if (mode != 3) {
      state.tables[kind] = *tables[kind];
    }
  }
  BackwardBits bits;
  if (!bits.open(section.subspan(pos), error)) {
    return false;
  }
  std::uint32_t state_ll = 0;
  std::uint32_t state_of = 0;
  std::uint32_t state_ml = 0;
  const FseTable& ll = *tables[kLiteralLength];
  const FseTable& of = *tables[kOffset];
  const FseTable& ml = *tables[kMatchLength];
  if (!bits.read(ll.log, state_ll, error) || !bits.read(of.log, state_of, error) ||
      !bits.read(ml.log, state_ml, error)) {
    return false;
  }
  sequences.reserve(sequences.size() + count);
  for (std::size_t i = 0; i < count; ++i) {
    const unsigned code_ll = ll.entries[state_ll].symbol;
    const unsigned code_of = of.entries[state_of].symbol;
    const unsigned code_ml = ml.entries[state_ml].symbol;
    if (code_ll > 35 || code_ml > 52 || code_of > 31) {
      return fail(error, "zstd.sequences", "a sequence code is out of range");
    }
    std::uint32_t extra = 0;
    if (!bits.read(code_of, extra, error)) {
      return false;
    }
    Sequence sequence;
    sequence.offset_value = (std::uint64_t{1} << code_of) + extra;
    if (!bits.read(kMatchBits[code_ml], extra, error)) {
      return false;
    }
    sequence.match = kMatchBase[code_ml] + extra;
    if (!bits.read(kLiteralBits[code_ll], extra, error)) {
      return false;
    }
    sequence.literals = kLiteralBase[code_ll] + extra;
    sequences.push_back(sequence);
    if (i + 1 < count) {
      // The states advance in the order literal length, match length, offset.
      std::uint32_t value = 0;
      const FseEntry& entry_ll = ll.entries[state_ll];
      if (!bits.read(entry_ll.bits, value, error)) {
        return false;
      }
      state_ll = entry_ll.base + value;
      const FseEntry& entry_ml = ml.entries[state_ml];
      if (!bits.read(entry_ml.bits, value, error)) {
        return false;
      }
      state_ml = entry_ml.base + value;
      const FseEntry& entry_of = of.entries[state_of];
      if (!bits.read(entry_of.bits, value, error)) {
        return false;
      }
      state_of = entry_of.base + value;
    }
  }
  if (bits.bits_left() != 0) {
    return fail(error, "zstd.sequences", "the sequence bit stream has bits left over");
  }
  return true;
}

// Runs the sequences of one block into the frame output (RFC 8878, section 3.1.1.3.2.3).
bool execute_block(const std::vector<std::byte>& literals, const std::vector<Sequence>& sequences,
                   SequenceState& state, std::uint64_t window, std::size_t frame_start,
                   std::vector<std::byte>& out, Error& error) {
  std::size_t next_literal = 0;
  for (const Sequence& sequence : sequences) {
    if (next_literal + sequence.literals > literals.size()) {
      return fail(error, "zstd.sequences", "a sequence takes more literals than the block has");
    }
    out.insert(out.end(), literals.begin() + static_cast<std::ptrdiff_t>(next_literal),
               literals.begin() + static_cast<std::ptrdiff_t>(next_literal + sequence.literals));
    next_literal += sequence.literals;

    // Offsets 1 to 3 name a repeat, and the literal count decides which one (RFC 8878, 3.1.2.5).
    std::uint64_t offset = 0;
    std::array<std::uint64_t, 3>& repeat = state.repeat;
    if (sequence.offset_value > 3) {
      offset = sequence.offset_value - 3;
      repeat = {offset, repeat[0], repeat[1]};
    } else {
      const std::size_t index =
          static_cast<std::size_t>(sequence.offset_value - 1 + (sequence.literals == 0 ? 1 : 0));
      if (index == 3) {
        if (repeat[0] <= 1) {
          return fail(error, "zstd.offset", "a repeat offset is zero");
        }
        offset = repeat[0] - 1;
        repeat = {offset, repeat[0], repeat[1]};
      } else {
        offset = repeat[index];
        if (index == 1) {
          repeat = {offset, repeat[0], repeat[2]};
        } else if (index == 2) {
          repeat = {offset, repeat[0], repeat[1]};
        }
      }
    }
    if (offset == 0 || offset > out.size() - frame_start || offset > window) {
      return fail(error, "zstd.offset", "a match reaches before the start of the output");
    }
    for (std::uint32_t i = 0; i < sequence.match; ++i) {
      out.push_back(out[out.size() - offset]);
    }
  }
  out.insert(out.end(), literals.begin() + static_cast<std::ptrdiff_t>(next_literal),
             literals.end());
  return true;
}

// XXH64 (the specification's algorithm, seed 0). The frame checksum is its low 32 bits.
constexpr std::uint64_t kPrime1 = 0x9E37'79B1'85EB'CA87ULL;
constexpr std::uint64_t kPrime2 = 0xC2B2'AE3D'27D4'EB4FULL;
constexpr std::uint64_t kPrime3 = 0x1656'67B1'9E37'79F9ULL;
constexpr std::uint64_t kPrime4 = 0x85EB'CA77'C2B2'AE63ULL;
constexpr std::uint64_t kPrime5 = 0x27D4'EB2F'1656'67C5ULL;

std::uint64_t rotate_left(std::uint64_t value, unsigned bits) {
  return (value << bits) | (value >> (64U - bits));
}

std::uint64_t read64(const std::byte* at) {
  std::uint64_t value = 0;
  for (unsigned i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(at[i])) << (8 * i);
  }
  return value;
}

std::uint64_t xxh_round(std::uint64_t accumulator, std::uint64_t input) {
  accumulator += input * kPrime2;
  return rotate_left(accumulator, 31) * kPrime1;
}

std::uint64_t xxh_merge(std::uint64_t accumulator, std::uint64_t value) {
  accumulator ^= xxh_round(0, value);
  return accumulator * kPrime1 + kPrime4;
}

std::uint64_t xxh64(std::span<const std::byte> data) {
  const std::byte* at = data.data();
  std::size_t left = data.size();
  std::uint64_t hash = 0;
  if (left >= 32) {
    std::uint64_t v1 = kPrime1 + kPrime2;
    std::uint64_t v2 = kPrime2;
    std::uint64_t v3 = 0;
    std::uint64_t v4 = 0 - kPrime1;
    while (left >= 32) {
      v1 = xxh_round(v1, read64(at));
      v2 = xxh_round(v2, read64(at + 8));
      v3 = xxh_round(v3, read64(at + 16));
      v4 = xxh_round(v4, read64(at + 24));
      at += 32;
      left -= 32;
    }
    hash = rotate_left(v1, 1) + rotate_left(v2, 7) + rotate_left(v3, 12) + rotate_left(v4, 18);
    hash = xxh_merge(hash, v1);
    hash = xxh_merge(hash, v2);
    hash = xxh_merge(hash, v3);
    hash = xxh_merge(hash, v4);
  } else {
    hash = kPrime5;
  }
  hash += static_cast<std::uint64_t>(data.size());
  while (left >= 8) {
    hash ^= xxh_round(0, read64(at));
    hash = rotate_left(hash, 27) * kPrime1 + kPrime4;
    at += 8;
    left -= 8;
  }
  if (left >= 4) {
    std::uint64_t word = 0;
    for (unsigned i = 0; i < 4; ++i) {
      word |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(at[i])) << (8 * i);
    }
    hash ^= word * kPrime1;
    hash = rotate_left(hash, 23) * kPrime2 + kPrime3;
    at += 4;
    left -= 4;
  }
  while (left > 0) {
    hash ^= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(*at)) * kPrime5;
    hash = rotate_left(hash, 11) * kPrime1;
    ++at;
    --left;
  }
  hash ^= hash >> 33U;
  hash *= kPrime2;
  hash ^= hash >> 29U;
  hash *= kPrime3;
  hash ^= hash >> 32U;
  return hash;
}

Result<std::vector<std::byte>> error_result(const Error& error) {
  return make_error<std::vector<std::byte>>(Status::InvalidInput, error.code, error.message);
}

// One frame, from its magic number to its checksum. `out` receives its content.
bool decode_frame(std::span<const std::byte> input, std::size_t& pos, std::vector<std::byte>& out,
                  const ZstdOptions& options, Error& error) {
  if (input.size() - pos < 5) {
    return fail(error, "zstd.truncated", "a frame header is cut short");
  }
  if (read_le(input, pos, 4) != kMagic) {
    return fail(error, "zstd.magic", "a frame does not start with the Zstandard magic number");
  }
  pos += 4;
  const std::uint8_t descriptor = byte_at(input, pos++);
  const unsigned content_size_flag = descriptor >> 6U;
  const bool single_segment = ((descriptor >> 5U) & 1U) != 0;
  const bool has_checksum = ((descriptor >> 2U) & 1U) != 0;
  const unsigned dictionary_flag = descriptor & 3U;
  if ((descriptor & 0x08U) != 0) {
    return fail(error, "zstd.header", "a reserved bit of the frame header is set");
  }
  std::uint64_t window = 0;
  if (!single_segment) {
    if (pos >= input.size()) {
      return fail(error, "zstd.truncated", "a frame's window descriptor is missing");
    }
    const std::uint8_t descriptor_window = byte_at(input, pos++);
    const std::uint64_t base = std::uint64_t{1} << (10U + (descriptor_window >> 3U));
    window = base + (base / 8U) * (descriptor_window & 7U);
  }
  const std::size_t dictionary_bytes = dictionary_flag == 3 ? 4 : dictionary_flag;
  if (input.size() - pos < dictionary_bytes) {
    return fail(error, "zstd.truncated", "a frame's dictionary id is cut short");
  }
  for (std::size_t i = 0; i < dictionary_bytes; ++i) {
    if (byte_at(input, pos + i) != 0) {
      return fail(error, "zstd.dictionary", "the frame names a dictionary, which is not supported");
    }
  }
  pos += dictionary_bytes;
  std::size_t content_bytes =
      content_size_flag == 0 ? (single_segment ? 1U : 0U) : (std::size_t{1} << content_size_flag);
  if (content_size_flag == 3) {
    content_bytes = 8;
  }
  if (input.size() - pos < content_bytes) {
    return fail(error, "zstd.truncated", "a frame's content size is cut short");
  }
  const bool has_size = content_bytes != 0;
  std::uint64_t content_size = 0;
  for (std::size_t i = 0; i < content_bytes; ++i) {
    content_size |= static_cast<std::uint64_t>(byte_at(input, pos + i)) << (8 * i);
  }
  pos += content_bytes;
  if (content_bytes == 2) {
    content_size += 256;
  }
  if (single_segment) {
    window = content_size;
  }

  const std::size_t frame_start = out.size();
  SequenceState sequences_state;
  std::optional<HuffmanTable> tree;
  bool last = false;
  while (!last) {
    if (input.size() - pos < 3) {
      return fail(error, "zstd.truncated", "a block header is cut short");
    }
    const std::uint32_t header = read_le(input, pos, 3);
    pos += 3;
    last = (header & 1U) != 0;
    const unsigned type = (header >> 1U) & 3U;
    const std::size_t size = header >> 3U;
    if (size > kMaxBlockSize) {
      return fail(error, "zstd.block", "a block is larger than the frame allows");
    }
    if (type == 3) {
      return fail(error, "zstd.block", "a block has the reserved type");
    }
    if (input.size() - pos < (type == 1 ? 1U : size)) {
      return fail(error, "zstd.truncated", "a block is cut short");
    }
    if (type == 0) {
      out.insert(out.end(), input.begin() + static_cast<std::ptrdiff_t>(pos),
                 input.begin() + static_cast<std::ptrdiff_t>(pos + size));
      pos += size;
    } else if (type == 1) {
      out.insert(out.end(), size, input[pos]);
      pos += 1;
    } else {
      const std::span<const std::byte> block = input.subspan(pos, size);
      std::size_t at = 0;
      std::vector<std::byte> literals;
      std::vector<Sequence> sequences;
      if (!decode_literals(block, at, tree, literals, error) ||
          !decode_sequences(block.subspan(at), sequences_state, sequences, error)) {
        return false;
      }
      if (!execute_block(literals, sequences, sequences_state, window, frame_start, out, error)) {
        return false;
      }
      pos += size;
    }
    if (out.size() > options.max_output_bytes) {
      return fail(error, "zstd.limit", "the output is larger than the limit");
    }
  }
  const std::size_t produced = out.size() - frame_start;
  if (has_size && produced != content_size) {
    return fail(error, "zstd.size", "the frame's content is not its declared size");
  }
  if (has_checksum) {
    if (input.size() - pos < 4) {
      return fail(error, "zstd.truncated", "the frame's checksum is cut short");
    }
    const auto expected = static_cast<std::uint32_t>(read_le(input, pos, 4));
    pos += 4;
    const auto actual = static_cast<std::uint32_t>(
        xxh64(std::span<const std::byte>(out.data() + frame_start, produced)));
    if (actual != expected) {
      return fail(error, "zstd.checksum", "the frame's content does not match its checksum");
    }
  }
  return true;
}

}  // namespace

Result<std::vector<std::byte>> zstd_decompress(std::span<const std::byte> input,
                                               const ZstdOptions& options) {
  Error error;
  std::vector<std::byte> out;
  std::size_t pos = 0;
  if (input.empty()) {
    return error_result(Error{"zstd.truncated", "there is no frame"});
  }
  while (pos < input.size()) {
    if (input.size() - pos < 4) {
      return error_result(Error{"zstd.truncated", "trailing bytes are not a frame"});
    }
    const std::uint32_t magic = read_le(input, pos, 4);
    if ((magic & kSkippableMask) == kSkippableStart) {
      // A skippable frame: a magic number, its size, and that many bytes to ignore.
      if (input.size() - pos < 8) {
        return error_result(Error{"zstd.truncated", "a skippable frame's size is cut short"});
      }
      const std::size_t size = read_le(input, pos + 4, 4);
      if (input.size() - pos - 8 < size) {
        return error_result(Error{"zstd.truncated", "a skippable frame is cut short"});
      }
      pos += 8 + size;
      continue;
    }
    if (!decode_frame(input, pos, out, options, error)) {
      return error_result(error);
    }
  }
  return out;
}

}  // namespace donkey
