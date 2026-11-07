#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "donkey/binary/zstd.h"
#include "donkey/core/sha256.h"

// The fixtures in tests/fixtures/compress/zstd were made with the `zstandard` Python package
// (libzstd 1.5, see tests/fixtures/compress/PROVENANCE.md). The expected digests are of the
// original, uncompressed data, computed by Python's hashlib when the fixtures were made.

namespace {

std::string fixture(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/compress/zstd/" + name;
}

std::vector<std::byte> read_file(const std::string& path) {
  std::ifstream file(path, std::ios::binary);
  const std::vector<char> raw((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
  std::vector<std::byte> bytes;
  bytes.reserve(raw.size());
  for (const char c : raw) {
    bytes.push_back(static_cast<std::byte>(c));
  }
  return bytes;
}

std::string digest_of(const std::vector<std::byte>& bytes) {
  return donkey::Sha256::hex(std::span<const std::byte>(bytes));
}

std::string code_of(const donkey::Result<std::vector<std::byte>>& result) {
  return result.has_value() ? std::string("ok") : result.diagnostic().code;
}

}  // namespace

// Long text in 128 KiB blocks: compressed blocks with Huffman literals, sequences and repeat
// offsets, and the content checksum.
TEST(Zstd, DecodesAMultiBlockFrameToItsOriginal) {
  const auto frame = read_file(fixture("text-multiblock.zst"));
  auto decoded = donkey::zstd_decompress(frame);
  ASSERT_TRUE(decoded.has_value())
      << decoded.diagnostic().code << ": " << decoded.diagnostic().message;
  EXPECT_EQ(decoded.value().size(), 300000U);
  EXPECT_EQ(digest_of(decoded.value()),
            "4781fcb1d85305961132291471a1a465e5213db861bdb9be8057227a903475fa");
}

// Incompressible data is stored as raw blocks.
TEST(Zstd, DecodesIncompressibleDataFromRawBlocks) {
  const auto frame = read_file(fixture("random-raw.zst"));
  auto decoded = donkey::zstd_decompress(frame);
  ASSERT_TRUE(decoded.has_value()) << decoded.diagnostic().code;
  EXPECT_EQ(decoded.value().size(), 20000U);
  EXPECT_EQ(digest_of(decoded.value()),
            "474dfd5ae970de0d4fdd89485201ec38a0eb2bca5bf695e4d7d29852539fe350");
}

// A run of one byte is a run-length block: 200 KB from a 30-byte frame.
TEST(Zstd, DecodesARunOfOneByteFromRunLengthBlocks) {
  const auto frame = read_file(fixture("zeros-rle.zst"));
  auto decoded = donkey::zstd_decompress(frame);
  ASSERT_TRUE(decoded.has_value()) << decoded.diagnostic().code;
  ASSERT_EQ(decoded.value().size(), 200000U);
  EXPECT_EQ(digest_of(decoded.value()),
            "4cbbd9be0cba685835755f827758705db5a413c5494c34262cd25946a73e7582");
}

// Frames are decoded one after another, and a skippable frame between them contributes nothing.
TEST(Zstd, ConcatenatedFramesAndSkippableFramesDecodeInOrder) {
  const auto frame = read_file(fixture("two-frames-skippable.zst"));
  auto decoded = donkey::zstd_decompress(frame);
  ASSERT_TRUE(decoded.has_value()) << decoded.diagnostic().code;
  std::string expected;
  for (int i = 0; i < 100; ++i) {
    expected += "hello ";
  }
  for (int i = 0; i < 50; ++i) {
    expected += "world";
  }
  const std::string actual(reinterpret_cast<const char*>(decoded.value().data()),
                           decoded.value().size());
  EXPECT_EQ(actual, expected);
}

// A frame that names a dictionary cannot be decoded without it, so it is refused by name.
TEST(Zstd, AFrameThatNamesADictionaryIsRefused) {
  const auto frame = read_file(fixture("dictionary.zst"));
  EXPECT_EQ(code_of(donkey::zstd_decompress(frame)), "zstd.dictionary");
}

// Copies from three alternating distances, with short literal runs between them: the encoder
// codes most offsets as repeats, so every repeat rule (offsets 1 to 3, with and without literals)
// is on the path to the right answer.
TEST(Zstd, DecodesRepeatedOffsetsToTheOriginal) {
  const auto frame = read_file(fixture("repeat-offsets.zst"));
  auto decoded = donkey::zstd_decompress(frame);
  ASSERT_TRUE(decoded.has_value())
      << decoded.diagnostic().code << ": " << decoded.diagnostic().message;
  EXPECT_EQ(decoded.value().size(), 39973U);
  EXPECT_EQ(digest_of(decoded.value()),
            "e25aa767b267996ed7f9cd3571a62c2f672be01a86212092171c797e8023007d");
}

// Flipping a byte of the checksum makes the frame wrong, not partly right.
TEST(Zstd, AWrongChecksumIsAnError) {
  auto frame = read_file(fixture("zeros-rle.zst"));
  ASSERT_GE(frame.size(), 4U);
  frame.back() = static_cast<std::byte>(std::to_integer<std::uint8_t>(frame.back()) ^ 0x5A);
  EXPECT_EQ(code_of(donkey::zstd_decompress(frame)), "zstd.checksum");
}

// A frame cut short is reported as cut short, at every length, never as a partial result.
TEST(Zstd, ATruncatedFrameIsCodedAtEveryLength) {
  const auto frame = read_file(fixture("text-multiblock.zst"));
  for (const std::size_t length : {std::size_t{0}, std::size_t{3}, std::size_t{5}, std::size_t{9},
                                   frame.size() / 2, frame.size() - 1}) {
    const std::span<const std::byte> cut(frame.data(), length);
    const std::string code = code_of(donkey::zstd_decompress(cut));
    EXPECT_EQ(code.rfind("zstd.", 0), 0U) << "length " << length << ": " << code;
    EXPECT_NE(code, "ok") << "length " << length;
  }
}

// The output is capped: a frame that would produce more than the limit is refused.
TEST(Zstd, TheOutputLimitIsEnforced) {
  const auto frame = read_file(fixture("text-multiblock.zst"));
  donkey::ZstdOptions options;
  options.max_output_bytes = 1000;
  EXPECT_EQ(code_of(donkey::zstd_decompress(frame, options)), "zstd.limit");
}

TEST(Zstd, BytesThatAreNotAFrameAreRefusedByMagic) {
  const std::vector<std::byte> bytes(16, std::byte{0x41});
  EXPECT_EQ(code_of(donkey::zstd_decompress(bytes)), "zstd.magic");
}

TEST(Zstd, AnEmptyInputHasNoFrame) {
  EXPECT_EQ(code_of(donkey::zstd_decompress(std::span<const std::byte>{})), "zstd.truncated");
}
