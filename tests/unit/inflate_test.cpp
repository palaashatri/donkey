#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "donkey/binary/inflate.h"

namespace {

std::string fixture(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/compress/" + name;
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

}  // namespace

// The streams and their plaintext are written by Python's zlib (see
// tests/fixtures/compress/PROVENANCE.md); zlib is the oracle for every block type.
TEST(Inflate, DynamicHuffmanBlocksReproduceThePlaintext) {
  const auto stream = read_file(fixture("dynamic.z"));
  const auto plain = read_file(fixture("sample.txt"));
  auto out = donkey::inflate_zlib(stream);
  ASSERT_TRUE(out.has_value()) << out.diagnostic().code << ": " << out.diagnostic().message;
  EXPECT_EQ(out.value(), plain);
}

TEST(Inflate, StoredBlocksReproduceThePlaintext) {
  const auto stream = read_file(fixture("stored.z"));
  const auto plain = read_file(fixture("sample.txt"));
  auto out = donkey::inflate_zlib(stream);
  ASSERT_TRUE(out.has_value()) << out.diagnostic().code;
  EXPECT_EQ(out.value(), plain);
}

TEST(Inflate, FixedHuffmanBlocksReproduceThePlaintext) {
  const auto stream = read_file(fixture("fixed.z"));
  const auto plain = read_file(fixture("fixed.txt"));
  auto out = donkey::inflate_zlib(stream);
  ASSERT_TRUE(out.has_value()) << out.diagnostic().code;
  EXPECT_EQ(out.value(), plain);
}

TEST(Inflate, AWrongHeaderIsRejectedAsAHeader) {
  auto stream = read_file(fixture("fixed.z"));
  stream[0] = static_cast<std::byte>(0x79);  // compression method is not deflate
  auto out = donkey::inflate_zlib(stream);
  ASSERT_FALSE(out.has_value());
  EXPECT_EQ(out.diagnostic().code, "inflate.header");
}

TEST(Inflate, AWrongChecksumIsRejectedNotReturned) {
  auto stream = read_file(fixture("dynamic.z"));
  stream.back() = static_cast<std::byte>(static_cast<std::uint8_t>(stream.back()) ^ 0x01);
  auto out = donkey::inflate_zlib(stream);
  ASSERT_FALSE(out.has_value());
  EXPECT_EQ(out.diagnostic().code, "inflate.checksum");
}

TEST(Inflate, ATruncatedStreamIsAnErrorNotPartialOutput) {
  const auto stream = read_file(fixture("dynamic.z"));
  const std::span<const std::byte> cut(stream.data(), stream.size() / 2);
  auto out = donkey::inflate_zlib(cut);
  ASSERT_FALSE(out.has_value());
  EXPECT_EQ(out.diagnostic().code.rfind("inflate.", 0), 0U) << out.diagnostic().code;
}

TEST(Inflate, TheOutputLimitIsEnforced) {
  const auto stream = read_file(fixture("dynamic.z"));
  donkey::InflateOptions options;
  options.max_output_bytes = 1000;
  auto out = donkey::inflate_zlib(stream, options);
  ASSERT_FALSE(out.has_value());
  EXPECT_EQ(out.diagnostic().code, "inflate.too_large");
}

// A corrupted stream may decode to a different result or fail. Either way it must end in a
// deterministic outcome with an `inflate.` code, never a crash or an out-of-range read.
TEST(Inflate, CorruptedStreamsEndInACodedOutcome) {
  const auto stream = read_file(fixture("dynamic.z"));
  for (std::size_t i = 2; i < stream.size(); i += 97) {
    auto damaged = stream;
    damaged[i] = static_cast<std::byte>(static_cast<std::uint8_t>(damaged[i]) ^ 0x5a);
    auto out = donkey::inflate_zlib(damaged);
    if (!out.has_value()) {
      EXPECT_EQ(out.diagnostic().code.rfind("inflate.", 0), 0U) << "byte " << i;
    }
  }
}
