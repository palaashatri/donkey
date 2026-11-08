#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/binary/records.h"

namespace {

using Bytes = std::vector<std::uint8_t>;

std::string hex_of(const Bytes& bytes) {
  static const char* const kDigits = "0123456789ABCDEF";
  std::string text;
  for (const std::uint8_t byte : bytes) {
    text += kDigits[byte >> 4U];
    text += kDigits[byte & 0x0FU];
  }
  return text;
}

/// One Intel HEX record with a correct checksum: type 0 is data, 1 end of file, 4 extended
/// linear address, 5 start linear address.
std::string intel_record(std::uint8_t type, std::uint16_t address, const Bytes& data) {
  Bytes bytes{static_cast<std::uint8_t>(data.size()), static_cast<std::uint8_t>(address >> 8U),
              static_cast<std::uint8_t>(address & 0xFFU), type};
  bytes.insert(bytes.end(), data.begin(), data.end());
  std::uint8_t sum = 0;
  for (const std::uint8_t byte : bytes) {
    sum = static_cast<std::uint8_t>(sum + byte);
  }
  bytes.push_back(static_cast<std::uint8_t>(0U - sum));
  return ":" + hex_of(bytes);
}

/// One Motorola S-record with a correct checksum; `width` is the address width in bytes.
std::string srecord(int type, std::uint32_t address, int width, const Bytes& data) {
  Bytes bytes{static_cast<std::uint8_t>(width + data.size() + 1)};
  for (int i = width - 1; i >= 0; --i) {
    bytes.push_back(static_cast<std::uint8_t>(address >> (8 * i)));
  }
  bytes.insert(bytes.end(), data.begin(), data.end());
  std::uint8_t sum = 0;
  for (const std::uint8_t byte : bytes) {
    sum = static_cast<std::uint8_t>(sum + byte);
  }
  bytes.push_back(static_cast<std::uint8_t>(0xFFU - sum));
  return "S" + std::to_string(type) + hex_of(bytes);
}

std::span<const std::byte> as_bytes(const std::string& text) {
  return std::span<const std::byte>(reinterpret_cast<const std::byte*>(text.data()), text.size());
}

std::string joined(const std::vector<std::string>& lines) {
  std::string text;
  for (const std::string& line : lines) {
    text += line + "\n";
  }
  return text;
}

}  // namespace

TEST(Records, IntelHexLoadsDataAtItsAddressesWithErasedGaps) {
  // The extended linear address puts the data at 0x08000000; the gap is 0xFF.
  const std::string text = joined({
      intel_record(4, 0, {0x08, 0x00}),
      intel_record(0, 0x0000, {0x01, 0x02, 0x03, 0x04}),
      intel_record(0, 0x0010, {0xAA}),
      intel_record(5, 0, {0x08, 0x00, 0x01, 0x00}),
      intel_record(1, 0, {}),
  });
  ASSERT_EQ(donkey::detect_record_format(as_bytes(text)), donkey::RecordFormat::IntelHex);
  const auto decoded =
      donkey::decode_records(as_bytes(text), donkey::RecordFormat::IntelHex, 1 << 20);
  ASSERT_TRUE(decoded.has_value()) << decoded.diagnostic().message;
  EXPECT_EQ(decoded.value().base, 0x08000000U);
  ASSERT_EQ(decoded.value().bytes.size(), 0x11U);
  EXPECT_EQ(std::to_integer<unsigned>(decoded.value().bytes[0]), 0x01U);
  EXPECT_EQ(std::to_integer<unsigned>(decoded.value().bytes[3]), 0x04U);
  EXPECT_EQ(std::to_integer<unsigned>(decoded.value().bytes[4]), 0xFFU);
  EXPECT_EQ(std::to_integer<unsigned>(decoded.value().bytes[0x10]), 0xAAU);
  EXPECT_TRUE(decoded.value().has_entry_point);
  EXPECT_EQ(decoded.value().entry_point, 0x08000100U);
}

TEST(Records, SRecordsWithThirtyTwoBitAddressesAndAHeader) {
  const std::string text = joined({
      srecord(0, 0, 2, {'h', 'i'}),
      srecord(3, 0x1000, 4, {'A', 'B'}),
      srecord(3, 0x1002, 4, {'C'}),
      srecord(7, 0x1000, 4, {}),
  });
  ASSERT_EQ(donkey::detect_record_format(as_bytes(text)), donkey::RecordFormat::SRecord);
  const auto decoded =
      donkey::decode_records(as_bytes(text), donkey::RecordFormat::SRecord, 1 << 20);
  ASSERT_TRUE(decoded.has_value()) << decoded.diagnostic().message;
  EXPECT_EQ(decoded.value().base, 0x1000U);
  ASSERT_EQ(decoded.value().bytes.size(), 3U);
  EXPECT_EQ(std::to_integer<char>(decoded.value().bytes[0]), 'A');
  EXPECT_EQ(std::to_integer<char>(decoded.value().bytes[2]), 'C');
  EXPECT_TRUE(decoded.value().has_entry_point);
  EXPECT_EQ(decoded.value().entry_point, 0x1000U);
}

TEST(Records, ABadChecksumIsAnErrorThatNamesTheLine) {
  std::string bad = intel_record(0, 0, {0x01, 0x02});
  bad.back() = bad.back() == '0' ? '1' : '0';  // change the checksum
  const std::string text = joined({intel_record(0, 0, {0x01}), bad});
  const auto decoded =
      donkey::decode_records(as_bytes(text), donkey::RecordFormat::IntelHex, 1 << 20);
  ASSERT_FALSE(decoded.has_value());
  EXPECT_EQ(decoded.diagnostic().code, "records.checksum");
  EXPECT_EQ(decoded.diagnostic().message.rfind("line 2:", 0), 0U) << decoded.diagnostic().message;
}

TEST(Records, UnknownTypesAndRecordsAfterTheEndAreErrors) {
  const std::string unknown = joined({intel_record(0, 0, {0x01}), intel_record(0x07, 0, {})});
  const auto a = donkey::decode_records(as_bytes(unknown), donkey::RecordFormat::IntelHex, 1 << 20);
  ASSERT_FALSE(a.has_value());
  EXPECT_EQ(a.diagnostic().code, "records.unknown_type");

  const std::string after =
      joined({intel_record(0, 0, {0x01}), intel_record(1, 0, {}), intel_record(0, 0, {0x02})});
  const auto b = donkey::decode_records(as_bytes(after), donkey::RecordFormat::IntelHex, 1 << 20);
  ASSERT_FALSE(b.has_value());
  EXPECT_EQ(b.diagnostic().code, "records.after_end");
}

TEST(Records, AFileWithNoDataIsAnError) {
  const std::string text = joined({intel_record(1, 0, {})});
  const auto decoded =
      donkey::decode_records(as_bytes(text), donkey::RecordFormat::IntelHex, 1 << 20);
  ASSERT_FALSE(decoded.has_value());
  EXPECT_EQ(decoded.diagnostic().code, "records.no_data");
}

TEST(Records, TheFlatImageIsLimitedInSize) {
  // Two records 64 KiB apart would need a 64 KiB image; the limit is 256 bytes.
  const std::string text = joined({
      intel_record(0, 0x0000, {0x01}),
      intel_record(4, 0, {0x00, 0x01}),
      intel_record(0, 0x0000, {0x02}),
  });
  const auto decoded = donkey::decode_records(as_bytes(text), donkey::RecordFormat::IntelHex, 256);
  ASSERT_FALSE(decoded.has_value());
  EXPECT_EQ(decoded.diagnostic().code, "records.too_large");
  EXPECT_EQ(decoded.diagnostic().status, donkey::Status::ResourceLimit);
}

TEST(Records, DetectionLooksAtTheFirstLineOnly) {
  EXPECT_EQ(donkey::detect_record_format(as_bytes("hello, not a record\n")),
            donkey::RecordFormat::None);
  EXPECT_EQ(donkey::detect_record_format(as_bytes(":12")), donkey::RecordFormat::None);
  EXPECT_EQ(donkey::detect_record_format(as_bytes("   \n:00000001FF\n")),
            donkey::RecordFormat::IntelHex);
  EXPECT_EQ(donkey::detect_record_format(as_bytes("S9030000FC\n")), donkey::RecordFormat::SRecord);
  EXPECT_EQ(donkey::detect_record_format(as_bytes("")), donkey::RecordFormat::None);
}

TEST(Records, AnIntelHexFileLoadsAsAFlatImageAtItsBase) {
  const std::string text = joined({
      intel_record(4, 0, {0x20, 0x00}),
      intel_record(0, 0x0100, {0xDE, 0xAD, 0xBE, 0xEF}),
      intel_record(1, 0, {}),
  });
  const std::filesystem::path path =
      std::filesystem::temp_directory_path() / "donkey-records-load-test.hex";
  {
    std::ofstream file(path, std::ios::binary);
    file << text;
  }
  const auto loaded = donkey::load_binary(path.string());
  std::filesystem::remove(path);
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  const donkey::BinaryImage& image = loaded.value().image;
  EXPECT_EQ(image.format, donkey::BinaryFormat::Raw);
  EXPECT_EQ(image.format_detail, "Intel HEX");
  EXPECT_EQ(image.image_base, 0x20000100U);
  EXPECT_EQ(loaded.value().data.span().size(), 4U);
}
