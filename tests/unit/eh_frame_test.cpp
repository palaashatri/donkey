#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

#include "donkey/binary/eh_frame.h"
#include "donkey/binary/image.h"

namespace {

using donkey::EhFrameReadResult;
using donkey::Endian;

std::vector<std::byte> bytes_of(std::initializer_list<unsigned> values) {
  std::vector<std::byte> out;
  for (const unsigned value : values) {
    out.push_back(static_cast<std::byte>(value & 0xFFU));
  }
  return out;
}

void append_u32(std::vector<std::byte>& out, std::uint32_t value) {
  for (int shift = 0; shift < 32; shift += 8) {
    out.push_back(static_cast<std::byte>((value >> shift) & 0xFFU));
  }
}

void append_u64(std::vector<std::byte>& out, std::uint64_t value) {
  for (int shift = 0; shift < 64; shift += 8) {
    out.push_back(static_cast<std::byte>((value >> shift) & 0xFFU));
  }
}

/// A 32-bit CIE with augmentation "zR", FDE encoding `encoding`, and the standard fields.
/// Its id is 0, and the record is 17 bytes: length, id, version, "zR", alignments, the return
/// register, the augmentation length and the encoding.
std::vector<std::byte> cie_record(std::uint8_t encoding) {
  std::vector<std::byte> body = bytes_of({0x00, 0x00, 0x00, 0x00,  // CIE id
                                          0x01,                    // version
                                          'z', 'R', 0x00,          // augmentation "zR"
                                          0x01,                    // code alignment (uleb)
                                          0x78,                    // data alignment (sleb -8)
                                          0x10,                    // return register
                                          0x01,                    // augmentation data length
                                          encoding});
  std::vector<std::byte> out;
  append_u32(out, static_cast<std::uint32_t>(body.size()));
  out.insert(out.end(), body.begin(), body.end());
  return out;
}

/// A 32-bit FDE. `id` is the distance from its id field back to the CIE at offset 0: an FDE at
/// record offset `r` has its id field at r + 4, so its id is r + 4. `start_field` is the encoded
/// pc_begin as it is stored.
std::vector<std::byte> fde_record(std::uint32_t id, std::uint32_t start_field,
                                  std::uint32_t range) {
  std::vector<std::byte> out;
  append_u32(out, 4 + 4 + 4 + 1);  // id, pc_begin, pc_range, augmentation length
  append_u32(out, id);
  append_u32(out, start_field);
  append_u32(out, range);
  out.push_back(std::byte{0});  // augmentation data length
  return out;
}

std::vector<std::byte> concat(std::initializer_list<std::vector<std::byte>> parts) {
  std::vector<std::byte> out;
  for (const auto& part : parts) {
    out.insert(out.end(), part.begin(), part.end());
  }
  return out;
}

constexpr std::uint64_t kBase = 0x400000;

}  // namespace

TEST(EhFrame, ReadsPcRelativeFdeRanges) {
  // The CIE is at offset 0 (17 bytes); the FDE is at 17 and its id field at 21, so the id is 21.
  // Its pc_begin field is at 25 and encodes 0x401000 relative to that field (sdata4, pcrel).
  const std::uint32_t field_address = static_cast<std::uint32_t>(kBase + 25);
  const std::uint32_t start_field = 0x401000U - field_address;
  const auto section = concat({cie_record(0x1b), fde_record(21, start_field, 0x20)});
  auto result = donkey::read_eh_frame(section, kBase, 8, Endian::Little);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  ASSERT_EQ(result.value().functions.size(), 1U);
  EXPECT_EQ(result.value().functions[0].start, 0x401000U);
  EXPECT_EQ(result.value().functions[0].size, 0x20U);
  EXPECT_EQ(result.value().malformed_records, 0U);
  EXPECT_FALSE(result.value().truncated);
  EXPECT_EQ(result.value().records, 2U);
}

TEST(EhFrame, Reads64BitLengthRecordsWithAbsoluteEncodings) {
  // A 64-bit CIE: 0xffffffff, its 8-byte length, and an 8-byte id of 0.
  std::vector<std::byte> cie;
  append_u32(cie, 0xffffffffU);
  const std::uint64_t cie_body = 8 + 1 + 3 + 1 + 1 + 1 + 1 + 1;  // id, fields below
  append_u64(cie, cie_body);
  append_u64(cie, 0);              // CIE id (64-bit form)
  cie.push_back(std::byte{0x01});  // version
  for (const char c : std::string("zR")) {
    cie.push_back(static_cast<std::byte>(c));
  }
  cie.push_back(std::byte{0x00});
  cie.push_back(std::byte{0x01});  // code alignment
  cie.push_back(std::byte{0x78});  // data alignment
  cie.push_back(std::byte{0x10});  // return register
  cie.push_back(std::byte{0x01});  // augmentation length
  cie.push_back(std::byte{0x00});  // absptr: 8 bytes, absolute
  // A 64-bit FDE for the CIE at offset 0. Its id field is at 12 + 8 = 20 (after the header).
  std::vector<std::byte> fde;
  append_u32(fde, 0xffffffffU);
  const std::uint64_t fde_body = 8 + 8 + 8 + 1;
  append_u64(fde, fde_body);
  const std::uint64_t id_field = static_cast<std::uint64_t>(cie.size()) + 12;
  append_u64(fde, id_field);    // distance back to the CIE
  append_u64(fde, 0x402000);    // pc_begin, absolute
  append_u64(fde, 0x30);        // pc_range
  fde.push_back(std::byte{0});  // augmentation length
  const auto section = concat({cie, fde});
  auto result = donkey::read_eh_frame(section, kBase, 8, Endian::Little);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  ASSERT_EQ(result.value().functions.size(), 1U);
  EXPECT_EQ(result.value().functions[0].start, 0x402000U);
  EXPECT_EQ(result.value().functions[0].size, 0x30U);
  EXPECT_EQ(result.value().malformed_records, 0U);
}

TEST(EhFrame, ZeroStartsAndZeroRangesAreSkippedNotCounted) {
  const auto section =
      concat({cie_record(0x0b), fde_record(21, 0, 0x10), fde_record(38, 0x1000, 0)});
  auto result = donkey::read_eh_frame(section, kBase, 8, Endian::Little);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  EXPECT_TRUE(result.value().functions.empty());
  EXPECT_EQ(result.value().malformed_records, 0U);
}

TEST(EhFrame, DataRelativeEncodingIsRefusedAndCountedAsMalformed) {
  // R = datarel|sdata4 (0x3b) needs the data base, which this reader does not have.
  const auto section = concat({cie_record(0x3b), fde_record(21, 0x10, 0x20)});
  auto result = donkey::read_eh_frame(section, kBase, 8, Endian::Little);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  EXPECT_TRUE(result.value().functions.empty());
  EXPECT_EQ(result.value().malformed_records, 1U);
}

TEST(EhFrame, ARecordLengthPastTheSectionStopsTheWalkAndIsReported) {
  auto section = cie_record(0x0b);
  append_u32(section, 0x1000);  // claims 4096 bytes; none follow
  auto result = donkey::read_eh_frame(section, kBase, 8, Endian::Little);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  EXPECT_TRUE(result.value().truncated);
  EXPECT_EQ(result.value().records, 1U);
}

TEST(EhFrame, BadCiePointerIsMalformedAndDoesNotStopTheWalk) {
  // An FDE whose id points past its own start (no CIE can be there), then a good FDE.
  const auto section =
      concat({cie_record(0x0b), fde_record(0x4000, 0x1000, 0x10), fde_record(38, 0x2000, 0x10)});
  auto result = donkey::read_eh_frame(section, kBase, 8, Endian::Little);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  EXPECT_EQ(result.value().malformed_records, 1U);
  EXPECT_FALSE(result.value().truncated);
  ASSERT_EQ(result.value().functions.size(), 1U);
  EXPECT_EQ(result.value().functions[0].start, 0x2000U);
}

TEST(EhFrame, TerminatorStopsTheWalk) {
  // CIE, a zero-length terminator, then an FDE that must not be read.
  auto section = cie_record(0x0b);
  append_u32(section, 0);
  const auto tail = fde_record(25, 0x1000, 0x10);  // after the terminator, at offset 21
  section.insert(section.end(), tail.begin(), tail.end());
  auto result = donkey::read_eh_frame(section, kBase, 8, Endian::Little);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  EXPECT_TRUE(result.value().functions.empty());
  EXPECT_EQ(result.value().records, 1U);
  EXPECT_FALSE(result.value().truncated);
}

TEST(EhFrame, RecordLimitTruncatesAndKeepsWhatWasRead) {
  const auto section =
      concat({cie_record(0x0b), fde_record(21, 0x1000, 0x10), fde_record(38, 0x2000, 0x10)});
  auto result = donkey::read_eh_frame(section, kBase, 8, Endian::Little, /*max_records=*/2);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  EXPECT_TRUE(result.value().truncated);
  ASSERT_EQ(result.value().functions.size(), 1U);
  EXPECT_EQ(result.value().functions[0].start, 0x1000U);
}

TEST(EhFrame, TruncatedHeaderIsReportedNotRead) {
  const auto section = bytes_of({0x10, 0x00, 0x00});  // a length that does not fit
  auto result = donkey::read_eh_frame(section, kBase, 8, Endian::Little);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  EXPECT_TRUE(result.value().truncated);
  EXPECT_TRUE(result.value().functions.empty());
}

TEST(EhFrame, RejectsAPointerSizeThatIsNeitherFourNorEight) {
  auto result = donkey::read_eh_frame({}, kBase, 3, Endian::Little);
  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.diagnostic().code, "elf.eh_frame_pointer_size");
}

TEST(EhFrame, EmptySectionHasNoRecords) {
  auto result = donkey::read_eh_frame({}, kBase, 8, Endian::Little);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  EXPECT_TRUE(result.value().functions.empty());
  EXPECT_EQ(result.value().records, 0U);
}

TEST(EhFrame, ImageWithoutEhFrameYieldsNothing) {
  donkey::BinaryImage image;
  image.bits = 64;
  auto result = donkey::read_eh_frame_of_image(image, {});
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  EXPECT_TRUE(result.value().functions.empty());
}

// The committed fixture tests/fixtures/link/libtailcall.so was built by gcc -O2 -shared -fPIC. Its
// six FDE ranges below are what `readelf --debug-dump=frames` prints for it.
TEST(EhFrame, FixtureFdesMatchReadelf) {
  const std::string path = std::string(DONKEY_FIXTURE_DIR) + "/link/libtailcall.so";
  std::ifstream in(path, std::ios::binary);
  ASSERT_TRUE(in.good()) << path;
  std::vector<std::byte> file;
  {
    std::vector<char> raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    for (const char c : raw) {
      file.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
    }
  }
  auto loaded = donkey::load_binary(path);
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  auto result = donkey::read_eh_frame_of_image(loaded.value().image, file);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  const std::vector<std::pair<std::uint64_t, std::uint64_t>> expected = {
      {0x1020, 0x30}, {0x1050, 0x10}, {0x1060, 0x20},
      {0x1140, 0x0c}, {0x1150, 0x08}, {0x1160, 0x15}};
  ASSERT_EQ(result.value().functions.size(), expected.size());
  for (std::size_t i = 0; i < expected.size(); ++i) {
    EXPECT_EQ(result.value().functions[i].start, expected[i].first);
    EXPECT_EQ(result.value().functions[i].size, expected[i].second);
  }
  EXPECT_EQ(result.value().malformed_records, 0U);
}
