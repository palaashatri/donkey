// LC_FUNCTION_STARTS (G23-T3): the reader against llvm-objdump's list for the stripped fixtures,
// its refusals, and the seeds the analysis takes from it. Fixtures and oracle:
// tests/fixtures/function_starts/PROVENANCE.md.

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/function_starts.h"
#include "donkey/binary/image.h"
#include "donkey/binary/isolation.h"

namespace {

std::string fixture(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/function_starts/" + name;
}

std::vector<std::byte> bytes(std::initializer_list<int> values) {
  std::vector<std::byte> out;
  for (const int value : values) {
    out.push_back(static_cast<std::byte>(value));
  }
  return out;
}

}  // namespace

// `llvm-objdump --macho --function-starts` lists four starts in each stripped fixture.
TEST(FunctionStarts, MatchTheOracle) {
  const std::vector<std::pair<std::string, std::vector<std::uint64_t>>> expected = {
      {"starts_x86_64", {0x1000003b0, 0x1000003c0, 0x1000003d0, 0x1000003f0}},
      {"starts_arm64", {0x100000360, 0x100000368, 0x100000370, 0x100000388}},
  };
  for (const auto& [name, starts] : expected) {
    auto loaded = donkey::load_binary(fixture(name));
    ASSERT_TRUE(loaded.has_value()) << name << ": " << loaded.diagnostic().message;
    EXPECT_NE(loaded.value().image.function_starts_size, 0U) << name;
    auto read = donkey::read_function_starts_of_image(loaded.value().image, loaded.value().data);
    ASSERT_TRUE(read.has_value()) << name << ": " << read.diagnostic().message;
    EXPECT_EQ(read.value(), starts) << name;
  }
}

TEST(FunctionStarts, AnImageWithoutATableHasNoStarts) {
  auto loaded = donkey::load_binary(std::string(DONKEY_FIXTURE_DIR) + "/binaries/tiny-macho-arm64");
  ASSERT_TRUE(loaded.has_value());
  EXPECT_EQ(loaded.value().image.function_starts_size, 0U);
  auto read = donkey::read_function_starts_of_image(loaded.value().image, loaded.value().data);
  ASSERT_TRUE(read.has_value());
  EXPECT_TRUE(read.value().empty());
}

TEST(FunctionStarts, DecodesDeltasAndStopsAtZero) {
  // 0x3b0 (two bytes), 0x10, 0x20, then the end and padding that is not read.
  const auto table = bytes({0xb0, 0x07, 0x10, 0x20, 0x00, 0x7f, 0x7f});
  auto read = donkey::read_function_starts(table, 0x1000, 0x1000, false);
  ASSERT_TRUE(read.has_value()) << read.diagnostic().message;
  EXPECT_EQ(read.value(), (std::vector<std::uint64_t>{0x13b0, 0x13c0, 0x13e0}));
  // Thumb starts lose their low bit.
  auto thumb = donkey::read_function_starts(bytes({0x81, 0x02, 0x04, 0x00}), 0x1000, 0x1000, true);
  ASSERT_TRUE(thumb.has_value());
  EXPECT_EQ(thumb.value(), (std::vector<std::uint64_t>{0x1100, 0x1104}));
}

// The range is half open: a start at the end of __TEXT is outside it, and an address that would
// wrap past the top of the address space is refused, not taken modulo 2^64.
TEST(FunctionStarts, RefusesTheEndOfTextAndAWrappingAddress) {
  auto at_end = donkey::read_function_starts(bytes({0x10, 0x00}), 0x1000, 0x10, false);
  ASSERT_FALSE(at_end.has_value());
  EXPECT_EQ(at_end.diagnostic().code, "function_starts.outside_text");
  auto last = donkey::read_function_starts(bytes({0x0f, 0x00}), 0x1000, 0x10, false);
  ASSERT_TRUE(last.has_value()) << last.diagnostic().message;
  EXPECT_EQ(last.value(), (std::vector<std::uint64_t>{0x100f}));
  auto wraps =
      donkey::read_function_starts(bytes({0x10, 0x00}), 0xfffffffffffffff8ULL, 0x20, false);
  ASSERT_FALSE(wraps.has_value());
  EXPECT_EQ(wraps.diagnostic().code, "function_starts.outside_text");
}

TEST(FunctionStarts, RefusesBrokenTables) {
  // A ULEB128 longer than 10 bytes.
  auto long_uleb = donkey::read_function_starts(
      bytes({0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}), 0x1000, 0x1000,
      false);
  ASSERT_FALSE(long_uleb.has_value());
  EXPECT_EQ(long_uleb.diagnostic().code, "function_starts.bad_uleb128");
  // A tenth byte with bits past 64.
  auto wide = donkey::read_function_starts(
      bytes({0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02}), 0x1000, 0x1000, false);
  ASSERT_FALSE(wide.has_value());
  EXPECT_EQ(wide.diagnostic().code, "function_starts.bad_uleb128");
  // The data ends inside a delta.
  auto cut = donkey::read_function_starts(bytes({0x10, 0x80}), 0x1000, 0x1000, false);
  ASSERT_FALSE(cut.has_value());
  EXPECT_EQ(cut.diagnostic().code, "function_starts.bad_uleb128");
  // A start past __TEXT: 0x800 + 0x900 > 0x1000.
  auto outside =
      donkey::read_function_starts(bytes({0x80, 0x10, 0x80, 0x12}), 0x1000, 0x1000, false);
  ASSERT_FALSE(outside.has_value());
  EXPECT_EQ(outside.diagnostic().code, "function_starts.outside_text");
  // More starts than the limit.
  auto many = donkey::read_function_starts(bytes({0x01, 0x01, 0x01}), 0x1000, 0x1000, false, 2);
  ASSERT_FALSE(many.has_value());
  EXPECT_EQ(many.diagnostic().code, "function_starts.too_many");
}

// The loader refuses a table that lies outside the file: the fixture with the table's size raised
// past the end.
TEST(FunctionStarts, LoaderRefusesATableOutsideTheFile) {
  auto loaded = donkey::load_binary(fixture("starts_x86_64"));
  ASSERT_TRUE(loaded.has_value());
  std::vector<std::byte> data(loaded.value().data.begin(), loaded.value().data.end());
  // Find LC_FUNCTION_STARTS (0x26) among the load commands and give it a huge datasize.
  const auto u32 = [&](std::size_t at) {
    std::uint32_t value = 0;
    for (int byte = 3; byte >= 0; --byte) {
      value =
          (value << 8U) | std::to_integer<std::uint32_t>(data[at + static_cast<std::size_t>(byte)]);
    }
    return value;
  };
  std::size_t at = 32;
  const std::uint32_t commands = u32(16);
  bool patched = false;
  for (std::uint32_t i = 0; i < commands; ++i) {
    if (u32(at) == 0x26) {
      data[at + 15] = std::byte{0x7f};
      patched = true;
      break;
    }
    at += u32(at + 4);
  }
  ASSERT_TRUE(patched);
  auto refused = donkey::parse_binary(data, "starts_x86_64");
  ASSERT_FALSE(refused.has_value());
  EXPECT_EQ(refused.diagnostic().code, "macho.bad_function_starts");
}

namespace {

std::uint32_t le32(const std::vector<std::byte>& data, std::size_t at) {
  if (data.size() < 4 || at > data.size() - 4) {
    ADD_FAILURE() << "read past the end at " << at;
    return 0;
  }
  std::uint32_t value = 0;
  for (int byte = 3; byte >= 0; --byte) {
    value =
        (value << 8U) | std::to_integer<std::uint32_t>(data[at + static_cast<std::size_t>(byte)]);
  }
  return value;
}

void put_be32(std::vector<std::byte>& data, std::size_t at, std::uint32_t value) {
  if (data.size() < 4 || at > data.size() - 4) {
    ADD_FAILURE() << "write past the end at " << at;
    return;
  }
  for (int byte = 0; byte < 4; ++byte) {
    data[at + static_cast<std::size_t>(byte)] =
        static_cast<std::byte>((value >> (24U - 8U * static_cast<unsigned>(byte))) & 0xffU);
  }
}

}  // namespace

// A second LC_FUNCTION_STARTS is refused: the fixture with another linkedit_data command (16
// bytes: LC_CODE_SIGNATURE, LC_DATA_IN_CODE, LC_DYLD_EXPORTS_TRIE or LC_DYLD_CHAINED_FIXUPS)
// relabelled as one.
TEST(FunctionStarts, LoaderRefusesASecondTable) {
  for (const std::string name : {"starts_x86_64", "starts_arm64"}) {
    auto loaded = donkey::load_binary(fixture(name));
    ASSERT_TRUE(loaded.has_value());
    std::vector<std::byte> data(loaded.value().data.begin(), loaded.value().data.end());
    std::size_t at = 32;
    const std::uint32_t commands = le32(data, 16);
    bool patched = false;
    for (std::uint32_t i = 0; i < commands; ++i) {
      const std::uint32_t command = le32(data, at);
      if (le32(data, at + 4) == 16 && (command == 0x1d || command == 0x29 ||
                                       command == 0x80000033U || command == 0x80000034U)) {
        data[at] = std::byte{0x26};
        data[at + 1] = std::byte{0};
        data[at + 2] = std::byte{0};
        data[at + 3] = std::byte{0};
        patched = true;
        break;
      }
      at += le32(data, at + 4);
    }
    ASSERT_TRUE(patched) << name;
    auto refused = donkey::parse_binary(data, name);
    ASSERT_FALSE(refused.has_value()) << name;
    EXPECT_EQ(refused.diagnostic().code, "macho.bad_function_starts") << name;
    EXPECT_NE(refused.diagnostic().message.find("second"), std::string::npos)
        << refused.diagnostic().message;
  }
}

// In a fat file the table's offset is relative to its slice: the x86-64 fixture wrapped in a fat
// header, its slice at 0x1000, gives the same starts as the thin file.
TEST(FunctionStarts, AFatSliceGivesTheSameStartsAsTheThinFile) {
  auto thin = donkey::load_binary(fixture("starts_x86_64"));
  ASSERT_TRUE(thin.has_value());
  const auto& thin_data = thin.value().data;
  auto thin_starts = donkey::read_function_starts_of_image(thin.value().image, thin_data);
  ASSERT_TRUE(thin_starts.has_value());
  ASSERT_EQ(thin_starts.value().size(), 4U);

  constexpr std::size_t kSlice = 0x1000;
  std::vector<std::byte> fat(kSlice, std::byte{0});
  put_be32(fat, 0, 0xCAFEBABEU);
  put_be32(fat, 4, 1);            // one architecture
  put_be32(fat, 8, 0x01000007U);  // CPU_TYPE_X86_64
  put_be32(fat, 12, 3);           // CPU_SUBTYPE_X86_64_ALL
  put_be32(fat, 16, static_cast<std::uint32_t>(kSlice));
  put_be32(fat, 20, static_cast<std::uint32_t>(thin_data.size()));
  put_be32(fat, 24, 12);  // 2^12 alignment
  fat.insert(fat.end(), thin_data.begin(), thin_data.end());

  auto image = donkey::parse_binary(fat, "starts_x86_64.fat");
  ASSERT_TRUE(image.has_value()) << image.diagnostic().message;
  EXPECT_EQ(image.value().function_starts_offset,
            thin.value().image.function_starts_offset + kSlice);
  auto fat_starts = donkey::read_function_starts_of_image(image.value(), fat);
  ASSERT_TRUE(fat_starts.has_value()) << fat_starts.diagnostic().message;
  EXPECT_EQ(fat_starts.value(), thin_starts.value());
}

// An isolated load gives the parent the table's place in the file, as a direct load does.
TEST(FunctionStarts, AnIsolatedLoadGivesTheSameStarts) {
  if (!donkey::process_isolation_available()) {
    GTEST_SKIP() << "OS process isolation not supported on this platform";
  }
  auto direct = donkey::load_binary(fixture("starts_x86_64"));
  ASSERT_TRUE(direct.has_value()) << direct.diagnostic().message;
  auto isolated = donkey::load_binary_isolated(fixture("starts_x86_64"));
  ASSERT_TRUE(isolated.has_value()) << isolated.diagnostic().message;
  EXPECT_EQ(isolated.value().image.function_starts_offset,
            direct.value().image.function_starts_offset);
  EXPECT_EQ(isolated.value().image.function_starts_size, direct.value().image.function_starts_size);
  auto direct_starts =
      donkey::read_function_starts_of_image(direct.value().image, direct.value().data);
  auto isolated_starts =
      donkey::read_function_starts_of_image(isolated.value().image, isolated.value().data);
  ASSERT_TRUE(direct_starts.has_value());
  ASSERT_TRUE(isolated_starts.has_value()) << isolated_starts.diagnostic().message;
  EXPECT_EQ(isolated_starts.value().size(), 4U);
  EXPECT_EQ(isolated_starts.value(), direct_starts.value());
}

// Stripped, the image names only its entry point; the table gives the other three functions, each
// marked with its provenance.
TEST(Analysis, MachOFunctionStartsSeedAStrippedBinary) {
  for (const std::string name : {"starts_x86_64", "starts_arm64"}) {
    auto loaded = donkey::load_binary(fixture(name));
    ASSERT_TRUE(loaded.has_value());
    auto analysis = donkey::analyze(loaded.value().image, loaded.value().data);
    ASSERT_TRUE(analysis.has_value()) << analysis.diagnostic().message;
    auto starts = donkey::read_function_starts_of_image(loaded.value().image, loaded.value().data);
    ASSERT_TRUE(starts.has_value());
    for (const std::uint64_t start : starts.value()) {
      const auto& functions = analysis.value().functions;
      const auto found =
          std::find_if(functions.begin(), functions.end(),
                       [&](const donkey::Function& f) { return f.address == start; });
      ASSERT_NE(found, functions.end()) << name << " " << std::hex << start;
      EXPECT_TRUE(found->from_function_starts) << name << " " << std::hex << start;
    }
  }
}

// The Mach-O header at the start of __TEXT lies in the executable segment but in no section. The
// exported `__mh_execute_header` symbol names it; it is a header, not a function.
TEST(Analysis, TheMachOHeaderIsNotAFunction) {
  for (const std::string& path : {fixture("starts_x86_64"), fixture("starts_arm64"),
                                  std::string(DONKEY_FIXTURE_DIR) + "/dsym/dbg"}) {
    auto loaded = donkey::load_binary(path);
    ASSERT_TRUE(loaded.has_value()) << path;
    const auto& symbols = loaded.value().image.symbols;
    const auto header = std::find_if(symbols.begin(), symbols.end(), [](const donkey::Symbol& s) {
      return s.name == "__mh_execute_header";
    });
    ASSERT_NE(header, symbols.end()) << path;
    auto analysis = donkey::analyze(loaded.value().image, loaded.value().data);
    ASSERT_TRUE(analysis.has_value()) << analysis.diagnostic().message;
    for (const donkey::Function& function : analysis.value().functions) {
      EXPECT_NE(function.address, header->address) << path << " " << function.name;
    }
  }
}
