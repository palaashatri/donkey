#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "donkey/binary/debug_info.h"
#include "donkey/binary/image.h"
#include "donkey/binary/separate_debug.h"

namespace {

std::string fixture(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/compress/" + name;
}

std::string dsym_fixture(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/dsym/" + name;
}

// Windows reports paths with '\' separators; the suffixes used here are written with '/'.
bool ends_with(const std::string& text, const std::string& suffix) {
  std::string normalized = text;
  std::replace(normalized.begin(), normalized.end(), '\\', '/');
  return normalized.size() >= suffix.size() &&
         normalized.compare(normalized.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::vector<std::byte> read_all(const std::filesystem::path& path) {
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

void write_all(const std::filesystem::path& path, const std::vector<std::byte>& bytes) {
  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  for (const std::byte value : bytes) {
    file.put(static_cast<char>(value));
  }
}

}  // namespace

// The CRC-32 of the standard check string is the value every CRC-32 implementation gives.
TEST(SeparateDebug, Crc32MatchesTheStandardCheckValue) {
  const std::string check = "123456789";
  std::vector<std::byte> bytes;
  for (const char c : check) {
    bytes.push_back(static_cast<std::byte>(c));
  }
  EXPECT_EQ(donkey::gnu_crc32(bytes), 0xCBF43926U);
}

// The debuglink route: the stripped binary names dwarf-plain.debug, which sits beside it. Its
// CRC-32 is the one objcopy stored, so the file is accepted and reads the same functions.
TEST(SeparateDebug, DebugLinkFindsTheFileBesideTheBinary) {
  auto stripped = donkey::load_binary(fixture("stripped-debuglink.elf"));
  ASSERT_TRUE(stripped.has_value()) << stripped.diagnostic().message;
  auto none = donkey::read_debug_info(stripped.value().image, stripped.value().data);
  EXPECT_FALSE(none.has_value());  // the binary itself has no DWARF

  auto found = donkey::find_separate_debug_file(stripped.value().image, stripped.value().data,
                                                fixture("stripped-debuglink.elf"));
  ASSERT_TRUE(found.has_value()) << found.diagnostic().code << ": " << found.diagnostic().message;
  EXPECT_TRUE(ends_with(found.value(), "/dwarf-plain.debug")) << found.value();

  auto debug = donkey::load_binary(found.value());
  ASSERT_TRUE(debug.has_value()) << debug.diagnostic().message;
  auto info = donkey::read_debug_info(debug.value().image, debug.value().data);
  ASSERT_TRUE(info.has_value()) << info.diagnostic().code;
  bool has_entry = false;
  for (const donkey::DebugFunction& function : info.value().functions) {
    if (function.name == "sample_entry") {
      has_entry = true;
    }
  }
  EXPECT_TRUE(has_entry);
}

// The build-id route: the binary's build id names the file in the debug directory's tree.
TEST(SeparateDebug, BuildIdFindsTheFileInTheDebugTree) {
  auto stripped = donkey::load_binary(fixture("stripped-buildid.elf"));
  ASSERT_TRUE(stripped.has_value()) << stripped.diagnostic().message;
  EXPECT_EQ(donkey::build_id_hex(stripped.value().image, stripped.value().data),
            "50ecf7656faf58fb7c4dc466e4d17a79ff0d318d");

  donkey::SeparateDebugOptions options;
  options.debug_directories = {fixture("debug")};
  auto found = donkey::find_separate_debug_file(stripped.value().image, stripped.value().data,
                                                fixture("stripped-buildid.elf"), options);
  ASSERT_TRUE(found.has_value()) << found.diagnostic().code << ": " << found.diagnostic().message;
  EXPECT_TRUE(
      ends_with(found.value(), "/.build-id/50/ecf7656faf58fb7c4dc466e4d17a79ff0d318d.debug"))
      << found.value();
}

// A file the link names that is not the one it was made from is refused with a code, and no
// debug information is taken from it.
TEST(SeparateDebug, AFileWithAnotherCrcIsRefused) {
  auto stripped = donkey::load_binary(fixture("bogus/stripped-bogus.elf"));
  ASSERT_TRUE(stripped.has_value()) << stripped.diagnostic().message;
  auto found = donkey::find_separate_debug_file(stripped.value().image, stripped.value().data,
                                                fixture("bogus/stripped-bogus.elf"));
  ASSERT_FALSE(found.has_value());
  EXPECT_EQ(found.diagnostic().code, "debug.crc");
}

// Neither a build-id nor a debuglink: nothing to look for. (Ubuntu's linker adds a build-id by
// default, so dwarf-plain.elf has one and is not this case.)
TEST(SeparateDebug, ABinaryWithNoLinkNamesNoFile) {
  const std::string path = std::string(DONKEY_FIXTURE_DIR) + "/binaries/tiny-elf-x86_64";
  auto plain = donkey::load_binary(path);
  ASSERT_TRUE(plain.has_value()) << plain.diagnostic().message;
  auto found = donkey::find_separate_debug_file(plain.value().image, plain.value().data, path);
  ASSERT_FALSE(found.has_value());
  EXPECT_EQ(found.diagnostic().code, "debug.no_link");
}

TEST(SeparateDebug, AMissingFileIsNotFoundNotGuessed) {
  auto stripped = donkey::load_binary(fixture("stripped-buildid.elf"));
  ASSERT_TRUE(stripped.has_value());
  donkey::SeparateDebugOptions options;
  options.debug_directories = {"/nonexistent/donkey-test-debug"};
  auto found = donkey::find_separate_debug_file(stripped.value().image, stripped.value().data,
                                                fixture("stripped-buildid.elf"), options);
  ASSERT_FALSE(found.has_value());
  EXPECT_EQ(found.diagnostic().code, "debug.not_found");
}

// The Mach-O route (G07-T2): the executable's LC_UUID names the .dSYM bundle beside it. The
// bundle's DWARF file carries the same UUID, so it is accepted, and it reads the source's
// functions.
TEST(SeparateDebug, DsymFindsTheBundleWhoseUuidMatches) {
  auto binary = donkey::load_binary(dsym_fixture("dbg"));
  ASSERT_TRUE(binary.has_value()) << binary.diagnostic().message;
  EXPECT_EQ(binary.value().image.format, donkey::BinaryFormat::MachO);
  EXPECT_EQ(binary.value().image.uuid, "4c4c442755553144a16f211e69eacde5");
  auto none = donkey::read_debug_info(binary.value().image, binary.value().data);
  EXPECT_FALSE(none.has_value());  // dsymutil moved the DWARF out of the executable

  auto found = donkey::find_separate_debug_file(binary.value().image, binary.value().data,
                                                dsym_fixture("dbg"));
  ASSERT_TRUE(found.has_value()) << found.diagnostic().code << ": " << found.diagnostic().message;
  EXPECT_TRUE(ends_with(found.value(), "/dbg.dSYM/Contents/Resources/DWARF/dbg")) << found.value();

  auto debug = donkey::load_binary(found.value());
  ASSERT_TRUE(debug.has_value()) << debug.diagnostic().message;
  auto info = donkey::read_debug_info(debug.value().image, debug.value().data);
  ASSERT_TRUE(info.has_value()) << info.diagnostic().code;
  bool has_add = false;
  for (const donkey::DebugFunction& function : info.value().functions) {
    if (function.name == "add") {
      has_add = true;
    }
  }
  EXPECT_TRUE(has_add);
}

// A .dSYM whose UUID is not the executable's is refused, never used. The copy changes the last
// byte of the UUID in the bundle's DWARF file, so the bundle stays readable but names another
// build.
TEST(SeparateDebug, ADsymWithAnotherUuidIsRefused) {
  namespace fs = std::filesystem;
  const fs::path dir = fs::temp_directory_path() / "donkey-dsym-uuid-test";
  fs::remove_all(dir);
  fs::create_directories(dir / "dbg.dSYM" / "Contents" / "Resources" / "DWARF");
  fs::copy_file(dsym_fixture("dbg"), dir / "dbg");
  std::vector<std::byte> dwarf = read_all(dsym_fixture("dbg.dSYM/Contents/Resources/DWARF/dbg"));
  const std::array<std::byte, 16> uuid = {
      std::byte{0x4c}, std::byte{0x4c}, std::byte{0x44}, std::byte{0x27},
      std::byte{0x55}, std::byte{0x55}, std::byte{0x31}, std::byte{0x44},
      std::byte{0xa1}, std::byte{0x6f}, std::byte{0x21}, std::byte{0x1e},
      std::byte{0x69}, std::byte{0xea}, std::byte{0xcd}, std::byte{0xe5}};
  const auto at = std::search(dwarf.begin(), dwarf.end(), uuid.begin(), uuid.end());
  ASSERT_NE(at, dwarf.end());
  *(at + 15) = std::byte{0x00};
  write_all(dir / "dbg.dSYM" / "Contents" / "Resources" / "DWARF" / "dbg", dwarf);

  auto binary = donkey::load_binary((dir / "dbg").string());
  ASSERT_TRUE(binary.has_value()) << binary.diagnostic().message;
  auto found = donkey::find_separate_debug_file(binary.value().image, binary.value().data,
                                                (dir / "dbg").string());
  ASSERT_FALSE(found.has_value());
  EXPECT_EQ(found.diagnostic().code, "debug.uuid");
  fs::remove_all(dir);
}

// Without the bundle the executable names no file, and nothing is guessed.
TEST(SeparateDebug, AMachOExecutableWithoutItsBundleIsNotFound) {
  namespace fs = std::filesystem;
  const fs::path dir = fs::temp_directory_path() / "donkey-dsym-missing-test";
  fs::remove_all(dir);
  fs::create_directories(dir);
  fs::copy_file(dsym_fixture("dbg"), dir / "dbg");
  auto binary = donkey::load_binary((dir / "dbg").string());
  ASSERT_TRUE(binary.has_value()) << binary.diagnostic().message;
  auto found = donkey::find_separate_debug_file(binary.value().image, binary.value().data,
                                                (dir / "dbg").string());
  ASSERT_FALSE(found.has_value());
  EXPECT_EQ(found.diagnostic().code, "debug.not_found");
  fs::remove_all(dir);
}
