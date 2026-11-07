#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include "donkey/binary/debug_info.h"
#include "donkey/binary/image.h"
#include "donkey/binary/separate_debug.h"

namespace {

std::string fixture(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/compress/" + name;
}

bool ends_with(const std::string& text, const std::string& suffix) {
  return text.size() >= suffix.size() &&
         text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
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
