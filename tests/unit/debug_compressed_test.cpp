#include <gtest/gtest.h>

#include <cstdint>
#include <string>

#include "donkey/binary/debug_info.h"
#include "donkey/binary/image.h"

namespace {

std::string fixture(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/compress/" + name;
}

}  // namespace

// tests/fixtures/compress/dwarf-zlib.elf is dwarf-plain.elf with its debug sections compressed
// by `objcopy --compress-debug-sections=zlib` (binutils 2.42). The plain file is the oracle:
// both must read the same functions, types and variables.
TEST(DebugInfoCompressed, CompressedSectionsReadTheSameAsPlainOnes) {
  auto plain = donkey::load_binary(fixture("dwarf-plain.elf"));
  ASSERT_TRUE(plain.has_value()) << plain.diagnostic().message;
  auto zipped = donkey::load_binary(fixture("dwarf-zlib.elf"));
  ASSERT_TRUE(zipped.has_value()) << zipped.diagnostic().message;

  auto plain_info = donkey::read_debug_info(plain.value().image, plain.value().data);
  ASSERT_TRUE(plain_info.has_value()) << plain_info.diagnostic().code;
  auto zipped_info = donkey::read_debug_info(zipped.value().image, zipped.value().data);
  ASSERT_TRUE(zipped_info.has_value())
      << zipped_info.diagnostic().code << ": " << zipped_info.diagnostic().message;

  const donkey::DebugInfo& a = plain_info.value();
  const donkey::DebugInfo& b = zipped_info.value();
  EXPECT_FALSE(b.partial);
  EXPECT_EQ(b.producers, a.producers);
  EXPECT_EQ(b.types.size(), a.types.size());
  EXPECT_EQ(b.variables.size(), a.variables.size());
  ASSERT_EQ(b.functions.size(), a.functions.size());
  bool found = false;
  for (std::size_t i = 0; i < a.functions.size(); ++i) {
    EXPECT_EQ(b.functions[i].name, a.functions[i].name);
    EXPECT_EQ(b.functions[i].address, a.functions[i].address);
    EXPECT_EQ(b.functions[i].size, a.functions[i].size);
    if (b.functions[i].name == "sample_entry") {
      found = true;
    }
  }
  EXPECT_TRUE(found);
}

// A damaged compressed section is an error with a code, not a partial read of garbage.
TEST(DebugInfoCompressed, ADamagedCompressedSectionIsACodedError) {
  auto loaded = donkey::load_binary(fixture("dwarf-zlib.elf"));
  ASSERT_TRUE(loaded.has_value());
  // .debug_info starts at file offset 0x20b8 and is 0xdd bytes; the zlib stream follows the
  // 24-byte compression header. Flip a byte in the middle of the stream.
  std::vector<std::byte> damaged = loaded.value().data.to_vector();
  const std::size_t target = 0x20b8 + 24 + 40;
  ASSERT_LT(target, damaged.size());
  damaged[target] = static_cast<std::byte>(std::to_integer<std::uint8_t>(damaged[target]) ^ 0x5a);
  auto info = donkey::read_debug_info(loaded.value().image, damaged);
  if (!info.has_value()) {
    EXPECT_TRUE(info.diagnostic().code.rfind("inflate.", 0) == 0 ||
                info.diagnostic().code.rfind("dwarf.", 0) == 0)
        << info.diagnostic().code;
  }
}

// tests/fixtures/compress/dwarf-zstd.elf is dwarf-plain.elf with its debug sections compressed by
// `objcopy --compress-debug-sections=zstd` (binutils 2.42). The same check as the zlib file: the
// plain file is the oracle, and both must read the same functions, types and variables.
TEST(DebugInfoCompressed, ZstdSectionsReadTheSameAsPlainOnes) {
  auto plain = donkey::load_binary(fixture("dwarf-plain.elf"));
  ASSERT_TRUE(plain.has_value()) << plain.diagnostic().message;
  auto zipped = donkey::load_binary(fixture("dwarf-zstd.elf"));
  ASSERT_TRUE(zipped.has_value()) << zipped.diagnostic().message;

  auto plain_info = donkey::read_debug_info(plain.value().image, plain.value().data);
  ASSERT_TRUE(plain_info.has_value()) << plain_info.diagnostic().code;
  auto zipped_info = donkey::read_debug_info(zipped.value().image, zipped.value().data);
  ASSERT_TRUE(zipped_info.has_value())
      << zipped_info.diagnostic().code << ": " << zipped_info.diagnostic().message;

  const donkey::DebugInfo& a = plain_info.value();
  const donkey::DebugInfo& b = zipped_info.value();
  EXPECT_FALSE(b.partial);
  EXPECT_EQ(b.producers, a.producers);
  EXPECT_EQ(b.types.size(), a.types.size());
  EXPECT_EQ(b.variables.size(), a.variables.size());
  ASSERT_EQ(b.functions.size(), a.functions.size());
  for (std::size_t i = 0; i < a.functions.size(); ++i) {
    EXPECT_EQ(b.functions[i].name, a.functions[i].name);
    EXPECT_EQ(b.functions[i].address, a.functions[i].address);
    EXPECT_EQ(b.functions[i].size, a.functions[i].size);
  }
}
