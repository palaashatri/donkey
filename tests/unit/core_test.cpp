#include <gtest/gtest.h>

#include <cstdint>
#include <span>
#include <string>

#include "donkey/binary/core.h"
#include "donkey/binary/image.h"

namespace {

std::string fixture(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/core/" + name;
}

}  // namespace

// The expected values were read from `gdb` on the same core (`info registers`, `info threads`,
// `info proc mappings`); see tests/fixtures/core/PROVENANCE.md.
TEST(Core, ReadsTheThreadAndTheMappingsOfAnX8664Core) {
  auto loaded = donkey::load_binary(fixture("sleeper.core"));
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  auto core = donkey::read_elf_core(loaded.value().image, loaded.value().data);
  ASSERT_TRUE(core.has_value()) << core.diagnostic().code;
  const donkey::CoreInfo& info = core.value();

  EXPECT_FALSE(info.partial);
  EXPECT_EQ(info.process_name, "sleeper");

  ASSERT_EQ(info.threads.size(), 1U);
  const donkey::CoreThread& thread = info.threads[0];
  EXPECT_EQ(thread.pid, 8251U);
  EXPECT_EQ(thread.pc, 0x4112f4U);  // pause+20, where the thread was parked
  EXPECT_EQ(thread.sp, 0x7ffc29d24f98ULL);
  bool found_rax = false;
  for (const auto& [name, value] : thread.registers) {
    if (name == "rax") {
      found_rax = true;
      EXPECT_EQ(value, 0xfffffffffffffdfeULL);  // -514, the value gdb printed
    }
  }
  EXPECT_TRUE(found_rax);
  EXPECT_EQ(thread.registers.size(), 27U);

  // gdb lists five file-backed mappings; the first is the program's first page.
  ASSERT_EQ(info.mappings.size(), 5U);
  EXPECT_EQ(info.mappings[0].start, 0x400000U);
  EXPECT_EQ(info.mappings[0].end, 0x401000U);
  EXPECT_EQ(info.mappings[0].file_offset, 0U);
  EXPECT_NE(info.mappings[0].path.find("sleeper"), std::string::npos) << info.mappings[0].path;
  EXPECT_EQ(info.mappings[1].file_offset, 0x1000U);  // offsets are stored in pages
}

TEST(Core, AnExecutableIsNotACore) {
  auto loaded = donkey::load_binary(std::string(DONKEY_FIXTURE_DIR) + "/binaries/tiny-elf-x86_64");
  ASSERT_TRUE(loaded.has_value());
  auto core = donkey::read_elf_core(loaded.value().image, loaded.value().data);
  ASSERT_FALSE(core.has_value());
  EXPECT_EQ(core.diagnostic().code, "core.not_a_core");
}

// A core cut off inside its notes keeps what was read and says what was lost: it is partial,
// and no thread or mapping is invented.
TEST(Core, ATruncatedCoreIsPartialAndBounded) {
  auto loaded = donkey::load_binary(fixture("sleeper.core"));
  ASSERT_TRUE(loaded.has_value());
  const auto& data = loaded.value().data;
  // Cut the file just inside the PT_NOTE segment (0x54238, 0x6794 bytes): it then runs past the
  // end.
  const std::span<const std::byte> cut(data.data(), 0x54238 + 0x200);
  auto core = donkey::read_elf_core(loaded.value().image, cut);
  ASSERT_TRUE(core.has_value()) << core.diagnostic().code;
  EXPECT_TRUE(core.value().partial);
  EXPECT_LE(core.value().threads.size(), 1U);
  EXPECT_LE(core.value().mappings.size(), 5U);
}

// The thread and mapping limits hold: nothing past them is read, and the result says so.
TEST(Core, ThreadAndMappingLimitsAreEnforced) {
  auto loaded = donkey::load_binary(fixture("sleeper.core"));
  ASSERT_TRUE(loaded.has_value());
  donkey::CoreOptions options;
  options.max_mappings = 1;
  auto core = donkey::read_elf_core(loaded.value().image, loaded.value().data, options);
  ASSERT_TRUE(core.has_value());
  EXPECT_TRUE(core.value().partial);
  EXPECT_LE(core.value().mappings.size(), 1U);
}
