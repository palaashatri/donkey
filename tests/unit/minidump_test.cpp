#include <gtest/gtest.h>

#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "donkey/binary/minidump.h"

namespace {

std::string fixture(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/minidump/" + name;
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

const std::uint64_t* register_value(const donkey::MinidumpThread& thread, const std::string& name) {
  for (const auto& [register_name, value] : thread.registers) {
    if (register_name == name) {
      return &value;
    }
  }
  return nullptr;
}

}  // namespace

// The threads of tests/fixtures/minidump/make_sample_minidump.py: their ids, stacks, and the
// registers their contexts hold. The instruction and stack pointers come from the context.
TEST(MinidumpReader, ReadsTheThreadsAndTheirRegisters) {
  const auto file = read_file(fixture("sample.dmp"));
  auto result = donkey::read_minidump(file);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().code;
  const donkey::MinidumpInfo& info = result.value();
  EXPECT_FALSE(info.partial);
  EXPECT_EQ(info.processor_architecture, 9U);
  EXPECT_EQ(info.architecture_name(), "x86-64");
  EXPECT_EQ(info.major_version, 10U);
  EXPECT_EQ(info.build_number, 22621U);

  ASSERT_EQ(info.threads.size(), 2U);
  const donkey::MinidumpThread& first = info.threads[0];
  EXPECT_EQ(first.id, 0x1234U);
  EXPECT_EQ(first.stack_start, 0x7FFE00000000U);
  EXPECT_EQ(first.stack_size, 0x1000U);
  EXPECT_EQ(first.pc, 0x140001000U);
  EXPECT_EQ(first.sp, 0x7FFE00000F00U);
  const std::uint64_t* rax = register_value(first, "rax");
  ASSERT_NE(rax, nullptr);
  EXPECT_EQ(*rax, 0x1111U);
  const std::uint64_t* r15 = register_value(first, "r15");
  ASSERT_NE(r15, nullptr);
  EXPECT_EQ(*r15, 0xFEDCBA9876543210U);
  EXPECT_EQ(first.registers.size(), 18U);  // the registers the reader names, in context order

  const donkey::MinidumpThread& second = info.threads[1];
  EXPECT_EQ(second.id, 0x1235U);
  EXPECT_EQ(second.pc, 0x7FF800012340U);
  EXPECT_EQ(second.sp, 0x7FFE00011FF0U);
}

// The modules, with their base, size, timestamp and checksum. The second name is written in
// UTF-16 and is read as UTF-8, so its first letter is two bytes.
TEST(MinidumpReader, ReadsTheModulesAndTheirNames) {
  const auto file = read_file(fixture("sample.dmp"));
  auto result = donkey::read_minidump(file);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().code;
  const donkey::MinidumpInfo& info = result.value();
  ASSERT_EQ(info.modules.size(), 2U);
  EXPECT_EQ(info.modules[0].name, "C:\\build\\sample.exe");
  EXPECT_EQ(info.modules[0].base, 0x140000000U);
  EXPECT_EQ(info.modules[0].size, 0x4000U);
  EXPECT_EQ(info.modules[0].timestamp, 0x65000000U);
  EXPECT_EQ(info.modules[0].checksum, 0x1A2BU);
  EXPECT_EQ(info.modules[1].name, "\xc3\x9cnicode.dll");
  EXPECT_EQ(info.modules[1].base, 0x7FF800000000U);
  EXPECT_EQ(info.modules[1].size, 0x200000U);
}

// The memory ranges (the 64-bit list), the exception, and the bytes of each range by address.
TEST(MinidumpReader, ReadsTheMemoryRangesTheExceptionAndTheirBytes) {
  const auto file = read_file(fixture("sample.dmp"));
  auto result = donkey::read_minidump(file);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().code;
  const donkey::MinidumpInfo& info = result.value();
  ASSERT_EQ(info.memory.size(), 2U);
  EXPECT_EQ(info.memory[0].address, 0x140001000U);
  EXPECT_EQ(info.memory[0].size, 256U);
  EXPECT_EQ(info.memory[1].address, 0x7FFE00000F00U);
  EXPECT_EQ(info.memory[1].size, 0x40U);

  ASSERT_TRUE(info.has_exception);
  EXPECT_EQ(info.exception.thread_id, 0x1234U);
  EXPECT_EQ(info.exception.code, 0xC0000005U);
  EXPECT_EQ(info.exception.address, 0x140001010U);

  auto inside = donkey::read_minidump_memory(file, info, 0x140001010, 4);
  ASSERT_TRUE(inside.has_value()) << inside.diagnostic().code;
  ASSERT_EQ(inside.value().size(), 4U);
  EXPECT_EQ(inside.value()[0], std::byte{0x10});
  EXPECT_EQ(inside.value()[3], std::byte{0x13});

  auto stack = donkey::read_minidump_memory(file, info, 0x7FFE00000F00, 0x40);
  ASSERT_TRUE(stack.has_value()) << stack.diagnostic().code;
  for (const std::byte value : stack.value()) {
    EXPECT_EQ(value, std::byte{0xAB});
  }

  // Memory the dump does not hold is absent, and a read that runs past the end of a range is
  // refused too: it is not a shorter read of the bytes that are there.
  auto absent = donkey::read_minidump_memory(file, info, 0x200000, 4);
  ASSERT_FALSE(absent.has_value());
  EXPECT_EQ(absent.diagnostic().code, "minidump.memory_absent");
  auto past_end = donkey::read_minidump_memory(file, info, 0x140001000 + 254, 4);
  ASSERT_FALSE(past_end.has_value());
  EXPECT_EQ(past_end.diagnostic().code, "minidump.memory_absent");
}

TEST(MinidumpReader, ANonMinidumpIsRejectedWithItsCode) {
  const auto file = read_file(fixture("sample.dmp"));
  std::vector<std::byte> not_a_dump = file;
  ASSERT_GE(not_a_dump.size(), 4U);
  not_a_dump[0] = std::byte{'X'};
  EXPECT_FALSE(donkey::is_minidump(not_a_dump));
  auto result = donkey::read_minidump(not_a_dump);
  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.diagnostic().code, "minidump.not_a_minidump");
}

// A directory that is not inside the file is an error, not a read of whatever bytes are there.
TEST(MinidumpReader, ATruncatedFileHasNoReadableDirectory) {
  const auto file = read_file(fixture("sample.dmp"));
  const std::vector<std::byte> cut(file.begin(), file.begin() + 40);
  auto result = donkey::read_minidump(cut);
  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.diagnostic().code, "minidump.bad_directory");
}

// A stream whose bytes run past the end of the file is reported and skipped: the other streams
// are still read, and the result is partial rather than wrong.
TEST(MinidumpReader, AStreamPastTheFileIsReportedAndSkipped) {
  const auto file = read_file(fixture("sample.dmp"));
  std::vector<std::byte> damaged = file;
  // The module list is the third directory entry (index 2); its rva is the last word of the entry.
  const std::size_t entry = 32 + 12 * 2;
  const std::uint32_t past = static_cast<std::uint32_t>(file.size() + 100);
  for (int i = 0; i < 4; ++i) {
    damaged[entry + 8 + static_cast<std::size_t>(i)] =
        static_cast<std::byte>((past >> (8 * i)) & 0xffU);
  }
  auto result = donkey::read_minidump(damaged);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().code;
  EXPECT_TRUE(result.value().partial);
  EXPECT_TRUE(result.value().modules.empty());
  ASSERT_FALSE(result.value().diagnostics.empty());
  EXPECT_EQ(result.value().diagnostics[0].code, "minidump.stream_out_of_range");
  EXPECT_EQ(result.value().threads.size(), 2U);  // the streams before it are kept
}
