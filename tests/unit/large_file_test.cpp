// Memory-budget tests for large inputs (M10, A24). A real ELF fixture is
// extended to the target size (sparse where the file system allows it), then
// loaded and analysed. The budget is on anonymous (heap) memory: mapped file
// pages are clean, file-backed and reclaimable, so they are reported but not
// counted against the budget.
//
// Built twice: donkey_unit_tests runs the 100 MiB case; donkey_large_tests
// (Release builds only) also runs 1 GiB, which takes tens of seconds in a
// Debug build.

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// clang-format off
#include <psapi.h>
// clang-format on
#elif defined(__APPLE__)
#include <mach/mach.h>
#include <unistd.h>
#else
#include <unistd.h>
#endif

namespace {

/// Bytes of memory this process owns that are not backed by a file: Linux
/// RssAnon, macOS physical footprint, Windows private commit.
std::optional<std::uint64_t> anonymous_bytes() {
#if defined(__linux__)
  std::ifstream status("/proc/self/status");
  std::string key;
  while (status >> key) {
    if (key == "RssAnon:") {
      std::uint64_t kib = 0;
      status >> kib;
      return kib * 1024;
    }
    std::string rest;
    std::getline(status, rest);
  }
  return std::nullopt;
#elif defined(__APPLE__)
  task_vm_info_data_t info{};
  mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
  if (task_info(mach_task_self(), TASK_VM_INFO, reinterpret_cast<task_info_t>(&info), &count) !=
      KERN_SUCCESS) {
    return std::nullopt;
  }
  return info.phys_footprint;
#elif defined(_WIN32)
  PROCESS_MEMORY_COUNTERS_EX counters{};
  if (!GetProcessMemoryInfo(GetCurrentProcess(),
                            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters),
                            sizeof(counters))) {
    return std::nullopt;
  }
  return counters.PrivateUsage;
#else
  return std::nullopt;
#endif
}

const char* host_name() {
#if defined(__linux__)
  return "Linux";
#elif defined(__APPLE__)
  return "macOS";
#elif defined(_WIN32)
  return "Windows";
#elif defined(__FreeBSD__)
  return "FreeBSD";
#else
  return "unknown";
#endif
}

std::string make_large_image(std::uint64_t size) {
  const auto path =
      (std::filesystem::temp_directory_path() /
       ("donkey-large-" + std::to_string(size) + "-" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".elf"))
          .string();
  std::filesystem::copy_file(std::string(DONKEY_FIXTURE_DIR) + "/binaries/tiny-elf-x86_64", path,
                             std::filesystem::copy_options::overwrite_existing);
  std::filesystem::resize_file(path, size);
  return path;
}

/// Load and analyse an image of `size` bytes and check the anonymous-memory
/// budget. Prints one measurement record line for the CI log.
void check_budget(std::uint64_t size, std::uint64_t budget) {
  const std::string path = make_large_image(size);
  const auto before = anonymous_bytes();
  if (!before) {
    std::filesystem::remove(path);
    GTEST_SKIP() << "no anonymous-memory counter on " << host_name();
  }
  std::uint64_t peak = *before;
  std::uint64_t progress_done = 0;
  std::uint64_t progress_total = 0;
  const auto started = std::chrono::steady_clock::now();
  {
    donkey::LoadOptions options;
    options.progress = [&](std::uint64_t done, std::uint64_t total) {
      progress_done = done;
      progress_total = total;
      if (auto now = anonymous_bytes()) {
        peak = std::max(peak, *now);
      }
    };
    auto loaded = donkey::load_binary(path, options);
    ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
    EXPECT_TRUE(loaded.value().data.mapped());
    EXPECT_EQ(loaded.value().data.size(), size);
    EXPECT_EQ(loaded.value().image.file_size, size);
    auto analysis = donkey::analyze(loaded.value().image, loaded.value().data);
    ASSERT_TRUE(analysis.has_value()) << analysis.diagnostic().message;
    EXPECT_FALSE(analysis.value().instructions.empty());
    if (auto now = anonymous_bytes()) {
      peak = std::max(peak, *now);
    }
  }
  const double seconds =
      std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
  std::filesystem::remove(path);

  EXPECT_EQ(progress_total, size);
  EXPECT_EQ(progress_done, size);
  const std::uint64_t growth = peak > *before ? peak - *before : 0;
  std::printf(
      "[measurement] host=%s file_bytes=%llu seconds=%.2f anonymous_growth_bytes=%llu "
      "budget_bytes=%llu\n",
      host_name(), static_cast<unsigned long long>(size), seconds,
      static_cast<unsigned long long>(growth), static_cast<unsigned long long>(budget));
  EXPECT_LT(growth, budget) << "loading and analysing a " << size
                            << "-byte file allocated too much";
}

TEST(LargeFile, Mapped100MiBImageStaysWithinMemoryBudget) {
  check_budget(100ULL << 20, 48ULL << 20);
}

#if defined(DONKEY_LARGE_FILE_TESTS)
TEST(LargeFile, Mapped1GiBImageStaysWithinMemoryBudget) {
  check_budget(1ULL << 30, 48ULL << 20);
}
#endif

TEST(LargeFile, SmallFilesAreReadIntoMemory) {
  auto loaded = donkey::load_binary(std::string(DONKEY_FIXTURE_DIR) + "/binaries/tiny-elf-x86_64");
  ASSERT_TRUE(loaded.has_value());
  EXPECT_FALSE(loaded.value().data.mapped());
}

TEST(LargeFile, OversizedFilesAreRejectedBeforeAnyAllocation) {
  const std::string path = make_large_image(8ULL << 20);
  donkey::LoadOptions options;
  options.max_file_bytes = 4ULL << 20;
  auto loaded = donkey::load_binary(path, options);
  std::filesystem::remove(path);
  ASSERT_FALSE(loaded.has_value());
  EXPECT_EQ(loaded.diagnostic().code, "io.file_too_large");
}

}  // namespace
