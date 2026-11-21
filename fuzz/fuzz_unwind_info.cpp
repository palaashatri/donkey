// libFuzzer entry point for the Mach-O __unwind_info reader (G23-T3). The input is the bytes of one
// section. The harness asserts that the reader never crashes, that a rejection carries an
// `unwind_info.` code, and that every entry it returns lies in [image base, end), strictly
// ascending, and within the entry limit.
//
// Build: cmake -DDONKEY_BUILD_FUZZERS=ON with clang (see CMakeLists.txt)
// Run:   build/fuzz-clang/fuzz_unwind_info <scratch corpus copy> -max_total_time=60

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "donkey/binary/unwind_info.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  constexpr std::size_t kMaxFuzzInput = 1U << 20;
  if (size == 0 || size > kMaxFuzzInput) {
    return 0;
  }
  const std::span<const std::byte> section(reinterpret_cast<const std::byte*>(data), size);
  constexpr std::uint64_t kBase = 0x100000000;
  constexpr std::size_t kLimit = 4096;
  const auto result = donkey::read_unwind_info(section, kBase, donkey::Endian::Little, kLimit);
  if (!result) {
    if (result.diagnostic().code.rfind("unwind_info.", 0) != 0) {
      std::abort();
    }
    return 0;
  }
  const donkey::UnwindInfo& info = result.value();
  if (info.entries.size() > kLimit || (!info.entries.empty() && info.end == 0)) {
    std::abort();
  }
  std::uint64_t previous = 0;
  bool first = true;
  for (const donkey::UnwindInfoEntry& entry : info.entries) {
    if (entry.start < kBase || entry.start >= info.end || (!first && entry.start <= previous)) {
      std::abort();
    }
    previous = entry.start;
    first = false;
  }
  return 0;
}
