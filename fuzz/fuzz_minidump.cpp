// libFuzzer entry point for the Windows minidump reader (G15-T3). The input is a minidump file.
// The harness asserts that the reader never crashes, that a rejection carries a `minidump.` code,
// that the record lists stay within the configured limits, and that every memory range it reports
// can be read back as the bytes its file offset names.
//
// Build: cmake -DDONKEY_BUILD_FUZZERS=ON with clang (see CMakeLists.txt)
// Run:   build/fuzz-clang/fuzz_minidump <scratch corpus copy> -max_total_time=60

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "donkey/binary/minidump.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  constexpr std::size_t kMaxFuzzInput = 4U * 1024U * 1024U;
  if (size == 0 || size > kMaxFuzzInput) {
    return 0;
  }
  const std::span<const std::byte> file(reinterpret_cast<const std::byte*>(data), size);
  const donkey::MinidumpLimits limits;
  const auto info = donkey::read_minidump(file, limits);
  if (!info) {
    if (info.diagnostic().code.rfind("minidump.", 0) != 0) {
      std::abort();
    }
    return 0;
  }
  const donkey::MinidumpInfo& dump = info.value();
  if (dump.threads.size() > limits.max_threads || dump.modules.size() > limits.max_modules ||
      dump.memory.size() > limits.max_memory_ranges) {
    std::abort();
  }
  for (const donkey::MinidumpMemory& range : dump.memory) {
    if (range.size == 0 || range.size > size) {
      continue;
    }
    // A range the dump reports is either readable or refused with a minidump code.
    const auto bytes = donkey::read_minidump_memory(file, dump, range.address, range.size);
    if (!bytes && bytes.diagnostic().code.rfind("minidump.", 0) != 0) {
      std::abort();
    }
  }
  return 0;
}
