// libFuzzer entry point for the .eh_frame reader (G23-T1). The input is the bytes of one section.
// The harness asserts that the reader never crashes, that a rejection carries an `elf.eh_frame`
// code, that every range it reports is non-empty, and that the counts stay consistent with the
// record limit.
//
// Build: cmake -DDONKEY_BUILD_FUZZERS=ON with clang (see CMakeLists.txt)
// Run:   build/fuzz-clang/fuzz_eh_frame <scratch corpus copy> -max_total_time=60

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "donkey/binary/eh_frame.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  constexpr std::size_t kMaxFuzzInput = 1U << 20;
  if (size == 0 || size > kMaxFuzzInput) {
    return 0;
  }
  const std::span<const std::byte> section(reinterpret_cast<const std::byte*>(data), size);
  // The first byte picks the pointer size, so both forms are reached.
  const unsigned pointer_size = (data[0] & 1U) != 0 ? 8U : 4U;
  constexpr std::size_t kLimit = 4096;
  const auto result =
      donkey::read_eh_frame(section, 0x400000, pointer_size, donkey::Endian::Little, kLimit);
  if (!result) {
    if (result.diagnostic().code.rfind("elf.eh_frame", 0) != 0) {
      std::abort();
    }
    return 0;
  }
  const donkey::EhFrameReadResult& read = result.value();
  if (read.records > kLimit || read.malformed_records > read.records) {
    std::abort();
  }
  for (const donkey::EhFrameFunction& function : read.functions) {
    if (function.start == 0 || function.size == 0) {
      std::abort();
    }
  }
  return 0;
}
