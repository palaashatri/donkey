// libFuzzer entry point for the PDB reader (G06). The input is a PDB file. The harness asserts
// that the reader never crashes, that a rejection carries a `pdb.` code, and that the record
// lists stay within the configured limits.
//
// Build: cmake -DDONKEY_BUILD_FUZZERS=ON with clang (see CMakeLists.txt)
// Run:   build/fuzz-clang/fuzz_pdb <scratch corpus copy> -max_total_time=60

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "donkey/binary/pdb.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  constexpr std::size_t kMaxFuzzInput = 4U * 1024U * 1024U;
  if (size == 0 || size > kMaxFuzzInput) {
    return 0;
  }
  const std::span<const std::byte> file(reinterpret_cast<const std::byte*>(data), size);
  const donkey::PdbLimits limits;
  const auto info = donkey::read_pdb(file, limits);
  if (!info) {
    if (info.diagnostic().code.rfind("pdb.", 0) != 0) {
      std::abort();
    }
    return 0;
  }
  if (info.value().functions.size() > limits.max_records ||
      info.value().variables.size() > limits.max_records ||
      info.value().types.size() > limits.max_types) {
    std::abort();
  }
  return 0;
}
