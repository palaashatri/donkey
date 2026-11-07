// libFuzzer entry point for the ELF core reader (G15-T3). The input is a file's bytes. The
// harness parses them as an image and reads its threads and mappings. It asserts that the
// reader never crashes, that a rejection carries a `core.` code, and that the reader keeps
// its configured limits.
//
// Build: cmake -DDONKEY_BUILD_FUZZERS=ON with clang (see CMakeLists.txt)
// Run:   build/fuzz-clang/fuzz_core <scratch corpus copy> -max_total_time=60

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "donkey/binary/core.h"
#include "donkey/binary/image.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  constexpr std::size_t kMaxFuzzInput = 4U * 1024U * 1024U;
  if (size == 0 || size > kMaxFuzzInput) {
    return 0;
  }
  const std::span<const std::byte> bytes(reinterpret_cast<const std::byte*>(data), size);
  auto image = donkey::parse_binary(bytes, "<fuzz>");
  if (!image) {
    return 0;  // a rejected image is a valid, deterministic outcome
  }
  const donkey::CoreOptions options;
  const auto core = donkey::read_elf_core(image.value(), bytes, options);
  if (!core) {
    if (core.diagnostic().code.rfind("core.", 0) != 0) {
      std::abort();
    }
    return 0;
  }
  if (core.value().threads.size() > options.max_threads ||
      core.value().mappings.size() > options.max_mappings) {
    std::abort();
  }
  return 0;
}
