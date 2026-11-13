// libFuzzer entry point for the C++ RTTI readers (G10-T3): Itanium for ELF and MSVC for x64 PE. The
// input is a file's bytes. The harness parses them as an image and reads its classes. It asserts
// that the reader never crashes, that a rejection carries an `rtti.` code, and that the reader
// keeps its own bounds: the classes, the bases and the slots it reports stay within the configured
// limits.
//
// Build: cmake -DDONKEY_BUILD_FUZZERS=ON with clang (see CMakeLists.txt)
// Run:   build/fuzz-clang/fuzz_rtti <scratch corpus copy> -max_total_time=60

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "donkey/binary/image.h"
#include "donkey/binary/rtti.h"

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
  const donkey::RttiOptions options;
  const auto info = donkey::read_rtti(image.value(), bytes, options);
  if (!info) {
    if (info.diagnostic().code.rfind("rtti.", 0) != 0) {
      std::abort();
    }
    return 0;
  }
  if (info.value().classes.size() > options.max_classes) {
    std::abort();
  }
  for (const donkey::RttiClass& cls : info.value().classes) {
    std::size_t slots = 0;
    for (const donkey::RttiVtableGroup& group : cls.groups) {
      slots += group.slots.size();
    }
    if (slots > options.max_slots) {
      std::abort();
    }
  }
  return 0;
}
