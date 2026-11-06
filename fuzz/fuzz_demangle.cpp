// libFuzzer entry point for the Itanium C++ ABI demangler (G10-T1). The input is the name
// text. The harness asserts that the demangler never crashes, that every rejection carries a
// `demangle.` code, and that an accepted name stays within the output limit.
//
// Build: cmake --preset fuzz-macos
// Run:   build/fuzz-macos/fuzz_demangle tests/fuzz/corpus/demangle -max_total_time=60

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

#include "donkey/binary/demangle.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::string_view name(reinterpret_cast<const char*>(data), size);
  const donkey::DemangleOptions options;
  const auto demangled = donkey::demangle_itanium(name, options);
  if (!demangled) {
    // A rejection must carry a code in the demangler's namespace, so it can be reported.
    if (demangled.diagnostic().code.rfind("demangle.", 0) != 0) {
      std::abort();
    }
    return 0;
  }
  if (demangled.value().size() > options.max_output_bytes) {
    std::abort();  // the output limit is part of the contract
  }
  return 0;
}
