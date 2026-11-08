// libFuzzer entry point for the `donkey-cli serve` request handling (G11-T1). The input is read as
// newline-separated JSON-RPC requests through a fresh session, the way the server reads stdin. The
// harness asserts nothing beyond the absence of a crash, a hang or a sanitizer report: every
// request must get a well-formed response or none (a notification).
//
// Build: cmake -DDONKEY_BUILD_FUZZERS=ON with clang (see CMakeLists.txt)
// Run:   build/fuzz-clang/fuzz_rpc tests/fuzz/corpus/rpc -max_total_time=60

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "serve.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::string_view input(reinterpret_cast<const char*>(data), size);
  const std::string output = donkey::cli::serve_text(input);
  (void)output;
  return 0;
}
