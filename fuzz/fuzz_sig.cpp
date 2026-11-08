// libFuzzer entry point for the signature set reader (G09-T1). The input is the JSON text of a
// signature set. The harness asserts that the reader never crashes, that a rejection carries a
// code, and that an accepted set meets its own rules: it writes back to the same canonical text,
// and every signature's prefix, wildcards and length agree.
//
// Build: cmake --build build/fuzz-clang --target fuzz_sig
// Run:   build/fuzz-clang/fuzz_sig tests/fuzz/corpus/sig -max_total_time=60

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

#include "donkey/analysis/signatures.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::string_view text(reinterpret_cast<const char*>(data), size);
  const auto parsed = donkey::parse_signature_set(text);
  if (!parsed) {
    if (parsed.diagnostic().code.empty()) {
      std::abort();
    }
    return 0;
  }
  const donkey::SignatureSet& set = parsed.value();
  const std::string canonical = donkey::write_signature_set(set);
  const auto again = donkey::parse_signature_set(canonical);
  if (!again || donkey::write_signature_set(again.value()) != canonical) {
    std::abort();  // an accepted set must read back to the same canonical text
  }
  for (const donkey::Signature& signature : set.signatures) {
    const std::size_t expected = signature.length < 32 ? signature.length : 32;
    if (signature.prefix.size() != expected || signature.length == 0) {
      std::abort();
    }
    std::uint64_t previous_end = 0;
    for (const donkey::SignatureWildcard& span : signature.wildcards) {
      if (span.length == 0 || span.offset < previous_end ||
          static_cast<std::uint64_t>(span.offset) + span.length > signature.length) {
        std::abort();
      }
      previous_end = static_cast<std::uint64_t>(span.offset) + span.length;
    }
  }
  return 0;
}
