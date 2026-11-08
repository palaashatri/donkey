// libFuzzer entry point for the signature generator (G09-T2). The input is a file: an ELF
// relocatable object or a static archive. The harness asserts that the generator never crashes,
// that a rejection carries a code, and that an accepted result meets the format it writes: every
// signature has a prefix of min(32, length) bytes, sorted in-range wildcards, and a canonical text
// that reads back to the same set.
//
// Build: cmake --build build/fuzz-clang --target fuzz_sig_object
// Run:   build/fuzz-clang/fuzz_sig_object tests/fuzz/corpus/sig_object -max_total_time=60

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string>

#include "donkey/analysis/signature_gen.h"
#include "donkey/analysis/signatures.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  donkey::SignatureGenOptions options;
  options.library = "fuzz";
  options.version = "1";
  options.license = "MIT";
  const std::span<const std::byte> file(reinterpret_cast<const std::byte*>(data), size);
  const auto generated = donkey::generate_signatures(file, options);
  if (!generated) {
    if (generated.diagnostic().code.empty()) {
      std::abort();
    }
    return 0;
  }
  const donkey::SignatureSet& set = generated.value().set;
  for (const donkey::Signature& signature : set.signatures) {
    const std::size_t expected = signature.length < 32 ? signature.length : 32;
    if (signature.length == 0 || signature.prefix.size() != expected || signature.name.empty()) {
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
  const std::string canonical = donkey::write_signature_set(set);
  const auto again = donkey::parse_signature_set(canonical);
  if (!again || donkey::write_signature_set(again.value()) != canonical) {
    std::abort();  // a generated set must read back to the same canonical text
  }
  return 0;
}
