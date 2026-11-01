// libFuzzer entry point for the untrusted-input pipeline: raw bytes are
// parsed as ELF/PE/Mach-O, their DWARF read, analysed with tight bounds, and every discovered
// function is lifted, verified and printed. The harness asserts the core
// invariant that a successfully lifted function always verifies, and that a
// verified function always renders; violations become fuzz crashes.
//
// Build: cmake --preset fuzz-macos
// Run:   build/fuzz-macos/fuzz/fuzz_binary tests/fuzz/corpus/binary

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/debug_info.h"
#include "donkey/binary/image.h"
#include "donkey/ir/ir.h"
#include "donkey/ir/lift.h"

namespace {

constexpr std::size_t kMaxFuzzInput = 4U * 1024U * 1024U;
constexpr std::size_t kMaxInstructions = 20'000;
constexpr std::size_t kMaxFunctions = 256;

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size == 0 || size > kMaxFuzzInput) {
    return 0;
  }
  const std::span<const std::byte> bytes(reinterpret_cast<const std::byte*>(data), size);

  auto image = donkey::parse_binary(bytes, "<fuzz>");
  if (!image) {
    return 0;  // Rejection is a valid, deterministic outcome.
  }

  // DWARF reader: bounded, and every type it reports must render.
  donkey::DebugInfoOptions debug_options;
  debug_options.max_entries = 200'000;
  if (auto debug = donkey::read_debug_info(image.value(), bytes, debug_options)) {
    for (const auto& function : debug.value().functions) {
      (void)debug.value().prototype(function);
    }
    for (const auto& [offset, type] : debug.value().types) {
      (void)debug.value().type_name(offset);
    }
  }

  donkey::AnalysisOptions options;
  options.max_instructions = kMaxInstructions;
  options.max_strings = 2'000;
  options.min_string_length = 4;
  auto analysis = donkey::analyze(image.value(), bytes, options);
  if (!analysis) {
    return 0;
  }

  std::size_t lifted_count = 0;
  for (const donkey::Function& function : analysis.value().functions) {
    if (lifted_count++ >= kMaxFunctions) {
      break;
    }
    auto lifted = donkey::lift_function(image.value(), analysis.value(), function);
    if (!lifted) {
      continue;
    }
    auto verified = donkey::verify_ir(lifted.value());
    if (!verified.has_value()) {
      // The lifter must never emit IR that fails its own verifier. Print the
      // diagnostic so a crash report names the invariant, then abort.
      std::fprintf(stderr, "FUZZ invariant violated: verifier rejected lifted IR (%s: %s)\n",
                   verified.diagnostic().code.c_str(), verified.diagnostic().message.c_str());
      __builtin_trap();
    }
    auto text = donkey::format_pseudocode(lifted.value());
    if (!text.has_value()) {
      std::fprintf(stderr, "FUZZ invariant violated: verified IR did not render (%s: %s)\n",
                   text.diagnostic().code.c_str(), text.diagnostic().message.c_str());
      __builtin_trap();
    }
  }
  return 0;
}
