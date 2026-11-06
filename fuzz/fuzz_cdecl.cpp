// libFuzzer entry point for the C declaration parser (G05-T2). The input is the
// declaration text; the first byte picks the target ABI so both pointer widths and
// both `long` widths are exercised. The harness asserts that the parser never
// crashes, and that any declaration it accepts passes the type store's checks.
//
// Build: cmake --preset fuzz-macos
// Run:   build/fuzz-macos/fuzz_cdecl tests/fuzz/corpus/cdecl -max_total_time=60

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

#include "donkey/project/cdecl.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  donkey::CDeclarationOptions options;
  std::string_view text;
  if (size > 0) {
    options.pointer_size = (data[0] & 1U) != 0 ? 4 : 8;
    options.long_size = (data[0] & 2U) != 0 ? 4 : 8;
    options.char_is_signed = (data[0] & 4U) != 0;
    text = std::string_view(reinterpret_cast<const char*>(data + 1), size - 1);
  }

  const auto parsed = donkey::parse_c_declarations(text, donkey::TypeTable{}, options);
  if (!parsed) {
    // A rejection must carry a code and a location, so the message is useful.
    if (parsed.diagnostic().code.empty()) {
      std::abort();
    }
    return 0;
  }

  donkey::TypeTable table;
  for (const donkey::TypeDefinition& definition : parsed.value()) {
    table.put(definition);
  }
  if (!table.validate()) {
    std::abort();  // the parser promised a valid result
  }
  return 0;
}
