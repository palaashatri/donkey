// libFuzzer entry point for the type library reader (G22-T1). The input is a whole library file:
// its header, the empty line and the C text. The harness asserts that the reader never crashes,
// that a refusal carries a code, and that an accepted library has library provenance on every type
// and passes the type store's checks.
//
// Most inputs are refused by the header or the body hash. A seed with a correct hash (the corpus
// in tests/fuzz/corpus/typelib) reaches the C text.
//
// Build: cmake --preset fuzz-macos
// Run:   build/fuzz-macos/fuzz_typelib tests/fuzz/corpus/typelib -max_total_time=60

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

#include "donkey/project/typelib.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::string_view text(reinterpret_cast<const char*>(data), size);
  const auto library = donkey::read_type_library(text, donkey::TypeTable{});
  if (!library) {
    // A rejection must carry a code, so the message can be shown and matched.
    if (library.diagnostic().code.empty()) {
      std::abort();
    }
    return 0;
  }

  donkey::TypeTable table;
  for (const donkey::TypeDefinition& definition : library.value().types) {
    if (definition.provenance != donkey::TypeProvenance::Library) {
      std::abort();  // every type of a library carries the library's provenance
    }
    table.put(definition);
  }
  if (!table.validate()) {
    std::abort();  // the reader promised a valid type set
  }
  return 0;
}
