#pragma once

// Type library generator (G22-T2). Turns preprocessed C headers into a type library file in the
// format of typelib.h. The preprocessor itself is not run here: a build-time script runs it
// (`gcc -E -P` or `clang -E -P`, owner decision of 2026-11-17) and passes its output in, with the
// command it used, so the library records how it was made.
//
// Each top-level declaration is kept only when Donkey's own C parser accepts it against the
// declarations kept before it, so the library parses on its own exactly as the reader requires.
// Every other declaration is listed in the library as `skipped: <name>: <reason>`, never dropped
// quietly. Before it returns, the generated text is read back with read_type_library, and a
// text the reader refuses is an error, not a file.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "donkey/core/result.h"
#include "donkey/project/typelib.h"

namespace donkey {

/// The header values of the library to make. Each maps to the key of the same name in typelib.h;
/// `body_sha256` and `declarations` are computed.
struct TypeLibraryMakeOptions {
  std::string library;
  std::string library_version;
  std::string platform = "linux";
  std::string architecture = "x86_64";
  std::string abi = "sysv";
  std::string data_model = "LP64";
  std::uint64_t pointer_size = 8;
  std::uint64_t long_size = 8;
  bool char_is_signed = true;
  std::string source;
  std::string source_sha256;
  std::string licence;
  std::string licence_file;
  std::string licence_sha256;
  std::string generator_command;
  std::string preprocessor;
  std::string created;  ///< YYYY-MM-DD
  std::vector<TypeLibrarySourceFile> source_files;
  std::vector<TypeLibraryMacro> macros;
  std::vector<std::string> notes;
};

/// What make_type_library produced.
struct TypeLibraryMakeResult {
  std::string text;                         ///< the whole library file
  std::size_t kept = 0;                     ///< top-level declarations kept
  std::vector<TypeLibrarySkipped> skipped;  ///< also listed in `text`
};

/// The generator's own name and version, written as the library's `generator` value.
inline constexpr std::string_view kTypeLibraryGenerator = "donkey-cli typelib make 1";

/// The top-level declarations of preprocessed C text, in order: each ends at a `;` outside braces
/// and parentheses, or is a function definition (a body in braces after a parameter list). Each is
/// returned on one line, with the tokens that do not change a type removed: `restrict` and its
/// spellings, `__extension__`, `__inline`, `_Noreturn`, `__attribute__((...))`, `__asm__(...)`,
/// and `#` lines the preprocessor kept. Exposed for the tests.
[[nodiscard]] std::vector<std::string> split_c_declarations(std::string_view preprocessed);

/// Makes a library from `preprocessed`. Refusals: `typelib_make.options` (an option the format
/// refuses, found when the result is read back), `typelib_make.empty` (no declaration was kept),
/// `typelib_make.too_many_skipped` (the skipped list does not fit the header bounds), and any
/// refusal of read_type_library on the result.
[[nodiscard]] Result<TypeLibraryMakeResult> make_type_library(std::string_view preprocessed,
                                                              const TypeLibraryMakeOptions& options);

}  // namespace donkey
