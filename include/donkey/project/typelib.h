#pragma once

// Type libraries (G22-T1): a versioned text file of C declarations for one platform and ABI.
// This header defines the format and the bounded reader. The reader only reads: it does not
// apply a type to any code (that is G22-T3), and it does not bundle any library (G22-T2).
//
// File layout. Plain ASCII, lines end with LF (a CR anywhere is refused).
//
//   donkey-typelib 1            the format line. Another version number is refused.
//   <key>: <value>              one line per single key, in any order (the list is below).
//   <record>                    repeated records, after every single key, in this order:
//   source_file: <path> <sha256>   a relative path (no leading '/', no '.' or '..' segment,
//   macro: NAME=value               no backslash or ':') and the file's SHA-256. A path may
//   skipped: <name>: <reason>       appear once. Keeps the order of the lines.
//   note: <text>
//   <empty line>                ends the header.
//   <C text>                    parsed by parse_c_declarations (the rest of the file).
//
// The single keys are library, library_version, platform, architecture, abi, data_model,
// pointer_size, long_size, char_is_signed, source, source_sha256, licence, licence_file,
// licence_sha256, generator, generator_command, preprocessor, created, body_sha256 and
// declarations. Each is required, and each may appear once. Values are printable ASCII,
// non-empty, with these closed sets:
//   platform        linux, freebsd, windows, macos
//   architecture    x86_64, aarch64
//   abi             sysv (x86_64), aapcs64 (aarch64), win64 (x86_64, windows)
//   data_model      LP64 (sysv and aapcs64; long 8) or LLP64 (win64; long 4)
//   pointer_size    8 (4 is refused: no listed data model has 4-byte pointers)
//   long_size       8 for LP64, 4 for LLP64
//   char_is_signed  true or false
//   created         YYYY-MM-DD
//   source_sha256, licence_sha256, body_sha256   64 lowercase hex digits
//   declarations    counts the body parsed with only the built-in names: the number of type
//                   definitions that parse returns, scalar, pointer and array types included.
//                   It does not depend on the table the library is read into. A library must
//                   parse on its own, so it may not name a type that is not built in or
//                   declared in its own text.
//   preprocessor    `none`, or the preprocessor's name and version
//
// body_sha256 is the SHA-256 of the C text: the bytes that follow the empty line, up to the
// end of the file, exactly as stored (no line ending is added or removed). The reader refuses
// a file whose body does not match.
//
// Diagnostics. Each refusal has a stable code under `typelib.`. A header error's message begins
// `line L:` with the line in the file. A refusal from the C text keeps the parser's `cdecl.`
// code and its position, and rewrites `line L, column C:` so that L is the line in the library
// file. A refusal found after parsing (a duplicate name, an invalid type set) has no source
// position, so its message has none.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "donkey/core/result.h"
#include "donkey/project/types.h"

namespace donkey {

/// Largest library file, in bytes. Checked before the whole file is read.
inline constexpr std::size_t kMaxTypeLibraryBytes = 4 * 1024 * 1024;
/// Most lines before the empty line that ends the header (the format line included).
inline constexpr std::size_t kMaxTypeLibraryHeaderLines = 4096;
/// Longest header line, in bytes.
inline constexpr std::size_t kMaxTypeLibraryHeaderLineBytes = 256;
/// Most type definitions a library may declare.
inline constexpr std::uint64_t kMaxTypeLibraryDeclarations = 20000;

/// A file a library was generated from (`source_file` record).
struct TypeLibrarySourceFile {
  std::string path;    ///< relative to the source, as given
  std::string sha256;  ///< 64 lowercase hex digits
};

/// A preprocessor macro that was set when the library was generated (`macro` record).
struct TypeLibraryMacro {
  std::string name;
  std::string value;  ///< may be empty
};

/// A declaration that was left out of the library, and why (`skipped` record).
struct TypeLibrarySkipped {
  std::string name;
  std::string reason;
};

/// A type library read from a file. Every header value is kept as written, after its checks. The
/// repeated records keep their file order. Every type in `types` has provenance `Library`.
struct TypeLibrary {
  std::string library;
  std::string library_version;
  std::string platform;
  std::string architecture;
  std::string abi;
  std::string data_model;
  std::uint64_t pointer_size = 0;
  std::uint64_t long_size = 0;
  bool char_is_signed = false;
  std::string source;
  std::string source_sha256;
  std::string licence;
  std::string licence_file;
  std::string licence_sha256;
  std::string generator;
  std::string generator_command;
  std::string preprocessor;
  std::string created;
  std::string body_sha256;
  std::uint64_t declarations = 0;

  std::vector<TypeLibrarySourceFile> source_files;
  std::vector<TypeLibraryMacro> macros;
  std::vector<TypeLibrarySkipped> skipped;
  std::vector<std::string> notes;

  /// The declared types, ids from `known.next_id()` upwards, in declaration order.
  std::vector<TypeDefinition> types;
};

/// Reads a type library from `text`, with no file access. The C text must parse on its own, with
/// the built-in names only. `known` is the table the library joins: the library's types take their
/// ids from `known.next_id()` upwards, and the result is checked as a whole with `known`.
///
/// Refusals (InvalidInput unless noted):
///   typelib.format                 missing or malformed format line, a header line without
///                                  `key: value`, or no empty line after the header
///   typelib.version                a format version other than 1
///   typelib.unknown_key            a key that is not in the list above
///   typelib.duplicate_key          a single key given twice
///   typelib.missing_key            a required single key absent
///   typelib.bad_value              a value outside its set or form, an empty value, a character
///                                  outside printable ASCII, or an ABI that does not belong to the
///                                  architecture or platform
///   typelib.record_order           a repeated record out of order, or a single key after one
///   typelib.duplicate_path         two source_file records with the same path
///   typelib.data_model_mismatch    a data model, long size or pointer size that contradicts
///                                  the ABI
///   typelib.carriage_return        a CR byte in the file
///   typelib.body_hash              the C text does not match body_sha256
///   typelib.declaration_count      the declarations count differs from the parsed count
///   typelib.duplicate_name         one name declared twice in one C name space (struct,
///                                  union and enum tags share one; typedefs and functions
///                                  share the other)
///   typelib.type_and_function      one name used for a typedef and for a function
///   typelib.invalid_types          the types do not pass TypeTable::validate with `known`; the
///                                  parser's own final check (cdecl.invalid_type) is reported as
///                                  this
///   cdecl.*                        a refusal of the C text, located as described above
/// and ResourceLimit for a bound:
///   typelib.too_large              the file is over kMaxTypeLibraryBytes
///   typelib.too_many_lines         more than kMaxTypeLibraryHeaderLines header lines
///   typelib.line_too_long          a header line over kMaxTypeLibraryHeaderLineBytes
///   typelib.too_many_declarations  a declarations count over kMaxTypeLibraryDeclarations
[[nodiscard]] Result<TypeLibrary> read_type_library(std::string_view text,
                                                    const TypeTable& known = {});

/// Reads the library file at `path`. A file over kMaxTypeLibraryBytes is refused with
/// `typelib.too_large` from its size, before any of it is read. A file that cannot be read is
/// `typelib.io`.
///
/// This does not choose a directory to look in. A caller passes the path; the bundled libraries
/// live under `typelibs/` (installed next to the other data), and no per-user library directory
/// is defined yet.
[[nodiscard]] Result<TypeLibrary> load_type_library(const std::filesystem::path& path);

}  // namespace donkey
