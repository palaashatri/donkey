#pragma once

// A bounded parser for a subset of C declarations (G05-T2): struct, union, enum,
// typedef, pointers, arrays, function prototypes and the fixed-width integer names.
// It turns the declarations into type definitions for the type store; it does not run
// a preprocessor, evaluate expressions other than integer literals, or accept C++.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "donkey/core/result.h"
#include "donkey/project/types.h"

namespace donkey {

/// The sizes the parser assumes for the target ABI. The defaults are LP64, the
/// System V and Apple x86-64 and AArch64 model. `long double` is always 16 bytes.
struct CDeclarationOptions {
  std::uint64_t pointer_size = 8;  ///< bytes; 4 or 8
  std::uint64_t long_size = 8;     ///< bytes of `long` and `unsigned long`; 4 or 8
  /// Whether plain `char` is signed: true on x86-64 and Apple arm64, false on
  /// Linux AArch64.
  bool char_is_signed = true;
};

/// Largest input the parser accepts, in bytes.
inline constexpr std::size_t kMaxCDeclarationBytes = 1024 * 1024;
/// Deepest nesting of pointers, parameter lists and array dimensions.
inline constexpr int kMaxCDeclarationNesting = 64;

/// The name space of a C name. The tags of structs, unions and enums share one; typedef names and
/// function names (C's ordinary identifiers) share the other.
enum class CNameSpace : std::uint8_t { Tag, Ordinary };

/// A name the text declares, in declaration order: a tag the first time the text names it (by a
/// definition or a forward reference), a typedef name, or a function prototype's name. Names that
/// come from the known table are not listed.
struct CDeclaredName {
  std::string name;
  CNameSpace space = CNameSpace::Ordinary;
  /// Struct, Union or Enum for a tag. Typedef for a typedef name, also one that names an untagged
  /// struct, union or enum (`typedef struct { ... } name;`, whose type takes the name). Function
  /// for a prototype.
  TypeKind kind = TypeKind::Void;
};

/// Parses the declarations in `text` against the types already in `known`, which
/// supply the names of earlier struct, union, enum and typedef declarations. The
/// result is the types the text declares, with ids from `known.next_id()` upwards
/// in order of declaration, provenance `User`. A function prototype becomes a
/// `Function` type named after the function. Struct and union layouts follow the
/// ABI (natural alignment, padded size). The caller may put the result into a table
/// and validate it.
///
/// Errors are `InvalidInput` with a code under `cdecl.` and a message that begins
/// `line L, column C:`. Input over `kMaxCDeclarationBytes` is `ResourceLimit`.
///
/// When `names` is given, it is cleared and receives the names the text declares, with their name
/// space (see `CDeclaredName`). It is complete only when the parse succeeds.
[[nodiscard]] Result<std::vector<TypeDefinition>> parse_c_declarations(
    std::string_view text, const TypeTable& known, const CDeclarationOptions& options = {},
    std::vector<CDeclaredName>* names = nullptr);

}  // namespace donkey
