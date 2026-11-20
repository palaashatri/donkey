#pragma once

// A bounded parser for a subset of C declarations (G05-T2): struct, union, enum,
// typedef, pointers, arrays, bit-fields, function prototypes and the fixed-width integer
// names. Array sizes, enumerator values and bit-field widths are integer constant
// expressions (literals, enumeration constants, sizeof, integer casts and the C operators).
// It turns the declarations into type definitions for the type store; it does not run
// a preprocessor or accept C++.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "donkey/core/result.h"
#include "donkey/project/types.h"

namespace donkey {

/// How bit-fields are laid out. The placement rule is the same for the two modelled ABIs (a field
/// starts at the next free bit unless it would cross a unit of its type's size); they differ in
/// whether an unnamed bit-field's type aligns the record.
enum class CBitFieldLayout : std::uint8_t {
  SystemV,     ///< System V x86-64: an unnamed bit-field does not align the record
  Aapcs64,     ///< AAPCS64 (AArch64 Linux): an unnamed bit-field's type aligns the record too
  Unmodelled,  ///< any other ABI (Win64, Apple arm64): a bit-field is refused
};

/// The sizes the parser assumes for the target ABI. The defaults are LP64, the
/// System V and Apple x86-64 and AArch64 model. `long double` is always 16 bytes.
struct CDeclarationOptions {
  std::uint64_t pointer_size = 8;  ///< bytes; 4 or 8
  std::uint64_t long_size = 8;     ///< bytes of `long` and `unsigned long`; 4 or 8
  /// Whether plain `char` is signed: true on x86-64 and Apple arm64, false on
  /// Linux AArch64.
  bool char_is_signed = true;
  /// The bit-field rules; the default is System V x86-64's.
  CBitFieldLayout bit_fields = CBitFieldLayout::SystemV;
};

/// Largest input the parser accepts, in bytes.
inline constexpr std::size_t kMaxCDeclarationBytes = 1024 * 1024;
/// Deepest nesting of pointers, parameter lists and array dimensions.
inline constexpr int kMaxCDeclarationNesting = 64;

/// The name space of a C name. The tags of structs, unions and enums share one; typedef names and
/// function names (C's ordinary identifiers) share the other.
enum class CNameSpace : std::uint8_t { Tag, Ordinary };

/// A name the text declares at file scope, in declaration order: a tag the first time the text
/// names it (by a definition or a forward reference), a typedef name, an enumeration constant, or a
/// function prototype's name. Names that come from the known table are not listed, and neither are
/// tags and constants declared inside a parameter list, whose scope ends with it (C11 6.2.1). A
/// definition that completes a tag the text named earlier by a forward reference is listed again,
/// with `completes` set, at the definition.
struct CDeclaredName {
  std::string name;
  CNameSpace space = CNameSpace::Ordinary;
  /// Struct, Union or Enum for a tag. Typedef for a typedef name, also one that names an untagged
  /// struct, union or enum (`typedef struct { ... } name;`, whose type takes the name). Function
  /// for a prototype. Enum, in the ordinary name space, for an enumeration constant.
  TypeKind kind = TypeKind::Void;
  /// The definition of a tag this text named earlier only by a forward reference: not a second
  /// declaration of the name.
  bool completes = false;
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
