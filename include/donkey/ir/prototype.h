#pragma once

// Applies a function prototype (a C signature from user or debug information) to
// recovered IR (G05-T3). A prototype changes names and types only: it never changes a
// statement, so the function computes what it computed before. A prototype that
// disagrees with the inferred signature or with the accesses through a pointer
// parameter is refused, and the function is left as it was.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "donkey/core/result.h"
#include "donkey/ir/ir.h"

namespace donkey {

/// One member of a structure. `width` is the member's size in bytes when it is a
/// scalar (integer, pointer or float); a member of another kind has width 0 and
/// cannot match an access.
struct IrTypeField {
  std::string name;
  std::uint64_t offset = 0;
  std::uint8_t width = 0;
};

/// A structure a pointer parameter points to: its name and members.
struct IrTypeLayout {
  std::string name;
  std::vector<IrTypeField> fields;
};

/// One parameter of a prototype. `width` and `floating_point` must agree with the
/// inferred parameter at the same position; a pointer has width 8.
struct IrPrototypeParameter {
  std::string name;
  std::uint8_t width = 8;
  bool floating_point = false;
  /// Set when the parameter is a pointer to this structure.
  std::optional<IrTypeLayout> pointee;
};

struct IrPrototype {
  std::string name;
  /// Width of the return value in bytes; 0 for void.
  std::uint8_t return_width = 0;
  bool return_floating_point = false;
  std::vector<IrPrototypeParameter> parameters;
};

/// Applies `prototype` to `function`. Checks, in order: the parameter count; each
/// width and class (integer or floating point) and the return width; the parameter
/// names (identifiers, unique); and, for each pointer parameter with a pointee, that
/// every field the function accesses through it is a member at the same offset with
/// the same width. Only then does the function change: parameters are renamed and
/// typed, pointer structures take the structure's name and member names, and the
/// statements are not touched.
///
/// Errors are `InvalidInput` with a code under `ir.prototype_`. The function is not
/// changed on error.
[[nodiscard]] Result<bool> apply_prototype(IrFunction& function, const IrPrototype& prototype);

}  // namespace donkey
