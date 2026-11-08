#pragma once

// User names for the locals of a recovered function (G12-T3). A name is for display only: the
// registers, statements, types and layouts of the IR do not change. The names are applied after
// the debug names of the same function, so a user name replaces a debug name.

#include <cstddef>
#include <string>
#include <vector>

#include "donkey/core/result.h"
#include "donkey/ir/ir.h"

namespace donkey {

/// A user name for one local. `variable` is "arg:<index>" for the parameter at that index of
/// IrFunction::parameters, or "frame:<base register>:<signed offset>" for the local whose base
/// register and offset are those of an IrLocalVariable. The same keys are stored by the project
/// (donkey::LocalName).
struct UserLocalName {
  std::string variable;
  std::string name;
};

struct LocalNameResult {
  /// Parameters and frame slots that were named.
  std::size_t applied = 0;
  /// Keys that name nothing: a parameter index the function does not have, or a frame slot that no
  /// access uses. They are skipped, and the function gets a note for each one.
  std::size_t stale = 0;
};

/// True when `name` is a C identifier of at most 128 bytes that is not a C keyword: the names that
/// apply_user_local_names accepts.
[[nodiscard]] bool user_local_name_usable(const std::string& name) noexcept;

/// Applies `names` to `function`. A frame slot that the function accesses but that has no local
/// yet becomes one, with the width of its accesses, so the decompiler declares it. The whole set is
/// refused, and the function is left as it was, when a name is not a C identifier or is a C
/// keyword, when a key is malformed or given twice, or when an applied name equals another
/// parameter or local name of the function. Refusals are `InvalidInput` with a code under
/// `ir.local_name_`.
[[nodiscard]] Result<LocalNameResult> apply_user_local_names(
    IrFunction& function, const std::vector<UserLocalName>& names);

}  // namespace donkey
