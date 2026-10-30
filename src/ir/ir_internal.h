#pragma once

#include <optional>
#include <string>

#include "donkey/ir/ir.h"

namespace donkey::detail {

/// Render one non-control-flow statement (or a `return`) without indentation.
/// `previous` is the statement before it in the same block; conditions on a
/// compare/test depend on it.
std::string render_statement(const IrFunction& function, const IrStatement& statement,
                             const IrStatement* previous);

/// The textual condition of a conditional branch, e.g. `rax == 0x0`, derived
/// from the branch's condition and the compare/test that precedes it. When
/// `negate` is true, an exactly complementary condition is used (so `==`
/// becomes `!=`); conditions without a total complement are wrapped in `!(...)`.
std::string render_condition(const IrFunction& function, const IrStatement& statement,
                             const IrStatement* previous, bool negate = false);

struct StructuredLine {
  std::string text;
  std::uint64_t source_address = 0;
};

/// Structured rendering of the function body, or `nullopt` when the control-flow
/// graph does not match a shape this structurer models. Callers must fall back
/// to labeled blocks with explicit `goto` when `nullopt` is returned; no guessed
/// structure is ever emitted.
std::optional<std::string> format_structured_body(const IrFunction& function);
std::optional<std::vector<StructuredLine>> format_structured_body_lines(const IrFunction& function);

}  // namespace donkey::detail
