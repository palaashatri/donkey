#pragma once

#include "session.h"
#include "workspace.h"

namespace donkey::ui::views {

void overview(const Document& document, UiState& state);
void sections(const Document& document, UiState& state);
void functions(const Document& document, UiState& state);
void disassembly(const Document& document, UiState& state);
void decompiler(const Document& document, UiState& state);
void hex(const Document& document, UiState& state);
void strings(const Document& document, UiState& state);
void xrefs(const Document& document, UiState& state);
void diagnostics(const Document& document, UiState& state);

}  // namespace donkey::ui::views
