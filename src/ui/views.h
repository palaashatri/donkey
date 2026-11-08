#pragma once

#include "session.h"
#include "workspace.h"

namespace donkey::ui::views {

/// The name a view shows for a function: the user's rename as typed, otherwise the demangled form
/// of its symbol (G10-T4). The raw symbol is what a tooltip shows when the two differ.
[[nodiscard]] std::string shown_function_name(UiState& state, const Function& function);
void overview(const Document& document, UiState& state);
void sections(const Document& document, UiState& state);
void functions(const Document& document, UiState& state);
void disassembly(const Document& document, UiState& state);
void decompiler(const Document& document, UiState& state);
void cfg_graph(const Document& document, UiState& state);
void hex(const Document& document, UiState& state);
void strings(const Document& document, UiState& state);
void xrefs(const Document& document, UiState& state);
void bookmarks(const Document& document, UiState& state);
/// The defined data ranges (G12-T2): arrays, strings and undefined bytes, with Edit and Remove.
void data_ranges(const Document& document, UiState& state);
void debugger(const Document& document, UiState& state);
void diagnostics(const Document& document, UiState& state);
/// Itanium classes from the image's RTTI (G10-T3): name, kind, direct bases, vtable and slot
/// count. Selecting a class navigates to its vtable, or its typeinfo when it has none (G10-T4).
void classes(const Document& document, UiState& state);
/// The Search window (G17): byte, immediate and regular expression searches of the open document.
void search(const Document& document, UiState& state);

}  // namespace donkey::ui::views
