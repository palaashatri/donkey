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
/// One node of the cross-reference graph: a function at a call level (0 is the selected one,
/// negative are callers, positive callees), with its raw symbol and the readable name it is drawn
/// with.
struct XrefNode {
  std::uint64_t address = 0;
  int level = 0;
  std::string raw;
  std::string shown;
};
/// A call from one node to another, both in the graph.
struct XrefEdge {
  std::uint64_t from = 0;
  std::uint64_t to = 0;
  bool operator==(const XrefEdge& other) const { return from == other.from && to == other.to; }
};
struct XrefNeighbourhood {
  std::uint64_t center = 0;
  std::vector<XrefNode> nodes;
  std::vector<XrefEdge> edges;
  bool truncated = false;  ///< the node limit stopped the walk
};
/// The call neighbourhood of the function at `center`: callers and callees up to `depth` calls out,
/// at most `max_nodes` functions (G17). Built from the analysis's direct calls only.
[[nodiscard]] XrefNeighbourhood xref_neighbourhood(const Document& document, UiState& state,
                                                   std::uint64_t center, int depth,
                                                   std::size_t max_nodes);
/// The cross-reference graph window (G17).
void xref_graph(const Document& document, UiState& state);
/// The function that contains `address`, by the rule the call graph panel uses (G10-T4), or
/// nullptr.
[[nodiscard]] const Function* function_containing_address(const Document& document,
                                                          std::uint64_t address);
/// The Symbols window (G17): the image's symbols, filtered by the words typed.
void symbols(const Document& document, UiState& state);
/// The symbol indices the Symbols window lists, in symbol order (the filter applied).
[[nodiscard]] std::vector<std::size_t> symbol_listing(const Document& document, UiState& state);
/// The readable name a symbol is shown with (G10-T4); the raw name is the tooltip.
[[nodiscard]] std::string symbol_shown_name(UiState& state, const Symbol& symbol);
/// The Search window (G17): byte, immediate and regular expression searches of the open document.
void search(const Document& document, UiState& state);

}  // namespace donkey::ui::views
