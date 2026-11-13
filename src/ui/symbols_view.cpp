// The Symbols window (G17): every symbol of the image, filtered by the words typed, with its kind,
// binding and size. Names are shown readable, with the raw symbol as the tooltip (G10-T4).

#include <cctype>
#include <cstdio>
#include <string>
#include <vector>

#include "components.h"
#include "imgui.h"
#include "names.h"
#include "views.h"
#include "workspace.h"

namespace donkey::ui::views {
namespace {

std::string lowercase(std::string text) {
  for (char& c : text) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return text;
}

/// Whether a symbol passes the filter: each word typed must be part of its raw name or its readable
/// name, in either case (as the command palette matches).
bool symbol_passes(const std::string& raw, const std::string& shown, const std::string& filter) {
  if (filter.empty()) {
    return true;
  }
  const std::string lower_raw = lowercase(raw);
  const std::string lower_shown = lowercase(shown);
  std::size_t start = 0;
  while (start < filter.size()) {
    while (start < filter.size() && filter[start] == ' ') {
      ++start;
    }
    std::size_t end = start;
    while (end < filter.size() && filter[end] != ' ') {
      ++end;
    }
    if (end > start) {
      const std::string word = lowercase(filter.substr(start, end - start));
      if (lower_raw.find(word) == std::string::npos &&
          lower_shown.find(word) == std::string::npos) {
        return false;
      }
    }
    start = end;
  }
  return true;
}

}  // namespace

std::string symbol_shown_name(UiState& state, const Symbol& symbol) {
  return cached_readable_name(state.readable_names, symbol.name);
}

std::vector<std::size_t> symbol_listing(const Document& document, UiState& state) {
  std::vector<std::size_t> listed;
  const auto& symbols = document.loaded.image.symbols;
  for (std::size_t i = 0; i < symbols.size(); ++i) {
    const std::string shown = symbol_shown_name(state, symbols[i]);
    if (symbol_passes(symbols[i].name, shown, state.symbol_filter)) {
      listed.push_back(i);
    }
  }
  return listed;
}

void symbols(const Document& document, UiState& state) {
  components::search_field("##symbolfilter", state.symbol_filter, "Filter symbols");
  const std::vector<std::size_t> listed = symbol_listing(document, state);
  ImGui::TextDisabled("%zu of %zu symbols", listed.size(),
                      document.loaded.image.symbols.size());

  const ImGuiTableFlags flags = ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_RowBg |
                                ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV;
  if (!ImGui::BeginTable("##symbols", 5, flags)) {
    return;
  }
  ImGui::TableSetupScrollFreeze(0, 1);
  ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch, 1.0f);
  ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthStretch, 0.8f);
  ImGui::TableSetupColumn("Binding", ImGuiTableColumnFlags_WidthStretch, 0.7f);
  ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthStretch, 0.6f);
  ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 3.0f);
  ImGui::TableHeadersRow();

  ImGuiListClipper clipper;
  clipper.Begin(static_cast<int>(listed.size()));
  while (clipper.Step()) {
    for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
      const Symbol& symbol = document.loaded.image.symbols[listed[static_cast<std::size_t>(row)]];
      const std::string shown = symbol_shown_name(state, symbol);
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      if (symbol.address != 0) {
        if (ImGui::Selectable(components::format_address(symbol.address).c_str(),
                              state.selected_address == symbol.address,
                              ImGuiSelectableFlags_SpanAllColumns)) {
          state.navigate_to(symbol.address, &document);
        }
      } else {
        ImGui::TextDisabled("-");
      }
      ImGui::TableSetColumnIndex(1);
      ImGui::TextUnformatted(symbol_kind_name(symbol.kind));
      ImGui::TableSetColumnIndex(2);
      ImGui::TextUnformatted(symbol_binding_name(symbol.binding));
      ImGui::TableSetColumnIndex(3);
      ImGui::Text("%llu", static_cast<unsigned long long>(symbol.size));
      ImGui::TableSetColumnIndex(4);
      ImGui::TextUnformatted(shown.c_str());
      if (ImGui::IsItemHovered() && shown != symbol.name) {
        ImGui::SetTooltip("%s", symbol.name.c_str());
      }
    }
  }
  ImGui::EndTable();
}

}  // namespace donkey::ui::views
