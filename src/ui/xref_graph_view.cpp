// The cross-reference graph window (G17): the call neighbourhood of the selected function, drawn as
// nodes and edges. Callers are on the left and callees on the right, one column per call depth. The
// nodes come from the analysis's call graph, bounded by a depth and a node limit; nothing is
// guessed (indirect calls are not in the call graph and are not drawn).

#include <algorithm>
#include <cstdio>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "components.h"
#include "imgui.h"
#include "names.h"
#include "views.h"
#include "workspace.h"

namespace donkey::ui::views {
namespace {

constexpr float kColumnWidth = 240.0f;
constexpr float kRowHeight = 34.0f;
constexpr float kNodeWidth = 210.0f;
constexpr float kNodeHeight = 26.0f;

const Function* function_at_or_containing(const Document& document, std::uint64_t address) {
  const Function* best = nullptr;
  for (const Function& function : document.analysis.functions) {
    if (function.address == address) {
      return &function;
    }
    if (function.has_extent && address >= function.address && address < function.end_address &&
        (best == nullptr || function.address > best->address)) {
      best = &function;
    }
  }
  return best;
}

}  // namespace

XrefNeighbourhood xref_neighbourhood(const Document& document, UiState& state, std::uint64_t center,
                                     int depth, std::size_t max_nodes) {
  XrefNeighbourhood out;
  out.center = center;
  std::map<std::uint64_t, int> level_of;  // address -> signed level; the centre is 0
  level_of[center] = 0;
  const CallGraph& graph = document.analysis.call_graph;

  // Callers, one level per step outward, then callees the same way. A node is added once, at the
  // shallowest level it is reached.
  const auto expand = [&](bool upward) {
    std::vector<std::uint64_t> frontier{center};
    for (int step = 1; step <= depth && !frontier.empty(); ++step) {
      std::vector<std::uint64_t> next;
      for (const std::uint64_t node : frontier) {
        const auto edges = upward ? graph.callers_of(node) : graph.callees_of(node);
        for (const CallGraphEdge& edge : edges) {
          const std::uint64_t other = upward ? edge.caller : edge.callee;
          if (level_of.count(other) != 0) {
            continue;
          }
          if (level_of.size() >= max_nodes) {
            out.truncated = true;
            return;
          }
          level_of[other] = upward ? -step : step;
          next.push_back(other);
        }
      }
      frontier = std::move(next);
    }
  };
  expand(true);
  expand(false);

  for (const auto& [address, level] : level_of) {
    XrefNode node;
    node.address = address;
    node.level = level;
    const Function* function = function_at_or_containing(document, address);
    node.raw = function != nullptr ? function->name : components::format_address(address);
    node.shown = cached_readable_name(state.readable_names, node.raw);
    out.nodes.push_back(std::move(node));
  }
  // Edges between nodes in the set, from the call graph (each call once).
  for (const auto& [address, level] : level_of) {
    for (const CallGraphEdge& edge : graph.callees_of(address)) {
      if (level_of.count(edge.callee) != 0) {
        XrefEdge e{address, edge.callee};
        if (std::find(out.edges.begin(), out.edges.end(), e) == out.edges.end()) {
          out.edges.push_back(e);
        }
      }
    }
  }
  return out;
}

void xref_graph(const Document& document, UiState& state) {
  const Function* selected = function_at_or_containing(document, state.selected_address);
  if (selected == nullptr) {
    ImGui::TextDisabled("Select a function to see its callers and callees.");
    return;
  }
  static const char* const kDepths =
      "1 call deep\0"
      "2 calls deep\0";
  int depth_index = state.xref_depth - 1;
  ImGui::SetNextItemWidth(160.0f);
  if (ImGui::Combo("##xrefdepth", &depth_index, kDepths)) {
    state.xref_depth = depth_index + 1;
  }
  const XrefNeighbourhood graph =
      xref_neighbourhood(document, state, selected->address, state.xref_depth, 64);
  ImGui::SameLine();
  ImGui::TextDisabled("%zu functions, %zu calls%s", graph.nodes.size(), graph.edges.size(),
                      graph.truncated ? " (node limit reached)" : "");

  if (!ImGui::BeginChild("##xrefgraph", ImVec2(0.0f, 0.0f), ImGuiChildFlags_None,
                         ImGuiWindowFlags_HorizontalScrollbar)) {
    ImGui::EndChild();
    return;
  }
  // Positions: a column per level (callers negative, callees positive), nodes in address order.
  std::map<int, int> row_in_level;
  std::unordered_map<std::uint64_t, ImVec2> at;
  int min_level = 0;
  for (const XrefNode& node : graph.nodes) {
    min_level = std::min(min_level, node.level);
  }
  std::vector<const XrefNode*> ordered;
  for (const XrefNode& node : graph.nodes) {
    ordered.push_back(&node);
  }
  std::sort(ordered.begin(), ordered.end(),
            [](const XrefNode* a, const XrefNode* b) { return a->address < b->address; });
  const ImVec2 origin = ImGui::GetCursorScreenPos();
  for (const XrefNode* node : ordered) {
    const int row = row_in_level[node->level]++;
    const float x = static_cast<float>(node->level - min_level) * kColumnWidth + 8.0f;
    const float y = static_cast<float>(row) * kRowHeight + 8.0f;
    at[node->address] = ImVec2(origin.x + x, origin.y + y);
  }
  ImDrawList* draw = ImGui::GetWindowDrawList();
  for (const XrefEdge& edge : graph.edges) {
    const ImVec2 from = at[edge.from];
    const ImVec2 to = at[edge.to];
    draw->AddLine(ImVec2(from.x + kNodeWidth, from.y + kNodeHeight * 0.5f),
                  ImVec2(to.x, to.y + kNodeHeight * 0.5f), IM_COL32(150, 170, 200, 255), 1.5f);
  }
  for (const XrefNode* node : ordered) {
    const ImVec2 corner = at[node->address];
    const bool is_center = node->address == selected->address;
    ImGui::SetCursorScreenPos(corner);
    ImGui::PushID(static_cast<int>(node->address & 0x7fffffffU));
    const bool clicked = ImGui::InvisibleButton("##node", ImVec2(kNodeWidth, kNodeHeight));
    const bool hovered = ImGui::IsItemHovered();
    ImGui::PopID();
    draw->AddRectFilled(corner, ImVec2(corner.x + kNodeWidth, corner.y + kNodeHeight),
                        is_center ? IM_COL32(60, 90, 140, 255) : IM_COL32(40, 46, 56, 255), 4.0f);
    draw->AddRect(corner, ImVec2(corner.x + kNodeWidth, corner.y + kNodeHeight),
                  hovered ? IM_COL32(200, 220, 255, 255) : IM_COL32(90, 100, 120, 255), 4.0f);
    draw->AddText(ImVec2(corner.x + 6.0f, corner.y + 5.0f), IM_COL32(230, 235, 245, 255),
                  node->shown.c_str());
    if (hovered && node->shown != node->raw) {
      ImGui::SetTooltip("%s", node->raw.c_str());
    }
    if (clicked) {
      state.navigate_to(node->address, &document);
    }
  }
  ImGui::EndChild();
}

}  // namespace donkey::ui::views
