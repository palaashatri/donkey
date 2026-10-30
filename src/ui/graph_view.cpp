#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "components.h"
#include "imgui.h"
#include "views.h"

namespace donkey::ui::views {
namespace {

constexpr float kNodeWidth = 240.0f;
constexpr float kHeaderHeight = 20.0f;
constexpr float kLineHeight = 15.0f;
constexpr float kNodePadding = 6.0f;
constexpr float kColumnGap = 56.0f;
constexpr float kRowGap = 18.0f;
constexpr std::size_t kMaxInstructionsPerNode = 4;
constexpr std::size_t kMaxNodes = 512;

const Function* selected_function(const Document& document, std::uint64_t address) {
  const AnalysisResult& analysis = document.analysis;
  if (analysis.functions.empty()) {
    return nullptr;
  }
  for (const Function& function : analysis.functions) {
    if (function.address == address) {
      return &function;
    }
  }
  for (const Function& function : analysis.functions) {
    if (function.has_extent && address >= function.address && address < function.end_address) {
      return &function;
    }
  }
  return &analysis.functions.front();
}

struct Node {
  const BasicBlock* block = nullptr;
  ImVec2 position;
  ImVec2 size;
};

float node_height(const BasicBlock& block) {
  const std::size_t lines = std::min<std::size_t>(block.instruction_count, kMaxInstructionsPerNode);
  return kHeaderHeight + kNodePadding * 2.0f + static_cast<float>(lines) * kLineHeight;
}

/// Builds a simple layered layout: each block gets a rank from a breadth-first
/// walk of the function's own edges, ranks advance left-to-right and blocks in
/// the same rank stack top-to-bottom. This is deterministic and bounded; it is
/// not a crossing-minimal graph layout.
std::vector<Node> layout(const AnalysisResult& analysis, const Function& function) {
  std::vector<const BasicBlock*> blocks;
  for (const BasicBlock& block : analysis.cfg.blocks) {
    if (block.function == function.id) {
      blocks.push_back(&block);
    }
  }
  if (blocks.empty()) {
    return {};
  }
  std::sort(blocks.begin(), blocks.end(),
            [](const BasicBlock* a, const BasicBlock* b) { return a->address < b->address; });
  const std::size_t limit = std::min(blocks.size(), kMaxNodes);

  std::vector<std::uint32_t> rank(limit, 0);
  std::vector<bool> visited(limit, false);
  // Entry is the lowest-addressed block; seeds are the only entry we know.
  visited[0] = true;
  std::vector<std::size_t> frontier{0};
  while (!frontier.empty()) {
    std::vector<std::size_t> next;
    for (const std::size_t index : frontier) {
      const BasicBlock* source = blocks[index];
      for (const CfgEdge& edge : analysis.cfg.edges) {
        if (edge.to == 0 || edge.from < source->address || edge.from >= source->end_address) {
          continue;
        }
        for (std::size_t candidate = 0; candidate < limit; ++candidate) {
          if (blocks[candidate]->address == edge.to && !visited[candidate]) {
            visited[candidate] = true;
            rank[candidate] = rank[index] + 1;
            next.push_back(candidate);
            break;
          }
        }
      }
    }
    frontier = std::move(next);
  }
  // Unreachable blocks still need a slot: put them after the deepest rank.
  std::uint32_t deepest = 0;
  for (const std::uint32_t value : rank) {
    deepest = std::max(deepest, value);
  }
  for (std::size_t i = 0; i < limit; ++i) {
    if (!visited[i]) {
      rank[i] = deepest + 1;
    }
  }

  std::vector<std::uint32_t> rank_count(deepest + 3, 0);
  for (const std::uint32_t value : rank) {
    ++rank_count[value];
  }

  std::vector<Node> nodes;
  nodes.reserve(limit);
  std::vector<std::uint32_t> slot(deepest + 3, 0);
  for (std::size_t i = 0; i < limit; ++i) {
    const BasicBlock* block = blocks[i];
    const std::uint32_t column = rank[i];
    const std::uint32_t row = slot[column]++;
    const float total = static_cast<float>(rank_count[column]);
    const float y =
        (static_cast<float>(row) - (total - 1.0f) * 0.5f) * (node_height(*block) + kRowGap);
    Node node;
    node.block = block;
    node.size = ImVec2(kNodeWidth, node_height(*block));
    node.position = ImVec2(static_cast<float>(column) * (kNodeWidth + kColumnGap), y);
    nodes.push_back(node);
  }
  return nodes;
}

}  // namespace

void cfg_graph(const Document& document, UiState& state) {
  const Function* function = selected_function(document, state.selected_address);
  if (function == nullptr) {
    ImGui::TextDisabled("No function seeds were discovered.");
    return;
  }

  if (state.graph_document != &document || state.graph_function != function->address) {
    state.graph_document = &document;
    state.graph_function = function->address;
    state.graph_zoom = 0.0f;
    state.graph_pan = ImVec2(0.0f, 0.0f);
  }

  const std::vector<Node> nodes = layout(document.analysis, *function);
  if (nodes.empty()) {
    ImGui::TextDisabled("No basic blocks for this function.");
    return;
  }

  components::heading("Control-flow graph");
  ImGui::SameLine();
  ImGui::TextDisabled("%s", components::format_address(function->address).c_str());
  ImGui::SameLine();
  components::badge(
      document.analysis.cfg.partial ? "Partial" : "Complete",
      components::status_color(document.analysis.cfg.partial ? "Partial" : "Complete"));
  ImGui::SameLine();
  ImGui::TextDisabled("%zu blocks, estimated extents", nodes.size());

  ImGui::SameLine();
  if (ImGui::SmallButton("Fit")) {
    state.graph_zoom = 0.0f;
    state.graph_pan = ImVec2(0.0f, 0.0f);
    state.graph_user_adjusted = false;
  }
  ImGui::SameLine();
  ImGui::TextDisabled("drag to pan, wheel to zoom, click a block to select");

  const ImVec2 canvas_origin = ImGui::GetCursorScreenPos();
  ImVec2 canvas_size = ImGui::GetContentRegionAvail();
  canvas_size.x = std::max(canvas_size.x, 1.0f);
  canvas_size.y = std::max(canvas_size.y, 1.0f);
  ImDrawList* draw = ImGui::GetWindowDrawList();
  const ImVec2 canvas_end(canvas_origin.x + canvas_size.x, canvas_origin.y + canvas_size.y);
  draw->PushClipRect(canvas_origin, canvas_end, true);
  draw->AddRectFilled(canvas_origin, canvas_end, IM_COL32(18, 20, 24, 255));

  // Compute the content bounds so the initial view fits.
  ImVec2 min(0.0f, 0.0f);
  ImVec2 max(0.0f, 0.0f);
  for (const Node& node : nodes) {
    min.x = std::min(min.x, node.position.x);
    min.y = std::min(min.y, node.position.y);
    max.x = std::max(max.x, node.position.x + node.size.x);
    max.y = std::max(max.y, node.position.y + node.size.y);
  }
  const ImVec2 content_size(max.x - min.x, max.y - min.y);
  const float fit_zoom =
      std::min(1.0f, std::min((canvas_size.x - 40.0f) / std::max(content_size.x, 1.0f),
                              (canvas_size.y - 40.0f) / std::max(content_size.y, 1.0f)));
  const bool canvas_changed = std::abs(canvas_size.x - state.graph_canvas_size.x) > 1.0f ||
                              std::abs(canvas_size.y - state.graph_canvas_size.y) > 1.0f;
  if (state.graph_zoom <= 0.0f || (!state.graph_user_adjusted && canvas_changed)) {
    state.graph_zoom = fit_zoom > 0.05f ? fit_zoom : 0.05f;
    state.graph_pan = ImVec2(
        (canvas_size.x - content_size.x * state.graph_zoom) * 0.5f - min.x * state.graph_zoom,
        (canvas_size.y - content_size.y * state.graph_zoom) * 0.5f - min.y * state.graph_zoom);
    state.graph_canvas_size = canvas_size;
  }

  ImGui::InvisibleButton("##cfgcanvas", canvas_size,
                         ImGuiButtonFlags_MouseButtonLeft | ImGuiButtonFlags_MouseButtonRight);
  if (ImGui::IsItemHovered()) {
    const float wheel = ImGui::GetIO().MouseWheel;
    if (wheel != 0.0f) {
      const float previous = state.graph_zoom;
      const float updated = std::clamp(previous * (wheel > 0.0f ? 1.15f : 0.87f), 0.05f, 4.0f);
      const ImVec2 mouse(ImGui::GetIO().MousePos.x - canvas_origin.x,
                         ImGui::GetIO().MousePos.y - canvas_origin.y);
      state.graph_pan.x = mouse.x - (mouse.x - state.graph_pan.x) * (updated / previous);
      state.graph_pan.y = mouse.y - (mouse.y - state.graph_pan.y) * (updated / previous);
      state.graph_zoom = updated;
      state.graph_user_adjusted = true;
    }
  }
  if (ImGui::IsItemActive() && ImGui::IsMouseDragging(ImGuiMouseButton_Left)) {
    const ImVec2 delta = ImGui::GetIO().MouseDelta;
    state.graph_pan.x += delta.x;
    state.graph_pan.y += delta.y;
    state.graph_user_adjusted = true;
  }

  const float zoom = state.graph_zoom;
  auto to_screen = [&](const ImVec2& content) {
    return ImVec2(canvas_origin.x + state.graph_pan.x + content.x * zoom,
                  canvas_origin.y + state.graph_pan.y + content.y * zoom);
  };

  // Edges first so nodes sit above them.
  for (const CfgEdge& edge : document.analysis.cfg.edges) {
    const BasicBlock* source = nullptr;
    for (const Node& node : nodes) {
      if (edge.from >= node.block->address && edge.from < node.block->end_address) {
        source = node.block;
        break;
      }
    }
    if (source == nullptr || edge.to == 0) {
      continue;
    }
    const Node* target = nullptr;
    for (const Node& node : nodes) {
      if (node.block->address == edge.to) {
        target = &node;
        break;
      }
    }
    if (target == nullptr) {
      continue;
    }
    const Node* source_node = nullptr;
    for (const Node& node : nodes) {
      if (node.block == source) {
        source_node = &node;
        break;
      }
    }
    if (source_node == nullptr) {
      continue;
    }
    const ImVec2 from = to_screen(ImVec2(source_node->position.x + source_node->size.x,
                                         source_node->position.y + source_node->size.y * 0.5f));
    const ImVec2 to =
        to_screen(ImVec2(target->position.x, target->position.y + target->size.y * 0.5f));
    const float reach = std::max(24.0f, (to.x - from.x) * 0.5f);
    ImU32 colour = IM_COL32(120, 126, 140, 200);
    if (edge.kind == CfgEdgeKind::ConditionalTrue) {
      colour = IM_COL32(96, 196, 128, 220);
    } else if (edge.kind == CfgEdgeKind::ConditionalFalse) {
      colour = IM_COL32(208, 160, 96, 220);
    } else if (edge.kind == CfgEdgeKind::Call) {
      colour = IM_COL32(120, 156, 220, 200);
    } else if (edge.kind == CfgEdgeKind::Indirect) {
      colour = IM_COL32(208, 120, 120, 220);
    }
    draw->AddBezierCubic(from, ImVec2(from.x + reach, from.y), ImVec2(to.x - reach, to.y), to,
                         colour, 1.6f * zoom);
    const ImVec2 direction(to.x - from.x, to.y - from.y);
    const float length = std::sqrt(direction.x * direction.x + direction.y * direction.y);
    if (length > 1.0f) {
      const ImVec2 unit(direction.x / length, direction.y / length);
      const ImVec2 normal(-unit.y, unit.x);
      const float head = 6.0f * zoom;
      const ImVec2 base(to.x - unit.x * head, to.y - unit.y * head);
      draw->AddTriangleFilled(
          to, ImVec2(base.x + normal.x * head * 0.5f, base.y + normal.y * head * 0.5f),
          ImVec2(base.x - normal.x * head * 0.5f, base.y - normal.y * head * 0.5f), colour);
    }
  }

  // Nodes.
  std::uint64_t clicked_address = 0;
  for (const Node& node : nodes) {
    const ImVec2 top_left = to_screen(node.position);
    const ImVec2 bottom_right =
        to_screen(ImVec2(node.position.x + node.size.x, node.position.y + node.size.y));
    const bool selected = state.selected_address >= node.block->address &&
                          state.selected_address < node.block->end_address;
    const ImU32 background = selected ? IM_COL32(46, 58, 76, 255) : IM_COL32(30, 33, 40, 255);
    const ImU32 border = selected ? IM_COL32(120, 170, 255, 255) : IM_COL32(70, 76, 90, 255);
    draw->AddRectFilled(top_left, bottom_right, background, 4.0f * zoom);
    draw->AddRect(top_left, bottom_right, border, 4.0f * zoom, 0, 1.5f * zoom);

    const ImU32 header_colour = selected ? IM_COL32(64, 82, 108, 255) : IM_COL32(40, 45, 55, 255);
    draw->AddRectFilled(top_left, ImVec2(bottom_right.x, top_left.y + kHeaderHeight * zoom),
                        header_colour, 4.0f * zoom);
    char label[64];
    std::snprintf(label, sizeof(label), "loc_%llx",
                  static_cast<unsigned long long>(node.block->address));
    draw->AddText(ImVec2(top_left.x + kNodePadding * zoom, top_left.y + 3.0f * zoom),
                  IM_COL32(200, 210, 230, 255), label);
    if (node.block->instruction_count > 0) {
      char count[32];
      std::snprintf(count, sizeof(count), "%u insn",
                    static_cast<unsigned>(node.block->instruction_count));
      const ImVec2 text_size = ImGui::CalcTextSize(count);
      draw->AddText(
          ImVec2(bottom_right.x - text_size.x - kNodePadding * zoom, top_left.y + 3.0f * zoom),
          IM_COL32(140, 148, 165, 255), count);
    }

    float line_y = top_left.y + (kHeaderHeight + kNodePadding) * zoom;
    const std::size_t shown =
        std::min<std::size_t>(node.block->instruction_count, kMaxInstructionsPerNode);
    for (std::size_t i = 0; i < shown; ++i) {
      const std::size_t index = node.block->first_instruction + i;
      if (index >= document.analysis.instructions.size()) {
        break;
      }
      const Instruction& instruction = document.analysis.instructions[index];
      char text[96];
      std::snprintf(text, sizeof(text), "%s %s", instruction.mnemonic.c_str(),
                    instruction.operands.c_str());
      draw->AddText(ImVec2(top_left.x + kNodePadding * zoom, line_y), IM_COL32(170, 180, 200, 255),
                    text);
      line_y += kLineHeight * zoom;
    }
    if (node.block->instruction_count > kMaxInstructionsPerNode) {
      draw->AddText(ImVec2(top_left.x + kNodePadding * zoom, line_y), IM_COL32(120, 128, 145, 255),
                    "...");
    }

    // Hit test in screen space. Record the hit and apply it after the loop so
    // the clip rect is always popped.
    if (clicked_address == 0 && ImGui::IsMouseClicked(ImGuiMouseButton_Left) &&
        ImGui::IsItemHovered()) {
      const ImVec2 mouse = ImGui::GetIO().MousePos;
      if (mouse.x >= top_left.x && mouse.x <= bottom_right.x && mouse.y >= top_left.y &&
          mouse.y <= bottom_right.y) {
        clicked_address = node.block->address;
        if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
          if (node.block->instruction_count > 0) {
            const std::size_t last_idx =
                node.block->first_instruction + node.block->instruction_count - 1;
            if (last_idx < document.analysis.instructions.size()) {
              const auto& last_ins = document.analysis.instructions[last_idx];
              if (last_ins.direct_target.has_value()) {
                clicked_address = last_ins.direct_target.value();
              }
            }
          }
        }
      }
    }
  }

  if (clicked_address != 0) {
    state.navigate_to(clicked_address, &document);
  }

  draw->PopClipRect();
}

}  // namespace donkey::ui::views
