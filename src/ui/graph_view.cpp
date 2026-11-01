#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "components.h"
#include "donkey/analysis/graph_layout.h"
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

/// Build (or reuse) the layout and node-to-node edges of `function`.
const UiState::GraphCache& graph_cache(const Document& document, const Function& function,
                                       UiState& state) {
  auto& cache = state.graph_cache;
  if (cache != nullptr && cache->document == &document && cache->function == function.address) {
    return *cache;
  }
  cache = std::make_shared<UiState::GraphCache>();
  cache->document = &document;
  cache->function = function.address;
  GraphLayoutOptions options;
  options.node_width = kNodeWidth;
  options.header_height = kHeaderHeight;
  options.line_height = kLineHeight;
  options.node_padding = kNodePadding;
  options.column_gap = kColumnGap;
  options.row_gap = kRowGap;
  options.max_lines_per_node = kMaxInstructionsPerNode;
  const ControlFlowGraph& cfg = document.analysis.cfg;
  cache->layout = layout_function_graph(cfg, function.id, options);

  // Node lookup by block start; edges resolved once to node indices.
  std::vector<std::pair<std::uint64_t, std::size_t>> starts;
  starts.reserve(cache->layout.nodes.size());
  for (std::size_t i = 0; i < cache->layout.nodes.size(); ++i) {
    starts.emplace_back(cfg.blocks[cache->layout.nodes[i].block_index].address, i);
  }
  std::sort(starts.begin(), starts.end());
  auto node_starting_at = [&](std::uint64_t address) -> std::optional<std::size_t> {
    auto it =
        std::lower_bound(starts.begin(), starts.end(), std::make_pair(address, std::size_t{0}));
    if (it != starts.end() && it->first == address) {
      return it->second;
    }
    return std::nullopt;
  };
  auto node_containing = [&](std::uint64_t address) -> std::optional<std::size_t> {
    auto it = std::upper_bound(starts.begin(), starts.end(),
                               std::make_pair(address, std::numeric_limits<std::size_t>::max()));
    if (it == starts.begin()) {
      return std::nullopt;
    }
    --it;
    const BasicBlock& block = cfg.blocks[cache->layout.nodes[it->second].block_index];
    if (address >= block.address && address < block.end_address) {
      return it->second;
    }
    return std::nullopt;
  };
  for (const CfgEdge& edge : cfg.edges) {
    if (edge.to == 0) {
      continue;
    }
    const auto from = node_containing(edge.from);
    const auto to = node_starting_at(edge.to);
    if (from && to) {
      cache->edges.push_back({*from, *to, edge.kind});
    }
  }
  return *cache;
}

/// First node whose block contains `query` as an address, or whose
/// instruction text contains it.
std::optional<std::size_t> find_node(const Document& document, const UiState::GraphCache& cache,
                                     const std::string& query) {
  if (query.empty()) {
    return std::nullopt;
  }
  const ControlFlowGraph& cfg = document.analysis.cfg;
  char* end = nullptr;
  const std::uint64_t address = std::strtoull(query.c_str(), &end, 16);
  const bool numeric = end != nullptr && *end == '\0';
  for (std::size_t i = 0; i < cache.layout.nodes.size(); ++i) {
    const BasicBlock& block = cfg.blocks[cache.layout.nodes[i].block_index];
    if (numeric && address >= block.address && address < block.end_address) {
      return i;
    }
    for (std::uint32_t k = 0; k < block.instruction_count; ++k) {
      const std::size_t index = block.first_instruction + k;
      if (index >= document.analysis.instructions.size()) {
        break;
      }
      const Instruction& instruction = document.analysis.instructions[index];
      if ((instruction.mnemonic + " " + instruction.operands).find(query) != std::string::npos) {
        return i;
      }
    }
  }
  return std::nullopt;
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

  const UiState::GraphCache& cache = graph_cache(document, *function, state);
  const std::vector<GraphNode>& nodes = cache.layout.nodes;
  const ControlFlowGraph& cfg = document.analysis.cfg;
  if (nodes.empty()) {
    ImGui::TextDisabled("No basic blocks for this function.");
    return;
  }

  components::heading("Control-flow graph");
  ImGui::SameLine();
  ImGui::TextDisabled("%s", components::format_address(function->address).c_str());
  ImGui::SameLine();
  components::badge(cfg.partial ? "Partial" : "Complete",
                    components::status_color(cfg.partial ? "Partial" : "Complete"));
  ImGui::SameLine();
  if (cache.layout.truncated) {
    ImGui::TextDisabled("%zu of %zu blocks shown (layout limit)", nodes.size(),
                        cache.layout.total_blocks);
  } else {
    ImGui::TextDisabled("%zu blocks, estimated extents", nodes.size());
  }

  ImGui::SameLine();
  if (ImGui::SmallButton("Fit")) {
    state.graph_zoom = 0.0f;
    state.graph_pan = ImVec2(0.0f, 0.0f);
    state.graph_user_adjusted = false;
  }
  ImGui::SameLine();
  ImGui::SetNextItemWidth(200.0f);
  const bool search =
      ImGui::InputTextWithHint("##graph_search", "find address or text", state.graph_search,
                               sizeof(state.graph_search), ImGuiInputTextFlags_EnterReturnsTrue);
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

  // Content bounds so the initial view fits.
  ImVec2 min(0.0f, 0.0f);
  ImVec2 max(0.0f, 0.0f);
  for (const GraphNode& node : nodes) {
    min.x = std::min(min.x, node.x);
    min.y = std::min(min.y, node.y);
    max.x = std::max(max.x, node.x + node.width);
    max.y = std::max(max.y, node.y + node.height);
  }
  const ImVec2 content_size(max.x - min.x, max.y - min.y);
  const float fit_zoom =
      std::min(1.0f, std::min((canvas_size.x - 40.0f) / std::max(content_size.x, 1.0f),
                              (canvas_size.y - 40.0f) / std::max(content_size.y, 1.0f)));
  const bool canvas_changed = std::abs(canvas_size.x - state.graph_canvas_size.x) > 1.0f ||
                              std::abs(canvas_size.y - state.graph_canvas_size.y) > 1.0f;
  if (state.graph_zoom <= 0.0f || (!state.graph_user_adjusted && canvas_changed)) {
    state.graph_zoom = std::clamp(fit_zoom, 0.05f, 1.0f);
    state.graph_pan = ImVec2(
        (canvas_size.x - content_size.x * state.graph_zoom) * 0.5f - min.x * state.graph_zoom,
        (canvas_size.y - content_size.y * state.graph_zoom) * 0.5f - min.y * state.graph_zoom);
    state.graph_canvas_size = canvas_size;
  }
  if (search) {
    if (const auto found = find_node(document, cache, state.graph_search)) {
      const GraphNode& node = nodes[*found];
      state.graph_zoom = std::max(state.graph_zoom, 0.6f);
      state.graph_pan =
          ImVec2(canvas_size.x * 0.5f - (node.x + node.width * 0.5f) * state.graph_zoom,
                 canvas_size.y * 0.5f - (node.y + node.height * 0.5f) * state.graph_zoom);
      state.graph_user_adjusted = true;
      state.navigate_to(cfg.blocks[node.block_index].address, &document);
    }
  }

  ImGui::InvisibleButton("##cfgcanvas", canvas_size,
                         ImGuiButtonFlags_MouseButtonLeft | ImGuiButtonFlags_MouseButtonRight);
  if (ImGui::IsItemHovered()) {
    const float wheel = ImGui::GetIO().MouseWheel;
    if (wheel != 0.0f) {
      const float previous = state.graph_zoom;
      const float updated = std::clamp(previous * (wheel > 0.0f ? 1.15f : 0.87f), 0.02f, 4.0f);
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
  auto to_screen = [&](float x, float y) {
    return ImVec2(canvas_origin.x + state.graph_pan.x + x * zoom,
                  canvas_origin.y + state.graph_pan.y + y * zoom);
  };
  // Anything entirely outside the canvas is skipped, so large graphs cost
  // only what is visible.
  auto visible = [&](ImVec2 a, ImVec2 b) {
    return std::max(a.x, b.x) >= canvas_origin.x && std::min(a.x, b.x) <= canvas_end.x &&
           std::max(a.y, b.y) >= canvas_origin.y && std::min(a.y, b.y) <= canvas_end.y;
  };
  const bool draw_text = zoom >= 0.35f;

  // Edges first so nodes sit above them.
  for (const auto& edge : cache.edges) {
    const GraphNode& source = nodes[edge.from];
    const GraphNode& target = nodes[edge.to];
    const ImVec2 from = to_screen(source.x + source.width, source.y + source.height * 0.5f);
    const ImVec2 to = to_screen(target.x, target.y + target.height * 0.5f);
    if (!visible(from, to)) {
      continue;
    }
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
  for (const GraphNode& node : nodes) {
    const BasicBlock& block = cfg.blocks[node.block_index];
    const ImVec2 top_left = to_screen(node.x, node.y);
    const ImVec2 bottom_right = to_screen(node.x + node.width, node.y + node.height);
    if (!visible(top_left, bottom_right)) {
      continue;
    }
    const bool selected =
        state.selected_address >= block.address && state.selected_address < block.end_address;
    const ImU32 background = selected ? IM_COL32(46, 58, 76, 255) : IM_COL32(30, 33, 40, 255);
    const ImU32 border = selected ? IM_COL32(120, 170, 255, 255) : IM_COL32(70, 76, 90, 255);
    draw->AddRectFilled(top_left, bottom_right, background, 4.0f * zoom);
    draw->AddRect(top_left, bottom_right, border, 4.0f * zoom, 0, 1.5f * zoom);

    const ImU32 header_colour = selected ? IM_COL32(64, 82, 108, 255) : IM_COL32(40, 45, 55, 255);
    draw->AddRectFilled(top_left, ImVec2(bottom_right.x, top_left.y + kHeaderHeight * zoom),
                        header_colour, 4.0f * zoom);
    if (draw_text) {
      char label[64];
      std::snprintf(label, sizeof(label), "loc_%llx",
                    static_cast<unsigned long long>(block.address));
      draw->AddText(ImVec2(top_left.x + kNodePadding * zoom, top_left.y + 3.0f * zoom),
                    IM_COL32(200, 210, 230, 255), label);
      if (block.instruction_count > 0) {
        char count[32];
        std::snprintf(count, sizeof(count), "%u insn",
                      static_cast<unsigned>(block.instruction_count));
        const ImVec2 text_size = ImGui::CalcTextSize(count);
        draw->AddText(
            ImVec2(bottom_right.x - text_size.x - kNodePadding * zoom, top_left.y + 3.0f * zoom),
            IM_COL32(140, 148, 165, 255), count);
      }
      float line_y = top_left.y + (kHeaderHeight + kNodePadding) * zoom;
      const std::size_t shown =
          std::min<std::size_t>(block.instruction_count, kMaxInstructionsPerNode);
      for (std::size_t i = 0; i < shown; ++i) {
        const std::size_t index = block.first_instruction + i;
        if (index >= document.analysis.instructions.size()) {
          break;
        }
        const Instruction& instruction = document.analysis.instructions[index];
        char text[96];
        std::snprintf(text, sizeof(text), "%s %s", instruction.mnemonic.c_str(),
                      instruction.operands.c_str());
        draw->AddText(ImVec2(top_left.x + kNodePadding * zoom, line_y),
                      IM_COL32(170, 180, 200, 255), text);
        line_y += kLineHeight * zoom;
      }
      if (block.instruction_count > kMaxInstructionsPerNode) {
        draw->AddText(ImVec2(top_left.x + kNodePadding * zoom, line_y),
                      IM_COL32(120, 128, 145, 255), "...");
      }
    }

    // Hit test in screen space. Record the hit and apply it after the loop so
    // the clip rect is always popped.
    if (clicked_address == 0 && ImGui::IsMouseClicked(ImGuiMouseButton_Left) &&
        ImGui::IsItemHovered()) {
      const ImVec2 mouse = ImGui::GetIO().MousePos;
      if (mouse.x >= top_left.x && mouse.x <= bottom_right.x && mouse.y >= top_left.y &&
          mouse.y <= bottom_right.y) {
        clicked_address = block.address;
        if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && block.instruction_count > 0) {
          const std::size_t last_idx = block.first_instruction + block.instruction_count - 1;
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

  if (clicked_address != 0) {
    state.navigate_to(clicked_address, &document);
  }

  draw->PopClipRect();
}

}  // namespace donkey::ui::views
