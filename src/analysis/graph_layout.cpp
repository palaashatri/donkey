#include "donkey/analysis/graph_layout.h"

#include <algorithm>
#include <unordered_map>

namespace donkey {

GraphLayout layout_function_graph(const ControlFlowGraph& cfg, FunctionId function,
                                  const GraphLayoutOptions& options) {
  GraphLayout layout;
  std::vector<std::size_t> blocks;
  for (std::size_t i = 0; i < cfg.blocks.size(); ++i) {
    if (cfg.blocks[i].function == function) {
      blocks.push_back(i);
    }
  }
  layout.total_blocks = blocks.size();
  if (blocks.empty()) {
    return layout;
  }
  std::sort(blocks.begin(), blocks.end(), [&](std::size_t a, std::size_t b) {
    return cfg.blocks[a].address < cfg.blocks[b].address;
  });
  if (blocks.size() > options.max_nodes) {
    blocks.resize(options.max_nodes);
    layout.truncated = true;
  }
  const std::size_t count = blocks.size();

  // Block start address -> position in `blocks`.
  std::unordered_map<std::uint64_t, std::size_t> by_address;
  by_address.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    by_address.emplace(cfg.blocks[blocks[i]].address, i);
  }
  // Edges sorted by source address, so each block finds its own with a
  // binary search over [address, end_address).
  std::vector<const CfgEdge*> edges;
  edges.reserve(cfg.edges.size());
  for (const CfgEdge& edge : cfg.edges) {
    if (edge.to != 0 && edge.kind != CfgEdgeKind::Call) {
      edges.push_back(&edge);
    }
  }
  std::sort(edges.begin(), edges.end(),
            [](const CfgEdge* a, const CfgEdge* b) { return a->from < b->from; });

  std::vector<std::uint32_t> rank(count, 0);
  std::vector<bool> visited(count, false);
  visited[0] = true;
  std::vector<std::size_t> frontier{0};
  std::uint32_t deepest = 0;
  while (!frontier.empty()) {
    std::vector<std::size_t> next;
    for (const std::size_t index : frontier) {
      const BasicBlock& source = cfg.blocks[blocks[index]];
      auto it = std::lower_bound(
          edges.begin(), edges.end(), source.address,
          [](const CfgEdge* edge, std::uint64_t value) { return edge->from < value; });
      for (; it != edges.end() && (*it)->from < source.end_address; ++it) {
        const auto target = by_address.find((*it)->to);
        if (target == by_address.end() || visited[target->second]) {
          continue;
        }
        visited[target->second] = true;
        rank[target->second] = rank[index] + 1;
        deepest = std::max(deepest, rank[target->second]);
        next.push_back(target->second);
      }
    }
    frontier = std::move(next);
  }
  for (std::size_t i = 0; i < count; ++i) {
    if (!visited[i]) {
      rank[i] = deepest + 1;
    }
  }

  auto height_of = [&](const BasicBlock& block) {
    const std::size_t lines =
        std::min<std::size_t>(block.instruction_count, options.max_lines_per_node);
    return options.header_height + options.node_padding * 2.0f +
           static_cast<float>(lines) * options.line_height;
  };
  std::vector<float> column_height(deepest + 2, 0.0f);
  for (std::size_t i = 0; i < count; ++i) {
    column_height[rank[i]] += height_of(cfg.blocks[blocks[i]]) + options.row_gap;
  }
  // Stack each column top to bottom, centred on y = 0.
  std::vector<float> cursor(deepest + 2, 0.0f);
  for (std::size_t r = 0; r < cursor.size(); ++r) {
    cursor[r] = -column_height[r] * 0.5f;
  }
  layout.nodes.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    const BasicBlock& block = cfg.blocks[blocks[i]];
    GraphNode node;
    node.block_index = blocks[i];
    node.rank = rank[i];
    node.width = options.node_width;
    node.height = height_of(block);
    node.x = static_cast<float>(rank[i]) * (options.node_width + options.column_gap);
    node.y = cursor[rank[i]];
    cursor[rank[i]] += node.height + options.row_gap;
    layout.nodes.push_back(node);
  }
  return layout;
}

}  // namespace donkey
