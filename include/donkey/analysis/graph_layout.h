#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "donkey/analysis/cfg.h"

namespace donkey {

struct GraphLayoutOptions {
  float node_width = 240.0f;
  float header_height = 20.0f;
  float line_height = 15.0f;
  float node_padding = 6.0f;
  float column_gap = 56.0f;
  float row_gap = 18.0f;
  std::size_t max_lines_per_node = 4;
  /// Blocks beyond this are left out and `truncated` is set; never silent.
  std::size_t max_nodes = 20'000;
};

struct GraphNode {
  std::size_t block_index = 0;  ///< index into ControlFlowGraph::blocks
  std::uint32_t rank = 0;       ///< breadth-first depth from the entry block
  float x = 0.0f;
  float y = 0.0f;
  float width = 0.0f;
  float height = 0.0f;
};

struct GraphLayout {
  std::vector<GraphNode> nodes;
  std::size_t total_blocks = 0;  ///< blocks the function has, laid out or not
  bool truncated = false;
};

/// Deterministic layered layout of one function's basic blocks: ranks come
/// from a breadth-first walk of the function's direct edges starting at its
/// lowest-addressed block, ranks advance left to right and blocks of a rank
/// stack top to bottom. O((V + E) log V); not crossing-minimal.
/// Unreachable blocks are placed one rank past the deepest.
[[nodiscard]] GraphLayout layout_function_graph(const ControlFlowGraph& cfg, FunctionId function,
                                                const GraphLayoutOptions& options = {});

}  // namespace donkey
