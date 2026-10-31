// Graph layout scaling (M3: a 10k-node synthetic graph must lay out without
// hanging the render thread). The layout runs on the render thread each time
// the shown function changes, so it has to stay well under a frame budget's
// order of magnitude even for very large functions.

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <map>
#include <string>

#include "donkey/analysis/analysis.h"
#include "donkey/analysis/graph_layout.h"
#include "donkey/binary/image.h"

namespace {

using donkey::BasicBlock;
using donkey::BasicBlockId;
using donkey::CfgEdge;
using donkey::CfgEdgeKind;
using donkey::ControlFlowGraph;
using donkey::FunctionId;
using donkey::GraphLayoutOptions;

/// `count` blocks of 16 bytes in one function: a chain where every block
/// falls through to the next and every fourth also branches four ahead,
/// plus a few unreachable blocks at the end.
ControlFlowGraph synthetic_function(std::size_t count, std::size_t unreachable = 0) {
  ControlFlowGraph cfg;
  const FunctionId fn{1};
  for (std::size_t i = 0; i < count + unreachable; ++i) {
    BasicBlock block;
    block.id = BasicBlockId{i + 1};
    block.function = fn;
    block.address = 0x1000 + i * 16;
    block.end_address = block.address + 16;
    block.first_instruction = static_cast<std::uint32_t>(i * 4);
    block.instruction_count = 4;
    cfg.blocks.push_back(block);
  }
  for (std::size_t i = 0; i + 1 < count; ++i) {
    const std::uint64_t last = 0x1000 + i * 16 + 12;
    cfg.edges.push_back(CfgEdge{last, 0x1000 + (i + 1) * 16, CfgEdgeKind::ConditionalFalse});
    if (i % 4 == 0 && i + 4 < count) {
      cfg.edges.push_back(CfgEdge{last, 0x1000 + (i + 4) * 16, CfgEdgeKind::ConditionalTrue});
    }
  }
  // An indirect edge with an unknown target must be ignored, not followed.
  cfg.edges.push_back(CfgEdge{0x1000 + 12, 0, CfgEdgeKind::Indirect});
  return cfg;
}

TEST(GraphLayout, TenThousandNodeFunctionLaysOutQuickly) {
  const ControlFlowGraph cfg = synthetic_function(10'000, 5);
  const auto started = std::chrono::steady_clock::now();
  const auto layout = donkey::layout_function_graph(cfg, FunctionId{1});
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - started);
  // Generous for unoptimised builds on slow CI machines; the old layout was
  // quadratic in blocks times edges and took minutes here.
  EXPECT_LT(elapsed.count(), 2000);
  ASSERT_EQ(layout.nodes.size(), 10'005U);
  EXPECT_EQ(layout.total_blocks, 10'005U);
  EXPECT_FALSE(layout.truncated);

  // Entry at rank 0; a block reached by a jump ahead sits at most one rank
  // after the block that reaches it first in breadth-first order.
  std::map<std::size_t, const donkey::GraphNode*> by_block;
  for (const auto& node : layout.nodes) {
    by_block[node.block_index] = &node;
  }
  EXPECT_EQ(by_block[0]->rank, 0U);
  EXPECT_EQ(by_block[4]->rank, 1U);  // 0 -> 4 directly
  EXPECT_EQ(by_block[1]->rank, 1U);  // 0 -> 1 fall-through
  // Unreachable blocks go one rank past the deepest reachable one.
  std::uint32_t deepest = 0;
  for (std::size_t i = 0; i < 10'000; ++i) {
    deepest = std::max(deepest, by_block[i]->rank);
  }
  EXPECT_EQ(by_block[10'000]->rank, deepest + 1);

  // Nodes in the same column never overlap.
  std::map<std::uint32_t, std::vector<const donkey::GraphNode*>> columns;
  for (const auto& node : layout.nodes) {
    columns[node.rank].push_back(&node);
  }
  for (auto& [rank, nodes] : columns) {
    std::sort(nodes.begin(), nodes.end(), [](auto* a, auto* b) { return a->y < b->y; });
    for (std::size_t i = 1; i < nodes.size(); ++i) {
      EXPECT_GE(nodes[i]->y, nodes[i - 1]->y + nodes[i - 1]->height) << "rank " << rank;
    }
  }
}

TEST(GraphLayout, LimitIsReportedNotSilent) {
  const ControlFlowGraph cfg = synthetic_function(300);
  GraphLayoutOptions options;
  options.max_nodes = 100;
  const auto layout = donkey::layout_function_graph(cfg, FunctionId{1}, options);
  EXPECT_EQ(layout.nodes.size(), 100U);
  EXPECT_EQ(layout.total_blocks, 300U);
  EXPECT_TRUE(layout.truncated);
}

TEST(GraphLayout, OtherFunctionsAndEmptyFunctionsAreHandled) {
  const ControlFlowGraph cfg = synthetic_function(10);
  EXPECT_TRUE(donkey::layout_function_graph(cfg, FunctionId{2}).nodes.empty());
  EXPECT_TRUE(donkey::layout_function_graph(ControlFlowGraph{}, FunctionId{1}).nodes.empty());
}

}  // namespace

// ---------------------------------------------------------------------------
// Call graph (M3) over the debuggee built from source on every platform.
// ---------------------------------------------------------------------------

namespace {

TEST(CallGraph, MainCallsTickDirectlyAndIndirectCallsStayUnresolved) {
  auto loaded = donkey::load_binary(DONKEY_TEST_DEBUGGEE_PATH);
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  auto analysis = donkey::analyze(loaded.value().image, loaded.value().data);
  ASSERT_TRUE(analysis.has_value());
  const auto& result = analysis.value();
  std::uint64_t main_address = 0;
  std::uint64_t tick_address = 0;
  for (const auto& function : result.functions) {
    if (function.name == "main" || function.name == "_main") {
      main_address = function.address;
    } else if (function.name.find("donkey_debuggee_tick") != std::string::npos) {
      tick_address = function.address;
    }
  }
  ASSERT_NE(main_address, 0U);
  ASSERT_NE(tick_address, 0U);

  const auto callees = result.call_graph.callees_of(main_address);
  EXPECT_TRUE(std::any_of(callees.begin(), callees.end(),
                          [&](const auto& edge) { return edge.callee == tick_address; }));
  const auto callers = result.call_graph.callers_of(tick_address);
  ASSERT_FALSE(callers.empty());
  for (const auto& edge : callers) {
    EXPECT_EQ(edge.caller, main_address);
    // The site is inside main and decodes as a call to tick.
    EXPECT_GT(edge.site, main_address);
  }
  // Every edge's target comes from a decoded direct call, never a guess.
  for (const auto& edge : result.call_graph.edges) {
    bool found = false;
    for (const auto& instruction : result.instructions) {
      if (instruction.address == edge.site) {
        EXPECT_EQ(instruction.direct_target.value_or(0), edge.callee);
        found = true;
      }
    }
    EXPECT_TRUE(found);
  }
  for (const auto& site : result.call_graph.unresolved) {
    for (const auto& instruction : result.instructions) {
      if (instruction.address == site.site) {
        EXPECT_FALSE(instruction.direct_target.has_value());
      }
    }
  }
}

}  // namespace
