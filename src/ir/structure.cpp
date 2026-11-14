#include "ir_internal.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace donkey::detail {

Graph build_graph(const IrFunction& function) {
  Graph graph;
  const std::size_t count = function.blocks.size();
  graph.successors.resize(count);
  graph.predecessors.resize(count);

  auto add_edge = [&](BlockId from, BlockId to) {
    if (to >= count) {
      graph.valid = false;
      return;
    }
    graph.successors[from].push_back(to);
    graph.predecessors[to].push_back(from);
  };

  for (BlockId index = 0; index < count; ++index) {
    if (function.blocks[index].statements.empty()) {
      graph.valid = false;
      continue;
    }
    const IrStatement& terminator = function.blocks[index].statements.back();
    switch (terminator.op) {
      case IrOp::Return:
        break;
      case IrOp::Branch:
        add_edge(index, terminator.a.block);
        break;
      case IrOp::CondBranch:
        add_edge(index, terminator.b.block);
        if (index + 1 < count) {
          add_edge(index, index + 1);
        } else {
          graph.valid = false;
        }
        break;
      case IrOp::Switch:
        if (terminator.a.kind == IrOperandKind::Block && terminator.a.block < count) {
          add_edge(index, terminator.a.block);
        } else {
          graph.valid = false;
        }
        for (const auto& sc : terminator.switch_cases) {
          if (sc.target_block < count) {
            add_edge(index, sc.target_block);
          } else {
            graph.valid = false;
          }
        }
        break;
      default:
        graph.valid = false;
        break;
    }
  }
  for (auto& successors : graph.successors) {
    std::sort(successors.begin(), successors.end());
    successors.erase(std::unique(successors.begin(), successors.end()), successors.end());
  }
  return graph;
}

std::vector<BitSet> compute_dominators(const Graph& graph) {
  const std::size_t count = graph.successors.size();
  std::vector<BitSet> dominators(count, BitSet::full(count));
  if (count == 0) {
    return dominators;
  }
  dominators[0] = BitSet(count);
  dominators[0].set(0);

  bool changed = true;
  while (changed) {
    changed = false;
    for (BlockId index = 1; index < count; ++index) {
      if (graph.predecessors[index].empty()) {
        continue;  // unreachable from the entry
      }
      BitSet next = BitSet::full(count);
      for (const BlockId predecessor : graph.predecessors[index]) {
        next.intersect(dominators[predecessor]);
      }
      next.set(index);
      if (!next.equals(dominators[index])) {
        dominators[index] = std::move(next);
        changed = true;
      }
    }
  }
  return dominators;
}

namespace {

/// Post-dominators over a virtual exit node. Every block without successors (a
/// return) flows into the exit node.
std::vector<BitSet> compute_post_dominators(const Graph& graph) {
  const std::size_t count = graph.successors.size();
  std::vector<BitSet> post(count + 1, BitSet::full(count + 1));
  post[count] = BitSet(count + 1);
  post[count].set(count);

  bool changed = true;
  while (changed) {
    changed = false;
    for (BlockId index = 0; index < count; ++index) {
      BitSet next = BitSet::full(count + 1);
      if (graph.successors[index].empty()) {
        next.intersect(post[count]);
      } else {
        for (const BlockId successor : graph.successors[index]) {
          next.intersect(post[successor]);
        }
      }
      next.set(index);
      if (!next.equals(post[index])) {
        post[index] = std::move(next);
        changed = true;
      }
    }
  }
  return post;
}

/// Immediate post-dominator of each block, or the virtual exit index when the
/// block can reach the exit by more than one path.
std::vector<BlockId> compute_immediate_post_dominators(const std::vector<BitSet>& post) {
  const std::size_t count = post.size() - 1;  // exclude the virtual exit
  std::vector<BlockId> immediate(count, kNoBlock);
  for (BlockId index = 0; index < count; ++index) {
    BlockId best = kNoBlock;
    std::size_t best_count = 0;
    for (BlockId candidate = 0; candidate <= count; ++candidate) {
      if (candidate == index || !post[index].test(candidate)) {
        continue;
      }
      const std::size_t candidate_count = post[candidate].count();
      if (candidate_count > best_count) {
        best_count = candidate_count;
        best = candidate;
      }
    }
    immediate[index] = best;
  }
  return immediate;
}

struct Loop {
  BlockId header = 0;
  BlockId exit = 0;
  bool is_do_while = false;
  bool negate_condition = false;
};

/// A while loop that prints as `for (init; test; step)`: the init is statement `init_index`
/// of the block before the header; the step is statements `step_first` to `step_last` of the
/// latch. A register step is one statement; a counter in memory is three (G04-T3).
struct ForPlan {
  BlockId preheader = 0;
  std::size_t init_index = 0;
  BlockId latch = 0;
  std::size_t step_first = 0;
  std::size_t step_last = 0;
};

/// True when the depth-first search from block 0 finds a retreating edge (one into a block on the
/// current path) whose target does not dominate its source. Such a graph is irreducible: no loop
/// structure can name the target as a header. A reducible graph has only back edges, whose targets
/// dominate their sources.
bool has_irreducible_retreat(const Graph& graph, const std::vector<BitSet>& dominators) {
  const std::size_t count = graph.successors.size();
  if (count == 0) {
    return false;
  }
  std::vector<std::uint8_t> state(count, 0);  // 0 unvisited, 1 on the path, 2 done
  std::vector<std::pair<BlockId, std::size_t>> path{{0, 0}};
  state[0] = 1;
  while (!path.empty()) {
    auto& [block, next] = path.back();
    if (next == graph.successors[block].size()) {
      state[block] = 2;
      path.pop_back();
      continue;
    }
    const BlockId successor = graph.successors[block][next++];
    if (successor >= count) {
      continue;
    }
    if (state[successor] == 1) {
      if (!dominators[block].test(successor)) {
        return true;
      }
    } else if (state[successor] == 0) {
      state[successor] = 1;
      path.emplace_back(successor, 0);
    }
  }
  return false;
}

/// A copy of the function in reverse postorder from the entry, for structuring when the original
/// layout fails (printing only; the IR is not changed). Reverse postorder puts a loop's header
/// before its body and a join after the branches into it, so the structurer's index ranges describe
/// the regions. Only the copy is reordered: a conditional branch falls through to the next block by
/// position, so when its fall-through block is no longer next, a block that only branches to it is
/// inserted right after the conditional branch. The entry block (block 0) is first. Blocks the
/// entry cannot reach are left out (the structurer rejects a function with them anyway).
// Node splitting (goal 8, step 2). An irreducible function has a retreating edge whose target
// does not dominate its source. Splitting that target into one copy per incoming edge removes the
// extra entry; the copies keep the source addresses. The splitter works on an explicit successor
// model (a fall-through is an edge like any other), repeats until no retreating edge is
// irreducible, and then lays the blocks out again with explicit branches. Two bounds keep the code
// size honest: a split may duplicate at most kSplitNodeBound statements, and a function at most
// kSplitFunctionBound in all. Past either bound the function stays labelled.
constexpr std::size_t kSplitNodeBound = 16;
constexpr std::size_t kSplitFunctionBound = 64;
constexpr std::size_t kSplitIterationBound = 64;

struct SplitNode {
  std::vector<IrStatement> body;
  IrStatement terminator;
  std::vector<BlockId>
      successors;  // Branch: one; CondBranch: taken, then fall-through; Return: none
  std::uint64_t address = 0;
  bool live = true;
};

std::string to_hex(std::uint64_t value) {
  char buffer[24];
  std::snprintf(buffer, sizeof buffer, "%llx", static_cast<unsigned long long>(value));
  return buffer;
}

std::optional<IrFunction> split_irreducible(const IrFunction& function, std::string& note) {
  const std::size_t count = function.blocks.size();
  std::vector<SplitNode> nodes;
  nodes.reserve(count);
  for (BlockId index = 0; index < count; ++index) {
    const IrBlock& block = function.blocks[index];
    if (block.statements.empty()) {
      note = "empty block";
      return std::nullopt;
    }
    SplitNode node;
    node.body.assign(block.statements.begin(), block.statements.end() - 1);
    node.terminator = block.statements.back();
    node.address = block.address;
    switch (node.terminator.op) {
      case IrOp::Return:
        break;
      case IrOp::Branch:
        node.successors.push_back(node.terminator.a.block);
        break;
      case IrOp::CondBranch:
        if (index + 1 >= count) {
          note = "a conditional branch falls off the function";
          return std::nullopt;
        }
        node.successors.push_back(node.terminator.b.block);
        node.successors.push_back(index + 1);
        break;
      default:
        note = "a terminator the splitter does not model";
        return std::nullopt;
    }
    for (const BlockId successor : node.successors) {
      if (successor >= count) {
        note = "a branch leaves the function";
        return std::nullopt;
      }
    }
    nodes.push_back(std::move(node));
  }

  std::size_t duplicated = 0;
  for (std::size_t iteration = 0; iteration < kSplitIterationBound; ++iteration) {
    // The graph of the live nodes, and its dominators.
    Graph graph;
    graph.successors.assign(nodes.size(), {});
    graph.predecessors.assign(nodes.size(), {});
    for (BlockId index = 0; index < nodes.size(); ++index) {
      if (!nodes[index].live) {
        continue;
      }
      for (const BlockId successor : nodes[index].successors) {
        graph.successors[index].push_back(successor);
        graph.predecessors[successor].push_back(index);
      }
    }
    const std::vector<BitSet> dominators = compute_dominators(graph);
    // The first retreating edge (by depth-first search from the entry) whose target does not
    // dominate its source names the node to split.
    std::optional<BlockId> target;
    {
      std::vector<std::uint8_t> state(nodes.size(), 0);  // 0 new, 1 on the path, 2 done
      std::vector<std::pair<BlockId, std::size_t>> path{{0, 0}};
      state[0] = 1;
      while (!path.empty() && !target) {
        const BlockId block = path.back().first;
        const std::size_t next = path.back().second;
        if (next == graph.successors[block].size()) {
          state[block] = 2;
          path.pop_back();
          continue;
        }
        path.back().second = next + 1;
        const BlockId successor = graph.successors[block][next];
        if (state[successor] == 1) {
          if (!dominators[block].test(successor)) {
            target = successor;
          }
        } else if (state[successor] == 0) {
          state[successor] = 1;
          path.emplace_back(successor, 0);
        }
      }
    }
    if (!target) {
      // Reducible: lay the live nodes out in reverse postorder, with explicit branches.
      std::vector<BlockId> postorder;
      {
        std::vector<std::uint8_t> seen(nodes.size(), 0);
        std::vector<std::pair<BlockId, std::size_t>> path{{0, 0}};
        seen[0] = 1;
        while (!path.empty()) {
          const BlockId block = path.back().first;
          const std::size_t next = path.back().second;
          if (next == graph.successors[block].size()) {
            postorder.push_back(block);
            path.pop_back();
            continue;
          }
          path.back().second = next + 1;
          const BlockId successor = graph.successors[block][next];
          if (seen[successor] == 0) {
            seen[successor] = 1;
            path.emplace_back(successor, 0);
          }
        }
      }
      std::vector<BlockId> order(postorder.rbegin(), postorder.rend());
      struct Entry {
        BlockId node;
        bool trampoline;
      };
      std::vector<Entry> entries;
      for (std::size_t k = 0; k < order.size(); ++k) {
        entries.push_back({order[k], false});
        const SplitNode& node = nodes[order[k]];
        if (node.terminator.op == IrOp::CondBranch) {
          const BlockId fall = node.successors[1];
          if (k + 1 >= order.size() || order[k + 1] != fall) {
            entries.push_back({fall, true});
          }
        }
      }
      std::vector<BlockId> position(nodes.size(), kNoBlock);
      for (std::size_t i = 0; i < entries.size(); ++i) {
        if (!entries[i].trampoline) {
          position[entries[i].node] = i;
        }
      }
      IrFunction out = function;
      out.blocks.clear();
      for (const Entry& entry : entries) {
        IrBlock block;
        if (entry.trampoline) {
          IrStatement branch;
          branch.op = IrOp::Branch;
          branch.a = IrOperand::block_ref(static_cast<std::uint32_t>(position[entry.node]));
          branch.width = 8;
          block.address = 0;
          block.statements.push_back(branch);
        } else {
          const SplitNode& node = nodes[entry.node];
          block.address = node.address;
          block.statements = node.body;
          IrStatement terminator = node.terminator;
          if (terminator.op == IrOp::Branch) {
            terminator.a =
                IrOperand::block_ref(static_cast<std::uint32_t>(position[node.successors[0]]));
          } else if (terminator.op == IrOp::CondBranch) {
            terminator.b =
                IrOperand::block_ref(static_cast<std::uint32_t>(position[node.successors[0]]));
          }
          block.statements.push_back(terminator);
        }
        out.blocks.push_back(std::move(block));
      }
      return out;
    }

    // Split the target: one copy per incoming edge, each copy with the target's statements and
    // successors. The original loses its predecessors and leaves the function.
    const BlockId split = *target;
    std::size_t edges = 0;  // incoming edges: a branch with both arms to the target counts twice
    for (BlockId index = 0; index < nodes.size(); ++index) {
      if (!nodes[index].live) {
        continue;
      }
      for (const BlockId successor : nodes[index].successors) {
        edges += successor == split ? 1 : 0;
      }
    }
    const std::size_t cost = edges < 2 ? 0 : (edges - 1) * (nodes[split].body.size() + 1);
    if (edges < 2) {
      note = "an irreducible region at 0x" + to_hex(nodes[split].address) +
             " has a single entry edge: it cannot be split";
      return std::nullopt;
    }
    if (cost > kSplitNodeBound || duplicated + cost > kSplitFunctionBound) {
      note = "an irreducible region at 0x" + to_hex(nodes[split].address) +
             ": the node-splitting bound is reached";
      return std::nullopt;
    }
    const SplitNode original = nodes[split];
    std::vector<BlockId> holders;
    for (BlockId index = 0; index < nodes.size(); ++index) {
      if (nodes[index].live) {
        holders.push_back(index);
      }
    }
    for (const BlockId holder : holders) {
      for (std::size_t slot = 0; slot < nodes[holder].successors.size(); ++slot) {
        if (nodes[holder].successors[slot] != split) {
          continue;
        }
        SplitNode copy = original;
        copy.live = true;
        nodes.push_back(std::move(copy));
        nodes[holder].successors[slot] = nodes.size() - 1;
      }
    }
    nodes[split].live = false;
    duplicated += cost;
  }
  note = "the node-splitting iteration bound is reached";
  return std::nullopt;
}

// The split of an irreducible function, or nullopt (with the reason in `note`) when the function is
// reducible or the split is over its bounds.
std::optional<IrFunction> split_if_irreducible(const IrFunction& function, std::string& note) {
  const Graph graph = build_graph(function);
  if (!graph.valid) {
    note = "invalid graph";
    return std::nullopt;
  }
  const std::vector<BitSet> dominators = compute_dominators(graph);
  if (!has_irreducible_retreat(graph, dominators)) {
    note = "reducible";
    return std::nullopt;
  }
  return split_irreducible(function, note);
}

std::optional<IrFunction> reverse_postorder_copy(const IrFunction& function) {
  const std::size_t count = function.blocks.size();
  if (count == 0) {
    return std::nullopt;
  }
  const Graph graph = build_graph(function);
  if (!graph.valid) {
    return std::nullopt;
  }
  // Entry: block 0. A trampoline at block 0 is laid out like any other block; measured on the
  // 1,986-function list, skipping it changed no output (AUDIT, goal 8).
  const BlockId entry = 0;
  // Depth-first postorder from the entry; the reverse of it is the layout.
  std::vector<std::uint8_t> seen(count, 0);
  std::vector<BlockId> postorder;
  std::vector<std::pair<BlockId, std::size_t>> path{{entry, 0}};
  seen[entry] = 1;
  while (!path.empty()) {
    auto& [block, next] = path.back();
    if (next == graph.successors[block].size()) {
      postorder.push_back(block);
      path.pop_back();
      continue;
    }
    const BlockId successor = graph.successors[block][next++];
    if (successor < count && seen[successor] == 0) {
      seen[successor] = 1;
      path.emplace_back(successor, 0);
    }
  }
  for (BlockId block = 0; block < count; ++block) {
    if (seen[block] == 0 && block != 0) {
      return std::nullopt;  // unreachable: do not guess a layout
    }
  }
  std::vector<BlockId> order(postorder.rbegin(), postorder.rend());
  // Lay out: each block, then (for a conditional branch whose fall-through is not next) a block
  // that branches to that fall-through.
  struct Slot {
    BlockId original;  // the block copied, or the fall-through it branches to when trampoline
    bool trampoline;
  };
  std::vector<Slot> slots;
  for (std::size_t k = 0; k < order.size(); ++k) {
    const BlockId block = order[k];
    slots.push_back({block, false});
    const IrStatement& terminator = function.blocks[block].statements.back();
    if (terminator.op == IrOp::CondBranch) {
      const BlockId fallthrough = block + 1;
      const BlockId next_block = k + 1 < order.size() ? order[k + 1] : kNoBlock;
      if (fallthrough >= count) {
        return std::nullopt;
      }
      if (next_block != fallthrough) {
        slots.push_back({fallthrough, true});
      }
    }
  }
  std::vector<std::uint32_t> position(count, 0);
  std::vector<bool> placed(count, false);
  for (std::size_t i = 0; i < slots.size(); ++i) {
    if (!slots[i].trampoline) {
      position[slots[i].original] = static_cast<std::uint32_t>(i);
      placed[slots[i].original] = true;
    }
  }
  IrFunction out = function;
  out.blocks.clear();
  for (std::size_t i = 0; i < slots.size(); ++i) {
    IrBlock block;
    if (slots[i].trampoline) {
      block.address = function.blocks[slots[i].original].address;
      IrStatement branch;
      branch.op = IrOp::Branch;
      branch.width = function.blocks[slots[i].original].statements.empty()
                         ? 8
                         : function.blocks[slots[i].original].statements.back().width;
      branch.a = IrOperand::block_ref(static_cast<std::uint32_t>(i));  // patched below
      block.statements.push_back(branch);
    } else {
      block = function.blocks[slots[i].original];
    }
    out.blocks.push_back(std::move(block));
  }
  // Now point every reference at its new position. A trampoline's target is its fall-through block.
  for (std::size_t i = 0; i < slots.size(); ++i) {
    IrBlock& block = out.blocks[i];
    if (slots[i].trampoline) {
      block.statements.back().a.block = position[slots[i].original];
      continue;
    }
    for (IrStatement& statement : block.statements) {
      for (IrOperand* operand : {&statement.a, &statement.b, &statement.c}) {
        if (operand->kind == IrOperandKind::Block) {
          if (!placed[operand->block]) {
            return std::nullopt;
          }
          operand->block = position[operand->block];
        }
      }
      for (IrSwitchCase& sc : statement.switch_cases) {
        if (!placed[sc.target_block]) {
          return std::nullopt;
        }
        sc.target_block = position[sc.target_block];
      }
    }
    // A conditional branch's fall-through is the block after it: the trampoline placed there, or
    // the block itself when it is next.
  }
  return out;
}

LineTag case_tag(std::uint64_t value) {
  LineTag tag = make_tag(LineKind::Case);
  tag.value = value;
  return tag;
}

/// The tag of `if (C) <jump>;`: `block` is the tested block, `follow` the block the jump names.
LineTag ifjump_tag(BlockId test, LineKind jump, BlockId target) {
  LineTag tag = make_tag(LineKind::IfJump, test, target);
  tag.jump = jump;
  return tag;
}

struct Structurer {
  Structurer(const IrFunction& function,
             const std::map<std::uint64_t, std::string>* string_literals)
      : function_(function), string_literals_(string_literals) {}

  std::optional<std::string> run() {
    const std::size_t count = function_.blocks.size();
    if (count == 0) {
      {
        note("empty function");
        return std::nullopt;
      }
    }
    graph_ = build_graph(function_);
    if (!graph_.valid) {
      {
        note("invalid graph");
        return std::nullopt;
      }
    }
    dominators_ = compute_dominators(graph_);
    if (has_irreducible_retreat(graph_, dominators_)) {
      note("irreducible control flow");
      return std::nullopt;
    }
    for (BlockId block = 1; block < count; ++block) {
      if (graph_.predecessors[block].empty()) {
        {
          note("unreachable block");
          return std::nullopt;
        }  // unreachable block: do not guess a layout
      }
    }
    const std::vector<BitSet> post = compute_post_dominators(graph_);
    immediate_post_dominator_ = compute_immediate_post_dominators(post);
    if (!find_loops()) {
      return std::nullopt;
    }
    plan_for_loops();
    if (!region_closed(0, count)) {
      {
        note("top-level region not closed");
        return std::nullopt;
      }
    }
    emit_range(0, count);
    if (!ok_) {
      {
        note("emission rejected");
        return std::nullopt;
      }
    }
    return out_;
  }

  [[nodiscard]] const std::vector<StructuredLine>& lines() const noexcept { return lines_; }
  [[nodiscard]] const std::string& reason() const noexcept { return reason_; }

  // ---- Fallback structuring (goal 8, step 1) -----------------------------------------------
  // Used only when the layout-based structurer and its reverse-postorder copy both reject a
  // function. An if joins at the branch block's immediate post-dominator, and its arms are the
  // blocks the branch dominates that reach the join without passing it. A loop is the natural
  // loop of its back edges; its follow block is the exit that post-dominates most of the body,
  // ties going to the earlier block in reverse postorder. Other exits print as break (to the
  // follow) or as the return block they reach. Blocks are emitted in control-flow order from each
  // region's entry, which is the reverse postorder of an acyclic region. Every block must be
  // emitted exactly once, or the attempt is rejected, so no statement is dropped.

  struct FbLoop {
    BlockId header = kNoBlock;
    std::vector<bool> body;
    bool has_follow = false;
    BlockId follow = kNoBlock;
  };

  std::optional<std::string> run_fallback() {
    const std::size_t count = function_.blocks.size();
    if (count == 0) {
      note("empty function");
      return std::nullopt;
    }
    graph_ = build_graph(function_);
    if (!graph_.valid) {
      note("invalid graph");
      return std::nullopt;
    }
    dominators_ = compute_dominators(graph_);
    if (has_irreducible_retreat(graph_, dominators_)) {
      note("irreducible control flow");
      return std::nullopt;
    }
    for (BlockId block = 1; block < count; ++block) {
      if (graph_.predecessors[block].empty()) {
        note("unreachable block");
        return std::nullopt;
      }
    }
    post_ = compute_post_dominators(graph_);
    immediate_post_dominator_ = compute_immediate_post_dominators(post_);
    fb_find_loops();
    fb_emitted_.assign(count, false);
    fb_failed_ = false;
    fb_duplicated_ = 0;
    fb_region(0, count, 0);
    if (fb_failed_) {
      return std::nullopt;
    }
    for (BlockId block = 0; block < count; ++block) {
      if (!fb_emitted_[block]) {
        note("a block is not reached by the fallback structurer");
        return std::nullopt;
      }
    }
    return out_;
  }

 private:
  enum class FbEdge : std::uint8_t { Continue, End, Reject };

  std::vector<BitSet> post_;
  std::vector<bool> fb_emitted_;
  bool fb_failed_ = false;
  // Return blocks are copied rather than rejected when reached twice: at most this many statements
  // per copied block, and this many duplicated statements per function.
  static constexpr std::size_t kReturnCopyMaxStatements = 8;
  static constexpr std::size_t kReturnCopyBudget = 64;
  std::size_t fb_duplicated_ = 0;

  [[nodiscard]] bool fb_is_return_block(BlockId block) const {
    return block < function_.blocks.size() && graph_.successors[block].empty() &&
           !function_.blocks[block].statements.empty() &&
           function_.blocks[block].statements.back().op == IrOp::Return;
  }
  std::vector<FbLoop> fb_loops_;
  std::vector<const FbLoop*> fb_active_;

  void fb_fail(const char* why) {
    fb_failed_ = true;
    note(why);
  }

  [[nodiscard]] std::vector<BlockId> fb_reverse_postorder() const {
    const std::size_t count = function_.blocks.size();
    std::vector<BlockId> postorder;
    std::vector<bool> seen(count, false);
    std::vector<std::pair<BlockId, std::size_t>> path{{0, 0}};
    seen[0] = true;
    while (!path.empty()) {
      const BlockId block = path.back().first;
      const std::size_t next = path.back().second;
      if (next == graph_.successors[block].size()) {
        postorder.push_back(block);
        path.pop_back();
        continue;
      }
      path.back().second = next + 1;
      const BlockId successor = graph_.successors[block][next];
      if (!seen[successor]) {
        seen[successor] = true;
        path.emplace_back(successor, 0);
      }
    }
    std::reverse(postorder.begin(), postorder.end());
    return postorder;
  }

  // Whether every path from `start` inside the loop reaches `follow`, or leaves the loop only by a
  // return block (a block with no successors).
  [[nodiscard]] bool reaches_follow_or_return(const std::vector<bool>& body, BlockId start,
                                              BlockId follow) const {
    std::vector<bool> seen(function_.blocks.size(), false);
    std::vector<BlockId> stack{start};
    seen[start] = true;
    while (!stack.empty()) {
      const BlockId block = stack.back();
      stack.pop_back();
      if (block == follow) {
        continue;
      }
      if (!body[block]) {
        if (!graph_.successors[block].empty()) {
          return false;  // leaves the loop by a non-return exit other than the follow
        }
        continue;
      }
      for (const BlockId successor : graph_.successors[block]) {
        if (!seen[successor]) {
          seen[successor] = true;
          stack.push_back(successor);
        }
      }
    }
    return true;
  }

  void fb_find_loops() {
    const std::size_t count = function_.blocks.size();
    std::vector<std::vector<BlockId>> latches(count);
    for (BlockId from = 0; from < count; ++from) {
      for (const BlockId to : graph_.successors[from]) {
        if (dominators_[from].test(to)) {
          latches[to].push_back(from);
        }
      }
    }
    std::vector<std::size_t> rank(count, count);
    const std::vector<BlockId> order = fb_reverse_postorder();
    for (std::size_t index = 0; index < order.size(); ++index) {
      rank[order[index]] = index;
    }
    fb_loops_.clear();
    for (BlockId header = 0; header < count; ++header) {
      if (latches[header].empty()) {
        continue;
      }
      FbLoop loop;
      loop.header = header;
      loop.body.assign(count, false);
      loop.body[header] = true;
      std::vector<BlockId> stack;
      for (const BlockId latch : latches[header]) {
        if (!loop.body[latch]) {
          loop.body[latch] = true;
          stack.push_back(latch);
        }
      }
      while (!stack.empty()) {
        const BlockId block = stack.back();
        stack.pop_back();
        for (const BlockId predecessor : graph_.predecessors[block]) {
          if (!loop.body[predecessor]) {
            loop.body[predecessor] = true;
            stack.push_back(predecessor);
          }
        }
      }
      std::vector<BlockId> exits;
      for (BlockId block = 0; block < count; ++block) {
        if (!loop.body[block]) {
          continue;
        }
        for (const BlockId successor : graph_.successors[block]) {
          if (!loop.body[successor]) {
            exits.push_back(successor);
          }
        }
      }
      std::sort(exits.begin(), exits.end());
      exits.erase(std::unique(exits.begin(), exits.end()), exits.end());
      BlockId best = kNoBlock;
      std::size_t best_count = 0;
      for (const BlockId exit : exits) {
        // A body block counts for this exit when every path from it reaches the exit before it
        // leaves the loop by a non-return exit. A return block is an exit that needs no follow.
        std::size_t post_count = 0;
        for (BlockId block = 0; block < count; ++block) {
          if (loop.body[block] && reaches_follow_or_return(loop.body, block, exit)) {
            ++post_count;
          }
        }
        if (post_count > best_count ||
            (post_count == best_count && best != kNoBlock && rank[exit] < rank[best])) {
          best_count = post_count;
          best = exit;
        }
      }
      if (best != kNoBlock && best_count > 0) {
        loop.has_follow = true;
        loop.follow = best;
      }
      fb_loops_.push_back(std::move(loop));
    }
  }

  [[nodiscard]] FbLoop* fb_loop_headed_by(BlockId block) {
    for (FbLoop& loop : fb_loops_) {
      if (loop.header == block) {
        return &loop;
      }
    }
    return nullptr;
  }

  [[nodiscard]] bool fb_active(BlockId block) const {
    for (const FbLoop* loop : fb_active_) {
      if (loop->header == block) {
        return true;
      }
    }
    return false;
  }

  // Where control goes after a block. Prints continue or break when the target is the header or
  // the follow of the innermost loop; the other exits of a loop are only a return block.
  FbEdge fb_edge(BlockId target, BlockId stop, BlockId root) {
    const std::size_t count = function_.blocks.size();
    if (target == stop) {
      return FbEdge::End;
    }
    if (target >= count) {
      return FbEdge::Reject;
    }
    if (!fb_active_.empty()) {
      const FbLoop& inner = *fb_active_.back();
      if (target == inner.header) {
        line("continue;", 0, make_tag(LineKind::Continue, inner.header));
        return FbEdge::End;
      }
      if (inner.has_follow && target == inner.follow) {
        line("break;", 0, make_tag(LineKind::Break, inner.follow));
        return FbEdge::End;
      }
      for (std::size_t outer = 0; outer + 1 < fb_active_.size(); ++outer) {
        const FbLoop& loop = *fb_active_[outer];
        if (target == loop.header || (loop.has_follow && target == loop.follow)) {
          return FbEdge::Reject;  // a jump out of two loops is not structured here
        }
      }
      if (!inner.body[target] && !fb_is_return_block(target)) {
        return FbEdge::Reject;  // the loop leaves to a block that is not its follow and not a
                                // return
      }
    }
    // A return block has no successors, so it cannot escape the region, and it may be printed
    // again as a copy (see fb_region).
    if (fb_is_return_block(target)) {
      return FbEdge::Continue;
    }
    if (fb_emitted_[target] || !dominators_[target].test(root)) {
      return FbEdge::Reject;
    }
    return FbEdge::Continue;
  }

  void fb_emit_loop(FbLoop& loop) {
    line("while (1) {", 0, make_tag(LineKind::WhileOpen, loop.header, loop.has_follow ? loop.follow : kNoBlock));
    ++indent_;
    fb_active_.push_back(&loop);
    fb_region(loop.header, kNoBlock, loop.header);
    fb_active_.pop_back();
    --indent_;
    line("}", 0, make_tag(LineKind::Close));
  }

  // Emits the blocks from `start` until `stop`, in control-flow order. `root` is the block the
  // region is dominated by: every block it emits must be dominated by it.
  void fb_region(BlockId start, BlockId stop, BlockId root) {
    const std::size_t count = function_.blocks.size();
    BlockId block = start;
    for (;;) {
      if (fb_failed_ || block == stop) {
        return;
      }
      if (block >= count) {
        fb_fail("a branch leaves the function");
        return;
      }
      if (fb_emitted_[block]) {
        // A return block reached again is printed as a copy, within the duplication bound.
        if (!fb_is_return_block(block)) {
          fb_fail("a block is reached twice");
          return;
        }
        const std::size_t size = function_.blocks[block].statements.size();
        if (size > kReturnCopyMaxStatements || fb_duplicated_ + size > kReturnCopyBudget) {
          fb_fail("the return duplication bound is reached");
          return;
        }
        fb_duplicated_ += size;
        emit_statements(block, true);
        return;
      }
      if (FbLoop* loop = fb_loop_headed_by(block); loop != nullptr && !fb_active(block)) {
        fb_emit_loop(*loop);
        if (fb_failed_ || !loop->has_follow) {
          return;
        }
        const FbEdge after = fb_edge(loop->follow, stop, root);
        if (after == FbEdge::Reject) {
          fb_fail("a loop leaves to a block that is not its follow");
          return;
        }
        if (after == FbEdge::End) {
          return;
        }
        block = loop->follow;
        continue;
      }
      fb_emitted_[block] = true;
      const IrStatement& terminator = function_.blocks[block].statements.back();
      if (terminator.op == IrOp::Return) {
        emit_statements(block, true);
        return;
      }
      if (terminator.op == IrOp::Branch) {
        emit_statements(block, false);
        const BlockId target = terminator.a.block;
        const FbEdge next = fb_edge(target, stop, root);
        if (next == FbEdge::Reject) {
          fb_fail("a branch leaves its region");
          return;
        }
        if (next == FbEdge::End) {
          return;
        }
        block = target;
        continue;
      }
      if (terminator.op == IrOp::CondBranch) {
        emit_statements(block, false, /*fold_flags=*/true);
        const BlockId taken = terminator.b.block;
        const BlockId fallthrough = block + 1;
        const BlockId join = immediate_post_dominator_[block];
        if (join == kNoBlock || taken >= count || fallthrough >= count) {
          fb_fail("an if without a join");
          return;
        }
        // An arm that is the innermost loop's header or follow is an edge, printed as continue or
        // break; any other arm is a region up to the join.
        const auto emit_arm = [&](BlockId target, BlockId arm_stop) {
          if (!fb_active_.empty() &&
              (target == fb_active_.back()->header ||
               (fb_active_.back()->has_follow && target == fb_active_.back()->follow))) {
            if (target != arm_stop) {
              fb_edge(target, kNoBlock, block);
            }
            return;
          }
          fb_region(target, arm_stop, block);
        };
        if (taken == join) {
          line("if (" + condition_of(block, true) + ") {", 0, make_tag(LineKind::IfOpen, block, kNoBlock, true));
          ++indent_;
          emit_arm(fallthrough, join);
          --indent_;
          line("}", 0, make_tag(LineKind::Close));
        } else if (fallthrough == join) {
          line("if (" + condition_of(block, false) + ") {", 0, make_tag(LineKind::IfOpen, block));
          ++indent_;
          emit_arm(taken, join);
          --indent_;
          line("}", 0, make_tag(LineKind::Close));
        } else {
          line("if (" + condition_of(block, false) + ") {", 0, make_tag(LineKind::IfOpen, block));
          ++indent_;
          emit_arm(taken, join);
          --indent_;
          line("} else {", 0, make_tag(LineKind::Else));
          ++indent_;
          emit_arm(fallthrough, join);
          --indent_;
          line("}", 0, make_tag(LineKind::Close));
        }
        if (fb_failed_ || join == count) {
          return;  // both arms leave by return
        }
        const FbEdge next = fb_edge(join, stop, root);
        if (next == FbEdge::Reject) {
          fb_fail("an if joins outside its region");
          return;
        }
        if (next == FbEdge::End) {
          return;
        }
        block = join;
        continue;
      }
      fb_fail("a terminator the fallback does not structure");
      return;
    }
  }

 private:
  void line(const std::string& text, std::uint64_t source_address = 0, LineTag tag = {}) {
    if (text.empty()) {  // a marker: zero width, printed nowhere
      lines_.push_back(StructuredLine{std::string(), source_address, tag});
      return;
    }
    std::string indented(static_cast<std::size_t>(indent_) * 2, ' ');
    indented += text;
    out_ += indented;
    out_ += '\n';
    lines_.push_back(StructuredLine{std::move(indented), source_address, tag});
  }

  static std::uint64_t statement_key(BlockId block, std::size_t index) {
    return (static_cast<std::uint64_t>(block) << 32U) | static_cast<std::uint64_t>(index);
  }

  void emit_statements(BlockId block, bool include_terminator, bool fold_flags = false) {
    const IrBlock& body = function_.blocks[block];
    const std::size_t limit = include_terminator || body.statements.empty()
                                  ? body.statements.size()
                                  : body.statements.size() - 1;
    // With fold_flags, the compare that sets the block's branch flags is not printed: the branch
    // condition already says it.
    // The flag setter is the statement right before the branch (an integer or a scalar float
    // compare).
    const IrStatement* folded = nullptr;
    if (fold_flags && body.statements.size() >= 2) {
      const IrStatement& setter = body.statements[body.statements.size() - 2];
      if (setter.op == IrOp::Compare || setter.op == IrOp::Test || setter.op == IrOp::FCompare) {
        folded = &setter;
      }
    }
    line("", 0, make_tag(LineKind::Marker, block));
    for (std::size_t index = 0; index < limit; ++index) {
      if (in_header_.count(statement_key(block, index)) != 0) {
        continue;  // printed in the header of the `for` loop it steps
      }
      if (folded != nullptr && &body.statements[index] == folded) {
        continue;
      }
      const IrStatement* previous = flags_producer(body, index);
      const std::string text =
          render_statement(function_, body.statements[index], previous, string_literals_);
      if (!text.empty()) {
        const LineKind kind =
            body.statements[index].op == IrOp::Return ? LineKind::Return : LineKind::Plain;
        line(text, body.statements[index].source_address, make_tag(kind, block));
        line_of_[statement_key(block, index)] = lines_.size() - 1;
      }
    }
  }

  /// Finds the while loops that can print as `for`: the header's only predecessors are the
  /// block before it and the latch (the loop's last block, which branches back to the
  /// header), the block before the header ends by entering the header and last assigns the
  /// counter, and the latch's last statement before its branch steps the same counter by a
  /// constant. Then no path skips the step and no path runs the init twice, so the step
  /// may be printed in the header. Nothing is changed here; emit_counted_loop does that.
  void plan_for_loops() {
    for (const auto& [header, loop] : loops_) {
      if (loop.is_do_while || header == 0 || loop.exit < header + 2) {
        continue;
      }
      const BlockId latch = loop.exit - 1;
      const IrBlock& preheader = function_.blocks[header - 1];
      const IrBlock& latch_block = function_.blocks[latch];
      const IrBlock& header_block = function_.blocks[header];
      if (preheader.statements.size() < 2 || latch_block.statements.size() < 2 ||
          header_block.statements.empty()) {
        continue;
      }
      const auto& entries = graph_.predecessors[header];
      if (entries.size() != 2 ||
          std::find(entries.begin(), entries.end(), header - 1) == entries.end() ||
          std::find(entries.begin(), entries.end(), latch) == entries.end()) {
        continue;
      }
      const IrStatement& enter = preheader.statements.back();
      const IrStatement& back = latch_block.statements.back();
      if (enter.op != IrOp::Branch || enter.a.block != header || back.op != IrOp::Branch ||
          back.a.block != header) {
        continue;
      }
      const std::size_t init_index = preheader.statements.size() - 2;
      const std::size_t step_last = latch_block.statements.size() - 2;
      const IrStatement& init = preheader.statements[init_index];
      if (!((init.op == IrOp::Assign && init.dest.kind == IrOperandKind::Register) ||
            (init.op == IrOp::Store && init.a.kind == IrOperandKind::Memory))) {
        continue;
      }
      const auto step_first = counter_step_first(latch_block, step_last, init);
      if (!step_first) {
        continue;
      }
      // The header's test must read flags set in the header, so the step's flags do not
      // reach it.
      if (flags_producer(header_block, header_block.statements.size() - 1) == nullptr) {
        continue;
      }
      for_plans_.emplace(header, ForPlan{header - 1, init_index, latch, *step_first, step_last});
    }
  }

  /// The first statement of the step of a `for` loop whose step ends at statement `last` of
  /// `latch`, or nothing. Two shapes qualify. A register counter: `r = r + c;` (or `- c`), where
  /// r is the register that `init` assigns. A counter in memory, which is what a compiler without
  /// optimisation produces: `t = M; t = t + c; M = t;`, where M is a memory operand and t is a
  /// register that no other statement of the function names. The three statements are moved
  /// into the header together, as `M = M + c`.
  std::optional<std::size_t> counter_step_first(const IrBlock& latch, std::size_t last,
                                                const IrStatement& init) const {
    const IrStatement& step = latch.statements[last];
    if (init.op == IrOp::Assign && init.dest.kind == IrOperandKind::Register &&
        (step.op == IrOp::Add || step.op == IrOp::Sub) &&
        step.dest.kind == IrOperandKind::Register && step.dest.reg == init.dest.reg &&
        step.a.kind == IrOperandKind::Register && step.a.reg == step.dest.reg &&
        step.b.kind == IrOperandKind::Constant) {
      return last;
    }
    if (last < 2) {
      return std::nullopt;
    }
    const IrStatement& load = latch.statements[last - 2];
    const IrStatement& add = latch.statements[last - 1];
    if ((load.op != IrOp::Assign && load.op != IrOp::Load) ||
        load.dest.kind != IrOperandKind::Register || load.a.kind != IrOperandKind::Memory ||
        load.dest.width != load.a.width) {
      return std::nullopt;
    }
    const std::string& temp = load.dest.reg;
    if (add.op != IrOp::Add || add.dest.kind != IrOperandKind::Register || add.dest.reg != temp ||
        add.a.kind != IrOperandKind::Register || add.a.reg != temp ||
        add.b.kind != IrOperandKind::Constant || add.width != load.a.width) {
      return std::nullopt;
    }
    if (step.op != IrOp::Store || step.a.kind != IrOperandKind::Memory ||
        !same_memory(step.a, load.a) || step.b.kind != IrOperandKind::Register ||
        step.b.reg != temp || step.b.width != load.a.width) {
      return std::nullopt;
    }
    // The temporary's four uses are the load, the add (written and read) and the store. Any
    // other use would need the value the moved statements leave behind.
    if (count_register_uses(temp) != 4) {
      return std::nullopt;
    }
    return last - 2;
  }

  static bool same_memory(const IrOperand& a, const IrOperand& b) {
    return a.kind == b.kind && a.reg == b.reg && a.index == b.index && a.scale == b.scale &&
           a.constant == b.constant && a.width == b.width;
  }

  /// How many operands of the function name register `name` directly.
  [[nodiscard]] std::size_t count_register_uses(const std::string& name) const {
    std::size_t uses = 0;
    for (const IrBlock& block : function_.blocks) {
      for (const IrStatement& statement : block.statements) {
        for (const IrOperand* operand :
             {&statement.dest, &statement.a, &statement.b, &statement.c}) {
          if (operand->kind == IrOperandKind::Register && operand->reg == name) {
            ++uses;
          }
        }
      }
    }
    return uses;
  }

  /// Prints a planned `for` loop, or returns false when the init is not the last line
  /// emitted before the loop (so the rendering cannot move it). Nothing is changed unless
  /// it returns true.
  bool emit_counted_loop(const Loop& loop, const ForPlan& plan) {
    const auto init_line = line_of_.find(statement_key(plan.preheader, plan.init_index));
    if (init_line == line_of_.end() || init_line->second + 1 != lines_.size()) {
      return false;
    }
    const IrBlock& preheader = function_.blocks[plan.preheader];
    const IrBlock& latch_block = function_.blocks[plan.latch];
    const IrStatement& init = preheader.statements[plan.init_index];
    std::string init_text = render_statement(
        function_, init, flags_producer(preheader, plan.init_index), string_literals_);
    std::string step_text = step_text_of(latch_block, plan);
    if (init_text.size() < 2 || step_text.size() < 2 || init_text.back() != ';' ||
        step_text.back() != ';') {
      return false;
    }
    init_text.pop_back();
    step_text.pop_back();
    const std::string condition = condition_of(loop.header, loop.negate_condition);

    // The init line comes out of the body above; the header prints the init instead.
    lines_.pop_back();
    out_.clear();
    for (const StructuredLine& emitted : lines_) {
      if (!emitted.text.empty()) {
        out_ += emitted.text;
        out_ += '\n';
      }
    }
    for (std::size_t index = plan.step_first; index <= plan.step_last; ++index) {
      in_header_.insert(statement_key(plan.latch, index));
    }
    line("for (" + init_text + "; " + condition + "; " + step_text + ") {", init.source_address, make_tag(LineKind::ForOpen, loop.header, loop.exit, loop.negate_condition, true));
    ++indent_;
    frames_.push_back(LoopFrame{loop.exit, 0});
    emit_range(loop.header + 1, loop.exit, loop.header);
    frames_.pop_back();
    --indent_;
    line("}", 0, make_tag(LineKind::Close));
    for (std::size_t index = plan.step_first; index <= plan.step_last; ++index) {
      in_header_.erase(statement_key(plan.latch, index));
    }
    return true;
  }

  /// The text of a planned loop's step, without its `;`. A register step is rendered as it
  /// is. A memory counter is rendered as one update of the counter's memory, `M = M + c`,
  /// built from the store and the add of the moved statements.
  std::string step_text_of(const IrBlock& latch, const ForPlan& plan) const {
    if (plan.step_first == plan.step_last) {
      return render_statement(function_, latch.statements[plan.step_last],
                              flags_producer(latch, plan.step_last), string_literals_);
    }
    const IrStatement& add = latch.statements[plan.step_last - 1];
    const IrStatement& store = latch.statements[plan.step_last];
    IrStatement update;
    update.op = IrOp::Add;
    update.dest = store.a;
    update.a = store.a;
    update.b = add.b;
    update.width = store.a.width;
    update.source_address = store.source_address;
    return render_statement(function_, update, nullptr, string_literals_);
  }

  bool find_loops() {
    const std::size_t count = graph_.successors.size();
    std::unordered_map<BlockId, BitSet> bodies;
    for (BlockId from = 0; from < count; ++from) {
      for (const BlockId to : graph_.successors[from]) {
        // A back edge is an edge whose target dominates its source (a natural loop). A graph with
        // a retreating edge that is not one is rejected in run() as irreducible.
        if (!dominators_[from].test(to)) {
          continue;
        }
        if (to > from) {
          {
            note("loop header placed after its latch");
            return false;
          }
        }
        auto found = bodies.find(to);
        if (found == bodies.end()) {
          found = bodies.emplace(to, BitSet(count)).first;
          found->second.set(to);
        }
        std::vector<BlockId> worklist{from};
        while (!worklist.empty()) {
          const BlockId current = worklist.back();
          worklist.pop_back();
          if (found->second.test(current)) {
            continue;
          }
          found->second.set(current);
          for (const BlockId predecessor : graph_.predecessors[current]) {
            if (predecessor != to) {
              worklist.push_back(predecessor);
            }
          }
        }
      }
    }

    for (auto& [header, body] : bodies) {
      const std::vector<BlockId> exits = outside_successors(body);
      BlockId exit = kNoBlock;
      if (exits.size() == 1) {
        exit = exits.front();
      } else if (exits.size() > 1) {
        // A `break` leaves the loop from a block that no path back to the header passes
        // through, so the natural body misses it. The loop's own test names the exit, and
        // the blocks the header dominates below that exit belong to the body.
        exit = test_exit(header, body, exits);
        if (exit == kNoBlock) {
          {
            note("loop exit not determined");
            return false;
          }
        }
        for (BlockId block = header + 1; block < exit; ++block) {
          if (!body.test(block) && dominators_[block].test(header)) {
            body.set(block);
          }
        }
        if (outside_successors(body) != std::vector<BlockId>{exit}) {
          {
            note("loop leaves through several blocks");
            return false;
          }
        }
      } else {
        {
          note("loop has no exit");
          return false;
        }
      }
      if (exit <= header) {
        {
          note("loop exit not after its header");
          return false;
        }
      }
      if (body.count() != exit - header) {
        {
          note("loop body not contiguous");
          return false;
        }  // non-contiguous loop body: labels/goto are more honest
      }
      for (BlockId block = header; block < exit; ++block) {
        if (!body.test(block)) {
          {
            note("loop body not contiguous");
            return false;
          }
        }
      }

      Loop loop;
      loop.header = header;
      loop.exit = exit;
      if (!describe_loop(loop, body, exit)) {
        {
          note("loop is not a while or do-while");
          return false;
        }
      }
      loops_.emplace(header, loop);
    }
    return true;
  }

  /// The blocks outside `body` that a block inside it branches to, in block order.
  [[nodiscard]] std::vector<BlockId> outside_successors(const BitSet& body) const {
    std::vector<BlockId> exits;
    for (BlockId block = 0; block < graph_.successors.size(); ++block) {
      if (!body.test(block)) {
        continue;
      }
      for (const BlockId successor : graph_.successors[block]) {
        if (!body.test(successor) &&
            std::find(exits.begin(), exits.end(), successor) == exits.end()) {
          exits.push_back(successor);
        }
      }
    }
    return exits;
  }

  /// The exit that a loop's own test leaves to, when it is one of `exits`. The tests
  /// are the header's conditional branch and the one that ends the body's last block.
  /// kNoBlock unless exactly one of them names an exit.
  [[nodiscard]] BlockId test_exit(BlockId header, const BitSet& body,
                                  const std::vector<BlockId>& exits) const {
    std::vector<BlockId> candidates;
    const auto consider = [&](BlockId block) {
      const IrBlock& candidate = function_.blocks[block];
      if (candidate.statements.empty() || candidate.statements.back().op != IrOp::CondBranch) {
        return;
      }
      const IrStatement& test = candidate.statements.back();
      for (const BlockId target :
           {static_cast<BlockId>(test.b.block), static_cast<BlockId>(block + 1)}) {
        const bool is_exit = std::find(exits.begin(), exits.end(), target) != exits.end();
        if (is_exit &&
            std::find(candidates.begin(), candidates.end(), target) == candidates.end()) {
          candidates.push_back(target);
        }
      }
    };
    consider(header);
    BlockId latch = header;
    for (BlockId block = header; block < graph_.successors.size(); ++block) {
      if (body.test(block)) {
        latch = block;
      }
    }
    consider(latch);
    return candidates.size() == 1 ? candidates.front() : kNoBlock;
  }

  bool describe_loop(Loop& loop, const BitSet& body, BlockId exit) {
    const IrBlock& header = function_.blocks[loop.header];
    if (header.statements.empty()) {
      {
        note("loop header empty");
        return false;
      }
    }
    const IrStatement& terminator = header.statements.back();
    if (terminator.op == IrOp::CondBranch) {
      const BlockId target = terminator.b.block;
      const BlockId fallthrough = loop.header + 1;
      if (target == fallthrough && fallthrough < exit) {
        loop.is_do_while = false;
        loop.negate_condition = false;
        return true;
      }
      if (target == exit && fallthrough < exit) {
        loop.is_do_while = false;
        loop.negate_condition = true;
        return true;
      }
    }

    // A loop of one block is its own latch: the block ends in the test that repeats it.
    const BlockId latch = exit - 1;
    if (latch < loop.header) {
      {
        note("loop latch before header");
        return false;
      }
    }
    const IrBlock& latch_block = function_.blocks[latch];
    if (latch_block.statements.empty()) {
      {
        note("loop latch empty");
        return false;
      }
    }
    const IrStatement& latch_terminator = latch_block.statements.back();
    if (latch_terminator.op != IrOp::CondBranch) {
      {
        note("loop latch not a conditional");
        return false;
      }
    }
    if (latch_terminator.b.block == loop.header && latch + 1 == exit) {
      loop.is_do_while = true;
      loop.negate_condition = false;
      return true;
    }
    if (latch_terminator.b.block == exit && latch + 1 == exit) {
      loop.is_do_while = true;
      loop.negate_condition = true;
      return true;
    }
    (void)body;
    {
      note("loop shape not while or do-while");
      return false;
    }
  }

  /// A region is closed when every edge inside it stays inside, leaves to
  /// `last`, returns, or continues to the enclosing loop header. Non-entry
  /// blocks may only be entered from inside it.
  bool region_closed(BlockId first, BlockId last, BlockId loop_header = kNoBlock,
                     BlockId exit_block = kNoBlock) const {
    const std::size_t count = graph_.successors.size();
    if (last > count || first >= last) {
      {
        note("region bounds");
        return false;
      }
    }
    for (BlockId block = first; block < last; ++block) {
      for (const BlockId successor : graph_.successors[block]) {
        if (successor >= first && successor < last) {
          continue;
        }
        if (successor == last || successor == loop_header || successor == exit_block) {
          continue;
        }
        {
          note("region not closed");
          return false;
        }
      }
      if (block != first) {
        for (const BlockId predecessor : graph_.predecessors[block]) {
          if (predecessor >= first && predecessor < last) {
            continue;
          }
          {
            note("region not closed");
            return false;
          }
        }
      }
    }
    return true;
  }

  std::string condition_of(BlockId branch_block, bool negate) const {
    const IrBlock& block = function_.blocks[branch_block];
    const IrStatement& branch = block.statements.back();
    const IrStatement* previous = flags_producer(block, block.statements.size() - 1);
    return render_condition(function_, branch, previous, negate, string_literals_);
  }

  void emit_range(BlockId first, BlockId last, BlockId loop_header = kNoBlock,
                  BlockId join_exit = kNoBlock) {
    BlockId index = first;
    while (index < last) {
      if (!ok_) {
        return;
      }
      const auto loop = loops_.find(index);
      if (loop != loops_.end()) {
        if (!emit_loop(loop->second, last)) {
          {
            note("loop emission rejected");
            ok_ = false;
          }
          return;
        }
        index = loop->second.exit;
        continue;
      }

      const IrBlock& block = function_.blocks[index];
      const IrStatement& terminator = block.statements.back();
      if (terminator.op == IrOp::Switch) {
        const BlockId join = immediate_post_dominator_[index];
        // Each case's body runs from its target up to the next case target
        // (or the join). It must leave through the join or a return: a case
        // that falls into the next one is not rendered as structured code.
        std::vector<BlockId> starts;
        for (const auto& sc : terminator.switch_cases) {
          starts.push_back(sc.target_block);
        }
        if (terminator.a.kind == IrOperandKind::Block) {
          starts.push_back(terminator.a.block);
        }
        std::sort(starts.begin(), starts.end());
        starts.erase(std::unique(starts.begin(), starts.end()), starts.end());
        auto case_end = [&](BlockId start) {
          BlockId end = join == kNoBlock ? static_cast<BlockId>(function_.blocks.size()) : join;
          for (const BlockId other : starts) {
            if (other > start && other < end) {
              end = other;
            }
          }
          return end;
        };
        for (const BlockId start : starts) {
          const BlockId end = case_end(start);
          if (start >= end || end > function_.blocks.size()) {
            continue;
          }
          const IrStatement& exit = function_.blocks[end - 1].statements.back();
          const bool leaves = exit.op == IrOp::Return ||
                              (exit.op == IrOp::Branch && join != kNoBlock && exit.a.block == join);
          if (!leaves && end != join) {
            {
              note("switch case falls into the next");
              ok_ = false;
            }  // fallthrough between cases: labels/goto are honest
            return;
          }
        }
        emit_statements(index, false);
        if (!frames_.empty()) {
          ++frames_.back().switch_depth;
        }
        line("switch (" + render_operand(function_, terminator.dest, string_literals_) + ") {", 0, make_tag(LineKind::SwitchOpen, index, join));
        ++indent_;
        for (const auto& sc : terminator.switch_cases) {
          char val_buf[32];
          std::snprintf(val_buf, sizeof(val_buf), "0x%llx",
                        static_cast<unsigned long long>(sc.value));
          line("case " + std::string(val_buf) + ":", 0, case_tag(sc.value));
          ++indent_;
          const bool ends_return =
              sc.target_block < function_.blocks.size() &&
              !function_.blocks[sc.target_block].statements.empty() &&
              function_.blocks[sc.target_block].statements.back().op == IrOp::Return;
          if (join != kNoBlock && sc.target_block < join) {
            emit_range(sc.target_block, case_end(sc.target_block), loop_header, join);
          } else if (sc.target_block < function_.blocks.size()) {
            emit_statements(sc.target_block, true);
          }
          if (!ends_return) {
            line("break;", 0, make_tag(LineKind::Break, join));
          }
          --indent_;
        }
        if (terminator.a.kind == IrOperandKind::Block) {
          line("default:", 0, make_tag(LineKind::Default));
          ++indent_;
          const bool ends_return =
              terminator.a.block < function_.blocks.size() &&
              !function_.blocks[terminator.a.block].statements.empty() &&
              function_.blocks[terminator.a.block].statements.back().op == IrOp::Return;
          if (join != kNoBlock && terminator.a.block < join) {
            emit_range(terminator.a.block, case_end(terminator.a.block), loop_header, join);
          } else if (terminator.a.block < function_.blocks.size()) {
            emit_statements(terminator.a.block, true);
          }
          if (!ends_return) {
            line("break;", 0, make_tag(LineKind::Break, join));
          }
          --indent_;
        }
        --indent_;
        line("}", 0, make_tag(LineKind::Close));
        if (!frames_.empty()) {
          --frames_.back().switch_depth;
        }
        // The arms leave to the join, so the region continues there. A join outside the region, or
        // none, would make the next block a case block that is already printed.
        if (join == kNoBlock || join > last) {
          {
            note("switch join outside its region");
            ok_ = false;
          }
          return;
        }
        index = join;
        continue;
      }
      if (terminator.op != IrOp::CondBranch) {
        if (terminator.op == IrOp::Branch) {
          emit_statements(index, false);
          if (!frames_.empty() && terminator.a.block == frames_.back().exit) {
            // Leaving the innermost loop from its body. Inside a switch, `break` would
            // leave the switch instead, so that case is left to labels.
            if (frames_.back().switch_depth > 0) {
              {
                note("break inside a switch inside a loop");
                ok_ = false;
              }
              return;
            }
            line("break;", 0, make_tag(LineKind::Break, frames_.back().exit));
            ++index;
            continue;
          }
          if (terminator.a.block == loop_header) {
            if (index + 1 != last) {
              line("continue;", 0, make_tag(LineKind::Continue, loop_header));
            }
          } else if (terminator.a.block != last && terminator.a.block != join_exit &&
                     terminator.a.block != index + 1) {
            {
              note("branch outside the region");
              ok_ = false;
            }  // branch to a block outside this region: bail out
            return;
          }
        } else {
          emit_statements(index, true);
        }
        ++index;
        continue;
      }

      const BlockId target = terminator.b.block;
      const BlockId fallthrough = index + 1;
      // The block's own statements run before its test: emit them first, or they are dropped.
      emit_statements(index, false, /*fold_flags=*/true);
      // A conditional branch back to the enclosing loop header skips the rest
      // of the iteration, which is exactly `continue`. Branches to the region
      // exit are handled as an if-guard below, never skipped: dropping them
      // would make the following blocks run unconditionally.
      if (loop_header != kNoBlock && target == loop_header) {
        line("if (" + condition_of(index, false) + ") continue;", 0, ifjump_tag(index, LineKind::Continue, loop_header));
        ++index;
        continue;
      }
      // A conditional branch to the innermost loop's exit is `if (cond) break;`, and the code after
      // it continues on the fall-through. Inside a switch, `break` would leave the switch instead.
      if (!frames_.empty() && target == frames_.back().exit) {
        if (frames_.back().switch_depth > 0) {
          {
            note("break inside a switch inside a loop");
            ok_ = false;
          }
          return;
        }
        line("if (" + condition_of(index, false) + ") break;", 0, ifjump_tag(index, LineKind::Break, frames_.back().exit));
        ++index;
        continue;
      }
      const BlockId join = immediate_post_dominator_[index];
      if (join == kNoBlock || join > last) {
        {
          note("if without join");
          ok_ = false;
        }
        return;
      }
      if (join == fallthrough) {
        if (target <= index || target >= join ||
            !region_closed(target, join, loop_header, innermost_loop_exit())) {
          {
            note("if region not closed");
            ok_ = false;
          }
          return;
        }
        line("if (" + condition_of(index, false) + ") {", 0, make_tag(LineKind::IfOpen, index));
        ++indent_;
        emit_range(target, join, loop_header);
        --indent_;
        line("}", 0, make_tag(LineKind::Close));
        index = join;
        continue;
      }
      if (join == target) {
        if (fallthrough <= index || fallthrough >= join ||
            !region_closed(fallthrough, join, loop_header, innermost_loop_exit())) {
          {
            note("if region not closed");
            ok_ = false;
          }
          return;
        }
        line("if (" + condition_of(index, true) + ") {", 0, make_tag(LineKind::IfOpen, index, kNoBlock, true));
        ++indent_;
        emit_range(fallthrough, join, loop_header);
        --indent_;
        line("}", 0, make_tag(LineKind::Close));
        index = join;
        continue;
      }
      if (join <= index || join > last) {
        {
          note("if join order");
          ok_ = false;
        }
        return;
      }
      if (fallthrough < target) {
        if (!region_closed(target, join, loop_header, innermost_loop_exit()) ||
            !region_closed(fallthrough, target, loop_header, join)) {
          {
            note("if region not closed");
            ok_ = false;
          }
          return;
        }
        line("if (" + condition_of(index, false) + ") {", 0, make_tag(LineKind::IfOpen, index));
        ++indent_;
        emit_range(target, join, loop_header);
        --indent_;
        line("} else {", 0, make_tag(LineKind::Else));
        ++indent_;
        emit_range(fallthrough, target, loop_header, join);
        --indent_;
        line("}", 0, make_tag(LineKind::Close));
      } else if (target < fallthrough) {
        if (!region_closed(target, fallthrough, loop_header, innermost_loop_exit()) ||
            !region_closed(fallthrough, join, loop_header, innermost_loop_exit())) {
          {
            note("if region not closed");
            ok_ = false;
          }
          return;
        }
        line("if (" + condition_of(index, false) + ") {", 0, make_tag(LineKind::IfOpen, index));
        ++indent_;
        emit_range(target, fallthrough, loop_header);
        --indent_;
        line("} else {", 0, make_tag(LineKind::Else));
        ++indent_;
        emit_range(fallthrough, join, loop_header);
        --indent_;
        line("}", 0, make_tag(LineKind::Close));
      } else {
        {
          note("branch order");
          ok_ = false;
        }
        return;
      }
      index = join;
    }
  }

  /// The exit of the innermost loop being emitted: a branch there is a `break`, which a region may
  /// contain (kNoBlock outside a loop).
  [[nodiscard]] BlockId innermost_loop_exit() const {
    return frames_.empty() ? kNoBlock : frames_.back().exit;
  }

  bool emit_loop(const Loop& loop, BlockId last) {
    if (loop.exit > last || !region_closed(loop.header, loop.exit)) {
      {
        note("loop region not closed");
        return false;
      }
    }
    if (!loop.is_do_while) {
      const BlockId first_body = loop.header + 1;
      if (first_body >= loop.exit) {
        {
          note("do-while body");
          return false;
        }
      }
      // The header must consist only of the condition that is rendered inline;
      // dropping statements would misrepresent the program.
      const IrBlock& header = function_.blocks[loop.header];
      if (header.statements.size() > 2) {
        {
          note("loop header with a test");
          return false;
        }
      }
      if (header.statements.size() == 2 && header.statements.front().op != IrOp::Compare &&
          header.statements.front().op != IrOp::Test) {
        {
          note("loop header not a test");
          return false;
        }
      }
      if (const auto plan = for_plans_.find(loop.header);
          plan != for_plans_.end() && emit_counted_loop(loop, plan->second)) {
        return true;
      }
      line("while (" + condition_of(loop.header, loop.negate_condition) + ") {", 0, make_tag(LineKind::WhileOpen, loop.header, loop.exit, loop.negate_condition, true));
      ++indent_;
      frames_.push_back(LoopFrame{loop.exit, 0});
      emit_range(first_body, loop.exit, loop.header);
      frames_.pop_back();
      --indent_;
      line("}", 0, make_tag(LineKind::Close));
      return true;
    }

    const BlockId latch = loop.exit - 1;
    const IrBlock& header = function_.blocks[loop.header];
    if (header.statements.empty()) {
      {
        note("loop header empty (do-while)");
        return false;
      }
    }
    if (latch != loop.header) {
      // A multi-block do-while body enters from the header by falling through.
      const IrStatement& terminator = header.statements.back();
      if (terminator.op != IrOp::Branch || terminator.a.block != loop.header + 1) {
        {
          note("loop latch not an exit");
          return false;
        }
      }
    }
    line("do {", 0, make_tag(LineKind::DoOpen, loop.header, loop.exit));
    ++indent_;
    frames_.push_back(LoopFrame{loop.exit, 0});
    if (latch == loop.header) {
      emit_statements(loop.header, false);
    } else {
      emit_statements(loop.header, false);
      emit_range(loop.header + 1, latch, loop.header);
      emit_statements(latch, false);
    }
    frames_.pop_back();
    --indent_;
    line("} while (" + condition_of(latch, loop.negate_condition) + ");", 0, make_tag(LineKind::DoClose, latch, kNoBlock, loop.negate_condition));
    return true;
  }

  const IrFunction& function_;
  const std::map<std::uint64_t, std::string>* string_literals_ = nullptr;
  Graph graph_;
  std::vector<BitSet> dominators_;
  std::vector<BlockId> immediate_post_dominator_;
  std::unordered_map<BlockId, Loop> loops_;
  /// A while loop's `for` form, keyed by its header (see plan_for_loops).
  std::unordered_map<BlockId, ForPlan> for_plans_;
  /// Statements printed in a `for` header rather than in the body (statement_key).
  std::unordered_set<std::uint64_t> in_header_;
  /// The index in lines_ of the line each statement was printed on (statement_key).
  std::unordered_map<std::uint64_t, std::size_t> line_of_;
  std::string out_;
  std::vector<StructuredLine> lines_;
  /// The loops being emitted, innermost last. A branch from a loop body to its exit is a
  /// `break`; `switch_depth` counts the switches the body is inside, where `break` means
  /// something else.
  struct LoopFrame {
    BlockId exit = 0;
    int switch_depth = 0;
  };
  std::vector<LoopFrame> frames_;
  int indent_ = 1;
  bool ok_ = true;
  /// The first reason the structurer rejected this function (empty when it did not).
  mutable std::string reason_;
  void note(const char* why) const {
    if (reason_.empty()) {
      reason_ = why;
    }
  }
};

}  // namespace

std::optional<std::string> format_structured_body(const IrFunction& function) {
  StructureResult result = structure_function(function, nullptr);
  if (result.outcome == StructureOutcome::Labelled) {
    return std::nullopt;
  }
  std::string text;
  for (const StructuredLine& line : result.lines) {
    if (!line.text.empty()) {
      text += line.text + "\n";
    }
  }
  return text;
}

std::optional<std::vector<StructuredLine>> format_structured_body_lines(
    const IrFunction& function, const std::map<std::uint64_t, std::string>* string_literals) {
  StructureResult result = structure_function(function, string_literals);
  if (result.outcome == StructureOutcome::Labelled) {
    return std::nullopt;
  }
  return std::move(result.lines);
}

StructureResult structure_function(const IrFunction& function,
                                   const std::map<std::uint64_t, std::string>* string_literals) {
  StructureResult result;
  // A candidate is accepted only when the control-flow check agrees with the IR. Each candidate is
  // checked against the function it was built from (a reordered copy or a split function has its
  // own blocks).
  const auto accept = [&result](const IrFunction& candidate, const Structurer& structurer) {
    if (auto mismatch = check_structured_control_flow(candidate, structurer.lines())) {
      ++result.oracle_rejections;
      if (result.oracle_detail.empty()) {
        result.oracle_detail = *mismatch;
      }
      return false;
    }
    result.lines = structurer.lines();
    return true;
  };
  // The layout as given first, so a function that structures keeps its output; then the
  // reverse-postorder copy, then the fallback, then the split of an irreducible function.
  {
    Structurer structurer(function, string_literals);
    if (structurer.run().has_value() && accept(function, structurer)) {
      result.outcome = StructureOutcome::Structured;
      return result;
    }
    result.legacy_reason = structurer.reason();
  }
  if (auto copy = reverse_postorder_copy(function)) {
    Structurer structurer(*copy, string_literals);
    if (structurer.run().has_value() && accept(*copy, structurer)) {
      result.outcome = StructureOutcome::Structured;
      return result;
    }
    result.legacy_reason = structurer.reason();
  }
  {
    Structurer fallback(function, string_literals);
    if (fallback.run_fallback().has_value() && accept(function, fallback)) {
      result.outcome = StructureOutcome::Structured;
      return result;
    }
    result.legacy_reason = fallback.reason();
  }
  std::string note;
  if (auto split = split_if_irreducible(function, note)) {
    Structurer structurer(*split, string_literals);
    if (structurer.run().has_value() && accept(*split, structurer)) {
      result.outcome = StructureOutcome::Structured;
      return result;
    }
    Structurer split_fallback(*split, string_literals);
    if (split_fallback.run_fallback().has_value() && accept(*split, split_fallback)) {
      result.outcome = StructureOutcome::Structured;
      return result;
    }
    result.legacy_reason = split_fallback.reason();
  }
  // Last, the goto structurer: every valid graph is printed as structured code with gotos for the
  // edges no structure expresses. It is checked like the candidates above.
  if (auto goto_structure = structure_with_gotos(function, string_literals)) {
    if (auto mismatch = check_structured_control_flow(function, goto_structure->lines)) {
      ++result.oracle_rejections;
      if (result.oracle_detail.empty()) {
        result.oracle_detail = *mismatch;
      }
    } else {
      result.lines = std::move(goto_structure->lines);
      result.gotos = goto_structure->gotos;
      result.outcome = result.gotos == 0 ? StructureOutcome::Structured : StructureOutcome::WithGotos;
      return result;
    }
  }
  result.lines.clear();
  result.outcome = StructureOutcome::Labelled;
  return result;
}

std::vector<BlockId> immediate_post_dominators(const IrFunction& function) {
  const Graph graph = build_graph(function);
  if (!graph.valid) {
    return {};
  }
  return compute_immediate_post_dominators(compute_post_dominators(graph));
}

}  // namespace donkey::detail

namespace donkey {

namespace {}  // namespace

StructureVerdict classify_structure(const IrFunction& function) {
  StructureVerdict verdict;
  if (function.blocks.empty()) {
    verdict.reason = "empty function";
    return verdict;
  }
  const detail::Graph graph = detail::build_graph(function);
  if (!graph.valid) {
    verdict.reason = "invalid graph";
    return verdict;
  }
  verdict.irreducible = detail::has_irreducible_retreat(graph, detail::compute_dominators(graph));
  const detail::StructureResult result = detail::structure_function(function, nullptr);
  verdict.gotos = result.gotos;
  verdict.oracle_rejections = result.oracle_rejections;
  verdict.oracle_detail = result.oracle_detail;
  switch (result.outcome) {
    case detail::StructureOutcome::Structured:
      verdict.cls = StructureClass::Structured;
      break;
    case detail::StructureOutcome::WithGotos:
      verdict.cls = StructureClass::GotoStructured;
      verdict.reason = result.legacy_reason;
      break;
    case detail::StructureOutcome::Labelled:
      verdict.cls = StructureClass::Other;
      verdict.reason = "no structure passes the control-flow check";
      break;
  }
  if (verdict.irreducible) {
    // A split that is over its bounds is the reason an irreducible function stays unsplit.
    std::string note;
    if (!detail::split_irreducible(function, note)) {
      verdict.reason = note;
    }
  }
  return verdict;
}

}  // namespace donkey
