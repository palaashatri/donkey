#include "ir_internal.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
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

struct Structurer {
  explicit Structurer(const IrFunction& function) : function_(function) {}

  std::optional<std::string> run() {
    const std::size_t count = function_.blocks.size();
    if (count == 0) {
      return std::nullopt;
    }
    graph_ = build_graph(function_);
    if (!graph_.valid) {
      return std::nullopt;
    }
    dominators_ = compute_dominators(graph_);
    for (BlockId block = 1; block < count; ++block) {
      if (graph_.predecessors[block].empty()) {
        return std::nullopt;  // unreachable block: do not guess a layout
      }
    }
    const std::vector<BitSet> post = compute_post_dominators(graph_);
    immediate_post_dominator_ = compute_immediate_post_dominators(post);
    if (!find_loops()) {
      return std::nullopt;
    }
    if (!region_closed(0, count)) {
      return std::nullopt;
    }
    emit_range(0, count);
    if (!ok_) {
      return std::nullopt;
    }
    return out_;
  }

  [[nodiscard]] const std::vector<StructuredLine>& lines() const noexcept { return lines_; }

 private:
  void line(const std::string& text, std::uint64_t source_address = 0) {
    std::string indented(static_cast<std::size_t>(indent_) * 2, ' ');
    indented += text;
    out_ += indented;
    out_ += '\n';
    lines_.push_back(StructuredLine{std::move(indented), source_address});
  }

  void emit_statements(BlockId block, bool include_terminator) {
    const IrBlock& body = function_.blocks[block];
    const std::size_t limit = include_terminator || body.statements.empty()
                                  ? body.statements.size()
                                  : body.statements.size() - 1;
    for (std::size_t index = 0; index < limit; ++index) {
      const IrStatement* previous = index == 0 ? nullptr : &body.statements[index - 1];
      const std::string text = render_statement(function_, body.statements[index], previous);
      if (!text.empty()) {
        line(text, body.statements[index].source_address);
      }
    }
  }

  bool find_loops() {
    const std::size_t count = graph_.successors.size();
    std::unordered_map<BlockId, BitSet> bodies;
    for (BlockId from = 0; from < count; ++from) {
      for (const BlockId to : graph_.successors[from]) {
        if (to > from) {
          continue;
        }
        if (!dominators_[from].test(to)) {
          return false;  // irreducible back edge
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
      std::vector<BlockId> exits;
      for (BlockId block = 0; block < count; ++block) {
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
      if (exits.size() != 1 || exits.front() <= header) {
        return false;
      }
      const BlockId exit = exits.front();
      if (body.count() != exit - header) {
        return false;  // non-contiguous loop body: labels/goto are more honest
      }
      for (BlockId block = header; block < exit; ++block) {
        if (!body.test(block)) {
          return false;
        }
      }

      Loop loop;
      loop.header = header;
      loop.exit = exit;
      if (!describe_loop(loop, body, exit)) {
        return false;
      }
      loops_.emplace(header, loop);
    }
    return true;
  }

  bool describe_loop(Loop& loop, const BitSet& body, BlockId exit) {
    const IrBlock& header = function_.blocks[loop.header];
    if (header.statements.empty()) {
      return false;
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

    const BlockId latch = exit - 1;
    if (latch <= loop.header) {
      return false;
    }
    const IrBlock& latch_block = function_.blocks[latch];
    if (latch_block.statements.empty()) {
      return false;
    }
    const IrStatement& latch_terminator = latch_block.statements.back();
    if (latch_terminator.op != IrOp::CondBranch) {
      return false;
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
    return false;
  }

  /// A region is closed when every edge inside it stays inside, leaves to
  /// `last`, returns, or continues to the enclosing loop header. Non-entry
  /// blocks may only be entered from inside it.
  bool region_closed(BlockId first, BlockId last, BlockId loop_header = kNoBlock,
                     BlockId exit_block = kNoBlock) const {
    const std::size_t count = graph_.successors.size();
    if (last > count || first >= last) {
      return false;
    }
    for (BlockId block = first; block < last; ++block) {
      for (const BlockId successor : graph_.successors[block]) {
        if (successor >= first && successor < last) {
          continue;
        }
        if (successor == last || successor == loop_header || successor == exit_block) {
          continue;
        }
        return false;
      }
      if (block != first) {
        for (const BlockId predecessor : graph_.predecessors[block]) {
          if (predecessor >= first && predecessor < last) {
            continue;
          }
          return false;
        }
      }
    }
    return true;
  }

  std::string condition_of(BlockId branch_block, bool negate) const {
    const IrBlock& block = function_.blocks[branch_block];
    const IrStatement& branch = block.statements.back();
    const IrStatement* previous =
        block.statements.size() >= 2 ? &block.statements[block.statements.size() - 2] : nullptr;
    return render_condition(function_, branch, previous, negate);
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
          ok_ = false;
          return;
        }
        index = loop->second.exit;
        continue;
      }

      const IrBlock& block = function_.blocks[index];
      const IrStatement& terminator = block.statements.back();
      if (terminator.op == IrOp::Switch) {
        const BlockId join = immediate_post_dominator_[index];
        emit_statements(index, false);
        line("switch (" + render_operand(function_, terminator.dest) + ") {");
        ++indent_;
        for (const auto& sc : terminator.switch_cases) {
          char val_buf[32];
          std::snprintf(val_buf, sizeof(val_buf), "0x%llx",
                        static_cast<unsigned long long>(sc.value));
          line("case " + std::string(val_buf) + ":");
          ++indent_;
          const bool ends_return =
              sc.target_block < function_.blocks.size() &&
              !function_.blocks[sc.target_block].statements.empty() &&
              function_.blocks[sc.target_block].statements.back().op == IrOp::Return;
          if (join != kNoBlock && sc.target_block < join) {
            emit_range(sc.target_block, join, loop_header);
          } else if (sc.target_block < function_.blocks.size()) {
            emit_statements(sc.target_block, true);
          }
          if (!ends_return) {
            line("break;");
          }
          --indent_;
        }
        if (terminator.a.kind == IrOperandKind::Block) {
          line("default:");
          ++indent_;
          const bool ends_return =
              terminator.a.block < function_.blocks.size() &&
              !function_.blocks[terminator.a.block].statements.empty() &&
              function_.blocks[terminator.a.block].statements.back().op == IrOp::Return;
          if (join != kNoBlock && terminator.a.block < join) {
            emit_range(terminator.a.block, join, loop_header);
          } else if (terminator.a.block < function_.blocks.size()) {
            emit_statements(terminator.a.block, true);
          }
          if (!ends_return) {
            line("break;");
          }
          --indent_;
        }
        --indent_;
        line("}");
        if (join != kNoBlock && join <= last) {
          index = join;
        } else {
          ++index;
        }
        continue;
      }
      if (terminator.op != IrOp::CondBranch) {
        if (terminator.op == IrOp::Branch) {
          emit_statements(index, false);
          if (terminator.a.block == loop_header) {
            if (index + 1 != last) {
              line("continue;");
            }
          } else if (terminator.a.block != last && terminator.a.block != join_exit) {
            ok_ = false;  // branch to a block outside this region: bail out
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
      // A conditional branch back to the enclosing loop header skips the rest
      // of the iteration, which is exactly `continue`. Branches to the region
      // exit are handled as an if-guard below, never skipped: dropping them
      // would make the following blocks run unconditionally.
      if (loop_header != kNoBlock && target == loop_header) {
        line("if (" + condition_of(index, false) + ") continue;");
        ++index;
        continue;
      }
      const BlockId join = immediate_post_dominator_[index];
      if (join == kNoBlock || join > last) {
        ok_ = false;
        return;
      }
      if (join == fallthrough) {
        if (target <= index || target >= join || !region_closed(target, join, loop_header)) {
          ok_ = false;
          return;
        }
        line("if (" + condition_of(index, false) + ") {");
        ++indent_;
        emit_range(target, join, loop_header);
        --indent_;
        line("}");
        index = join;
        continue;
      }
      if (join == target) {
        if (fallthrough <= index || fallthrough >= join ||
            !region_closed(fallthrough, join, loop_header)) {
          ok_ = false;
          return;
        }
        line("if (" + condition_of(index, true) + ") {");
        ++indent_;
        emit_range(fallthrough, join, loop_header);
        --indent_;
        line("}");
        index = join;
        continue;
      }
      if (join <= index || join > last) {
        ok_ = false;
        return;
      }
      if (fallthrough < target) {
        if (!region_closed(target, join, loop_header) ||
            !region_closed(fallthrough, target, loop_header, join)) {
          ok_ = false;
          return;
        }
        line("if (" + condition_of(index, false) + ") {");
        ++indent_;
        emit_range(target, join, loop_header);
        --indent_;
        line("} else {");
        ++indent_;
        emit_range(fallthrough, target, loop_header, join);
        --indent_;
        line("}");
      } else if (target < fallthrough) {
        if (!region_closed(target, fallthrough, loop_header) ||
            !region_closed(fallthrough, join, loop_header)) {
          ok_ = false;
          return;
        }
        line("if (" + condition_of(index, false) + ") {");
        ++indent_;
        emit_range(target, fallthrough, loop_header);
        --indent_;
        line("} else {");
        ++indent_;
        emit_range(fallthrough, join, loop_header);
        --indent_;
        line("}");
      } else {
        ok_ = false;
        return;
      }
      index = join;
    }
  }

  bool emit_loop(const Loop& loop, BlockId last) {
    if (loop.exit > last || !region_closed(loop.header, loop.exit)) {
      return false;
    }
    if (!loop.is_do_while) {
      const BlockId first_body = loop.header + 1;
      if (first_body >= loop.exit) {
        return false;
      }
      // The header must consist only of the condition that is rendered inline;
      // dropping statements would misrepresent the program.
      const IrBlock& header = function_.blocks[loop.header];
      if (header.statements.size() > 2) {
        return false;
      }
      if (header.statements.size() == 2 && header.statements.front().op != IrOp::Compare &&
          header.statements.front().op != IrOp::Test) {
        return false;
      }
      line("while (" + condition_of(loop.header, loop.negate_condition) + ") {");
      ++indent_;
      emit_range(first_body, loop.exit, loop.header);
      --indent_;
      line("}");
      return true;
    }

    const BlockId latch = loop.exit - 1;
    const IrBlock& header = function_.blocks[loop.header];
    if (header.statements.empty()) {
      return false;
    }
    if (latch != loop.header) {
      // A multi-block do-while body enters from the header by falling through.
      const IrStatement& terminator = header.statements.back();
      if (terminator.op != IrOp::Branch || terminator.a.block != loop.header + 1) {
        return false;
      }
    }
    line("do {");
    ++indent_;
    if (latch == loop.header) {
      emit_statements(loop.header, false);
    } else {
      emit_statements(loop.header, false);
      emit_range(loop.header + 1, latch, loop.header);
      emit_statements(latch, false);
    }
    --indent_;
    line("} while (" + condition_of(latch, loop.negate_condition) + ");");
    return true;
  }

  const IrFunction& function_;
  Graph graph_;
  std::vector<BitSet> dominators_;
  std::vector<BlockId> immediate_post_dominator_;
  std::unordered_map<BlockId, Loop> loops_;
  std::string out_;
  std::vector<StructuredLine> lines_;
  int indent_ = 1;
  bool ok_ = true;
};

}  // namespace

std::optional<std::string> format_structured_body(const IrFunction& function) {
  Structurer structurer(function);
  return structurer.run();
}

std::optional<std::vector<StructuredLine>> format_structured_body_lines(
    const IrFunction& function) {
  Structurer structurer(function);
  if (!structurer.run().has_value()) {
    return std::nullopt;
  }
  return structurer.lines();
}

}  // namespace donkey::detail
