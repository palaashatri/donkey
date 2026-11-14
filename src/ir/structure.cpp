#include "ir_internal.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
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
/// inserted right after the conditional branch. The entry block is first; a trampoline (a block at
/// address 0 that only branches) is not copied: the entry becomes its target. Blocks the entry
/// cannot reach are left out (the structurer rejects a function with them anyway).
std::optional<IrFunction> reverse_postorder_copy(const IrFunction& function) {
  const std::size_t count = function.blocks.size();
  if (count == 0) {
    return std::nullopt;
  }
  const Graph graph = build_graph(function);
  if (!graph.valid) {
    return std::nullopt;
  }
  // Entry: block 0, unless it is a trampoline to another block.
  BlockId entry = 0;
  while (entry < count && function.blocks[entry].address == 0 &&
         function.blocks[entry].statements.size() == 1 &&
         function.blocks[entry].statements.back().op == IrOp::Branch &&
         function.blocks[entry].statements.back().a.kind == IrOperandKind::Block &&
         function.blocks[entry].statements.back().a.block < count) {
    entry = function.blocks[entry].statements.back().a.block;
    if (entry == 0) {
      return std::nullopt;
    }
  }
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

 private:
  void line(const std::string& text, std::uint64_t source_address = 0) {
    std::string indented(static_cast<std::size_t>(indent_) * 2, ' ');
    indented += text;
    out_ += indented;
    out_ += '\n';
    lines_.push_back(StructuredLine{std::move(indented), source_address});
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
        line(text, body.statements[index].source_address);
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
      out_ += emitted.text;
      out_ += '\n';
    }
    for (std::size_t index = plan.step_first; index <= plan.step_last; ++index) {
      in_header_.insert(statement_key(plan.latch, index));
    }
    line("for (" + init_text + "; " + condition + "; " + step_text + ") {", init.source_address);
    ++indent_;
    frames_.push_back(LoopFrame{loop.exit, 0});
    emit_range(loop.header + 1, loop.exit, loop.header);
    frames_.pop_back();
    --indent_;
    line("}");
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
        line("switch (" + render_operand(function_, terminator.dest, string_literals_) + ") {");
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
            emit_range(sc.target_block, case_end(sc.target_block), loop_header, join);
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
            emit_range(terminator.a.block, case_end(terminator.a.block), loop_header, join);
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
        if (!frames_.empty()) {
          --frames_.back().switch_depth;
        }
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
            line("break;");
            ++index;
            continue;
          }
          if (terminator.a.block == loop_header) {
            if (index + 1 != last) {
              line("continue;");
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
        line("if (" + condition_of(index, false) + ") continue;");
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
        line("if (" + condition_of(index, false) + ") break;");
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
            !region_closed(fallthrough, join, loop_header, innermost_loop_exit())) {
          {
            note("if region not closed");
            ok_ = false;
          }
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
        if (!region_closed(target, fallthrough, loop_header, innermost_loop_exit()) ||
            !region_closed(fallthrough, join, loop_header, innermost_loop_exit())) {
          {
            note("if region not closed");
            ok_ = false;
          }
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
      line("while (" + condition_of(loop.header, loop.negate_condition) + ") {");
      ++indent_;
      frames_.push_back(LoopFrame{loop.exit, 0});
      emit_range(first_body, loop.exit, loop.header);
      frames_.pop_back();
      --indent_;
      line("}");
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
    line("do {");
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
    line("} while (" + condition_of(latch, loop.negate_condition) + ");");
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
  // The layout as given first, so a function that structures keeps its output; then the
  // reverse-postorder copy (printing only).
  {
    Structurer structurer(function, nullptr);
    if (auto body = structurer.run()) {
      return body;
    }
  }
  if (auto copy = reverse_postorder_copy(function)) {
    Structurer structurer(*copy, nullptr);
    if (auto body = structurer.run()) {
      return body;
    }
  }
  return std::nullopt;
}

std::optional<std::vector<StructuredLine>> format_structured_body_lines(
    const IrFunction& function, const std::map<std::uint64_t, std::string>* string_literals) {
  {
    Structurer structurer(function, string_literals);
    if (structurer.run().has_value()) {
      return structurer.lines();
    }
  }
  if (auto copy = reverse_postorder_copy(function)) {
    Structurer structurer(*copy, string_literals);
    if (structurer.run().has_value()) {
      return structurer.lines();
    }
  }
  return std::nullopt;
}

}  // namespace donkey::detail

namespace donkey {

namespace {}  // namespace

StructureVerdict classify_structure(const IrFunction& function) {
  if (function.blocks.empty()) {
    return {StructureClass::Other, "empty function"};
  }
  const detail::Graph graph = detail::build_graph(function);
  if (!graph.valid) {
    return {StructureClass::Other, "invalid graph"};
  }
  for (detail::BlockId block = 1; block < function.blocks.size(); ++block) {
    if (graph.predecessors[block].empty()) {
      return {StructureClass::Other, "unreachable block"};
    }
  }
  const std::vector<detail::BitSet> dominators = detail::compute_dominators(graph);
  if (detail::has_irreducible_retreat(graph, dominators)) {
    return {StructureClass::Irreducible, "a retreating edge's target does not dominate its source"};
  }
  std::string reason;
  {
    detail::Structurer structurer(function, nullptr);
    if (structurer.run().has_value()) {
      return {StructureClass::Structured, ""};
    }
    reason = structurer.reason().empty() ? "unclassified" : structurer.reason();
  }
  // The last attempt decides, so its reason is the one reported.
  if (auto copy = detail::reverse_postorder_copy(function)) {
    detail::Structurer structurer(*copy, nullptr);
    if (structurer.run().has_value()) {
      return {StructureClass::Structured, ""};
    }
    reason = structurer.reason().empty() ? "unclassified (copy)" : structurer.reason();
  }
  return {StructureClass::ReducibleRejected, reason};
}

}  // namespace donkey
