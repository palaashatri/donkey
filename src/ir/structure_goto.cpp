// The goto structurer (G04-T5): the last stage of structure_function.
//
// It prints every block of a valid graph once, as structured C, and uses `goto` only for an edge
// that no structured form expresses. Each block is printed where control first reaches it along a
// path that the rules below can express; every other edge into a printed block is a goto to a label
// on that block. The rules, tried in this order for an edge from the code being printed to a block T
// (`decide`):
//   1. T is where the enclosing region falls out (its stop, when the caller prints it next): nothing.
//   2. T is the header of the innermost loop: `continue;`.
//   3. T is the end (follow) of the innermost loop or switch: `break;`.
//   4. T is not printed yet, is dominated by the region's root and is not the end of an enclosing
//      construct: T is printed here, right after the code before it (sequence).
//   5. Otherwise `goto T;`, with a label on T.
// A conditional branch is printed as if/else with both arms walked up to its immediate
// post-dominator (its join): an arm that reaches the join falls out of the `if` when the join is
// printed after it, and jumps otherwise. A natural loop is printed as `while (test)` when its header
// is a pure test that leaves through one arm, and as `while (1)` otherwise; its follow is its exit
// that most of its body reaches. A switch prints each arm from its target, with `break;` where an arm
// reaches the join.
//
// The region stops are what make the output correct without a second pass over the text: an arm
// falls out only by reaching its stop, so the code after the `if` is the join's code exactly when the
// arm reached it. The control-flow check (check_structured_control_flow) verifies the result anyway.
//
// The emitter runs twice. The first run finds the blocks that a goto names; the second prints the
// labels. Both runs take the same decisions, because labels do not change the structure.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <iterator>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "ir_internal.h"

namespace donkey::detail {
namespace {

enum class Outcome : std::uint8_t { Falls, Jumps };

/// What to do after a block: walk on to `block` (not printed yet), or stop with an outcome.
struct Next {
  bool walk = false;
  BlockId block = kNoBlock;
  Outcome outcome = Outcome::Jumps;
};

/// The region being printed: the block its code is dominated by, and where it ends. `stop` is a block
/// that the region ends at: when `stop_falls`, reaching it falls out (the caller prints it next), and
/// otherwise reaching it is an ordinary edge (a goto, break or continue).
struct Ctx {
  BlockId root = kNoBlock;
  BlockId stop = kNoBlock;
  bool stop_falls = false;
};

/// An enclosing loop or switch: `follow` is where a break goes (kNoBlock when there is none), and
/// `header` is where a continue goes (loops only).
struct Frame {
  bool loop = false;
  BlockId header = kNoBlock;
  BlockId follow = kNoBlock;
};

/// A natural loop: the blocks of its body, its follow, and whether its header is a pure test that
/// leaves through one arm (then `stay` is the arm that stays in the loop).
struct LoopInfo {
  BlockId header = kNoBlock;
  std::vector<bool> body;
  BlockId follow = kNoBlock;
  bool pure = false;
  bool stay_taken = false;  ///< the taken arm stays in the loop (else the fall-through does)
  BlockId stay = kNoBlock;
};

bool is_flag_setter(const IrStatement& statement) {
  return statement.op == IrOp::Compare || statement.op == IrOp::Test ||
         statement.op == IrOp::FCompare;
}

class Emitter {
 public:
  Emitter(const IrFunction& function, const std::map<std::uint64_t, std::string>* literals,
          std::uint32_t rules, std::vector<bool> labelled)
      : function_(function), literals_(literals), rules_(rules), labelled_(std::move(labelled)) {}

  /// False when the graph is not valid (the caller then keeps the labelled form).
  bool prepare() {
    const std::size_t count = function_.blocks.size();
    if (count == 0) {
      return false;
    }
    graph_ = build_graph(function_);
    if (!graph_.valid) {
      return false;
    }
    dominators_ = compute_dominators(graph_);
    ipdom_ = immediate_post_dominators(function_);
    if (ipdom_.size() != count) {
      return false;
    }
    names_.resize(count);
    for (BlockId block = 0; block < count; ++block) {
      const std::uint64_t address = function_.blocks[block].address;
      std::size_t same = 0;
      for (BlockId other = 0; other < count; ++other) {
        same += function_.blocks[other].address == address ? 1 : 0;
      }
      char buffer[64];
      if (same > 1) {
        std::snprintf(buffer, sizeof buffer, "loc_%llx_%zu", static_cast<unsigned long long>(address),
                      static_cast<std::size_t>(block));
      } else {
        std::snprintf(buffer, sizeof buffer, "loc_%llx", static_cast<unsigned long long>(address));
      }
      names_[block] = buffer;
    }
    labelled_.resize(count, false);
    emitted_.assign(count, false);
    loop_of_.assign(count, -1);
    find_loops();
    order_ = reverse_postorder();
    for (BlockId block = 0; block < count; ++block) {
      if (std::find(order_.begin(), order_.end(), block) == order_.end()) {
        order_.push_back(block);  // unreachable: printed after the reachable code
      }
    }
    return true;
  }

  bool run() {
    const std::size_t count = function_.blocks.size();
    // The entry region: its root is the entry, and it has no stop.
    region(0, Ctx{0, kNoBlock, false});
    // Blocks the entry region did not reach (behind gotos only), in reverse postorder.
    for (const BlockId block : order_) {
      if (!emitted_[block]) {
        region(block, Ctx{block, kNoBlock, false});
      }
    }
    for (BlockId block = 0; block < count; ++block) {
      if (!emitted_[block]) {
        return false;  // a block with no printed code: internal error, never printed silently
      }
    }
    return true;
  }

  [[nodiscard]] const std::vector<StructuredLine>& lines() const { return lines_; }
  [[nodiscard]] std::size_t gotos() const { return gotos_; }

  /// The blocks named by a goto in the printed lines.
  [[nodiscard]] std::vector<bool> goto_targets() const {
    std::vector<bool> targets(function_.blocks.size(), false);
    for (const StructuredLine& line : lines_) {
      if (line.tag.kind == LineKind::Goto && line.tag.block != kNoBlock) {
        targets[line.tag.block] = true;
      }
      if (line.tag.kind == LineKind::IfJump && line.tag.jump == LineKind::Goto &&
          line.tag.follow != kNoBlock) {
        targets[line.tag.follow] = true;
      }
    }
    return targets;
  }

 private:
  const IrFunction& function_;
  const std::map<std::uint64_t, std::string>* literals_;
  std::uint32_t rules_;
  std::vector<bool> labelled_;
  Graph graph_;
  std::vector<BitSet> dominators_;
  std::vector<BlockId> ipdom_;
  std::vector<std::string> names_;
  std::vector<bool> emitted_;
  std::vector<int> loop_of_;
  std::vector<LoopInfo> loops_;
  std::vector<BlockId> order_;
  std::vector<Frame> frames_;
  std::vector<StructuredLine> lines_;
  int depth_ = 1;
  std::size_t gotos_ = 0;

  // ---- analysis -----------------------------------------------------------------------------

  std::vector<BlockId> reverse_postorder() const {
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

  /// Whether every path from `start` inside the body reaches `follow`, or leaves the body only by a
  /// return block.
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
          return false;
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

  void find_loops() {
    const std::size_t count = function_.blocks.size();
    std::vector<std::vector<BlockId>> latches(count);
    for (BlockId from = 0; from < count; ++from) {
      for (const BlockId to : graph_.successors[from]) {
        if (dominators_[from].test(to)) {
          latches[to].push_back(from);  // a back edge: its target dominates its source
        }
      }
    }
    const std::vector<BlockId> rpo = reverse_postorder();
    std::vector<std::size_t> rank(count, count);
    for (std::size_t index = 0; index < rpo.size(); ++index) {
      rank[rpo[index]] = index;
    }
    for (BlockId header = 0; header < count; ++header) {
      if (latches[header].empty()) {
        continue;
      }
      LoopInfo loop;
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
      // The follow: the exit most of the body reaches (ties: the earlier one in reverse postorder).
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
      std::size_t best_count = 0;
      for (const BlockId exit : exits) {
        std::size_t reach = 0;
        for (BlockId block = 0; block < count; ++block) {
          if (loop.body[block] && reaches_follow_or_return(loop.body, block, exit)) {
            ++reach;
          }
        }
        if (reach > best_count ||
            (reach == best_count && loop.follow != kNoBlock && rank[exit] < rank[loop.follow])) {
          best_count = reach;
          loop.follow = exit;
        }
      }
      if (loop.follow != kNoBlock && best_count == 0) {
        loop.follow = kNoBlock;
      }
      // A pure test: the header's only statements are a flag setter and its branch, and one arm
      // stays in the body while the other is the follow.
      const IrBlock& header_block = function_.blocks[header];
      const IrStatement& branch = header_block.statements.back();
      if (branch.op == IrOp::CondBranch && loop.follow != kNoBlock && header + 1 < count) {
        const std::size_t size = header_block.statements.size();
        const bool only_test =
            size == 1 || (size == 2 && is_flag_setter(header_block.statements[0]));
        const BlockId taken = branch.b.block;
        const BlockId fall = header + 1;
        const bool taken_in = loop.body[taken];
        const bool fall_in = loop.body[fall];
        if (only_test && taken_in != fall_in) {
          const BlockId leaves = taken_in ? fall : taken;
          if (leaves == loop.follow) {
            loop.pure = true;
            loop.stay_taken = taken_in;
            loop.stay = taken_in ? taken : fall;
          }
        }
      }
      loop_of_[header] = static_cast<int>(loops_.size());
      loops_.push_back(std::move(loop));
    }
  }

  // ---- emission helpers ----------------------------------------------------------------------

  std::size_t push(const std::string& text, std::uint64_t address, LineTag tag) {
    lines_.push_back(StructuredLine{std::string(static_cast<std::size_t>(depth_) * 2, ' ') + text,
                                    address, tag});
    return lines_.size() - 1;
  }

  /// Takes the lines printed since `mark`, out of the output.
  std::vector<StructuredLine> take(std::size_t mark) {
    std::vector<StructuredLine> taken(lines_.begin() + static_cast<std::ptrdiff_t>(mark), lines_.end());
    lines_.resize(mark);
    return taken;
  }

  void put(std::vector<StructuredLine>&& taken) {
    lines_.insert(lines_.end(), std::make_move_iterator(taken.begin()),
                  std::make_move_iterator(taken.end()));
  }

  void emit_goto(BlockId target) {
    push("goto " + names_[target] + ";", function_.blocks[target].address,
         make_tag(LineKind::Goto, target));
    ++gotos_;
  }

  [[nodiscard]] std::string condition_of(BlockId block_index, bool negate) const {
    const IrBlock& block = function_.blocks[block_index];
    const IrStatement& branch = block.statements.back();
    const IrStatement* previous = flags_producer(block, block.statements.size() - 1);
    return render_condition(function_, branch, previous, negate, literals_);
  }

  void emit_statements(BlockId block_index, bool include_terminator, bool fold_flags) {
    const IrBlock& block = function_.blocks[block_index];
    const std::size_t size = block.statements.size();
    const std::size_t limit = include_terminator ? size : size - 1;
    // With fold_flags the flag setter before a branch is not printed: the condition says it.
    const IrStatement* folded = nullptr;
    if (fold_flags && size >= 2 && is_flag_setter(block.statements[size - 2])) {
      folded = &block.statements[size - 2];
    }
    for (std::size_t index = 0; index < limit; ++index) {
      const IrStatement& statement = block.statements[index];
      if (&statement == folded) {
        continue;
      }
      const IrStatement* previous = flags_producer(block, index);
      const std::string text = render_statement(function_, statement, previous, literals_);
      if (text.empty()) {
        continue;
      }
      const LineKind kind = statement.op == IrOp::Return ? LineKind::Return : LineKind::Plain;
      push(text, statement.source_address, make_tag(kind, block_index));
    }
  }

  [[nodiscard]] bool loop_active(BlockId header) const {
    for (const Frame& frame : frames_) {
      if (frame.loop && frame.header == header) {
        return true;
      }
    }
    return false;
  }

  [[nodiscard]] const Frame* innermost_loop() const {
    for (auto frame = frames_.rbegin(); frame != frames_.rend(); ++frame) {
      if (frame->loop) {
        return &*frame;
      }
    }
    return nullptr;
  }

  /// Whether `target` can be printed next, inside the region: not printed, dominated by the root, not
  /// the end of an enclosing construct, and not the stop.
  [[nodiscard]] bool walkable(BlockId target, const Ctx& ctx) const {
    if ((rules_ & kGotoRuleSequence) == 0 || target >= function_.blocks.size() || emitted_[target]) {
      return false;
    }
    if (ctx.stop != kNoBlock && target == ctx.stop) {
      return false;
    }
    if (!dominators_[target].test(ctx.root)) {
      return false;
    }
    for (const Frame& frame : frames_) {
      if (frame.follow == target) {
        return false;
      }
    }
    return true;
  }

  Next done(Outcome outcome) const {
    Next next;
    next.outcome = outcome;
    return next;
  }

  Next walk(BlockId block) const {
    Next next;
    next.walk = true;
    next.block = block;
    return next;
  }

  /// The decision for an edge from the code being printed to `target` (rules 1 to 5 above).
  Next decide(BlockId target, const Ctx& ctx) {
    if (ctx.stop != kNoBlock && target == ctx.stop && ctx.stop_falls) {
      return done(Outcome::Falls);
    }
    if ((rules_ & kGotoRuleContinue) != 0) {
      const Frame* loop = innermost_loop();
      if (loop != nullptr && target == loop->header) {
        push("continue;", 0, make_tag(LineKind::Continue, target));
        return done(Outcome::Jumps);
      }
    }
    if ((rules_ & kGotoRuleBreak) != 0 && !frames_.empty() &&
        frames_.back().follow != kNoBlock && target == frames_.back().follow) {
      push("break;", 0, make_tag(LineKind::Break, target));
      return done(Outcome::Jumps);
    }
    if (walkable(target, ctx)) {
      return walk(target);
    }
    emit_goto(target);
    return done(Outcome::Jumps);
  }

  /// Prints the region from `start` until it stops, and returns how it ended.
  Outcome region(BlockId start, const Ctx& ctx) {
    BlockId current = start;
    for (;;) {
      const Next next = emit_block(current, ctx);
      if (!next.walk) {
        return next.outcome;
      }
      current = next.block;
    }
  }

  /// One arm of a branch: the edge into it, then its region when it is walked.
  Outcome arm(BlockId start, const Ctx& ctx) {
    const Next first = decide(start, ctx);
    if (!first.walk) {
      return first.outcome;
    }
    return region(first.block, ctx);
  }

  // ---- blocks ----------------------------------------------------------------------------------

  /// A loop whose header is entered here is printed as a loop; its follow is then the next decision.
  Next emit_loop(const LoopInfo& loop, const Ctx& ctx) {
    const BlockId header = loop.header;
    const BlockId follow = loop.follow;
    frames_.push_back(Frame{true, header, follow});
    const bool test_form = (rules_ & kGotoRuleWhileTest) != 0 && loop.pure;
    if (test_form) {
      emitted_[header] = true;
      const bool negated = !loop.stay_taken;
      const std::string label = labelled_[header] ? names_[header] + ": " : std::string();
      push(label + "while (" + condition_of(header, negated) + ") {", function_.blocks[header].address,
           make_tag(LineKind::WhileOpen, header, follow, negated, true));
      ++depth_;
      const Ctx body{header, header, true};
      const Next first = decide(loop.stay, body);
      if (first.walk) {
        region(first.block, body);
      }
      --depth_;
    } else {
      const std::string label = labelled_[header] ? names_[header] + ": " : std::string();
      push(label + "while (1) {", function_.blocks[header].address,
           make_tag(LineKind::WhileOpen, header, follow, false, false));
      ++depth_;
      region(header, Ctx{header, header, true});
      --depth_;
    }
    push("}", 0, make_tag(LineKind::Close));
    frames_.pop_back();
    if (follow == kNoBlock) {
      return done(Outcome::Jumps);
    }
    return decide(follow, ctx);
  }

  Next emit_block(BlockId block, const Ctx& ctx) {
    if ((rules_ & kGotoRuleLoop) != 0 && loop_of_[block] >= 0 && !emitted_[block] &&
        !loop_active(block)) {
      return emit_loop(loops_[static_cast<std::size_t>(loop_of_[block])], ctx);
    }
    emitted_[block] = true;
    const std::size_t marker = push(labelled_[block] ? names_[block] + ":" : std::string(),
                                    function_.blocks[block].address, make_tag(LineKind::Marker, block));
    const IrBlock& ir = function_.blocks[block];
    const IrStatement& terminator = ir.statements.back();
    Next result = done(Outcome::Jumps);
    switch (terminator.op) {
      case IrOp::Return:
        emit_statements(block, true, false);
        break;
      case IrOp::Branch:
        emit_statements(block, false, false);
        result = decide(terminator.a.block, ctx);
        break;
      case IrOp::CondBranch:
        emit_statements(block, false, true);
        result = conditional(block, ctx);
        break;
      case IrOp::Switch:
        emit_statements(block, false, false);
        result = switch_block(block, ctx);
        break;
      default:
        break;  // not reached for a valid graph (checked in prepare)
    }
    // A label needs a statement after it: an empty block gets an empty statement.
    if (labelled_[block] && lines_.size() == marker + 1) {
      lines_[marker].text += " ;";
    }
    return result;
  }

  /// The join of a branch or switch in `ctx`: Fall when the arms may fall out to it (it is the
  /// region's stop that falls, or it can be printed next), Jump when they must jump to it.
  [[nodiscard]] bool falls_to_join(BlockId join, const Ctx& ctx) const {
    if (join == kNoBlock || join >= function_.blocks.size()) {
      return false;
    }
    if (ctx.stop != kNoBlock && join == ctx.stop && ctx.stop_falls) {
      return true;
    }
    return walkable(join, ctx);
  }

  Next conditional(BlockId block, const Ctx& ctx) {
    const IrStatement& branch = function_.blocks[block].statements.back();
    const BlockId taken = branch.b.block;
    const BlockId fall = block + 1;
    if ((rules_ & kGotoRuleIfElse) == 0) {
      // Without the rule, the taken side is a goto and the fall-through goes on.
      push("if (" + condition_of(block, false) + ") goto " + names_[taken] + ";",
           function_.blocks[block].address, make_tag(LineKind::IfJump, block, taken));
      ++gotos_;
      return decide(fall, ctx);
    }
    const BlockId join = ipdom_[block];
    const bool has_join = join != kNoBlock && join < function_.blocks.size();
    const bool falls = falls_to_join(join, ctx);
    const Ctx taken_ctx{taken, has_join ? join : kNoBlock, falls};
    const Ctx fall_ctx{fall, has_join ? join : kNoBlock, falls};
    const std::uint64_t address = function_.blocks[block].address;

    std::size_t mark = lines_.size();
    ++depth_;
    const Outcome taken_outcome = arm(taken, taken_ctx);
    std::vector<StructuredLine> taken_lines = take(mark);
    mark = lines_.size();
    const Outcome fall_outcome = arm(fall, fall_ctx);
    std::vector<StructuredLine> fall_lines = take(mark);
    --depth_;

    const bool taken_empty = taken_lines.empty() && taken_outcome == Outcome::Falls;
    const bool fall_empty = fall_lines.empty() && fall_outcome == Outcome::Falls;
    if (!taken_empty || !fall_empty) {
      if (taken_empty) {
        push("if (" + condition_of(block, true) + ") {", address,
             make_tag(LineKind::IfOpen, block, kNoBlock, true));
        ++depth_;
        put(std::move(fall_lines));
        --depth_;
        push("}", 0, make_tag(LineKind::Close));
      } else if (fall_empty) {
        push("if (" + condition_of(block, false) + ") {", address,
             make_tag(LineKind::IfOpen, block, kNoBlock, false));
        ++depth_;
        put(std::move(taken_lines));
        --depth_;
        push("}", 0, make_tag(LineKind::Close));
      } else {
        push("if (" + condition_of(block, false) + ") {", address,
             make_tag(LineKind::IfOpen, block, kNoBlock, false));
        ++depth_;
        put(std::move(taken_lines));
        --depth_;
        push("} else {", 0, make_tag(LineKind::Else));
        ++depth_;
        put(std::move(fall_lines));
        --depth_;
        push("}", 0, make_tag(LineKind::Close));
      }
    }
    const bool fell = taken_outcome == Outcome::Falls || fall_outcome == Outcome::Falls;
    if (!fell || !has_join) {
      return done(Outcome::Jumps);
    }
    // Only an arm that falls out lets control reach the join, and then the join is printed next.
    return decide(join, ctx);
  }

  Next switch_block(BlockId block, const Ctx& ctx) {
    const IrStatement& terminator = function_.blocks[block].statements.back();
    const BlockId join = ipdom_[block];
    const bool has_join = join != kNoBlock && join < function_.blocks.size();
    const BlockId def = terminator.a.block;
    const bool falls = falls_to_join(join, ctx);
    const BlockId arm_stop = has_join ? join : kNoBlock;

    // Arms: one per distinct target, in the order the cases name them; the default is an arm too.
    std::vector<BlockId> targets;
    for (const IrSwitchCase& switch_case : terminator.switch_cases) {
      if (std::find(targets.begin(), targets.end(), switch_case.target_block) == targets.end()) {
        targets.push_back(switch_case.target_block);
      }
    }
    if (std::find(targets.begin(), targets.end(), def) == targets.end()) {
      targets.push_back(def);
    }

    frames_.push_back(Frame{false, kNoBlock, arm_stop});
    std::string operand = render_operand(function_, terminator.dest, literals_);
    push("switch (" + operand + ") {", function_.blocks[block].address,
         make_tag(LineKind::SwitchOpen, block, arm_stop));
    ++depth_;
    bool any_falls = false;
    for (const BlockId target : targets) {
      for (const IrSwitchCase& switch_case : terminator.switch_cases) {
        if (switch_case.target_block == target) {
          char value[32];
          std::snprintf(value, sizeof value, "0x%llx", static_cast<unsigned long long>(switch_case.value));
          LineTag tag = make_tag(LineKind::Case);
          tag.value = switch_case.value;
          push(std::string("case ") + value + ":", 0, tag);
        }
      }
      if (target == def) {
        push("default:", 0, make_tag(LineKind::Default));
      }
      ++depth_;
      Outcome outcome = Outcome::Jumps;
      if ((rules_ & kGotoRuleSwitch) != 0) {
        outcome = arm(target, Ctx{target, arm_stop, falls});
      } else {
        emit_goto(target);  // without the rule, every arm is a goto to its target
      }
      if (outcome == Outcome::Falls) {
        push("break;", 0, make_tag(LineKind::Break, arm_stop));
        any_falls = true;
      }
      --depth_;
    }
    --depth_;
    push("}", 0, make_tag(LineKind::Close));
    frames_.pop_back();
    if (!any_falls || !has_join) {
      return done(Outcome::Jumps);
    }
    return decide(join, ctx);
  }
};

}  // namespace

std::optional<GotoStructure> structure_with_gotos(const IrFunction& function,
                                                  const std::map<std::uint64_t, std::string>* string_literals,
                                                  std::uint32_t rules) {
  // The first run finds the labels; the second prints them. The structure is the same in both.
  Emitter first(function, string_literals, rules, {});
  if (!first.prepare() || !first.run()) {
    return std::nullopt;
  }
  Emitter second(function, string_literals, rules, first.goto_targets());
  if (!second.prepare() || !second.run()) {
    return std::nullopt;
  }
  GotoStructure result;
  result.lines = second.lines();
  result.gotos = second.gotos();
  return result;
}

}  // namespace donkey::detail
