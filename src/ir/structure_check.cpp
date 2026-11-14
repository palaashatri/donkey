// Control-flow check of printed structured code (G04-T5).
//
// The structurer tags every line with its role (LineTag). This file rebuilds the structured tree
// from those tags, lowers it to a flat list of operations with the C rules for jumps, conditions,
// switch arms (which fall into the next arm without a break) and loops (break and continue leave
// the innermost loop or switch), and then reads, for each IR block, the blocks that control reaches
// from it. Those are compared with the IR's successors, edge for edge: a condition's true side must
// enter the IR's taken block when the printed condition is the branch condition, and the fall-through
// block otherwise. The check does not look at the text of statements, only at the tags and the
// braces that the tags describe.
//
// A mismatch is a bug in the structurer: the printer must not print code whose control flow
// differs from the IR's. structure_function uses this check as a gate on each candidate structure.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <optional>
#include <string>
#include <vector>

#include "ir_internal.h"

namespace donkey::detail {
namespace {

struct Arm;

/// The shape of a node of the tree rebuilt from the tags.
enum class Shape : std::uint8_t { Leaf, IfJump, If, While, Do, Switch };

/// One node of the tree rebuilt from the tags.
struct Node {
  Shape shape = Shape::Leaf;
  LineKind kind = LineKind::Plain;  ///< a leaf: Plain, Marker, Return, Break, Continue or Goto
  BlockId block = kNoBlock;
  BlockId follow = kNoBlock;
  BlockId latch = kNoBlock;  ///< Do: the latch whose test closes the body
  bool negated = false;
  bool pure = false;
  bool has_alt = false;
  LineKind jump = LineKind::Plain;  ///< IfJump: the jump it guards
  std::size_t line = 0;             ///< index of the line the node came from
  std::vector<Node> body;           ///< If: then-arm; loops: body
  std::vector<Node> alt;            ///< If: else-arm
  std::vector<Arm> arms;            ///< Switch
};

struct Arm {
  bool is_default = false;
  std::uint64_t value = 0;
  std::vector<Node> body;
};

std::string describe(const StructuredLine& line, std::size_t index) {
  return "line " + std::to_string(index) + " ('" + line.text + "')";
}

/// The text of a line without its indentation.
std::string trimmed(const std::string& text) {
  const std::size_t first = text.find_first_not_of(' ');
  return first == std::string::npos ? std::string() : text.substr(first);
}

bool ends_with(const std::string& text, const std::string& suffix) {
  return text.size() >= suffix.size() &&
         text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool starts_with(const std::string& text, const std::string& prefix) {
  return text.compare(0, prefix.size(), prefix) == 0;
}

/// Rebuilds the tree from the tagged lines. Every opening tag must be closed by the tag that
/// belongs to it, and the text of each tag must agree with its brace.
class TagParser {
 public:
  explicit TagParser(const std::vector<StructuredLine>& lines) : lines_(lines) {}

  bool run(std::vector<Node>& out, std::string& error) {
    const bool ok = sequence(out);
    if (!ok) {
      error = error_;
      return false;
    }
    if (pos_ != lines_.size()) {
      error = "unexpected " + describe(lines_[pos_], pos_) + " outside any block";
      return false;
    }
    return true;
  }

 private:
  bool fail(const std::string& message) {
    if (error_.empty()) {
      error_ = message;
    }
    return false;
  }

  bool expect_close(const char* what) {
    if (pos_ >= lines_.size() || lines_[pos_].tag.kind != LineKind::Close ||
        trimmed(lines_[pos_].text) != "}") {
      return fail(std::string("missing the closing brace of ") + what);
    }
    ++pos_;
    return true;
  }

  /// Statements until a tag that closes or separates the enclosing construct (not consumed).
  bool sequence(std::vector<Node>& out) {
    while (pos_ < lines_.size()) {
      const StructuredLine& current = lines_[pos_];
      const LineTag& tag = current.tag;
      switch (tag.kind) {
        case LineKind::Else:
        case LineKind::Close:
        case LineKind::DoClose:
        case LineKind::Case:
        case LineKind::Default:
          return true;
        case LineKind::Plain:
        case LineKind::Marker:
        case LineKind::Return:
        case LineKind::Break:
        case LineKind::Continue:
        case LineKind::Goto: {
          Node leaf;
          leaf.kind = tag.kind;
          leaf.block = tag.block;
          leaf.line = pos_;
          out.push_back(std::move(leaf));
          ++pos_;
          break;
        }
        case LineKind::IfJump: {
          if (tag.jump != LineKind::Break && tag.jump != LineKind::Continue &&
              tag.jump != LineKind::Goto) {
            return fail("an if-jump without a jump: " + describe(current, pos_));
          }
          if (!starts_with(trimmed(current.text), "if (") || !ends_with(current.text, ";")) {
            return fail("an if-jump whose text is not `if (...) ...;`: " + describe(current, pos_));
          }
          Node node;
          node.shape = Shape::IfJump;
          node.block = tag.block;
          node.follow = tag.follow;
          node.jump = tag.jump;
          node.line = pos_;
          out.push_back(std::move(node));
          ++pos_;
          break;
        }
        case LineKind::IfOpen: {
          if (!starts_with(trimmed(current.text), "if (") || !ends_with(current.text, "{")) {
            return fail("an if whose text is not `if (...) {`: " + describe(current, pos_));
          }
          Node node;
          node.shape = Shape::If;
          node.block = tag.block;
          node.negated = tag.negated;
          node.line = pos_;
          ++pos_;
          if (!sequence(node.body)) {
            return false;
          }
          if (pos_ < lines_.size() && lines_[pos_].tag.kind == LineKind::Else) {
            if (trimmed(lines_[pos_].text) != "} else {") {
              return fail("an else whose text is not `} else {`: " + describe(lines_[pos_], pos_));
            }
            node.has_alt = true;
            ++pos_;
            if (!sequence(node.alt)) {
              return false;
            }
          }
          if (!expect_close("an if")) {
            return false;
          }
          out.push_back(std::move(node));
          break;
        }
        case LineKind::WhileOpen:
        case LineKind::ForOpen: {
          if (!ends_with(current.text, "{")) {
            return fail("a loop whose text does not open a brace: " + describe(current, pos_));
          }
          Node node;
          node.shape = Shape::While;
          node.block = tag.block;
          node.follow = tag.follow;
          node.negated = tag.negated;
          node.pure = tag.pure;
          node.line = pos_;
          ++pos_;
          if (!sequence(node.body)) {
            return false;
          }
          if (!expect_close("a loop")) {
            return false;
          }
          out.push_back(std::move(node));
          break;
        }
        case LineKind::DoOpen: {
          Node node;
          node.shape = Shape::Do;
          node.block = tag.block;
          node.follow = tag.follow;
          node.line = pos_;
          ++pos_;
          if (!sequence(node.body)) {
            return false;
          }
          if (pos_ >= lines_.size() || lines_[pos_].tag.kind != LineKind::DoClose ||
              !starts_with(trimmed(lines_[pos_].text), "} while (")) {
            return fail("a do loop without its `} while (...);`");
          }
          node.latch = lines_[pos_].tag.block;
          node.negated = lines_[pos_].tag.negated;
          ++pos_;
          out.push_back(std::move(node));
          break;
        }
        case LineKind::SwitchOpen: {
          if (!starts_with(trimmed(current.text), "switch (") || !ends_with(current.text, "{")) {
            return fail("a switch whose text is not `switch (...) {`: " + describe(current, pos_));
          }
          Node node;
          node.shape = Shape::Switch;
          node.block = tag.block;
          node.follow = tag.follow;
          node.line = pos_;
          ++pos_;
          if (pos_ >= lines_.size() || (lines_[pos_].tag.kind != LineKind::Case &&
                                        lines_[pos_].tag.kind != LineKind::Default)) {
            return fail("a switch with a statement before its first case");
          }
          while (pos_ < lines_.size() && (lines_[pos_].tag.kind == LineKind::Case ||
                                          lines_[pos_].tag.kind == LineKind::Default)) {
            Arm arm;
            arm.is_default = lines_[pos_].tag.kind == LineKind::Default;
            arm.value = lines_[pos_].tag.value;
            ++pos_;
            if (!sequence(arm.body)) {
              return false;
            }
            node.arms.push_back(std::move(arm));
          }
          if (!expect_close("a switch")) {
            return false;
          }
          out.push_back(std::move(node));
          break;
        }
      }
    }
    return true;
  }

  const std::vector<StructuredLine>& lines_;
  std::size_t pos_ = 0;
  std::string error_;
};

/// One operation of the lowered code. A Block op is the start of an IR block's code (a copy of it
/// when the block is printed twice). Jumps and conditional jumps name their targets as labels until
/// the labels are resolved to positions.
struct Op {
  enum class Kind : std::uint8_t { Block, Ret, Jump, CJump, Switch };
  Kind kind = Kind::Block;
  BlockId block = kNoBlock;  ///< Block: the block; CJump, Switch: the tested or dispatched block
  bool negated = false;      ///< CJump: the printed condition is the complement of the IR's
  bool goto_target = false;  ///< Jump: `block` is a goto target, resolved to its first Block op
  std::vector<std::size_t> labels;   ///< Jump: [0]; CJump: [0] true, [1] false; Switch: the arms
  std::vector<std::size_t> targets;  ///< the resolved positions of `labels` (same order)
  std::size_t line = 0;              ///< index of the line the op came from
};

constexpr std::size_t kUnplaced = std::numeric_limits<std::size_t>::max();

struct Frame {
  bool loop = false;
  BlockId follow = kNoBlock;      ///< the block a break names
  BlockId header = kNoBlock;      ///< loops: the block a continue names
  std::size_t follow_label = 0;   ///< where a break goes
  std::size_t continue_label = 0; ///< where a continue goes (the test of a do loop)
};

/// Lowers the tree to operations with C's jump rules.
class Lowerer {
 public:
  std::vector<Op> ops;
  std::vector<std::size_t> label_pos;
  std::string error;

  bool lower(const std::vector<Node>& nodes) {
    for (const Node& node : nodes) {
      if (!lower_node(node)) {
        return false;
      }
    }
    return true;
  }

 private:
  std::vector<Frame> frames_;

  std::size_t new_label() {
    label_pos.push_back(kUnplaced);
    return label_pos.size() - 1;
  }
  void place(std::size_t label) { label_pos[label] = ops.size(); }
  void emit(Op::Kind kind, BlockId block, std::size_t line) {
    Op op;
    op.kind = kind;
    op.block = block;
    op.line = line;
    ops.push_back(std::move(op));
  }
  bool fail(const std::string& message) {
    if (error.empty()) {
      error = message;
    }
    return false;
  }

  bool lower_jump(LineKind kind, BlockId claim, std::size_t line) {
    if (kind == LineKind::Goto) {
      emit(Op::Kind::Jump, claim, line);
      ops.back().goto_target = true;
      return true;
    }
    if (kind == LineKind::Break) {
      if (frames_.empty()) {
        return fail("break at line " + std::to_string(line) + " outside any loop or switch");
      }
      const Frame& frame = frames_.back();
      if (frame.follow != claim) {
        return fail("break at line " + std::to_string(line) + " names a block that is not the end "
                    "of the innermost loop or switch");
      }
      emit(Op::Kind::Jump, kNoBlock, line);
      ops.back().labels = {frame.follow_label};
      return true;
    }
    // Continue: the innermost loop, switches are passed through.
    for (auto frame = frames_.rbegin(); frame != frames_.rend(); ++frame) {
      if (!frame->loop) {
        continue;
      }
      if (frame->header != claim) {
        return fail("continue at line " + std::to_string(line) + " names a block that is not the "
                    "header of the innermost loop");
      }
      emit(Op::Kind::Jump, kNoBlock, line);
      ops.back().labels = {frame->continue_label};
      return true;
    }
    return fail("continue at line " + std::to_string(line) + " outside any loop");
  }

  bool lower_node(const Node& node) {
    switch (node.shape) {
      case Shape::Leaf:
        switch (node.kind) {
          case LineKind::Plain:
            return true;
          case LineKind::Marker:
            emit(Op::Kind::Block, node.block, node.line);
            return true;
          case LineKind::Return:
            emit(Op::Kind::Ret, node.block, node.line);
            return true;
          case LineKind::Break:
          case LineKind::Continue:
          case LineKind::Goto:
            return lower_jump(node.kind, node.block, node.line);
          default:
            return fail("an unexpected leaf at line " + std::to_string(node.line));
        }
      case Shape::IfJump: {
        // `if (C) <jump>;`: the true side jumps, the false side falls through.
        const std::size_t taken = new_label();
        const std::size_t after = new_label();
        emit(Op::Kind::CJump, node.block, node.line);
        ops.back().labels = {taken, after};
        place(taken);
        if (!lower_jump(node.jump, node.follow, node.line)) {
          return false;
        }
        place(after);
        return true;
      }
      case Shape::If: {
        emit(Op::Kind::CJump, node.block, node.line);
        ops.back().negated = node.negated;
        const std::size_t then_label = new_label();
        const std::size_t end = new_label();
        const std::size_t else_label = node.has_alt ? new_label() : end;
        ops.back().labels = {then_label, else_label};
        place(then_label);
        if (!lower(node.body)) {
          return false;
        }
        if (node.has_alt) {
          emit(Op::Kind::Jump, kNoBlock, node.line);
          ops.back().labels = {end};
          place(else_label);
          if (!lower(node.alt)) {
            return false;
          }
        }
        place(end);
        return true;
      }
      case Shape::While: {
        const std::size_t top = new_label();
        const std::size_t end = new_label();
        place(top);
        if (node.pure) {
          // The loop's test is the header's branch: `while (C)` runs the header, then tests it.
          emit(Op::Kind::Block, node.block, node.line);
          emit(Op::Kind::CJump, node.block, node.line);
          ops.back().negated = node.negated;
          const std::size_t body = new_label();
          ops.back().labels = {body, end};
          place(body);
        }
        frames_.push_back(Frame{true, node.follow, node.block, end, top});
        const bool ok = lower(node.body);
        frames_.pop_back();
        if (!ok) {
          return false;
        }
        emit(Op::Kind::Jump, kNoBlock, node.line);
        ops.back().labels = {top};
        place(end);
        return true;
      }
      case Shape::Do: {
        const std::size_t top = new_label();
        const std::size_t test = new_label();
        const std::size_t end = new_label();
        place(top);
        frames_.push_back(Frame{true, node.follow, node.block, end, test});
        const bool ok = lower(node.body);
        frames_.pop_back();
        if (!ok) {
          return false;
        }
        place(test);
        emit(Op::Kind::CJump, node.latch, node.line);
        ops.back().negated = node.negated;
        ops.back().labels = {top, end};
        place(end);
        return true;
      }
      case Shape::Switch: {
        const std::size_t end = new_label();
        emit(Op::Kind::Switch, node.block, node.line);
        std::vector<std::size_t> arm_labels;
        bool has_default = false;
        for (const Arm& arm : node.arms) {
          arm_labels.push_back(new_label());
          has_default = has_default || arm.is_default;
        }
        if (!has_default) {
          arm_labels.push_back(end);  // no matching case and no default: past the switch
        }
        ops.back().labels = arm_labels;
        frames_.push_back(Frame{false, node.follow, kNoBlock, end, end});
        for (std::size_t index = 0; index < node.arms.size(); ++index) {
          place(arm_labels[index]);
          if (!lower(node.arms[index].body)) {
            return false;
          }
        }
        frames_.pop_back();
        place(end);
        return true;
      }
    }
    return fail("an unexpected node at line " + std::to_string(node.line));
  }
};

/// Where control can go from a point of the lowered code: the blocks it reaches first, and whether
/// it reaches the end of the function.
struct Reach {
  std::vector<BlockId> blocks;
  bool exit = false;
  bool cycle = false;
};

/// The control-flow shape that follows one Block op: a single target, a condition, or a switch.
struct Tail {
  enum class Kind : std::uint8_t { Single, Cond, Multi };
  Kind kind = Kind::Single;
  Reach single;
  Reach taken;  ///< Cond: the true side
  Reach fall;   ///< Cond: the false side
  BlockId tested = kNoBlock;
  bool negated = false;
  std::vector<Reach> arms;  ///< Multi
};

/// Compares the lowered code with the IR. `ops` are resolved in place.
class Checker {
 public:
  Checker(const IrFunction& function, std::vector<Op>& ops, const std::vector<std::size_t>& label_pos)
      : function_(function), ops_(ops), label_pos_(label_pos) {}

  std::optional<std::string> run() {
    const std::size_t count = function_.blocks.size();
    first_block_.assign(count, kUnplaced);
    for (std::size_t pos = 0; pos < ops_.size(); ++pos) {
      const Op& op = ops_[pos];
      if (op.kind != Op::Kind::Block) {
        continue;
      }
      if (op.block >= count) {
        return "a printed block that the function does not have (line " + std::to_string(op.line) + ")";
      }
      if (first_block_[op.block] == kUnplaced) {
        first_block_[op.block] = pos;
      }
    }
    if (auto error = resolve()) {
      return error;
    }
    for (std::size_t block = 0; block < count; ++block) {
      if (first_block_[block] == kUnplaced) {
        return "block " + hex(block) + " is not printed";
      }
    }
    for (std::size_t pos = 0; pos < ops_.size(); ++pos) {
      if (ops_[pos].kind == Op::Kind::Block) {
        if (auto mismatch = check_block(pos, ops_[pos].block)) {
          return mismatch;
        }
      }
    }
    return std::nullopt;
  }

 private:
  const IrFunction& function_;
  std::vector<Op>& ops_;
  const std::vector<std::size_t>& label_pos_;
  std::vector<std::size_t> first_block_;

  /// Resolves every label to a position, and every goto to the first printed copy of its target.
  std::optional<std::string> resolve() {
    for (Op& op : ops_) {
      op.targets.clear();
      for (const std::size_t label : op.labels) {
        if (label >= label_pos_.size() || label_pos_[label] == kUnplaced) {
          return "a jump at line " + std::to_string(op.line) + " to a label that is not placed";
        }
        op.targets.push_back(label_pos_[label]);
      }
      if (op.goto_target) {
        if (op.block >= first_block_.size() || first_block_[op.block] == kUnplaced) {
          return "a goto at line " + std::to_string(op.line) + " to block " + hex(op.block) +
                 " that is not printed";
        }
        op.targets.push_back(first_block_[op.block]);
      }
    }
    return std::nullopt;
  }

  /// Follows unconditional jumps from `pos`: the first position that is not a jump, `ops.size()`
  /// at the end of the code, or kUnplaced for a cycle of jumps that never reaches an op.
  [[nodiscard]] std::size_t skip_jumps(std::size_t pos) const {
    for (std::size_t steps = 0; steps <= ops_.size(); ++steps) {
      if (pos >= ops_.size()) {
        return ops_.size();
      }
      if (ops_[pos].kind != Op::Kind::Jump) {
        return pos;
      }
      pos = ops_[pos].targets[0];
    }
    return kUnplaced;
  }

  /// The blocks and exits that control reaches first from `pos`.
  void reach(std::size_t pos, Reach& out, std::size_t depth) const {
    if (depth > ops_.size() + 2) {
      out.cycle = true;
      return;
    }
    pos = skip_jumps(pos);
    if (pos == kUnplaced) {
      out.cycle = true;
      return;
    }
    if (pos >= ops_.size()) {
      out.exit = true;
      return;
    }
    const Op& op = ops_[pos];
    switch (op.kind) {
      case Op::Kind::Block:
        out.blocks.push_back(op.block);
        return;
      case Op::Kind::Ret:
        out.exit = true;
        return;
      case Op::Kind::CJump:
        reach(op.targets[0], out, depth + 1);
        reach(op.targets[1], out, depth + 1);
        return;
      case Op::Kind::Switch:
        for (const std::size_t target : op.targets) {
          reach(target, out, depth + 1);
        }
        return;
      case Op::Kind::Jump:
        return;  // skip_jumps never returns a jump
    }
  }

  /// The control-flow shape that follows the Block op at `block_pos`.
  [[nodiscard]] Tail tail_of(std::size_t block_pos) const {
    Tail tail;
    const std::size_t first = skip_jumps(block_pos + 1);
    if (first == kUnplaced) {
      tail.single.cycle = true;
      return tail;
    }
    if (first < ops_.size() && ops_[first].kind == Op::Kind::CJump) {
      const Op& op = ops_[first];
      tail.kind = Tail::Kind::Cond;
      tail.tested = op.block;
      tail.negated = op.negated;
      reach(op.targets[0], tail.taken, 0);
      reach(op.targets[1], tail.fall, 0);
      return tail;
    }
    if (first < ops_.size() && ops_[first].kind == Op::Kind::Switch) {
      const Op& op = ops_[first];
      tail.kind = Tail::Kind::Multi;
      tail.tested = op.block;
      for (const std::size_t target : op.targets) {
        Reach arm;
        reach(target, arm, 0);
        tail.arms.push_back(std::move(arm));
      }
      return tail;
    }
    reach(block_pos + 1, tail.single, 0);
    return tail;
  }

  [[nodiscard]] static std::string hex(std::uint64_t value) {
    return "#" + std::to_string(value);
  }

  [[nodiscard]] static std::string describe(const Reach& reach) {
    if (reach.cycle) {
      return "a cycle of jumps";
    }
    std::string text;
    for (const BlockId block : reach.blocks) {
      text += (text.empty() ? "" : ", ") + hex(block);
    }
    if (reach.exit) {
      text += (text.empty() ? "" : ", ") + std::string("the end of the function");
    }
    return text.empty() ? std::string("nothing") : text;
  }

  /// True when `reach` is exactly the block `target`, and nothing else.
  [[nodiscard]] static bool is_exactly(const Reach& reach, BlockId target) {
    return !reach.cycle && !reach.exit && reach.blocks.size() == 1 && reach.blocks[0] == target;
  }

  std::optional<std::string> check_block(std::size_t pos, BlockId block) const {
    const IrBlock& ir = function_.blocks[block];
    const IrStatement& terminator = ir.statements.back();
    const std::string name = "block " + hex(block);
    const Tail tail = tail_of(pos);
    if (tail.single.cycle || tail.taken.cycle || tail.fall.cycle) {
      return name + ": the printed code loops without reaching a block";
    }
    switch (terminator.op) {
      case IrOp::Return:
        if (tail.kind != Tail::Kind::Single || !tail.single.exit || !tail.single.blocks.empty()) {
          return name + " returns, but the printed code continues to " + describe(tail.single);
        }
        return std::nullopt;
      case IrOp::Branch: {
        if (tail.kind != Tail::Kind::Single || !is_exactly(tail.single, terminator.a.block)) {
          return name + " branches to " + hex(terminator.a.block) + ", but the printed code continues to " +
                 describe(tail.single);
        }
        return std::nullopt;
      }
      case IrOp::CondBranch: {
        const BlockId taken = terminator.b.block;
        const BlockId fall = block + 1;
        if (tail.kind != Tail::Kind::Cond) {
          return name + " branches on a condition, but the printed code has no test for it";
        }
        if (tail.tested != block) {
          return name + " is printed as the test of " + hex(tail.tested);
        }
        // The printed condition holds exactly when the IR's does, unless the printer complemented it.
        const BlockId expect_true = tail.negated ? fall : taken;
        const BlockId expect_false = tail.negated ? taken : fall;
        if (!is_exactly(tail.taken, expect_true)) {
          return name + ": when the printed condition holds control goes to " + describe(tail.taken) +
                 ", the IR expects " + hex(expect_true);
        }
        if (!is_exactly(tail.fall, expect_false)) {
          return name + ": when the printed condition fails control goes to " + describe(tail.fall) +
                 ", the IR expects " + hex(expect_false);
        }
        return std::nullopt;
      }
      case IrOp::Switch: {
        if (tail.kind != Tail::Kind::Multi || tail.tested != block) {
          return name + " is a switch in the IR, but the printed code has no switch for it";
        }
        std::vector<BlockId> expected{terminator.a.block};
        for (const IrSwitchCase& switch_case : terminator.switch_cases) {
          expected.push_back(switch_case.target_block);
        }
        std::vector<BlockId> printed;
        for (const Reach& arm : tail.arms) {
          if (arm.cycle || arm.exit || arm.blocks.size() != 1) {
            // An arm that is empty and falls into the next one reaches that arm's block; any other
            // shape is a mismatch.
            return name + ": a switch arm reaches " + describe(arm) + ", not one block";
          }
          printed.push_back(arm.blocks[0]);
        }
        // The dispatch may also go past the switch when no arm matches (no default arm in the code).
        if (printed.size() == expected.size() + 1) {
          printed.pop_back();
        }
        std::sort(expected.begin(), expected.end());
        std::sort(printed.begin(), printed.end());
        if (printed != expected) {
          return name + ": the switch arms reach a different set of blocks than the IR's targets";
        }
        return std::nullopt;
      }
      default:
        return name + " ends in an operation the check does not model";
    }
  }
};


/// The condition the printer shows for the branch of `block` (complemented when `negated`), rendered
/// again here; empty when the block does not end in a conditional branch.
std::string expected_condition(const IrFunction& function, BlockId block, bool negated,
                               const std::map<std::uint64_t, std::string>* literals) {
  const IrBlock& ir = function.blocks[block];
  if (ir.statements.empty() || ir.statements.back().op != IrOp::CondBranch) {
    return std::string();
  }
  const IrStatement* previous = flags_producer(ir, ir.statements.size() - 1);
  return render_condition(function, ir.statements.back(), previous, negated, literals);
}

std::string hex_value(std::uint64_t value) {
  char buffer[32];
  std::snprintf(buffer, sizeof buffer, "0x%llx", static_cast<unsigned long long>(value));
  return buffer;
}

/// The text of each control line must say what its tag says: the condition of a branch, the value
/// of a case, and the keyword of a jump. Statements are not checked here.
std::optional<std::string> check_control_text(const IrFunction& function,
                                              const std::vector<StructuredLine>& lines,
                                              const std::map<std::uint64_t, std::string>* literals) {
  const std::size_t count = function.blocks.size();
  for (std::size_t index = 0; index < lines.size(); ++index) {
    const StructuredLine& line = lines[index];
    const LineTag& tag = line.tag;
    // A loop header may carry its label in front: "loc_X: while (...) {".
    std::string text = trimmed(line.text);
    if (starts_with(text, "loc_") && text.find(": ") != std::string::npos) {
      text = text.substr(text.find(": ") + 2);
    }
    const std::string where = describe(line, index);
    const auto wrong = [&](const std::string& expected) {
      return std::optional<std::string>(where + ": printed as '" + text + "', the tag says '" +
                                        expected + "'");
    };
    const auto block_ok = [&](BlockId block) { return block < count; };
    switch (tag.kind) {
      case LineKind::IfOpen: {
        if (!block_ok(tag.block)) return wrong("a block the function does not have");
        const std::string condition = expected_condition(function, tag.block, tag.negated, literals);
        if (text != "if (" + condition + ") {") return wrong("if (" + condition + ") {");
        break;
      }
      case LineKind::IfJump: {
        if (!block_ok(tag.block)) return wrong("a block the function does not have");
        const std::string condition = expected_condition(function, tag.block, false, literals);
        const std::string prefix = "if (" + condition + ") ";
        if (!starts_with(text, prefix)) return wrong(prefix + "...;");
        const std::string jump = text.substr(prefix.size());
        const std::string expected = tag.jump == LineKind::Break      ? "break;"
                                     : tag.jump == LineKind::Continue ? "continue;"
                                                                      : "goto ";
        if (tag.jump == LineKind::Goto ? !starts_with(jump, expected) : jump != expected) {
          return wrong(prefix + expected);
        }
        break;
      }
      case LineKind::WhileOpen: {
        if (tag.pure) {
          if (!block_ok(tag.block)) return wrong("a block the function does not have");
          const std::string condition = expected_condition(function, tag.block, tag.negated, literals);
          if (!starts_with(text, "while (" + condition + ") {")) {
            return wrong("while (" + condition + ") {");
          }
        } else if (text != "while (1) {") {
          return wrong("while (1) {");
        }
        break;
      }
      case LineKind::ForOpen: {
        if (!block_ok(tag.block)) return wrong("a block the function does not have");
        const std::string condition = expected_condition(function, tag.block, tag.negated, literals);
        if (!starts_with(text, "for (") || text.find("; " + condition + "; ") == std::string::npos) {
          return wrong("for (...; " + condition + "; ...) {");
        }
        break;
      }
      case LineKind::DoOpen:
        if (text != "do {") return wrong("do {");
        break;
      case LineKind::DoClose: {
        if (!block_ok(tag.block)) return wrong("a block the function does not have");
        const std::string condition = expected_condition(function, tag.block, tag.negated, literals);
        if (text != "} while (" + condition + ");") return wrong("} while (" + condition + ");");
        break;
      }
      case LineKind::Case:
        if (text != "case " + hex_value(tag.value) + ":") return wrong("case " + hex_value(tag.value) + ":");
        break;
      case LineKind::Default:
        if (text != "default:") return wrong("default:");
        break;
      case LineKind::Break:
        if (text != "break;") return wrong("break;");
        break;
      case LineKind::Continue:
        if (text != "continue;") return wrong("continue;");
        break;
      case LineKind::Goto:
        if (!starts_with(text, "goto ") || !ends_with(text, ";")) return wrong("goto ...;");
        break;
      case LineKind::Else:
        if (text != "} else {") return wrong("} else {");
        break;
      case LineKind::Close:
        if (text != "}") return wrong("}");
        break;
      case LineKind::SwitchOpen:
        if (!starts_with(text, "switch (") || !ends_with(text, "{")) return wrong("switch (...) {");
        break;
      case LineKind::Return:
        if (!starts_with(text, "return") || !ends_with(text, ";")) return wrong("return ...;");
        break;
      case LineKind::Plain:
      case LineKind::Marker:
        break;
    }
  }
  return std::nullopt;
}

}  // namespace

std::optional<std::string> check_structured_control_flow(
    const IrFunction& function, const std::vector<StructuredLine>& lines,
    const std::map<std::uint64_t, std::string>* string_literals) {
  if (!build_graph(function).valid) {
    return std::string("the control-flow graph is not valid");
  }
  if (auto mismatch = check_control_text(function, lines, string_literals)) {
    return mismatch;
  }
  std::vector<Node> tree;
  std::string error;
  if (!TagParser(lines).run(tree, error)) {
    return error;
  }
  Lowerer lowerer;
  if (!lowerer.lower(tree)) {
    return lowerer.error;
  }
  Checker checker(function, lowerer.ops, lowerer.label_pos);
  return checker.run();
}

}  // namespace donkey::detail
