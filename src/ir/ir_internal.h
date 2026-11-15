#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "donkey/ir/ir.h"

namespace donkey::detail {

using BlockId = std::size_t;
constexpr BlockId kNoBlock = static_cast<BlockId>(-1);

/// Fixed-size bit set over block indices.
class BitSet {
 public:
  BitSet() = default;
  explicit BitSet(std::size_t size) : size_(size), words_((size + 63) / 64, 0) {}

  static BitSet full(std::size_t size) {
    BitSet set(size);
    for (std::uint64_t& word : set.words_) {
      word = ~std::uint64_t{0};
    }
    set.mask();
    return set;
  }

  [[nodiscard]] bool test(std::size_t index) const {
    if (index >= size_) return false;
    return (words_[index / 64] >> (index % 64)) & 1U;
  }
  void set(std::size_t index) {
    if (index < size_) words_[index / 64] |= std::uint64_t{1} << (index % 64);
  }
  void intersect(const BitSet& other) {
    for (std::size_t i = 0; i < words_.size() && i < other.words_.size(); ++i) {
      words_[i] &= other.words_[i];
    }
  }
  [[nodiscard]] std::size_t count() const {
    std::size_t total = 0;
    for (const std::uint64_t word : words_) {
      total += static_cast<std::size_t>(__builtin_popcountll(word));
    }
    return total;
  }
  [[nodiscard]] bool equals(const BitSet& other) const { return words_ == other.words_; }

 private:
  void mask() {
    if (!words_.empty() && size_ % 64 != 0) {
      words_.back() &= (std::uint64_t{1} << (size_ % 64)) - 1;
    }
  }

  std::size_t size_ = 0;
  std::vector<std::uint64_t> words_;
};

struct Graph {
  std::vector<std::vector<BlockId>> successors;
  std::vector<std::vector<BlockId>> predecessors;
  bool valid = true;
};

Graph build_graph(const IrFunction& function);
std::vector<BitSet> compute_dominators(const Graph& graph);
/// Whether some block cannot be reached from the entry (block 0). A block with predecessors can
/// still be unreachable, as part of a cycle the entry does not reach.
bool has_unreachable_block(const Graph& graph);
/// The follow of the loop whose blocks are `body`: of the blocks outside the body that it branches
/// to, the one the most body blocks reach on every path inside the loop, before any other exit that
/// is not a return block (ties: the lower `rank`). kNoBlock when no body block counts for any exit.
/// Linear in the size of the graph.
BlockId choose_loop_follow(const Graph& graph, const std::vector<bool>& body,
                           const std::vector<std::size_t>& rank);

/// Render an operand into C-like expression text.
std::string render_operand(const IrFunction& function, const IrOperand& operand,
                           const std::map<std::uint64_t, std::string>* string_literals = nullptr);

/// Render one non-control-flow statement (or a `return`) without indentation.
/// `previous` is the statement before it in the same block; conditions on a
/// compare/test depend on it.
std::string render_statement(const IrFunction& function, const IrStatement& statement,
                             const IrStatement* previous,
                             const std::map<std::uint64_t, std::string>* string_literals = nullptr);

/// The textual condition of a conditional branch, e.g. `rax == 0x0`, derived
/// from the branch's condition and the compare/test that precedes it. When
/// `negate` is true, an exactly complementary condition is used (so `==`
/// becomes `!=`); conditions without a total complement are wrapped in `!(...)`.
std::string render_condition(const IrFunction& function, const IrStatement& statement,
                             const IrStatement* previous, bool negate = false,
                             const std::map<std::uint64_t, std::string>* string_literals = nullptr);

/// The Compare/Test whose flags the statement at `index` of `block` reads:
/// the nearest one before it in the block. Null when there is none, or when
/// a statement in between overwrites a register the comparison names (the
/// condition would then read as if it tested the new value).
const IrStatement* flags_producer(const IrBlock& block, std::size_t index);

/// Immediate post-dominator of every block (goal 8, step 1). A block that ends in a return flows
/// into a virtual exit whose index is the block count; a tail call is lifted as a return, so it
/// does too. The entry is `count` for a block whose paths reach the exit with no block in common
/// after it. An empty result means the graph is not valid.
std::vector<BlockId> immediate_post_dominators(const IrFunction& function);

/// The structural role of a printed line (G04-T5). The structurer tags each line it emits, and the
/// control-flow check (`check_structured_control_flow`) rebuilds the structured tree from these
/// tags alone, so the check reads what the printer decided, not the text.
enum class LineKind : std::uint8_t {
  Plain,       ///< a statement of block `block` that does not transfer control
  Marker,      ///< zero-width: block `block` starts here (its text is a label, or empty)
  Return,      ///< `return ...;` ending block `block`
  IfOpen,      ///< `if (C) {`: C is block `block`'s condition, complemented when `negated`
  IfJump,      ///< `if (C) <jump>;` where `jump` is Break, Continue or Goto; `block` is the test
  Else,        ///< `} else {`
  WhileOpen,   ///< `while (C) {` when `pure` (C is block `block`'s test) or `while (1) {`
  ForOpen,     ///< `for (init; C; step) {`: as WhileOpen with a pure test
  DoOpen,      ///< `do {`
  DoClose,     ///< `} while (C);`: C is the test of latch block `block`
  SwitchOpen,  ///< `switch (x) {`: `block` is the dispatch block, `follow` its join
  Case,        ///< `case v:`; `value` is v
  Default,     ///< `default:`
  Close,       ///< `}`
  Break,       ///< `break;`: `block` is the follow of the innermost loop or switch
  Continue,    ///< `continue;`: `block` is the header of the innermost loop
  Goto,        ///< `goto loc_X;`: `block` is the target
};

/// What the tag of a printed line says (see LineKind). Fields a kind does not use are left as set.
struct LineTag {
  LineKind kind = LineKind::Plain;
  BlockId block = kNoBlock;
  BlockId follow = kNoBlock;
  bool negated = false;
  bool pure = false;
  LineKind jump = LineKind::Plain;  ///< IfJump: Break, Continue or Goto
  std::uint64_t value = 0;          ///< Case
};

inline LineTag make_tag(LineKind kind, BlockId block = kNoBlock, BlockId follow = kNoBlock,
                        bool negated = false, bool pure = false) {
  LineTag tag;
  tag.kind = kind;
  tag.block = block;
  tag.follow = follow;
  tag.negated = negated;
  tag.pure = pure;
  return tag;
}

struct StructuredLine {
  std::string text;
  std::uint64_t source_address = 0;
  LineTag tag;
  /// The other statements printed in this line (the step of a `for` header).
  std::vector<std::uint64_t> folded_addresses;
};

/// How the printer shows a function (G04-T5). Structured: no goto. WithGotos: structured code with
/// `goto` only for edges that have no structured form. Labelled: the whole-function labelled form,
/// for an invalid graph, one that nests deeper than kMaxStructureNesting, or a candidate the
/// control-flow check refuses.
enum class StructureOutcome : std::uint8_t { Structured, WithGotos, Labelled };

struct StructureResult {
  StructureOutcome outcome = StructureOutcome::Labelled;
  std::vector<StructuredLine> lines;  ///< empty when Labelled
  std::size_t gotos = 0;
  /// Candidate structures the control-flow check refused before one passed (a bug in the
  /// candidate).
  std::size_t oracle_rejections = 0;
  /// The first refusal of the control-flow check, or empty.
  std::string oracle_detail;
  /// Why the layout-based structurer rejected the function (empty when it accepted it).
  std::string legacy_reason;
  /// Why the goto structurer refused the function (empty when it did not), for example a nesting
  /// deeper than kMaxStructureNesting.
  std::string refusal;
  /// The function whose blocks the lines' tags name, when it is not the input function: the
  /// reverse-postorder copy or the split function that was structured. Their block numbers differ
  /// from the input's, so the lines are checked against this function. Null for the input function.
  std::shared_ptr<const IrFunction> described;
};

/// Rules of the goto structurer (G04-T5, src/ir/structure_goto.cpp). Each can be switched off, so a
/// test can show what the rule does: with it off, the construct it prints is a goto instead.
inline constexpr std::uint32_t kGotoRuleSequence = 1U
                                                   << 0;   ///< a block printed after its only path
inline constexpr std::uint32_t kGotoRuleIfElse = 1U << 1;  ///< a condition as if/else at its join
inline constexpr std::uint32_t kGotoRuleLoop = 1U << 2;    ///< a natural loop as a loop
inline constexpr std::uint32_t kGotoRuleWhileTest = 1U << 3;  ///< a pure-test header as `while (C)`
inline constexpr std::uint32_t kGotoRuleBreak = 1U << 4;  ///< a branch to a loop's or switch's end
inline constexpr std::uint32_t kGotoRuleContinue = 1U << 5;  ///< a branch to a loop header
inline constexpr std::uint32_t kGotoRuleSwitch = 1U << 6;    ///< a switch with its arms printed
inline constexpr std::uint32_t kGotoRuleAll = 0x7FU;

struct GotoStructure {
  std::vector<StructuredLine> lines;
  std::size_t gotos = 0;
};

/// The deepest nesting of if, loop and switch statements that the printer and the control-flow
/// check accept (G04-T5). A candidate deeper than this is refused with a reason, so a crafted
/// function cannot exhaust the stack of the thread that prints it, and the labelled form is shown.
inline constexpr std::size_t kMaxStructureNesting = 128;

/// The goto structurer: structured lines for a valid graph, with `goto` only for the edges that no
/// enabled rule expresses. Nullopt, with the reason in `refusal`, when the graph is not valid, when
/// the code would nest deeper than kMaxStructureNesting, or when a block is left unprinted (an
/// internal error, never printed silently).
std::optional<GotoStructure> structure_with_gotos(
    const IrFunction& function, const std::map<std::uint64_t, std::string>* string_literals,
    std::uint32_t rules = kGotoRuleAll, std::string* refusal = nullptr);

/// The structure the printer uses for a function, after the control-flow check has accepted it.
StructureResult structure_function(const IrFunction& function,
                                   const std::map<std::uint64_t, std::string>* string_literals);

/// Rebuilds the control flow from the tagged lines and compares every block's successors with the
/// IR's, edge for edge: which block each arm of a condition enters, and where each goto, break and
/// continue goes. Returns the first mismatch, or nullopt when the lines describe the function's
/// control flow exactly.
///
/// It also checks the text of each control line against the tag: a printed condition is rendered
/// again from the IR and must match the tag's block and complement, and a case label must print the
/// tag's value. `string_literals` is the printer's table, when the printer had one.
std::optional<std::string> check_structured_control_flow(
    const IrFunction& function, const std::vector<StructuredLine>& lines,
    const std::map<std::uint64_t, std::string>* string_literals = nullptr);

/// Structured rendering of the function body, or `nullopt` when the control-flow
/// graph does not match a shape this structurer models. Callers must fall back
/// to labeled blocks with explicit `goto` when `nullopt` is returned; no guessed
/// structure is ever emitted.
std::optional<std::string> format_structured_body(const IrFunction& function);
std::optional<std::vector<StructuredLine>> format_structured_body_lines(
    const IrFunction& function,
    const std::map<std::uint64_t, std::string>* string_literals = nullptr);

}  // namespace donkey::detail
