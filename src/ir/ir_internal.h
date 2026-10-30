#pragma once

#include <cstdint>
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

/// Render an operand into C-like expression text.
std::string render_operand(const IrFunction& function, const IrOperand& operand);

/// Render one non-control-flow statement (or a `return`) without indentation.
/// `previous` is the statement before it in the same block; conditions on a
/// compare/test depend on it.
std::string render_statement(const IrFunction& function, const IrStatement& statement,
                             const IrStatement* previous);

/// The textual condition of a conditional branch, e.g. `rax == 0x0`, derived
/// from the branch's condition and the compare/test that precedes it. When
/// `negate` is true, an exactly complementary condition is used (so `==`
/// becomes `!=`); conditions without a total complement are wrapped in `!(...)`.
std::string render_condition(const IrFunction& function, const IrStatement& statement,
                             const IrStatement* previous, bool negate = false);

struct StructuredLine {
  std::string text;
  std::uint64_t source_address = 0;
};

/// Structured rendering of the function body, or `nullopt` when the control-flow
/// graph does not match a shape this structurer models. Callers must fall back
/// to labeled blocks with explicit `goto` when `nullopt` is returned; no guessed
/// structure is ever emitted.
std::optional<std::string> format_structured_body(const IrFunction& function);
std::optional<std::vector<StructuredLine>> format_structured_body_lines(const IrFunction& function);

}  // namespace donkey::detail
