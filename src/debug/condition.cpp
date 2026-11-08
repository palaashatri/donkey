#include "donkey/debug/condition.h"

#include <cctype>
#include <cstddef>
#include <limits>

namespace donkey::debug {
namespace {

constexpr std::size_t kMaxRegisterNameLength = 16;

const char* const kGrammar =
    "expected a register name or *address, then one of == != < <= > >=, then a number "
    "(decimal or 0x hex), for example `*0x4010 == 2` or `rdi != 0`";

/// A cursor over the condition text.
class Cursor {
 public:
  explicit Cursor(std::string_view text) : text_(text) {}

  [[nodiscard]] bool at_end() const noexcept { return pos_ >= text_.size(); }
  [[nodiscard]] char peek() const noexcept { return at_end() ? '\0' : text_[pos_]; }
  [[nodiscard]] char peek_at(std::size_t offset) const noexcept {
    return pos_ + offset < text_.size() ? text_[pos_ + offset] : '\0';
  }
  void advance(std::size_t count = 1) noexcept { pos_ += count; }
  void skip_space() noexcept {
    while (!at_end() && std::isspace(static_cast<unsigned char>(peek())) != 0) {
      ++pos_;
    }
  }

 private:
  std::string_view text_;
  std::size_t pos_ = 0;
};

Result<BreakCondition> malformed(std::string_view text, const char* detail) {
  return make_error<BreakCondition>(
      Status::InvalidInput, "debug.condition",
      std::string(detail) + ": " + kGrammar + " (got `" + std::string(text) + "`)");
}

/// A decimal or 0x hexadecimal number that fits in 64 bits.
bool parse_number(Cursor& cursor, std::uint64_t& out) {
  unsigned base = 10;
  if (cursor.peek() == '0' && (cursor.peek_at(1) == 'x' || cursor.peek_at(1) == 'X')) {
    base = 16;
    cursor.advance(2);
  }
  std::uint64_t value = 0;
  std::size_t digits = 0;
  while (true) {
    const char c = cursor.peek();
    unsigned digit = 0;
    if (c >= '0' && c <= '9') {
      digit = static_cast<unsigned>(c - '0');
    } else if (base == 16 && c >= 'a' && c <= 'f') {
      digit = static_cast<unsigned>(c - 'a' + 10);
    } else if (base == 16 && c >= 'A' && c <= 'F') {
      digit = static_cast<unsigned>(c - 'A' + 10);
    } else {
      break;
    }
    if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / base) {
      return false;  // does not fit in 64 bits
    }
    value = value * base + digit;
    ++digits;
    cursor.advance();
  }
  if (digits == 0) {
    return false;
  }
  out = value;
  return true;
}

/// An identifier: a letter or underscore, then letters, digits or underscores.
bool parse_identifier(Cursor& cursor, std::string& out) {
  const char first = cursor.peek();
  if (std::isalpha(static_cast<unsigned char>(first)) == 0 && first != '_') {
    return false;
  }
  while (true) {
    const char c = cursor.peek();
    if (std::isalnum(static_cast<unsigned char>(c)) == 0 && c != '_') {
      break;
    }
    if (out.size() >= kMaxRegisterNameLength) {
      return false;
    }
    out.push_back(c);
    cursor.advance();
  }
  return true;
}

}  // namespace

Result<BreakCondition> parse_break_condition(std::string_view text) {
  BreakCondition condition;
  condition.text = std::string(text);
  Cursor cursor(text);
  cursor.skip_space();
  if (cursor.peek() == '*') {
    cursor.advance();
    condition.memory = true;
    cursor.skip_space();
    if (cursor.peek() == '(') {
      cursor.advance();
      cursor.skip_space();
      if (!parse_number(cursor, condition.address)) {
        return malformed(text, "the address after `*(` is not a number");
      }
      cursor.skip_space();
      if (cursor.peek() != ')') {
        return malformed(text, "the address is not closed by `)`");
      }
      cursor.advance();
    } else if (!parse_number(cursor, condition.address)) {
      return malformed(text, "the address after `*` is not a number");
    }
  } else if (!parse_identifier(cursor, condition.register_name)) {
    return malformed(text, "the operand is neither a register name nor *address");
  }
  cursor.skip_space();
  const char first = cursor.peek();
  const char second = cursor.peek_at(1);
  if (first == '=' && second == '=') {
    condition.op = ConditionOp::Equal;
  } else if (first == '!' && second == '=') {
    condition.op = ConditionOp::NotEqual;
  } else if (first == '<' && second == '=') {
    condition.op = ConditionOp::LessEqual;
  } else if (first == '>' && second == '=') {
    condition.op = ConditionOp::GreaterEqual;
  } else if (first == '<') {
    condition.op = ConditionOp::Less;
  } else if (first == '>') {
    condition.op = ConditionOp::Greater;
  } else {
    return malformed(text, "the operator is not one of == != < <= > >=");
  }
  cursor.advance(condition.op == ConditionOp::Less || condition.op == ConditionOp::Greater ? 1 : 2);
  cursor.skip_space();
  if (!parse_number(cursor, condition.value)) {
    return malformed(text, "the value is not a number that fits in 64 bits");
  }
  cursor.skip_space();
  if (!cursor.at_end()) {
    return malformed(text, "unexpected text after the value");
  }
  return condition;
}

const char* condition_op_text(ConditionOp op) noexcept {
  switch (op) {
    case ConditionOp::Equal:
      return "==";
    case ConditionOp::NotEqual:
      return "!=";
    case ConditionOp::Less:
      return "<";
    case ConditionOp::LessEqual:
      return "<=";
    case ConditionOp::Greater:
      return ">";
    case ConditionOp::GreaterEqual:
      return ">=";
  }
  return "==";
}

bool condition_holds(const BreakCondition& condition, std::uint64_t operand) noexcept {
  switch (condition.op) {
    case ConditionOp::Equal:
      return operand == condition.value;
    case ConditionOp::NotEqual:
      return operand != condition.value;
    case ConditionOp::Less:
      return operand < condition.value;
    case ConditionOp::LessEqual:
      return operand <= condition.value;
    case ConditionOp::Greater:
      return operand > condition.value;
    case ConditionOp::GreaterEqual:
      return operand >= condition.value;
  }
  return false;
}

}  // namespace donkey::debug
