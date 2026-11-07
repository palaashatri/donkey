#include "donkey/core/json.h"

#include <cmath>
#include <cstdlib>
#include <unordered_set>
#include <utility>

namespace donkey {
namespace {

bool is_digit(char c) {
  return c >= '0' && c <= '9';
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

void append_utf8(std::string& out, std::uint32_t code_point) {
  if (code_point < 0x80U) {
    out.push_back(static_cast<char>(code_point));
  } else if (code_point < 0x800U) {
    out.push_back(static_cast<char>(0xc0U | (code_point >> 6U)));
    out.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
  } else if (code_point < 0x10000U) {
    out.push_back(static_cast<char>(0xe0U | (code_point >> 12U)));
    out.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3fU)));
    out.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
  } else {
    out.push_back(static_cast<char>(0xf0U | (code_point >> 18U)));
    out.push_back(static_cast<char>(0x80U | ((code_point >> 12U) & 0x3fU)));
    out.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3fU)));
    out.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
  }
}

class Parser {
 public:
  Parser(std::string_view text, const JsonLimits& limits) : text_(text), limits_(limits) {}

  Result<JsonValue> run() {
    if (text_.size() > limits_.max_bytes) {
      return fail("json.too_large", "the document is larger than the limit");
    }
    skip_space();
    auto value = parse_value(0);
    if (!value.has_value()) {
      return value;
    }
    skip_space();
    if (pos_ != text_.size()) {
      return fail("json.trailing", "text follows the value");
    }
    return value;
  }

 private:
  static Result<JsonValue> fail(const char* code, const char* message) {
    return make_error<JsonValue>(Status::InvalidInput, code, message);
  }

  [[nodiscard]] bool at_end() const noexcept { return pos_ >= text_.size(); }

  [[nodiscard]] char peek() const noexcept { return at_end() ? '\0' : text_[pos_]; }

  void skip_space() noexcept {
    while (!at_end()) {
      const char c = text_[pos_];
      if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
        break;
      }
      ++pos_;
    }
  }

  bool consume_literal(std::string_view literal) noexcept {
    if (text_.substr(pos_, literal.size()) != literal) {
      return false;
    }
    pos_ += literal.size();
    return true;
  }

  Result<JsonValue> parse_value(std::size_t depth) {
    if (depth > limits_.max_depth) {
      return fail("json.depth", "the nesting is deeper than the limit");
    }
    if (++nodes_ > limits_.max_nodes) {
      return fail("json.nodes", "the document has more values than the limit");
    }
    if (at_end()) {
      return fail("json.syntax", "a value was expected");
    }
    const char c = peek();
    JsonValue value;
    if (c == '{') {
      return parse_object(depth);
    }
    if (c == '[') {
      return parse_array(depth);
    }
    if (c == '"') {
      value.kind = JsonValue::Kind::String;
      if (!parse_string(value.text)) {
        return last_error_;
      }
      return value;
    }
    if (c == '-' || is_digit(c)) {
      return parse_number();
    }
    if (consume_literal("true")) {
      value.kind = JsonValue::Kind::Boolean;
      value.boolean = true;
      return value;
    }
    if (consume_literal("false")) {
      value.kind = JsonValue::Kind::Boolean;
      return value;
    }
    if (consume_literal("null")) {
      return value;
    }
    return fail("json.syntax", "an unexpected character starts a value");
  }

  Result<JsonValue> parse_number() {
    const std::size_t start = pos_;
    if (peek() == '-') {
      ++pos_;
    }
    if (peek() == '0') {
      ++pos_;
    } else if (is_digit(peek())) {
      while (is_digit(peek())) {
        ++pos_;
      }
    } else {
      return fail("json.number", "a digit was expected");
    }
    if (peek() == '.') {
      ++pos_;
      if (!is_digit(peek())) {
        return fail("json.number", "a digit was expected after the decimal point");
      }
      while (is_digit(peek())) {
        ++pos_;
      }
    }
    if (peek() == 'e' || peek() == 'E') {
      ++pos_;
      if (peek() == '+' || peek() == '-') {
        ++pos_;
      }
      if (!is_digit(peek())) {
        return fail("json.number", "a digit was expected in the exponent");
      }
      while (is_digit(peek())) {
        ++pos_;
      }
    }
    JsonValue value;
    value.kind = JsonValue::Kind::Number;
    value.text = std::string(text_.substr(start, pos_ - start));
    value.number = std::strtod(value.text.c_str(), nullptr);
    if (std::isinf(value.number)) {
      return fail("json.number_range", "the number is too large for a double");
    }
    return value;
  }

  // Decodes a string whose opening quote is at pos_. On failure the diagnostic is in last_error_.
  bool parse_string(std::string& out) {
    ++pos_;  // opening quote
    while (true) {
      if (at_end()) {
        last_error_ =
            make_error<JsonValue>(Status::InvalidInput, "json.syntax", "the string is not closed");
        return false;
      }
      const char c = text_[pos_++];
      if (c == '"') {
        return true;
      }
      if (static_cast<unsigned char>(c) < 0x20U) {
        last_error_ = make_error<JsonValue>(Status::InvalidInput, "json.control",
                                            "a control character is inside a string");
        return false;
      }
      if (c != '\\') {
        out.push_back(c);
        continue;
      }
      if (at_end()) {
        last_error_ = make_error<JsonValue>(Status::InvalidInput, "json.syntax",
                                            "the string ends in an escape");
        return false;
      }
      const char escape = text_[pos_++];
      switch (escape) {
        case '"':
        case '\\':
        case '/':
          out.push_back(escape);
          break;
        case 'b':
          out.push_back('\b');
          break;
        case 'f':
          out.push_back('\f');
          break;
        case 'n':
          out.push_back('\n');
          break;
        case 'r':
          out.push_back('\r');
          break;
        case 't':
          out.push_back('\t');
          break;
        case 'u': {
          std::uint32_t code_point = 0;
          if (!parse_hex4(code_point)) {
            return false;
          }
          if (code_point >= 0xdc00U && code_point <= 0xdfffU) {
            last_error_ = make_error<JsonValue>(Status::InvalidInput, "json.surrogate",
                                                "a low surrogate has no high surrogate before it");
            return false;
          }
          if (code_point >= 0xd800U && code_point <= 0xdbffU) {
            if (text_.substr(pos_, 2) != "\\u") {
              last_error_ = make_error<JsonValue>(Status::InvalidInput, "json.surrogate",
                                                  "a high surrogate has no low surrogate after it");
              return false;
            }
            pos_ += 2;
            std::uint32_t low = 0;
            if (!parse_hex4(low)) {
              return false;
            }
            if (low < 0xdc00U || low > 0xdfffU) {
              last_error_ = make_error<JsonValue>(Status::InvalidInput, "json.surrogate",
                                                  "a high surrogate is followed by a non-low one");
              return false;
            }
            code_point = 0x10000U + ((code_point - 0xd800U) << 10U) + (low - 0xdc00U);
          }
          append_utf8(out, code_point);
          break;
        }
        default:
          last_error_ =
              make_error<JsonValue>(Status::InvalidInput, "json.escape", "an unknown escape");
          return false;
      }
    }
  }

  bool parse_hex4(std::uint32_t& out) {
    if (text_.size() - pos_ < 4) {
      last_error_ = make_error<JsonValue>(Status::InvalidInput, "json.escape",
                                          "a \\u escape needs four hex digits");
      return false;
    }
    out = 0;
    for (int i = 0; i < 4; ++i) {
      const int digit = hex_value(text_[pos_++]);
      if (digit < 0) {
        last_error_ = make_error<JsonValue>(Status::InvalidInput, "json.escape",
                                            "a \\u escape needs four hex digits");
        return false;
      }
      out = (out << 4U) | static_cast<std::uint32_t>(digit);
    }
    return true;
  }

  Result<JsonValue> parse_array(std::size_t depth) {
    ++pos_;  // [
    JsonValue value;
    value.kind = JsonValue::Kind::Array;
    skip_space();
    if (peek() == ']') {
      ++pos_;
      return value;
    }
    while (true) {
      skip_space();
      auto item = parse_value(depth + 1);
      if (!item.has_value()) {
        return item;
      }
      value.items.push_back(std::move(item.value()));
      skip_space();
      if (peek() == ',') {
        ++pos_;
        continue;
      }
      if (peek() == ']') {
        ++pos_;
        return value;
      }
      return fail("json.syntax", "a comma or ] was expected");
    }
  }

  Result<JsonValue> parse_object(std::size_t depth) {
    ++pos_;  // {
    JsonValue value;
    value.kind = JsonValue::Kind::Object;
    std::unordered_set<std::string> seen;
    skip_space();
    if (peek() == '}') {
      ++pos_;
      return value;
    }
    while (true) {
      skip_space();
      if (peek() != '"') {
        return fail("json.syntax", "an object key must be a string");
      }
      std::string key;
      if (!parse_string(key)) {
        return last_error_;
      }
      if (!seen.insert(key).second) {
        return fail("json.duplicate_key", "an object repeats a key");
      }
      skip_space();
      if (peek() != ':') {
        return fail("json.syntax", "a colon was expected after a key");
      }
      ++pos_;
      skip_space();
      auto member = parse_value(depth + 1);
      if (!member.has_value()) {
        return member;
      }
      value.keys.push_back(std::move(key));
      value.items.push_back(std::move(member.value()));
      skip_space();
      if (peek() == ',') {
        ++pos_;
        continue;
      }
      if (peek() == '}') {
        ++pos_;
        return value;
      }
      return fail("json.syntax", "a comma or } was expected");
    }
  }

  std::string_view text_;
  JsonLimits limits_;
  std::size_t pos_ = 0;
  std::size_t nodes_ = 0;
  Result<JsonValue> last_error_ = make_error<JsonValue>(Status::InvalidInput, "json.syntax", "");
};

}  // namespace

const JsonValue* JsonValue::find(std::string_view key) const noexcept {
  if (kind != Kind::Object) {
    return nullptr;
  }
  for (std::size_t i = 0; i < keys.size(); ++i) {
    if (keys[i] == key) {
      return &items[i];
    }
  }
  return nullptr;
}

Result<JsonValue> parse_json(std::string_view text, const JsonLimits& limits) {
  Parser parser(text, limits);
  return parser.run();
}

}  // namespace donkey
