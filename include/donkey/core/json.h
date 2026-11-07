#pragma once

// A bounded JSON reader (RFC 8259) for the RPC front end (G11). It is strict: no comments, no
// trailing commas, no leading zeros, no NaN or Infinity, and no duplicate object keys. Every limit
// is checked before the work it bounds. Errors are `json.` diagnostics; nothing is partially
// returned.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "donkey/core/result.h"

namespace donkey {

struct JsonLimits {
  std::size_t max_bytes = 16U * 1024U * 1024U;
  std::size_t max_depth = 64;
  std::size_t max_nodes = 1'000'000;
};

struct JsonValue {
  enum class Kind : std::uint8_t { Null, Boolean, Number, String, Array, Object };

  Kind kind = Kind::Null;
  bool boolean = false;
  /// For a number: its value. Use `text` for its exact spelling.
  double number = 0.0;
  /// For a string: its decoded contents (UTF-8). For a number: its exact source text.
  std::string text;
  /// Array elements, or the values of an object (parallel to `keys`).
  std::vector<JsonValue> items;
  std::vector<std::string> keys;

  [[nodiscard]] bool is_null() const noexcept { return kind == Kind::Null; }
  [[nodiscard]] bool is_bool() const noexcept { return kind == Kind::Boolean; }
  [[nodiscard]] bool is_number() const noexcept { return kind == Kind::Number; }
  [[nodiscard]] bool is_string() const noexcept { return kind == Kind::String; }
  [[nodiscard]] bool is_array() const noexcept { return kind == Kind::Array; }
  [[nodiscard]] bool is_object() const noexcept { return kind == Kind::Object; }

  /// The member named `key` of an object, or nullptr when there is none (or this is not one).
  [[nodiscard]] const JsonValue* find(std::string_view key) const noexcept;
};

/// Parses exactly one JSON value that fills `text`, allowing surrounding whitespace only.
[[nodiscard]] Result<JsonValue> parse_json(std::string_view text, const JsonLimits& limits = {});

}  // namespace donkey
