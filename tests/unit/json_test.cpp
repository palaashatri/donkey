#include <gtest/gtest.h>

#include <cstddef>
#include <string>
#include <string_view>

#include "donkey/core/json.h"

namespace {

std::string code_of(std::string_view text, const donkey::JsonLimits& limits = {}) {
  const auto parsed = donkey::parse_json(text, limits);
  return parsed.has_value() ? std::string("ok") : parsed.diagnostic().code;
}

}  // namespace

TEST(Json, ParsesScalarsArraysAndObjects) {
  auto parsed =
      donkey::parse_json(R"( {"a": [1, 2.5, -0, true, false, null, "x"], "b": {"c": "d"}} )");
  ASSERT_TRUE(parsed.has_value()) << parsed.diagnostic().code;
  const donkey::JsonValue& root = parsed.value();
  ASSERT_TRUE(root.is_object());

  const donkey::JsonValue* a = root.find("a");
  ASSERT_NE(a, nullptr);
  ASSERT_TRUE(a->is_array());
  ASSERT_EQ(a->items.size(), 7U);
  EXPECT_DOUBLE_EQ(a->items[0].number, 1.0);
  EXPECT_DOUBLE_EQ(a->items[1].number, 2.5);
  EXPECT_EQ(a->items[1].text, "2.5");
  EXPECT_TRUE(a->items[3].is_bool());
  EXPECT_TRUE(a->items[3].boolean);
  EXPECT_FALSE(a->items[4].boolean);
  EXPECT_TRUE(a->items[5].is_null());
  EXPECT_EQ(a->items[6].text, "x");

  const donkey::JsonValue* b = root.find("b");
  ASSERT_NE(b, nullptr);
  ASSERT_NE(b->find("c"), nullptr);
  EXPECT_EQ(b->find("c")->text, "d");
  EXPECT_EQ(root.find("missing"), nullptr);
  EXPECT_EQ(a->find("a"), nullptr);  // find is for objects only
}

TEST(Json, DecodesEscapesAndSurrogatePairs) {
  auto parsed = donkey::parse_json(R"("\u00e9\ud83d\ude00\n\t\"\\\/")");
  ASSERT_TRUE(parsed.has_value()) << parsed.diagnostic().code;
  const std::string& text = parsed.value().text;
  // U+00E9 in UTF-8, then U+1F600 (a surrogate pair) in UTF-8, then the escapes.
  const std::string expected = "\xc3\xa9\xf0\x9f\x98\x80\n\t\"\\/";
  EXPECT_EQ(text, expected);
}

TEST(Json, KeepsTheSpellingOfNumbers) {
  auto parsed = donkey::parse_json("1.0e2");
  ASSERT_TRUE(parsed.has_value());
  EXPECT_EQ(parsed.value().text, "1.0e2");
  EXPECT_DOUBLE_EQ(parsed.value().number, 100.0);
}

TEST(Json, RejectsEachGrammarViolationWithItsCode) {
  EXPECT_EQ(code_of(""), "json.syntax");
  EXPECT_EQ(code_of("+1"), "json.syntax");
  EXPECT_EQ(code_of("01"), "json.trailing");  // "0" is a value, "1" is trailing text
  EXPECT_EQ(code_of("1."), "json.number");
  EXPECT_EQ(code_of("1e"), "json.number");
  EXPECT_EQ(code_of(".5"), "json.syntax");
  EXPECT_EQ(code_of("1e400"), "json.number_range");
  EXPECT_EQ(code_of("NaN"), "json.syntax");
  EXPECT_EQ(code_of("[1,]"), "json.syntax");
  EXPECT_EQ(code_of("{\"a\":1,}"), "json.syntax");
  EXPECT_EQ(code_of("{a:1}"), "json.syntax");
  EXPECT_EQ(code_of("[1] x"), "json.trailing");
  EXPECT_EQ(code_of("\"abc"), "json.syntax");
  EXPECT_EQ(code_of("\"a\x01z\""), "json.control");
  EXPECT_EQ(code_of("\"\\x\""), "json.escape");
  EXPECT_EQ(code_of("\"\\u12\""), "json.escape");
  EXPECT_EQ(code_of("\"\\uzzzz\""), "json.escape");
  EXPECT_EQ(code_of("\"\\udc00\""), "json.surrogate");
  EXPECT_EQ(code_of("\"\\ud800\""), "json.surrogate");
  EXPECT_EQ(code_of("\"\\ud800\\u0041\""), "json.surrogate");
  EXPECT_EQ(code_of("{\"a\":1,\"a\":2}"), "json.duplicate_key");
}

TEST(Json, EnforcesItsLimits) {
  donkey::JsonLimits bytes;
  bytes.max_bytes = 4;
  EXPECT_EQ(code_of("[1,2]", bytes), "json.too_large");
  EXPECT_EQ(code_of("[1]", bytes), "ok");

  donkey::JsonLimits nodes;
  nodes.max_nodes = 3;
  EXPECT_EQ(code_of("[1,2,3,4]", nodes), "json.nodes");
  EXPECT_EQ(code_of("[1,2]", nodes), "ok");

  // 64 nested arrays are allowed; the 65th level is not.
  EXPECT_EQ(code_of(std::string(64, '[') + std::string(64, ']')), "ok");
  EXPECT_EQ(code_of(std::string(70, '[')), "json.depth");
}

TEST(Json, FailsWithoutPartialResults) {
  // A malformed member after valid ones yields an error, never the members that parsed.
  const auto parsed = donkey::parse_json(R"({"method": "info", "params": {"path": )");
  EXPECT_FALSE(parsed.has_value());
  EXPECT_EQ(parsed.diagnostic().code.rfind("json.", 0), 0U);
}
