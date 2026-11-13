#include <gtest/gtest.h>

#include <cstdint>
#include <limits>
#include <string>

#include "donkey/debug/condition.h"

using donkey::debug::BreakCondition;
using donkey::debug::condition_holds;
using donkey::debug::ConditionOp;
using donkey::debug::parse_break_condition;

TEST(BreakCondition, ParsesARegisterOperandWithEveryOperator) {
  struct Case {
    const char* text;
    ConditionOp op;
  };
  const Case cases[] = {
      {"rax == 1", ConditionOp::Equal},  {"rax != 1", ConditionOp::NotEqual},
      {"rax < 1", ConditionOp::Less},    {"rax <= 1", ConditionOp::LessEqual},
      {"rax > 1", ConditionOp::Greater}, {"rax >= 1", ConditionOp::GreaterEqual},
  };
  for (const Case& c : cases) {
    auto parsed = parse_break_condition(c.text);
    ASSERT_TRUE(parsed.has_value()) << c.text << ": " << parsed.diagnostic().message;
    EXPECT_FALSE(parsed.value().memory);
    EXPECT_EQ(parsed.value().register_name, "rax");
    EXPECT_EQ(parsed.value().op, c.op) << c.text;
    EXPECT_EQ(parsed.value().value, 1U);
    EXPECT_EQ(parsed.value().text, c.text);
  }
}

TEST(BreakCondition, ParsesAMemoryOperandInBothForms) {
  auto bare = parse_break_condition("*0x4010 == 2");
  ASSERT_TRUE(bare.has_value()) << bare.diagnostic().message;
  EXPECT_TRUE(bare.value().memory);
  EXPECT_EQ(bare.value().address, 0x4010U);
  EXPECT_EQ(bare.value().value, 2U);

  auto parenthesised = parse_break_condition("  *( 4096 )!=0x10  ");
  ASSERT_TRUE(parenthesised.has_value()) << parenthesised.diagnostic().message;
  EXPECT_EQ(parenthesised.value().address, 4096U);
  EXPECT_EQ(parenthesised.value().op, ConditionOp::NotEqual);
  EXPECT_EQ(parenthesised.value().value, 16U);
}

TEST(BreakCondition, RefusesEveryMalformedConditionWithItsReason) {
  const char* malformed[] = {
      "",                                    // nothing
      "rax",                                 // no operator
      "rax ==",                              // no value
      "rax == 1 extra",                      // text after the value
      "rax === 1",                           // not an operator
      "rax = 1",                             // assignment is not a comparison
      "rax == -1",                           // no negative values
      "1 == rax",                            // an operand is a register name or *address
      "*0x == 1",                            // an address with no digits
      "*(0x10 == 1",                         // the address is not closed
      "* == 1",                              // `*` with no address
      "rax == 0x1ffffffffffffffff",          // does not fit in 64 bits
      "averyveryverylongregistername == 1",  // longer than a register name
  };
  for (const char* text : malformed) {
    auto parsed = parse_break_condition(text);
    ASSERT_FALSE(parsed.has_value()) << "accepted `" << text << "`";
    EXPECT_EQ(parsed.diagnostic().code, "debug.condition") << text;
    EXPECT_NE(parsed.diagnostic().message.find("expected a register name"), std::string::npos)
        << parsed.diagnostic().message;
  }
}

TEST(BreakCondition, ComparisonsAreUnsigned) {
  // -1 is the largest 64-bit value, so it is greater than 1 and not less than 1.
  BreakCondition greater;
  greater.op = ConditionOp::Greater;
  greater.value = 1;
  EXPECT_TRUE(condition_holds(greater, std::numeric_limits<std::uint64_t>::max()));
  EXPECT_FALSE(condition_holds(greater, 0));

  BreakCondition less;
  less.op = ConditionOp::Less;
  less.value = 1;
  EXPECT_FALSE(condition_holds(less, std::numeric_limits<std::uint64_t>::max()));
  EXPECT_TRUE(condition_holds(less, 0));
}

TEST(BreakCondition, EveryOperatorHasItsTruthTable) {
  const struct {
    ConditionOp op;
    bool below;  // operand 4 against value 5
    bool equal;  // operand 5 against value 5
    bool above;  // operand 6 against value 5
  } table[] = {
      {ConditionOp::Equal, false, true, false},   {ConditionOp::NotEqual, true, false, true},
      {ConditionOp::Less, true, false, false},    {ConditionOp::LessEqual, true, true, false},
      {ConditionOp::Greater, false, false, true}, {ConditionOp::GreaterEqual, false, true, true},
  };
  for (const auto& row : table) {
    BreakCondition condition;
    condition.op = row.op;
    condition.value = 5;
    EXPECT_EQ(condition_holds(condition, 4), row.below) << static_cast<int>(row.op);
    EXPECT_EQ(condition_holds(condition, 5), row.equal) << static_cast<int>(row.op);
    EXPECT_EQ(condition_holds(condition, 6), row.above) << static_cast<int>(row.op);
  }
}
