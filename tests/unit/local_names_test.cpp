#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "donkey/ir/ir.h"
#include "donkey/ir/local_names.h"

namespace {

using donkey::IrBlock;
using donkey::IrFunction;
using donkey::IrLocalVariable;
using donkey::IrOperand;
using donkey::IrParameter;
using donkey::IrStatement;
using donkey::UserLocalName;

/// Two parameters, one frame slot at rbp-8, and one statement that touches the slot. The operand
/// already carries a debug name, which a user name must replace.
IrFunction sample_function() {
  IrFunction function;
  IrParameter first;
  first.name = "a0";
  first.abi_register = "rdi";
  IrParameter second;
  second.name = "a1";
  second.abi_register = "rsi";
  function.parameters = {first, second};

  IrLocalVariable slot;
  slot.name = "local_8";
  slot.width = 4;
  slot.offset = -8;
  slot.base_reg = "rbp";
  function.local_variables.push_back(slot);

  IrStatement statement;
  statement.dest = IrOperand::memory_reference("rbp", "", 1, -8, 4);
  statement.dest.name = "dbg_total";
  IrBlock block;
  block.statements.push_back(statement);
  function.blocks.push_back(block);
  return function;
}

}  // namespace

TEST(LocalNames, ParameterAndFrameNamesApplyAndTheOperandsFollow) {
  IrFunction function = sample_function();
  const auto applied = donkey::apply_user_local_names(
      function, {UserLocalName{"arg:0", "count"}, UserLocalName{"frame:rbp:-8", "total"}});
  ASSERT_TRUE(applied.has_value()) << applied.diagnostic().message;
  EXPECT_EQ(applied.value().applied, 2U);
  EXPECT_EQ(applied.value().stale, 0U);
  EXPECT_EQ(function.parameters[0].name, "count");
  EXPECT_EQ(function.parameters[1].name, "a1");
  EXPECT_EQ(function.local_variables[0].name, "total");
  // The debug name on the operand is replaced, because it would otherwise win in the output.
  EXPECT_EQ(function.blocks[0].statements[0].dest.name, "total");
}

TEST(LocalNames, KeysThatNameNothingAreStaleAndTheRestStillApply) {
  IrFunction function = sample_function();
  const auto applied = donkey::apply_user_local_names(
      function, {UserLocalName{"arg:5", "x"}, UserLocalName{"frame:rsp:16", "y"},
                 UserLocalName{"arg:1", "second"}});
  ASSERT_TRUE(applied.has_value()) << applied.diagnostic().message;
  EXPECT_EQ(applied.value().applied, 1U);
  EXPECT_EQ(applied.value().stale, 2U);
  EXPECT_EQ(function.parameters[1].name, "second");
  EXPECT_EQ(function.local_variables[0].name, "local_8");
}

TEST(LocalNames, NothingThatMatchesChangesNothing) {
  IrFunction function = sample_function();
  const IrFunction before = sample_function();
  const auto applied = donkey::apply_user_local_names(function, {UserLocalName{"arg:9", "x"}});
  ASSERT_TRUE(applied.has_value());
  EXPECT_EQ(applied.value().applied, 0U);
  EXPECT_EQ(function.parameters[0].name, before.parameters[0].name);
  EXPECT_EQ(function.blocks[0].statements[0].dest.name, "dbg_total");
}

TEST(LocalNames, AKeywordOrANonIdentifierRefusesTheWholeSet) {
  IrFunction function = sample_function();
  const IrFunction before = sample_function();
  const auto refused = donkey::apply_user_local_names(
      function, {UserLocalName{"arg:0", "ok"}, UserLocalName{"arg:1", "int"}});
  ASSERT_FALSE(refused.has_value());
  EXPECT_EQ(refused.diagnostic().code, "ir.local_name_invalid");
  EXPECT_EQ(function.parameters[0].name, before.parameters[0].name);

  const auto digit_first = donkey::apply_user_local_names(function, {UserLocalName{"arg:0", "1x"}});
  ASSERT_FALSE(digit_first.has_value());
  EXPECT_EQ(digit_first.diagnostic().code, "ir.local_name_invalid");
}

TEST(LocalNames, AMalformedOrRepeatedKeyIsRefused) {
  for (const char* key : {"arg:", "arg:x", "frame:rbp", "frame:rbp:08", "frame:rbp:-0", "frame::8",
                          "frame:r-p:8", "local:1", "arg:1024"}) {
    IrFunction function = sample_function();
    const auto refused = donkey::apply_user_local_names(function, {UserLocalName{key, "name"}});
    ASSERT_FALSE(refused.has_value()) << key;
    EXPECT_EQ(refused.diagnostic().code, "ir.local_key_invalid") << key;
  }

  IrFunction function = sample_function();
  const auto repeated = donkey::apply_user_local_names(
      function, {UserLocalName{"arg:0", "a"}, UserLocalName{"arg:0", "b"}});
  ASSERT_FALSE(repeated.has_value());
  EXPECT_EQ(repeated.diagnostic().code, "ir.local_name_duplicate");
}

TEST(LocalNames, ANameThatCollidesIsRefusedWithoutChangingTheFunction) {
  // Renaming parameter 0 to the name that parameter 1 keeps collides with it.
  IrFunction function = sample_function();
  const auto collide = donkey::apply_user_local_names(function, {UserLocalName{"arg:0", "a1"}});
  ASSERT_FALSE(collide.has_value());
  EXPECT_EQ(collide.diagnostic().code, "ir.local_name_collision");
  EXPECT_EQ(function.parameters[0].name, "a0");

  // Two new names that are equal collide with each other.
  const auto same = donkey::apply_user_local_names(
      function, {UserLocalName{"arg:0", "shared"}, UserLocalName{"frame:rbp:-8", "shared"}});
  ASSERT_FALSE(same.has_value());
  EXPECT_EQ(same.diagnostic().code, "ir.local_name_collision");
  EXPECT_EQ(function.local_variables[0].name, "local_8");
}

TEST(LocalNames, ANameThatAnotherOperandKeepsIsRefused) {
  // The operand at rbp-8 is renamed, but a second operand at rbp-16 keeps its name, so taking that
  // name for the slot at rbp-8 is a collision.
  IrFunction function = sample_function();
  IrStatement other;
  other.dest = IrOperand::memory_reference("rbp", "", 1, -16, 4);
  other.dest.name = "kept";
  function.blocks[0].statements.push_back(other);
  const auto collide =
      donkey::apply_user_local_names(function, {UserLocalName{"frame:rbp:-8", "kept"}});
  ASSERT_FALSE(collide.has_value());
  EXPECT_EQ(collide.diagnostic().code, "ir.local_name_collision");
}

TEST(LocalNames, AFrameSlotWithoutALocalGetsOneFromItsAccesses) {
  // The decompiler does not recover locals, so the slot an access uses is created with the
  // width of that access, and it is declared like any other local.
  IrFunction function = sample_function();
  function.local_variables.clear();
  const auto applied =
      donkey::apply_user_local_names(function, {UserLocalName{"frame:rbp:-8", "total"}});
  ASSERT_TRUE(applied.has_value()) << applied.diagnostic().message;
  EXPECT_EQ(applied.value().applied, 1U);
  ASSERT_EQ(function.local_variables.size(), 1U);
  EXPECT_EQ(function.local_variables[0].name, "total");
  EXPECT_EQ(function.local_variables[0].width, 4);
  EXPECT_EQ(function.local_variables[0].base_reg, "rbp");
  EXPECT_EQ(function.local_variables[0].offset, -8);
  EXPECT_FALSE(function.local_variables[0].is_parameter);
  EXPECT_EQ(function.blocks[0].statements[0].dest.name, "total");
}

TEST(LocalNames, AStaleKeyLeavesANoteAndTheRestApplies) {
  IrFunction function = sample_function();
  const auto applied = donkey::apply_user_local_names(
      function, {UserLocalName{"frame:rsp:16", "gone"}, UserLocalName{"arg:1", "second"}});
  ASSERT_TRUE(applied.has_value()) << applied.diagnostic().message;
  EXPECT_EQ(applied.value().applied, 1U);
  EXPECT_EQ(applied.value().stale, 1U);
  EXPECT_EQ(function.parameters[1].name, "second");
  EXPECT_EQ(function.local_variables.size(), 1U);
  ASSERT_EQ(function.notes.size(), 1U);
  EXPECT_NE(function.notes[0].find("frame:rsp:16"), std::string::npos);
}
