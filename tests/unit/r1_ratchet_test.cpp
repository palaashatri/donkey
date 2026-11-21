// G20-T3: the R1 ratchet (tools/r1/r1_ratchet.h): the baseline round trip, and each rule of the
// check on small hand-made counts.

#include <gtest/gtest.h>

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

#include "r1_ratchet.h"

namespace {

using donkey::r1::Counts;

Counts counts(const std::string& file, char sha, std::size_t complete,
              std::optional<std::size_t> missed = std::nullopt) {
  Counts c;
  c.file = file;
  c.compiler = "gcc 13";
  c.sha256 = std::string(64, sha);
  c.complete = complete;
  c.unsupported = 2;
  c.invalid_ir = 0;
  c.missed_starts = missed;
  return c;
}

bool mentions(const std::vector<std::string>& lines, const std::string& text) {
  return std::any_of(lines.begin(), lines.end(),
                     [&](const std::string& line) { return line.find(text) != std::string::npos; });
}

}  // namespace

TEST(R1Ratchet, BaselineRoundTrips) {
  const std::vector<Counts> written = {counts("lua", 'a', 10), counts("lua.stripped", 'b', 9, 3)};
  // Written out of order, read back sorted.
  const auto read = donkey::r1::read_baseline(donkey::r1::write_baseline({written[1], written[0]}));
  ASSERT_TRUE(read.has_value()) << read.diagnostic().message;
  EXPECT_EQ(read.value(), written);
}

TEST(R1Ratchet, RefusesABadBaseline) {
  for (const char* text :
       {"[]", "{\"schema\": 2, \"binaries\": []}",
        "{\"schema\": 1, \"binaries\": [{\"file\": \"a\"}]}",
        // a negative or fractional count
        "{\"schema\": 1, \"binaries\": [{\"file\": \"a\", \"compiler\": \"c\", \"sha256\": "
        "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\", \"complete\": -1, "
        "\"unsupported\": 0, \"invalid_ir\": 0, \"error\": 0, \"missed_starts\": null}]}",
        "{\"schema\": 1, \"binaries\": [{\"file\": \"a\", \"compiler\": \"c\", \"sha256\": "
        "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\", \"complete\": 1.5, "
        "\"unsupported\": 0, \"invalid_ir\": 0, \"error\": 0, \"missed_starts\": null}]}"}) {
    EXPECT_FALSE(donkey::r1::read_baseline(text).has_value()) << text;
  }
  // The same file twice.
  const Counts one = counts("lua", 'a', 1);
  std::string twice = donkey::r1::write_baseline({one});
  const std::string line =
      twice.substr(twice.find("    {"), twice.find("}\n") - twice.find("    {") + 1);
  twice.insert(twice.find("    {"), line + ",\n");
  EXPECT_FALSE(donkey::r1::read_baseline(twice).has_value());
}

TEST(R1Ratchet, ReadsTheCountsOfAResult) {
  const std::string sha(64, 'c');
  const std::string text =
      "{\"schema\": 1, \"binaries\": [{\"file\": \"z.stripped\", \"variant\": \"stripped\", "
      "\"compiler\": \"gcc\", \"sha256\": \"" +
      sha +
      "\", \"error\": false, \"functions\": 9, "
      "\"complete\": 5, \"partial\": 3, \"unsupported\": 1, \"invalid_ir\": 0, \"starts\": "
      "{\"symbols\": 10, \"missed\": 2}}, {\"file\": \"z\", \"variant\": \"unstripped\", "
      "\"compiler\": \"gcc\", \"sha256\": \"" +
      sha +
      "\", \"error\": true, \"complete\": 0, "
      "\"unsupported\": 0, \"invalid_ir\": 0, \"starts\": null}]}";
  const auto read = donkey::r1::read_result_counts(text);
  ASSERT_TRUE(read.has_value()) << read.diagnostic().message;
  ASSERT_EQ(read.value().size(), 2U);
  EXPECT_EQ(read.value()[0].file, "z");
  EXPECT_TRUE(read.value()[0].error);
  EXPECT_FALSE(read.value()[0].missed_starts.has_value());
  EXPECT_EQ(read.value()[1].complete, 5U);
  EXPECT_EQ(read.value()[1].unsupported, 1U);
  EXPECT_EQ(read.value()[1].missed_starts, 2U);
}

TEST(R1Ratchet, FailsWhenACountGetsWorse) {
  const std::vector<Counts> baseline = {counts("a", 'a', 10), counts("b", 'b', 10, 4)};
  {
    std::vector<Counts> head = baseline;
    const auto outcome = donkey::r1::check(baseline, head);
    EXPECT_FALSE(outcome.failed());
    EXPECT_TRUE(outcome.improvements.empty());
    EXPECT_TRUE(outcome.warnings.empty());
    EXPECT_TRUE(outcome.needs_base.empty());
  }
  auto worse = [&](auto change, const std::string& expected) {
    std::vector<Counts> head = baseline;
    change(head);
    const auto outcome = donkey::r1::check(baseline, head);
    EXPECT_TRUE(outcome.failed()) << expected;
    EXPECT_TRUE(mentions(outcome.regressions, expected)) << expected;
  };
  worse([](auto& h) { h[0].complete = 9; }, "Complete dropped");
  worse([](auto& h) { h[0].unsupported = 3; }, "Unsupported rose");
  worse([](auto& h) { h[0].invalid_ir = 1; }, "InvalidIR rose");
  worse([](auto& h) { h[0].error = true; }, "error");
  worse([](auto& h) { h[1].missed_starts = 5; }, "missed starts rose");
}

TEST(R1Ratchet, ReportsACountThatGetsBetter) {
  const std::vector<Counts> baseline = {counts("a", 'a', 10, 4)};
  std::vector<Counts> head = baseline;
  head[0].complete = 12;
  head[0].missed_starts = 1;
  const auto outcome = donkey::r1::check(baseline, head);
  EXPECT_FALSE(outcome.failed());
  EXPECT_TRUE(mentions(outcome.improvements, "Complete rose, 10 -> 12"));
  EXPECT_TRUE(mentions(outcome.improvements, "missed starts fell, 4 -> 1"));
}

// Other bytes are never compared with counts of the old bytes: the base CLI on the new bytes is
// the reference, and a drop against it fails even when the head beats the stale baseline.
TEST(R1Ratchet, OtherBytesAreComparedWithTheBaseCliOnThoseBytes) {
  const std::vector<Counts> baseline = {counts("a", 'a', 10)};
  const std::vector<Counts> head = {counts("a", 'z', 11), counts("new", 'n', 3)};
  {
    const auto outcome = donkey::r1::check(baseline, head);
    EXPECT_FALSE(outcome.failed());
    EXPECT_EQ(outcome.needs_base, (std::vector<std::string>{"a", "new"}));
  }
  {
    const std::vector<Counts> base = {counts("a", 'z', 12), counts("new", 'n', 3)};
    const auto outcome = donkey::r1::check(baseline, head, &base);
    EXPECT_TRUE(outcome.failed());
    EXPECT_TRUE(mentions(outcome.regressions, "a (against the base CLI on the same bytes)"));
    EXPECT_TRUE(outcome.needs_base.empty());
    EXPECT_TRUE(mentions(outcome.warnings, "new: the baseline is out of date (a new binary)"));
  }
  {
    const std::vector<Counts> base = {counts("a", 'z', 11), counts("new", 'n', 3)};
    const auto outcome = donkey::r1::check(baseline, head, &base);
    EXPECT_FALSE(outcome.failed());
    EXPECT_TRUE(mentions(outcome.warnings, "a: the baseline is out of date (other bytes"));
  }
  {
    // A base measurement of yet other bytes is no reference.
    const std::vector<Counts> base = {counts("a", 'y', 11), counts("new", 'n', 3)};
    const auto outcome = donkey::r1::check(baseline, head, &base);
    EXPECT_EQ(outcome.needs_base, (std::vector<std::string>{"a"}));
  }
}

TEST(R1Ratchet, ADroppedBinaryIsListed) {
  const std::vector<Counts> baseline = {counts("a", 'a', 10), counts("gone", 'g', 1)};
  const std::vector<Counts> head = {counts("a", 'a', 10)};
  const auto outcome = donkey::r1::check(baseline, head);
  EXPECT_EQ(outcome.removed, (std::vector<std::string>{"gone"}));
}
