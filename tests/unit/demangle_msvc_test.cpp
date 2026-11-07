#include <gtest/gtest.h>

#include <fstream>
#include <set>
#include <string>
#include <vector>

#include "donkey/binary/demangle.h"

namespace {

std::string fixture(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/msvc/" + name;
}

std::vector<std::string> lines_of(const std::string& path) {
  std::ifstream file(path);
  std::vector<std::string> lines;
  std::string line;
  while (std::getline(file, line)) {
    if (!line.empty() && line[0] != '#') {
      lines.push_back(line);
    }
  }
  return lines;
}

}  // namespace

// Every name in the recorded corpus is either demangled to exactly llvm-undname's text, or is
// listed as unsupported and is rejected as such. Nothing is compared loosely, and an
// unsupported name is never printed as if it were understood.
TEST(DemangleMsvc, CorpusMatchesLlvmUndname) {
  const std::set<std::string> unsupported_names = [] {
    std::set<std::string> names;
    for (const std::string& line : lines_of(fixture("msvc-unsupported.txt"))) {
      names.insert(line);
    }
    return names;
  }();
  std::size_t matched = 0;
  std::size_t rejected = 0;
  std::vector<std::string> failures;
  for (const std::string& line : lines_of(fixture("msvc-pairs.txt"))) {
    const std::size_t tab = line.find('\t');
    ASSERT_NE(tab, std::string::npos) << "a corpus line has no tab: " << line;
    const std::string mangled = line.substr(0, tab);
    const std::string expected = line.substr(tab + 1);
    const auto actual = donkey::demangle_msvc(mangled);
    if (unsupported_names.count(mangled) != 0) {
      if (actual || actual.diagnostic().code != "demangle.unsupported") {
        failures.push_back(mangled + " must be rejected as demangle.unsupported");
      } else {
        ++rejected;
      }
      continue;
    }
    if (!actual) {
      failures.push_back(mangled + " -> " + actual.diagnostic().code + ": " +
                         actual.diagnostic().message);
    } else if (actual.value() != expected) {
      failures.push_back(mangled + " -> [" + actual.value() + "] expected [" + expected + "]");
    } else {
      ++matched;
    }
  }
  for (const std::string& failure : failures) {
    ADD_FAILURE() << failure;
  }
  EXPECT_GT(matched, 20U);
  EXPECT_EQ(rejected, unsupported_names.size());
}

TEST(DemangleMsvc, RecognisesOnlyTheQuestionMarkPrefix) {
  EXPECT_TRUE(donkey::is_msvc_name("?f@@YAXXZ"));
  EXPECT_FALSE(donkey::is_msvc_name("_ZN3foo3barEi"));
  EXPECT_FALSE(donkey::is_msvc_name(""));
  const auto not_mangled = donkey::demangle_msvc("plain");
  ASSERT_FALSE(not_mangled);
  EXPECT_EQ(not_mangled.diagnostic().code, "demangle.not_mangled");
}

TEST(DemangleMsvc, MalformedNamesAreSyntaxErrorsNotGuesses) {
  for (const char* name : {"?", "?get", "?get@Box", "?get@Box@ns@@QEBAHH", "?f@@YAXXZ junk",
                           "?f@@YAXHH", "?g@@3", "?h@@YAXH"}) {
    const auto result = donkey::demangle_msvc(name);
    ASSERT_FALSE(result) << name;
    EXPECT_EQ(result.diagnostic().code, "demangle.syntax") << name;
  }
}

TEST(DemangleMsvc, UnsupportedFormsAreNamedAsSuchNotSyntaxErrors) {
  for (const char* name :
       {"??_C@_01FJMABOPO@x?$AA@", "??_7Box@ns@@6B@", "??__Eg_box@@YAXXZ", "?f@@YAXP6AHH@Z@Z"}) {
    const auto result = donkey::demangle_msvc(name);
    ASSERT_FALSE(result) << name;
    EXPECT_EQ(result.diagnostic().code, "demangle.unsupported") << name;
  }
}

TEST(DemangleMsvc, EnforcesTheInputAndOutputLimits) {
  donkey::DemangleOptions tight;
  tight.max_input_bytes = 8;
  const auto too_long = donkey::demangle_msvc("?get@Box@ns@@QEBAHH@Z", tight);
  ASSERT_FALSE(too_long);
  EXPECT_EQ(too_long.diagnostic().code, "demangle.too_long");

  donkey::DemangleOptions small_output;
  small_output.max_output_bytes = 4;
  const auto too_large = donkey::demangle_msvc("?plain@@YAXXZ", small_output);
  ASSERT_FALSE(too_large);
  EXPECT_EQ(too_large.diagnostic().code, "demangle.too_large");
}
