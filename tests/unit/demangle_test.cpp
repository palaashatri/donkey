#include <gtest/gtest.h>

#include <cstddef>
#include <cstdio>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#include "donkey/binary/demangle.h"

namespace {

std::string corpus_path() {
  return std::string(DONKEY_FIXTURE_DIR) + "/cpp/itanium-pairs.txt";
}

}  // namespace

// The recorded corpus: mangled names from compiled fixtures, with c++filt's output.
TEST(Demangle, ItaniumCorpus) {
  std::ifstream file(corpus_path());
  ASSERT_TRUE(file.good()) << corpus_path();
  // A name the demangler reports as unsupported is counted, not compared: an expression
  // used as a template argument (`X...E`) is not in the grammar this demangler reads, and
  // the residual is recorded in the ledger. Any other error, or any different text, fails.
  std::size_t checked = 0;
  std::size_t matched = 0;
  std::size_t unsupported = 0;
  std::vector<std::string> failures;
  std::string line;
  while (std::getline(file, line)) {
    if (line.empty() || line[0] == '#') {
      continue;
    }
    const std::size_t tab = line.find('\t');
    ASSERT_NE(tab, std::string::npos) << "a corpus line has no tab: " << line;
    const std::string mangled = line.substr(0, tab);
    const std::string expected = line.substr(tab + 1);
    ++checked;
    const auto actual = donkey::demangle_itanium(mangled);
    if (!actual) {
      if (actual.diagnostic().code == "demangle.unsupported") {
        ++unsupported;
        std::printf("unsupported: %s (%s)\n", mangled.c_str(), actual.diagnostic().message.c_str());
      } else {
        failures.push_back(mangled + " -> error " + actual.diagnostic().code + ": " +
                           actual.diagnostic().message + " (want " + expected + ")");
      }
    } else if (actual.value() != expected) {
      failures.push_back(mangled + " -> " + actual.value() + " (want " + expected + ")");
    } else {
      ++matched;
    }
  }
  std::printf("itanium corpus: %zu names, %zu match, %zu unsupported\n", checked, matched,
              unsupported);
  EXPECT_GE(checked, 300U);
  EXPECT_GE(matched, 300U);
  for (std::size_t i = 0; i < failures.size() && i < 25; ++i) {
    ADD_FAILURE() << failures[i];
  }
  EXPECT_EQ(failures.size(), 0U) << "of " << checked << " names";
}

TEST(Demangle, RefusesWhatIsNotAnItaniumName) {
  const auto plain = donkey::demangle_itanium("main");
  ASSERT_FALSE(plain.has_value());
  EXPECT_EQ(plain.diagnostic().code, "demangle.not_mangled");
  EXPECT_FALSE(donkey::is_itanium_name("main"));
  EXPECT_TRUE(donkey::is_itanium_name("_Z3foov"));
}

TEST(Demangle, LimitsAreEnforced) {
  const std::string long_name = "_Z" + std::string(5000, 'a');
  const auto too_long = donkey::demangle_itanium(long_name);
  ASSERT_FALSE(too_long.has_value());
  EXPECT_EQ(too_long.diagnostic().code, "demangle.too_long");

  // 300 nested pointers exceed the depth limit of 256.
  const std::string deep = "_Z1f" + std::string(300, 'P') + "i";
  const auto too_deep = donkey::demangle_itanium(deep);
  ASSERT_FALSE(too_deep.has_value());
  EXPECT_EQ(too_deep.diagnostic().code, "demangle.too_deep");
}

TEST(Demangle, TruncatedAndUnsupportedNamesAreErrors) {
  const auto truncated = donkey::demangle_itanium("_ZN3foo");
  ASSERT_FALSE(truncated.has_value());
  EXPECT_EQ(truncated.diagnostic().code, "demangle.syntax");

  const auto unsupported = donkey::demangle_itanium("_ZTZ3foo");
  ASSERT_FALSE(unsupported.has_value());
}

// Thunks name the function they adjust (G10-T3 found them in vtables). The expected text is
// c++filt's output for each name.
TEST(Demangle, ThunksNameTheirTarget) {
  const std::pair<const char*, const char*> cases[] = {
      {"_ZThn16_NK6Tagged4nameEv", "non-virtual thunk to Tagged::name() const"},
      {"_ZThn16_N3Foo3barEi", "non-virtual thunk to Foo::bar(int)"},
      {"_ZTv0_n24_NK6Tagged4nameEv", "virtual thunk to Tagged::name() const"},
      {"_ZTh0_N3Foo3barEv", "non-virtual thunk to Foo::bar()"},
  };
  for (const auto& [mangled, expected] : cases) {
    const auto result = donkey::demangle_itanium(mangled);
    ASSERT_TRUE(result.has_value()) << mangled;
    EXPECT_EQ(result.value(), expected) << mangled;
  }
}
