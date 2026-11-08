#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/analysis/link_calls.h"
#include "donkey/binary/image.h"
#include "donkey/binary/link.h"
#include "donkey/binary/plt.h"

namespace {

std::string fixture(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/link/aarch64/" + name;
}

}  // namespace

TEST(PltStubsAArch64, NamesEveryStubOfABtiPltWhateverItsStride) {
  // lld 18 puts the two stubs of libconsumer.so 24 bytes apart, each starting with an ADRP. Both
  // must be named: a scan that only looks at 16-byte boundaries finds one and misses the other.
  auto consumer = donkey::load_binary(fixture("libconsumer.so"));
  ASSERT_TRUE(consumer.has_value());
  const std::map<std::uint64_t, std::string> stubs =
      donkey::plt_stub_imports(consumer.value().image, consumer.value().data);
  std::map<std::string, int> by_name;
  for (const auto& [address, name] : stubs) {
    ++by_name[name];
  }
  EXPECT_EQ(by_name["provided_fn"], 1);
  EXPECT_EQ(by_name["missing_fn"], 1);
  EXPECT_EQ(stubs.size(), 2U);
}

TEST(LinkCallsAArch64, ABranchThroughABtiStubIsBoundToTheProvidersExport) {
  auto consumer = donkey::load_binary(fixture("libconsumer.so"));
  auto provider = donkey::load_binary(fixture("libprovider.so.1"));
  ASSERT_TRUE(consumer.has_value() && provider.has_value());
  const std::vector<donkey::LinkInput> inputs{
      {&consumer.value().image, consumer.value().data},
      {&provider.value().image, provider.value().data},
  };
  const donkey::LinkResult linked = donkey::resolve_imports(inputs);
  auto consumer_analysis = donkey::analyze(consumer.value().image, consumer.value().data);
  auto provider_analysis = donkey::analyze(provider.value().image, provider.value().data);
  ASSERT_TRUE(consumer_analysis.has_value() && provider_analysis.has_value());
  const std::vector<donkey::AnalysisResult> analyses{consumer_analysis.value(),
                                                     provider_analysis.value()};
  auto resolved = donkey::resolve_import_calls(inputs, linked, analyses);
  ASSERT_TRUE(resolved.has_value());

  std::size_t bound = 0;
  std::size_t unbound = 0;
  for (const donkey::ImportCall& call : resolved.value()) {
    if (call.importer != 0) {
      continue;
    }
    if (call.provider == 1U) {
      EXPECT_EQ(call.name, "provided_fn");
      EXPECT_EQ(call.kind, donkey::XrefKind::Call);
      ++bound;
      // The provider's export: its address is the one the link recorded for that import.
      EXPECT_NE(call.to, 0U);
    } else if (call.provider == donkey::kUnboundImport) {
      EXPECT_EQ(call.name, "missing_fn");
      ++unbound;
    }
  }
  EXPECT_EQ(bound, 1U);
  EXPECT_EQ(unbound, 1U);
}
