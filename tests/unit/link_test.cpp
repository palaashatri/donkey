#include <gtest/gtest.h>

#include <cstddef>
#include <string>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/binary/link.h"

namespace {

std::string fixture(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/link/" + name;
}

const donkey::ImportBinding* binding_named(const donkey::LinkResult& result,
                                           const std::string& name, std::size_t importer) {
  for (const donkey::ImportBinding& binding : result.bindings) {
    if (binding.name == name && binding.importer == importer) {
      return &binding;
    }
  }
  return nullptr;
}

const donkey::Symbol* export_named(const donkey::BinaryImage& image, const std::string& name) {
  for (const donkey::Symbol& symbol : image.symbols) {
    if (symbol.exported && symbol.name == name) {
      return &symbol;
    }
  }
  return nullptr;
}

}  // namespace

TEST(Link, AnImportIsBoundToTheLibraryTheImporterNeedsNotTheFirstExporter) {
  // libother.so.1 is listed before libprovider.so.1 and exports the same name, but the consumer
  // needs only libprovider.so.1 (its DT_NEEDED entry), so that is the provider.
  auto consumer = donkey::load_binary(fixture("libconsumer.so"));
  auto other = donkey::load_binary(fixture("libother.so.1"));
  auto provider = donkey::load_binary(fixture("libprovider.so.1"));
  ASSERT_TRUE(consumer.has_value() && other.has_value() && provider.has_value());
  const std::vector<donkey::LinkInput> inputs{
      {&consumer.value().image, consumer.value().data},
      {&other.value().image, other.value().data},
      {&provider.value().image, provider.value().data},
  };
  const donkey::LinkResult result = donkey::resolve_imports(inputs);
  const donkey::ImportBinding* bound = binding_named(result, "provided_fn", 0);
  ASSERT_NE(bound, nullptr);
  EXPECT_EQ(bound->provider, 2U);
  EXPECT_EQ(bound->library, "libprovider.so.1");
  const donkey::Symbol* exported = export_named(provider.value().image, "provided_fn");
  ASSERT_NE(exported, nullptr);
  EXPECT_NE(bound->address, 0U);
  EXPECT_EQ(bound->address, exported->address);
}

TEST(Link, AnImportNoInputExportsIsUnbound) {
  auto consumer = donkey::load_binary(fixture("libconsumer.so"));
  auto provider = donkey::load_binary(fixture("libprovider.so.1"));
  ASSERT_TRUE(consumer.has_value() && provider.has_value());
  const std::vector<donkey::LinkInput> inputs{
      {&consumer.value().image, consumer.value().data},
      {&provider.value().image, provider.value().data},
  };
  const donkey::LinkResult result = donkey::resolve_imports(inputs);
  const donkey::ImportBinding* missing = binding_named(result, "missing_fn", 0);
  ASSERT_NE(missing, nullptr);
  EXPECT_EQ(missing->provider, donkey::kUnboundImport);
  EXPECT_EQ(missing->address, 0U);
  EXPECT_EQ(missing->library, "");
  // Every unbound binding is counted, and the count matches the bindings that have no provider.
  std::size_t unbound = 0;
  for (const donkey::ImportBinding& binding : result.bindings) {
    if (binding.provider == donkey::kUnboundImport) {
      ++unbound;
    }
  }
  EXPECT_EQ(result.unbound, unbound);
  EXPECT_GE(result.unbound, 1U);
}

TEST(Link, AnImportIsNotBoundToALibraryTheImporterDoesNotNeed) {
  // The only exporter of provided_fn in this set is libother.so.1, which the consumer does not
  // name in DT_NEEDED: the import stays unbound.
  auto consumer = donkey::load_binary(fixture("libconsumer.so"));
  auto other = donkey::load_binary(fixture("libother.so.1"));
  ASSERT_TRUE(consumer.has_value() && other.has_value());
  const std::vector<donkey::LinkInput> inputs{
      {&consumer.value().image, consumer.value().data},
      {&other.value().image, other.value().data},
  };
  const donkey::LinkResult result = donkey::resolve_imports(inputs);
  const donkey::ImportBinding* bound = binding_named(result, "provided_fn", 0);
  ASSERT_NE(bound, nullptr);
  EXPECT_EQ(bound->provider, donkey::kUnboundImport);
}

TEST(Link, ReadsTheSonameAndTheNeededLibrariesOfAnElfImage) {
  auto consumer = donkey::load_binary(fixture("libconsumer.so"));
  auto provider = donkey::load_binary(fixture("libprovider.so.1"));
  ASSERT_TRUE(consumer.has_value() && provider.has_value());
  const donkey::ElfLibraryNames needs =
      donkey::read_library_names(consumer.value().image, consumer.value().data);
  EXPECT_EQ(needs.soname, "");
  ASSERT_FALSE(needs.needed.empty());
  EXPECT_EQ(needs.needed.front(), "libprovider.so.1");
  const donkey::ElfLibraryNames names =
      donkey::read_library_names(provider.value().image, provider.value().data);
  EXPECT_EQ(names.soname, "libprovider.so.1");
  EXPECT_TRUE(names.needed.empty() || names.needed.front() != "libconsumer.so");
}

TEST(Link, NullInputsAreSkipped) {
  const std::vector<donkey::LinkInput> inputs{{nullptr, {}}};
  const donkey::LinkResult result = donkey::resolve_imports(inputs);
  EXPECT_TRUE(result.bindings.empty());
  EXPECT_EQ(result.unbound, 0U);
}
