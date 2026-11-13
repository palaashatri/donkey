#include <gtest/gtest.h>

#include <cstddef>
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
  return std::string(DONKEY_FIXTURE_DIR) + "/link/" + name;
}

const donkey::Symbol* export_named(const donkey::BinaryImage& image, const std::string& name) {
  for (const donkey::Symbol& symbol : image.symbols) {
    if (symbol.exported && symbol.name == name) {
      return &symbol;
    }
  }
  return nullptr;
}

const donkey::ImportCall* call_named(const std::vector<donkey::ImportCall>& calls,
                                     const std::string& name) {
  for (const donkey::ImportCall& call : calls) {
    if (call.name == name) {
      return &call;
    }
  }
  return nullptr;
}

}  // namespace

TEST(PltStubs, NamesEachStubByTheImportItCalls) {
  auto consumer = donkey::load_binary(fixture("libconsumer.so"));
  ASSERT_TRUE(consumer.has_value());
  const std::map<std::uint64_t, std::string> stubs =
      donkey::plt_stub_imports(consumer.value().image, consumer.value().data);
  std::map<std::string, int> by_name;
  for (const auto& [address, name] : stubs) {
    EXPECT_NE(address, 0U);
    ++by_name[name];
  }
  EXPECT_EQ(by_name["provided_fn"], 1);
  EXPECT_EQ(by_name["missing_fn"], 1);
}

TEST(PltStubs, EveryStubNamesAnImportOfItsOwnImage) {
  // The provider exports provided_fn and imports __cxa_finalize, so its stub can only name the
  // latter. An export of the image itself must never be given a stub.
  auto provider = donkey::load_binary(fixture("libprovider.so.1"));
  ASSERT_TRUE(provider.has_value());
  const std::map<std::uint64_t, std::string> stubs =
      donkey::plt_stub_imports(provider.value().image, provider.value().data);
  ASSERT_FALSE(stubs.empty());
  for (const auto& [address, name] : stubs) {
    bool imported = false;
    for (const donkey::Symbol& symbol : provider.value().image.symbols) {
      imported = imported || (symbol.name == name && symbol.imported);
    }
    EXPECT_TRUE(imported) << name;
  }
  EXPECT_EQ(donkey::plt_stub_imports(provider.value().image, provider.value().data).count(0U), 0U);
}

TEST(LinkCalls, ACallThroughAPltStubIsBoundToTheExportItsImporterNeeds) {
  // libother.so.1 is listed before libprovider.so.1 and exports the same name. The consumer needs
  // libprovider.so.1, so its call to provided_fn must go to that export.
  auto consumer = donkey::load_binary(fixture("libconsumer.so"));
  auto other = donkey::load_binary(fixture("libother.so.1"));
  auto provider = donkey::load_binary(fixture("libprovider.so.1"));
  ASSERT_TRUE(consumer.has_value() && other.has_value() && provider.has_value());
  const std::vector<donkey::LinkInput> inputs{
      {&consumer.value().image, consumer.value().data},
      {&other.value().image, other.value().data},
      {&provider.value().image, provider.value().data},
  };
  const donkey::LinkResult linked = donkey::resolve_imports(inputs);
  auto consumer_analysis = donkey::analyze(consumer.value().image, consumer.value().data);
  auto other_analysis = donkey::analyze(other.value().image, other.value().data);
  auto provider_analysis = donkey::analyze(provider.value().image, provider.value().data);
  ASSERT_TRUE(consumer_analysis.has_value() && other_analysis.has_value() &&
              provider_analysis.has_value());
  const std::vector<donkey::AnalysisResult> analyses{
      consumer_analysis.value(), other_analysis.value(), provider_analysis.value()};

  auto resolved = donkey::resolve_import_calls(inputs, linked, analyses);
  ASSERT_TRUE(resolved.has_value());
  const std::vector<donkey::ImportCall>& calls = resolved.value();

  const donkey::ImportCall* bound = call_named(calls, "provided_fn");
  ASSERT_NE(bound, nullptr);
  EXPECT_EQ(bound->importer, 0U);
  EXPECT_EQ(bound->provider, 2U);
  const donkey::Symbol* exported = export_named(provider.value().image, "provided_fn");
  ASSERT_NE(exported, nullptr);
  EXPECT_EQ(bound->to, exported->address);
  EXPECT_NE(bound->to, 0U);
  // The call is a real call instruction of the consumer, and it goes to the stub the PLT names.
  EXPECT_EQ(bound->kind, donkey::XrefKind::Call);
  bool is_an_xref = false;
  for (const donkey::Xref& xref : consumer_analysis.value().xrefs) {
    is_an_xref = is_an_xref || (xref.from == bound->from && xref.to == bound->stub &&
                                xref.kind == donkey::XrefKind::Call);
  }
  EXPECT_TRUE(is_an_xref);
}

TEST(LinkCalls, ACallToAnImportNoInputExportsIsListedUnbound) {
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
  const donkey::ImportCall* missing = call_named(resolved.value(), "missing_fn");
  ASSERT_NE(missing, nullptr);
  EXPECT_EQ(missing->provider, donkey::kUnboundImport);
  EXPECT_EQ(missing->to, 0U);
}

TEST(LinkCalls, OneAnalysisIsNeededForEachInput) {
  auto consumer = donkey::load_binary(fixture("libconsumer.so"));
  auto provider = donkey::load_binary(fixture("libprovider.so.1"));
  ASSERT_TRUE(consumer.has_value() && provider.has_value());
  const std::vector<donkey::LinkInput> inputs{
      {&consumer.value().image, consumer.value().data},
      {&provider.value().image, provider.value().data},
  };
  const donkey::LinkResult linked = donkey::resolve_imports(inputs);
  auto consumer_analysis = donkey::analyze(consumer.value().image, consumer.value().data);
  ASSERT_TRUE(consumer_analysis.has_value());
  const std::vector<donkey::AnalysisResult> one{consumer_analysis.value()};
  auto resolved = donkey::resolve_import_calls(inputs, linked, one);
  ASSERT_FALSE(resolved.has_value());
  EXPECT_EQ(resolved.diagnostic().code, "link.analyses_mismatch");
}

// libconsumer_got.so is built with -fno-plt, so its calls to provided_fn and missing_fn read their
// GOT slots (`call *slot(%rip)`) and have no PLT stub. It also loads provided_fn's slot without
// calling it (address_of_provided), and calls __gmon_start__ through a register it loaded.

TEST(GotSlots, NamesEachSlotByTheImportItLoads) {
  auto consumer = donkey::load_binary(fixture("libconsumer_got.so"));
  ASSERT_TRUE(consumer.has_value());
  const std::map<std::uint64_t, std::string> slots =
      donkey::got_import_slots(consumer.value().image, consumer.value().data);
  std::map<std::string, int> by_name;
  for (const auto& [address, name] : slots) {
    EXPECT_NE(address, 0U);
    ++by_name[name];
  }
  EXPECT_EQ(by_name["provided_fn"], 1);
  EXPECT_EQ(by_name["missing_fn"], 1);
}

TEST(LinkCalls, ACallThroughAGotSlotIsBoundToTheExportItsImporterNeeds) {
  // libother.so.1 is listed before libprovider.so.1 and exports the same name. The consumer needs
  // libprovider.so.1, so the call through its GOT slot must go to that export.
  auto consumer = donkey::load_binary(fixture("libconsumer_got.so"));
  auto other = donkey::load_binary(fixture("libother.so.1"));
  auto provider = donkey::load_binary(fixture("libprovider.so.1"));
  ASSERT_TRUE(consumer.has_value() && other.has_value() && provider.has_value());
  const std::vector<donkey::LinkInput> inputs{
      {&consumer.value().image, consumer.value().data},
      {&other.value().image, other.value().data},
      {&provider.value().image, provider.value().data},
  };
  const donkey::LinkResult linked = donkey::resolve_imports(inputs);
  auto consumer_analysis = donkey::analyze(consumer.value().image, consumer.value().data);
  auto other_analysis = donkey::analyze(other.value().image, other.value().data);
  auto provider_analysis = donkey::analyze(provider.value().image, provider.value().data);
  ASSERT_TRUE(consumer_analysis.has_value() && other_analysis.has_value() &&
              provider_analysis.has_value());
  const std::vector<donkey::AnalysisResult> analyses{
      consumer_analysis.value(), other_analysis.value(), provider_analysis.value()};

  auto resolved = donkey::resolve_import_calls(inputs, linked, analyses);
  ASSERT_TRUE(resolved.has_value());
  const donkey::ImportCall* bound = call_named(resolved.value(), "provided_fn");
  ASSERT_NE(bound, nullptr);
  EXPECT_EQ(bound->importer, 0U);
  EXPECT_EQ(bound->provider, 2U);
  const donkey::Symbol* exported = export_named(provider.value().image, "provided_fn");
  ASSERT_NE(exported, nullptr);
  EXPECT_EQ(bound->to, exported->address);
  EXPECT_NE(bound->to, 0U);
  EXPECT_EQ(bound->kind, donkey::XrefKind::Call);

  // The slot the call reads is the one the GLOB_DAT relocation names for provided_fn, and the
  // call instruction reads it: a data xref from the call to the slot.
  std::uint64_t slot = 0;
  for (const auto& [address, name] :
       donkey::got_import_slots(consumer.value().image, consumer.value().data)) {
    if (name == "provided_fn") {
      slot = address;
    }
  }
  ASSERT_NE(slot, 0U);
  EXPECT_EQ(bound->stub, slot);
  bool reads_slot = false;
  for (const donkey::Xref& xref : consumer_analysis.value().xrefs) {
    reads_slot = reads_slot || (xref.from == bound->from && xref.to == slot &&
                                xref.kind == donkey::XrefKind::Data);
  }
  EXPECT_TRUE(reads_slot);
}

TEST(LinkCalls, ACallThroughAGotSlotToAnImportNoInputExportsIsListedUnbound) {
  auto consumer = donkey::load_binary(fixture("libconsumer_got.so"));
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
  const donkey::ImportCall* missing = call_named(resolved.value(), "missing_fn");
  ASSERT_NE(missing, nullptr);
  EXPECT_EQ(missing->kind, donkey::XrefKind::Call);
  EXPECT_EQ(missing->provider, donkey::kUnboundImport);
  EXPECT_EQ(missing->to, 0U);
}

TEST(LinkCalls, ALoadOfAGotSlotThatIsNotCalledIsNotListed) {
  auto consumer = donkey::load_binary(fixture("libconsumer_got.so"));
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
  std::uint64_t slot = 0;
  for (const auto& [address, name] :
       donkey::got_import_slots(consumer.value().image, consumer.value().data)) {
    if (name == "provided_fn") {
      slot = address;
    }
  }
  ASSERT_NE(slot, 0U);
  // Two instructions read the slot: the call in got_consumer_fn and the load in
  // address_of_provided.
  int reads = 0;
  for (const donkey::Xref& xref : consumer_analysis.value().xrefs) {
    reads += (xref.to == slot && xref.kind == donkey::XrefKind::Data) ? 1 : 0;
  }
  EXPECT_EQ(reads, 2);

  auto resolved = donkey::resolve_import_calls(inputs, linked, analyses);
  ASSERT_TRUE(resolved.has_value());
  int listed = 0;
  for (const donkey::ImportCall& call : resolved.value()) {
    listed += (call.stub == slot) ? 1 : 0;
  }
  EXPECT_EQ(listed, 1);
}

TEST(LinkCalls, ACallThroughARegisterLoadedFromAGotSlotIsNotListed) {
  // _init loads __gmon_start__'s slot into rax and calls rax. No instruction calls the slot
  // itself, so the call is not bound to the import: a documented gap, not a guess.
  auto consumer = donkey::load_binary(fixture("libconsumer_got.so"));
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
  EXPECT_EQ(call_named(resolved.value(), "__gmon_start__"), nullptr);
}

// The fixture also calls own_fn, which the image defines and exports. With -fsemantic-interposition
// the call goes through a PLT stub whose JUMP_SLOT names own_fn, and the address the fixture takes
// of own_fn is a GLOB_DAT slot. Neither is an import of the image, so neither may be listed as one.

TEST(GotSlots, ASymbolTheImageDefinesIsNotAnImportSlot) {
  auto consumer = donkey::load_binary(fixture("libconsumer_got.so"));
  ASSERT_TRUE(consumer.has_value());
  for (const auto& [address, name] :
       donkey::got_import_slots(consumer.value().image, consumer.value().data)) {
    EXPECT_NE(name, "own_fn") << "slot " << address;
  }
}

TEST(PltStubs, AStubForAFunctionTheImageDefinesIsNotNamedAnImport) {
  auto consumer = donkey::load_binary(fixture("libconsumer_got.so"));
  ASSERT_TRUE(consumer.has_value());
  for (const auto& [address, name] :
       donkey::plt_stub_imports(consumer.value().image, consumer.value().data)) {
    EXPECT_NE(name, "own_fn") << "stub " << address;
  }
}

TEST(LinkCalls, ACallToAFunctionTheImageDefinesIsNotListed) {
  auto consumer = donkey::load_binary(fixture("libconsumer_got.so"));
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
  // The call is really there: the analysis sees a call to the own_fn stub.
  bool calls_own_stub = false;
  for (const donkey::Xref& xref : consumer_analysis.value().xrefs) {
    calls_own_stub = calls_own_stub || xref.kind == donkey::XrefKind::Call;
  }
  EXPECT_TRUE(calls_own_stub);
  const std::vector<donkey::AnalysisResult> analyses{consumer_analysis.value(),
                                                     provider_analysis.value()};
  auto resolved = donkey::resolve_import_calls(inputs, linked, analyses);
  ASSERT_TRUE(resolved.has_value());
  EXPECT_EQ(call_named(resolved.value(), "own_fn"), nullptr);
  // The imports of the same image are still listed.
  EXPECT_NE(call_named(resolved.value(), "provided_fn"), nullptr);
  EXPECT_NE(call_named(resolved.value(), "missing_fn"), nullptr);
}
