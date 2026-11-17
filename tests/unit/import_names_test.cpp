// Import stubs, GOT calls and thunks named by what they call (G24-T4). The fixtures are built from
// tests/fixtures/stubs/stubs.c (see PROVENANCE.md there); the oracle for each stub address is
// `objdump -d` on the same file.

#include <gtest/gtest.h>

#include <cstdint>
#include <map>
#include <string>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/binary/plt.h"
#include "donkey/ir/ir.h"
#include "donkey/ir/lift.h"

namespace {

std::string fixture(const std::string& directory, const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/" + directory + "/" + name;
}

struct Analyzed {
  donkey::LoadedBinary binary;
  donkey::AnalysisResult analysis;
};

Analyzed analyze_fixture(const std::string& directory, const std::string& name) {
  auto loaded = donkey::load_binary(fixture(directory, name));
  EXPECT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  Analyzed out{std::move(loaded.value()), {}};
  auto analysis = donkey::analyze(out.binary.image, out.binary.data);
  EXPECT_TRUE(analysis.has_value()) << analysis.diagnostic().message;
  out.analysis = std::move(analysis.value());
  return out;
}

const donkey::Function* function_at(const donkey::AnalysisResult& analysis,
                                    std::uint64_t address) {
  for (const donkey::Function& function : analysis.functions) {
    if (function.address == address) {
      return &function;
    }
  }
  return nullptr;
}

/// The pseudocode of the function that contains `address`.
std::string pseudocode_containing(const Analyzed& analyzed, std::uint64_t address) {
  for (const donkey::Function& function : analyzed.analysis.functions) {
    if (!function.has_extent || address < function.address || address >= function.end_address) {
      continue;
    }
    auto lifted = donkey::lift_function(analyzed.binary.image, analyzed.analysis, function);
    EXPECT_TRUE(lifted.has_value()) << lifted.diagnostic().message;
    auto text = donkey::format_pseudocode(lifted.value());
    EXPECT_TRUE(text.has_value()) << text.diagnostic().message;
    return text.value();
  }
  ADD_FAILURE() << "no function contains " << std::hex << address;
  return {};
}

}  // namespace

// `.plt.got` entries jump through a GLOB_DAT slot, not a JUMP_SLOT. objdump: `1050
// <__cxa_finalize@plt>`, an ENDBR64 then `jmp *0x2f6e(%rip)`, a 16-byte entry.
TEST(PltStubs, PltGotEntryIsNamedByItsGlobDatSlot) {
  auto loaded = donkey::load_binary(fixture("link", "libtailcall.so"));
  ASSERT_TRUE(loaded.has_value());
  const auto stubs = donkey::plt_stub_imports(loaded.value().image, loaded.value().data);
  ASSERT_TRUE(stubs.contains(0x1050));
  EXPECT_EQ(stubs.at(0x1050), "__cxa_finalize");
  // The second half of the 16-byte entry is not a stub of its own.
  EXPECT_FALSE(stubs.contains(0x1058));
}

// objdump on stubs_x86_64: `1060 <abort@plt>`, `1070 <puts@plt>` (in `.plt.sec`), and
// `1050 <__cxa_finalize@plt>` (in `.plt.got`).
TEST(Analysis, PltStubIsNamedByItsImport) {
  const Analyzed analyzed = analyze_fixture("stubs", "stubs_x86_64");
  const donkey::Function* abort_stub = function_at(analyzed.analysis, 0x1060);
  ASSERT_NE(abort_stub, nullptr);
  EXPECT_EQ(abort_stub->name, "abort@plt");
  EXPECT_EQ(abort_stub->import_name, "abort");
  const donkey::Function* puts_stub = function_at(analyzed.analysis, 0x1070);
  ASSERT_NE(puts_stub, nullptr);
  EXPECT_EQ(puts_stub->name, "puts@plt");
  EXPECT_EQ(donkey::call_target_name(analyzed.analysis, 0x1060), "abort");
  // A function with no name of its own gives no call name: it prints as sub_<hex>.
  EXPECT_EQ(donkey::call_target_name(analyzed.analysis, 0x1169), "");
}

// The decompiler prints the call by the import's own name, which is valid C: `abort();`, not
// `sub_1060();` and not `abort@plt();`. objdump: `1179: call 1060 <abort@plt>`,
// `1186: call 1070 <puts@plt>`.
TEST(Analysis, DecompilerPrintsImportCallsByName) {
  const Analyzed analyzed = analyze_fixture("stubs", "stubs_x86_64");
  const std::string check = pseudocode_containing(analyzed, 0x1179);
  EXPECT_NE(check.find("abort("), std::string::npos) << check;
  EXPECT_EQ(check.find("sub_1060"), std::string::npos) << check;
  EXPECT_EQ(check.find("@plt"), std::string::npos) << check;
  const std::string show = pseudocode_containing(analyzed, 0x1186);
  EXPECT_NE(show.find("puts("), std::string::npos) << show;
  // The stub itself prints under the import's name, with a note.
  const std::string stub = pseudocode_containing(analyzed, 0x1060);
  EXPECT_NE(stub.find(" abort(void) {"), std::string::npos) << stub;
  EXPECT_NE(stub.find("import stub"), std::string::npos) << stub;
}

// -fno-plt: `1139: call *0x2e91(%rip)` reads the slot 0x3fd0, which a GLOB_DAT for `abort` names.
TEST(Analysis, GotCallIsNamedByItsImport) {
  const Analyzed analyzed = analyze_fixture("stubs", "stubs_noplt_x86_64");
  ASSERT_TRUE(analyzed.analysis.import_slots.contains(0x3fd0));
  EXPECT_EQ(analyzed.analysis.import_slots.at(0x3fd0), "abort");
  const std::string check = pseudocode_containing(analyzed, 0x1139);
  EXPECT_NE(check.find("abort("), std::string::npos) << check;
  EXPECT_EQ(check.find("0x3fd0"), std::string::npos) << check;
}

// llvm-objdump on stubs_aarch64: `620 <abort@plt>`, `630 <puts@plt>`. The stub reader only reads
// bytes, so no AArch64 host is needed.
TEST(Analysis, AArch64PltStubIsNamed) {
  const Analyzed analyzed = analyze_fixture("stubs", "stubs_aarch64");
  const donkey::Function* abort_stub = function_at(analyzed.analysis, 0x620);
  ASSERT_NE(abort_stub, nullptr);
  EXPECT_EQ(abort_stub->name, "abort@plt");
  const donkey::Function* puts_stub = function_at(analyzed.analysis, 0x630);
  ASSERT_NE(puts_stub, nullptr);
  EXPECT_EQ(puts_stub->name, "puts@plt");
}

TEST(Analysis, CallTargetNamesAreCIdentifiers) {
  EXPECT_TRUE(donkey::is_c_identifier("abort"));
  EXPECT_TRUE(donkey::is_c_identifier("_ZN3foo3barEv"));
  EXPECT_FALSE(donkey::is_c_identifier("abort@plt"));
  EXPECT_FALSE(donkey::is_c_identifier("main.cold"));
  EXPECT_FALSE(donkey::is_c_identifier("9lives"));
  EXPECT_FALSE(donkey::is_c_identifier(""));
}

// PE (MinGW): the IAT slot of each import is named, so `call *slot(%rip)` prints by name. llvm-
// objdump -p lists KERNEL32's IAT at 0x8168, VirtualQuery tenth (0x1400081b0), and
// `1400018ca: callq *0x68e0(%rip) # 0x1400081b0`.
TEST(Analysis, PeIatCallIsNamedByItsImport) {
  const Analyzed analyzed = analyze_fixture("stubs", "stubs_x86_64.exe");
  ASSERT_TRUE(analyzed.analysis.import_slots.contains(0x1400081b0));
  EXPECT_EQ(analyzed.analysis.import_slots.at(0x1400081b0), "VirtualQuery");
  const std::string caller = pseudocode_containing(analyzed, 0x1400018ca);
  EXPECT_NE(caller.find("VirtualQuery("), std::string::npos) << caller;
}

// MinGW calls msvcrt through 8-byte thunks, `jmpq *slot(%rip)`: `140002698: jmpq *0x5b82(%rip)
// # 0x140008220`, the slot of abort (msvcrt's IAT starts at 0x81c0). The thunk is an import stub
// named `abort`, and `140001490: callq 0x140002698` prints as a call to abort.
TEST(Analysis, PeImportThunkIsNamedByItsImport) {
  const Analyzed analyzed = analyze_fixture("stubs", "stubs_x86_64.exe");
  const donkey::Function* thunk = function_at(analyzed.analysis, 0x140002698);
  ASSERT_NE(thunk, nullptr);
  EXPECT_EQ(thunk->name, "abort");
  EXPECT_EQ(thunk->import_name, "abort");
  const std::string caller = pseudocode_containing(analyzed, 0x140001490);
  EXPECT_NE(caller.find("abort();"), std::string::npos) << caller;
  // The thunk's own jump keeps its slot form: printed by name it would read as a self-call.
  const std::string stub = pseudocode_containing(analyzed, 0x140002698);
  EXPECT_EQ(stub.find("  abort("), std::string::npos) << stub;
}
