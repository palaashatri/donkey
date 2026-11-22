// G20-T2: the R1 measurement (tools/r1/r1_measure.h): reading binaries.json, counting a decompile
// output, grouping notes, and the function-symbol ground truth for stripped binaries, checked
// against readelf on a library with an IFUNC symbol.

#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "donkey/binary/image.h"
#include "r1_measure.h"

namespace {

const std::string kSha(64, 'a');

std::string binaries_json(const std::string& entries) {
  return "{\"schema\": 1, \"binaries\": [" + entries + "]}";
}

std::string entry(const std::string& file, const std::string& variant,
                  const std::string& twin = "") {
  return "{\"file\": \"" + file +
         "\", \"build\": \"b\", \"source\": \"s 1\", \"toolchain\": \"t\", "
         "\"architecture\": \"x86_64\", \"level\": \"O2\", \"variant\": \"" +
         variant +
         "\", \"unstripped\": " + (twin.empty() ? std::string("null") : "\"" + twin + "\"") +
         ", \"compiler\": \"gcc\", \"sha256\": \"" + kSha + "\"}";
}

}  // namespace

TEST(R1, ReadsBinaries) {
  auto read = donkey::r1::read_binaries(binaries_json(entry("a.so", "unstripped") + ", " +
                                                      entry("a.so.stripped", "stripped", "a.so")));
  ASSERT_TRUE(read.has_value()) << read.diagnostic().message;
  ASSERT_EQ(read.value().size(), 2U);
  EXPECT_EQ(read.value()[0].file, "a.so");
  EXPECT_TRUE(read.value()[0].unstripped.empty());
  EXPECT_EQ(read.value()[1].unstripped, "a.so");
  EXPECT_EQ(read.value()[1].variant, "stripped");
}

// A file name becomes a path: it must be a plain name, and a stripped copy needs its twin.
TEST(R1, RefusesUnsafeOrIncompleteBinaries) {
  for (const std::string& bad :
       {binaries_json(entry("../a.so", "unstripped")), binaries_json(entry("x/a.so", "unstripped")),
        binaries_json(entry("..", "unstripped")), binaries_json(entry("a.so", "other")),
        binaries_json(entry("a.so", "stripped")), binaries_json(entry("a.so", "stripped", "../b")),
        std::string("{\"schema\": 2, \"binaries\": []}"), std::string("[]"),
        std::string("not json")}) {
    auto read = donkey::r1::read_binaries(bad);
    ASSERT_FALSE(read.has_value()) << bad;
    EXPECT_EQ(read.diagnostic().code, "r1.bad_binaries") << bad;
  }
}

TEST(R1, CountsADecompileOutput) {
  const std::string json = R"({"truncated": false, "functions": [
    {"address": "0x1000", "name": "f", "status": "Complete", "notes": ["x86-64 subset; locals are not recovered"]},
    {"address": "0x1010", "name": "g", "status": "Partial", "notes": [
        "x86-64 subset; locals are not recovered",
        "outgoing call arguments and return values follow no modelled ABI",
        "jump leaves the function; treated as a tail call"]},
    {"address": "0x1020", "name": "h", "status": "Partial", "notes": [
        "signature inferred from System V AMD64 ABI register use, not debug info",
        "jump leaves the function; treated as a tail call",
        "jump leaves the function; treated as a tail call"]},
    {"address": "0x1030", "name": "u", "status": "Partial", "notes": [
        "x86-64 subset; locals are not recovered",
        "parameter names come from the debug information"]},
    {"address": "0x1038", "name": "r", "status": "Partial", "notes": [
        "x86-64 subset; locals are not recovered",
        "jump leaves the function; treated as a tail call"],
        "unsupported": ["rol rdx, cl", "syscall", "rol rax, 3"]},
    {"address": "0x1039", "name": "s", "status": "Partial", "notes": [
        "x86-64 subset; locals are not recovered"], "unsupported": ["syscall"]},
    {"address": "0x1040", "name": "v", "status": "Unsupported", "code": "ir.x"},
    {"address": "0x1050", "name": "w", "status": "InvalidIR", "code": "ir.y"}]})";
  auto measured = donkey::r1::measure_decompile("b", json);
  ASSERT_TRUE(measured.has_value()) << measured.diagnostic().message;
  const auto& m = measured.value();
  EXPECT_EQ(m.functions, 8U);
  EXPECT_EQ(m.complete, 1U);
  EXPECT_EQ(m.partial, 5U);
  EXPECT_EQ(m.unsupported, 1U);
  EXPECT_EQ(m.invalid_ir, 1U);
  EXPECT_TRUE(m.has_notes);
  EXPECT_EQ(m.first_notes.at("outgoing call arguments and return values follow no modelled ABI"),
            1U);
  // An instruction that is not lifted is counted once per mnemonic; with a specific note in the
  // same function, the note stays the first reason.
  EXPECT_EQ(m.first_notes.count("unsupported instruction 'rol'"), 0U);
  EXPECT_EQ(m.first_notes.at("jump leaves the function; treated as a tail call"), 2U);
  EXPECT_EQ(m.all_notes.at("unsupported instruction 'rol'"), 1U);
  // With no specific note, the unsupported instruction is the reason: not an unexplained Partial.
  EXPECT_EQ(m.first_notes.at("unsupported instruction 'syscall'"), 1U);
  EXPECT_EQ(m.all_notes.at("unsupported instruction 'syscall'"), 2U);
  // A note repeated within one function counts once.
  EXPECT_EQ(m.all_notes.at("jump leaves the function; treated as a tail call"), 3U);
  ASSERT_EQ(m.unexplained.size(), 1U);
  EXPECT_EQ(m.unexplained[0].address, "0x1030");
  EXPECT_EQ(m.starts, (std::set<std::uint64_t>{0x1000, 0x1010, 0x1020, 0x1030, 0x1038, 0x1039,
                                               0x1040, 0x1050}));
}

// Output from a CLI built before the notes array counts the same statuses and no reasons.
TEST(R1, AcceptsOutputWithoutNotes) {
  auto measured =
      donkey::r1::measure_decompile("b", R"({"functions": [{"address": "0x10", "status": "Partial"},
                             {"address": "0x20", "status": "Complete"}]})");
  ASSERT_TRUE(measured.has_value()) << measured.diagnostic().message;
  EXPECT_FALSE(measured.value().has_notes);
  EXPECT_EQ(measured.value().partial, 1U);
  EXPECT_EQ(measured.value().complete, 1U);
  EXPECT_TRUE(measured.value().first_notes.empty());
  EXPECT_TRUE(measured.value().unexplained.empty());
}

TEST(R1, RefusesUnusableDecompileOutput) {
  for (const std::string& bad :
       {std::string("{\"truncated\": true, \"functions\": []}"), std::string("{}"),
        std::string("{\"functions\": [{\"address\": \"x\", \"status\": \"Complete\"}]}"),
        std::string("{\"functions\": [{\"address\": \"0x1\", \"status\": \"Odd\"}]}"),
        std::string("{\"functions\": [{\"address\": \"0x1\", \"status\": \"Partial\", "
                    "\"notes\": \"x\"}]}"),
        std::string("{\"functions\": [")}) {
    auto measured = donkey::r1::measure_decompile("b", bad);
    ASSERT_FALSE(measured.has_value()) << bad;
    EXPECT_EQ(measured.diagnostic().code, "r1.bad_decompile") << bad;
  }
}

// An analysis that stopped at a resource limit may have missed functions: its output is not a
// whole-binary measurement. Other analysis diagnostics are recorded and the output is counted.
TEST(R1, RefusesAnAnalysisStoppedAtALimit) {
  for (const char* code :
       {"analysis.instruction_limit", "analysis.block_limit", "analysis.traversal_limit"}) {
    const std::string text =
        std::string(R"({"analysis_partial": true, "analysis_diagnostics": [")") + code +
        R"("], "functions": []})";
    auto measured = donkey::r1::measure_decompile("b", text);
    ASSERT_FALSE(measured.has_value()) << code;
    EXPECT_EQ(measured.diagnostic().code, "r1.bad_decompile");
    EXPECT_NE(measured.diagnostic().message.find(code), std::string::npos);
  }
  auto measured = donkey::r1::measure_decompile(
      "b", R"({"analysis_partial": true, "analysis_diagnostics": ["analysis.eh_frame_incomplete"],
               "functions": [{"address": "0x10", "status": "Complete", "notes": []}]})");
  ASSERT_TRUE(measured.has_value()) << measured.diagnostic().message;
  EXPECT_TRUE(measured.value().analysis_partial);
  EXPECT_EQ(measured.value().analysis_notes,
            (std::vector<std::string>{"analysis.eh_frame_incomplete"}));
  EXPECT_EQ(measured.value().complete, 1U);
  // An unreadable start table may leave functions out: counted, and marked.
  EXPECT_TRUE(measured.value().starts_may_be_missing);
}

// Only the diagnostic known to leave discovery whole is unmarked; an unknown one is marked.
TEST(R1, MarksAnalysesThatMayMissStarts) {
  using donkey::r1::leaves_starts_complete;
  EXPECT_TRUE(leaves_starts_complete("analysis.no_return_unverified"));
  for (const char* code : {"analysis.eh_frame_incomplete", "analysis.pdata_incomplete",
                           "analysis.init_fini_incomplete", "analysis.section_out_of_bounds",
                           "analysis.decode_stopped", "unwind_info.bad_page",
                           "function_starts.bad_offset", "analysis.something_new"}) {
    EXPECT_FALSE(leaves_starts_complete(code)) << code;
  }
  auto measured = donkey::r1::measure_decompile(
      "b", R"({"analysis_partial": true, "analysis_diagnostics": ["analysis.no_return_unverified"],
               "functions": [{"address": "0x10", "status": "Complete", "notes": []}]})");
  ASSERT_TRUE(measured.has_value()) << measured.diagnostic().message;
  EXPECT_FALSE(measured.value().starts_may_be_missing);
}

// The call census (G21): calls by kind of target, and, for a Partial function whose only reason is
// the unresolved-call note, the kinds and imports that keep it Partial. A function with another
// reason too is counted in the calls only.
TEST(R1, CountsUnresolvedCalls) {
  const std::string note = "outgoing call arguments and return values follow no modelled ABI";
  const std::string text =
      R"({"functions": [
        {"address": "0x10", "status": "Partial", "notes": [")" +
      note + R"("],
         "unresolved_calls": [{"address": "0x11", "kind": "import", "name": "memset"},
                              {"address": "0x12", "kind": "same_image"}]},
        {"address": "0x20", "status": "Partial", "notes": [")" +
      note + R"("],
         "unresolved_calls": [{"address": "0x21", "kind": "aarch64", "name": "memset"},
                              {"address": "0x22", "kind": "aarch64"}]},
        {"address": "0x30", "status": "Partial", "notes": [")" +
      note + R"(", "jump leaves the function; treated as a tail call"],
         "unresolved_calls": [{"address": "0x31", "kind": "indirect"}]},
        {"address": "0x40", "status": "Complete", "notes": [], "unresolved_calls": []},
        {"address": "0x50", "status": "Partial", "notes": [")" +
      note +
      R"(", "register x0 is read after a call that does not define it; the value is not the caller's, so the function is not Complete"],
         "unresolved_calls": [{"address": "0x51", "kind": "aarch64"}]},
        {"address": "0x60", "status": "Partial", "notes": ["jump leaves the function; treated as a tail call"],
         "unresolved_calls": [{"address": "0x61", "kind": "same_image"}]},
        {"address": "0x70", "status": "Partial", "notes": [")" +
      note + R"(", "statement limit reached"],
         "unresolved_calls": [{"address": "0x71", "kind": "import", "name": "free"}]}]})";
  auto measured = donkey::r1::measure_decompile("b", text);
  ASSERT_TRUE(measured.has_value()) << measured.diagnostic().message;
  const auto& m = measured.value();
  EXPECT_TRUE(m.has_call_census);
  EXPECT_EQ(m.calls_by_kind, (std::map<std::string, std::size_t>{{"aarch64_import", 1},
                                                                 {"aarch64_other", 2},
                                                                 {"import", 2},
                                                                 {"indirect", 1},
                                                                 {"same_image", 2}}));
  // A tail call's note and the clobber check's read of a register after an unresolved call are
  // reasons an unresolved call gives: 0x30, 0x50 and 0x60 count. 0x70 has a reason of its own.
  EXPECT_EQ(m.call_only_partial, 5U);
  EXPECT_EQ(m.call_only_by_kinds,
            (std::map<std::string, std::size_t>{{"aarch64_import+aarch64_other", 1},
                                                {"aarch64_other", 1},
                                                {"import+same_image", 1},
                                                {"indirect", 1},
                                                {"same_image", 1}}));
  EXPECT_EQ(m.call_only_imports, (std::map<std::string, std::size_t>{{"memset", 2}}));
  // Output from a CLI before the census has no unresolved_calls arrays.
  auto older = donkey::r1::measure_decompile(
      "b", R"({"functions": [{"address": "0x10", "status": "Partial", "notes": []}]})");
  ASSERT_TRUE(older.has_value());
  EXPECT_FALSE(older.value().has_call_census);
  // The census is missing whatever the status: a Complete function, or a Partial one without
  // notes, of an older CLI has no list either.
  auto complete_only = donkey::r1::measure_decompile(
      "b", R"({"functions": [{"address": "0x10", "status": "Complete", "notes": []}]})");
  ASSERT_TRUE(complete_only.has_value());
  EXPECT_FALSE(complete_only.value().has_call_census);
  auto without_notes = donkey::r1::measure_decompile(
      "b", R"({"functions": [{"address": "0x10", "status": "Partial"}]})");
  ASSERT_TRUE(without_notes.has_value());
  EXPECT_FALSE(without_notes.value().has_call_census);
  // An entry that was never lifted carries no list and does not make the census absent.
  auto unlifted = donkey::r1::measure_decompile(
      "b", R"({"functions": [{"address": "0x10", "status": "Unsupported"},
                             {"address": "0x20", "status": "Complete", "notes": [],
                              "unresolved_calls": []}]})");
  ASSERT_TRUE(unlifted.has_value());
  EXPECT_TRUE(unlifted.value().has_call_census);
}

TEST(R1, NormalisesNotes) {
  using donkey::r1::normalise_note;
  EXPECT_EQ(normalise_note("a jump at 0x1149 to sub_1234 leaves 3 blocks"),
            "a jump at 0xN to sub_N leaves N blocks");
  // Digits inside names stay: registers, the architecture.
  EXPECT_EQ(normalise_note("both rax and xmm0 are written on x86-64"),
            "both rax and xmm0 are written on x86-64");
  EXPECT_EQ(normalise_note("register r12 is read"), "register r12 is read");
  EXPECT_TRUE(donkey::r1::is_generic_note("AArch64 subset; locals are not recovered"));
  EXPECT_TRUE(donkey::r1::is_generic_note(
      "x86-32 subset; register aliases are not canonicalised, cdecl stack arguments are not "
      "recovered and locals are not recovered"));
  EXPECT_FALSE(donkey::r1::is_generic_note("jump leaves the function; treated as a tail call"));
  // A resolved tail call says how it was lifted, not why the function is Partial.
  EXPECT_TRUE(donkey::r1::is_generic_note(
      "a jump to a known function is lifted as a call with its inferred arguments and result, "
      "followed by a return"));
  EXPECT_TRUE(donkey::r1::is_generic_note(
      "a jump to a C library function is lifted as a call of its model, followed by a return"));
}

TEST(R1, ComparesStarts) {
  const auto cmp = donkey::r1::compare_starts({1, 2, 3, 4}, {2, 3, 9});
  EXPECT_EQ(cmp.truth, 4U);
  EXPECT_EQ(cmp.found, 3U);
  EXPECT_EQ(cmp.matched, 2U);
  EXPECT_EQ(cmp.missed, 2U);
  EXPECT_EQ(cmp.extra, 1U);
  // A found start that is a stub is counted as a stub, not as an extra start.
  const auto with_stub = donkey::r1::compare_starts({1, 2}, {1, 7, 9}, {7});
  EXPECT_EQ(with_stub.stubs, 1U);
  EXPECT_EQ(with_stub.extra, 1U);
  EXPECT_EQ(with_stub.missed, 1U);
}

// The ground truth is Donkey's own ELF reader; readelf checks it: every FUNC and IFUNC symbol
// defined in the library, with its value and size, and nothing else.
TEST(R1, SymbolsMatchReadelf) {
#ifndef DONKEY_R1_IFUNC_PATH
  GTEST_SKIP() << "the IFUNC library is built on ELF hosts with GCC or Clang only";
#else
  const std::string path = DONKEY_R1_IFUNC_PATH;
  std::unique_ptr<FILE, int (*)(FILE*)> pipe(popen(("readelf -sW '" + path + "'").c_str(), "r"),
                                             pclose);
  ASSERT_NE(pipe, nullptr);
  std::string text;
  char buffer[4096];
  while (std::fgets(buffer, sizeof buffer, pipe.get()) != nullptr) {
    text += buffer;
  }
  if (text.find("Symbol table") == std::string::npos) {
    GTEST_SKIP() << "readelf is not available";
  }
  // "Num: Value Size Type Bind Vis Ndx Name"
  std::set<std::pair<std::uint64_t, std::uint64_t>> readelf;
  bool saw_ifunc = false;
  std::istringstream lines(text);
  std::string line;
  while (std::getline(lines, line)) {
    std::istringstream fields(line);
    std::string num, value, size, type, bind, vis, ndx;
    if (!(fields >> num >> value >> size >> type >> bind >> vis >> ndx) || num.back() != ':') {
      continue;
    }
    if ((type != "FUNC" && type != "IFUNC") || ndx == "UND") {
      continue;
    }
    saw_ifunc = saw_ifunc || type == "IFUNC";
    readelf.emplace(std::stoull(value, nullptr, 16), std::stoull(size, nullptr, 0));
  }
  ASSERT_TRUE(saw_ifunc) << text;

  auto loaded = donkey::load_binary(path);
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  std::set<std::pair<std::uint64_t, std::uint64_t>> donkey_symbols;
  for (const donkey::Symbol& symbol : loaded.value().image.symbols) {
    if (symbol.kind == donkey::SymbolKind::Function && !symbol.imported && symbol.address != 0) {
      donkey_symbols.emplace(symbol.address, symbol.size);
    }
  }
  EXPECT_EQ(donkey_symbols, readelf);
  // The starts the measurement uses are those addresses, all in executable sections.
  std::set<std::uint64_t> starts;
  for (const auto& [address, size] : readelf) {
    starts.insert(address);
  }
  EXPECT_EQ(donkey::r1::function_symbol_starts(loaded.value().image), starts);
#endif
}
