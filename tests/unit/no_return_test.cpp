// No-return calls (G24-T3): the version reader, the fixed list and its provider binding, the CFG
// and lifter effects, propagation, the verifier rules and the evaluator. Fixtures: see
// tests/fixtures/stubs/PROVENANCE.md; the oracle for each address is `objdump -d` on the same file.

#include <gtest/gtest.h>

#include <algorithm>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/analysis/no_return.h"
#include "donkey/binary/elf_load_scope.h"
#include "donkey/binary/elf_versions.h"
#include "donkey/binary/image.h"
#include "donkey/binary/link.h"
#include "donkey/ir/eval.h"
#include "donkey/ir/ir.h"
#include "donkey/ir/lift.h"
#include "ir_internal.h"

namespace {

using donkey::AnalysisOptions;
using donkey::AnalysisResult;
using donkey::BinaryImage;

std::string fixture(const std::string& directory, const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/" + directory + "/" + name;
}

struct Analyzed {
  donkey::LoadedBinary binary;
  AnalysisResult analysis;
};

/// The fixture sysroot whose libraries an image of `architecture` loads (tests/fixtures/loadscope):
/// a stand-in libc.so.6 with glibc's version names, so no result depends on the host's libraries.
donkey::ElfLibrarySearch fixture_libraries(donkey::Architecture architecture) {
  donkey::ElfLibrarySearch search;
  search.sysroot =
      fixture("loadscope",
              architecture == donkey::Architecture::AArch64 ? "sysroot-aarch64" : "sysroot-x86_64");
  return search;
}

Analyzed analyze_fixture(const std::string& name, const std::string& directory = "stubs",
                         const std::vector<std::string>& library_paths = {}) {
  auto loaded = donkey::load_binary(fixture(directory, name));
  EXPECT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  Analyzed out{std::move(loaded.value()), {}};
  AnalysisOptions options;
  options.library_search = fixture_libraries(out.binary.image.architecture);
  for (const std::string& path : library_paths) {
    options.library_search.paths.push_back(fixture("loadscope", path));
  }
  auto analysis = donkey::analyze(out.binary.image, out.binary.data, options);
  EXPECT_TRUE(analysis.has_value()) << analysis.diagnostic().message;
  out.analysis = std::move(analysis.value());
  return out;
}

const donkey::Function* function_at(const AnalysisResult& analysis, std::uint64_t address) {
  for (const donkey::Function& function : analysis.functions) {
    if (function.address == address) {
      return &function;
    }
  }
  return nullptr;
}

/// The function at `address`, or an empty one with a test failure when there is none.
const donkey::Function& function_ref(const AnalysisResult& analysis, std::uint64_t address) {
  if (const donkey::Function* function = function_at(analysis, address)) {
    return *function;
  }
  ADD_FAILURE() << "no function at " << address;
  static const donkey::Function none{};
  return none;
}

bool has_edge(const AnalysisResult& analysis, std::uint64_t from, std::uint64_t to) {
  for (const donkey::CfgEdge& edge : analysis.cfg.edges) {
    if (edge.from == from && edge.to == to && edge.kind != donkey::CfgEdgeKind::Call) {
      return true;
    }
  }
  return false;
}

bool has_edge_from(const AnalysisResult& analysis, std::uint64_t from) {
  for (const donkey::CfgEdge& edge : analysis.cfg.edges) {
    if (edge.from == from && edge.kind != donkey::CfgEdgeKind::Call) {
      return true;
    }
  }
  return false;
}

/// A raw x86-64 image of `bytes` at 0x1000 (int3 padding to `size`), with a function symbol at
/// each of `starts`.
std::pair<std::vector<std::byte>, BinaryImage> raw_image(
    std::initializer_list<std::pair<std::size_t, std::vector<std::uint8_t>>> pieces,
    std::size_t size, std::initializer_list<std::uint64_t> starts) {
  std::vector<std::byte> data(size, std::byte{0xcc});
  for (const auto& [offset, bytes] : pieces) {
    for (std::size_t i = 0; i < bytes.size(); ++i) {
      data[offset + i] = static_cast<std::byte>(bytes[i]);
    }
  }
  BinaryImage image;
  image.path = "<synthetic>";
  image.architecture = donkey::Architecture::X86_64;
  image.format = donkey::BinaryFormat::Raw;
  image.bits = 64;
  image.file_size = data.size();
  donkey::Section section;
  section.id = donkey::SectionId{1};
  section.name = ".text";
  section.file_size = data.size();
  section.address = 0x1000;
  section.virtual_size = data.size();
  section.readable = true;
  section.executable = true;
  section.has_file_data = true;
  image.sections.push_back(section);
  std::size_t n = 0;
  for (const std::uint64_t start : starts) {
    donkey::Symbol symbol;
    symbol.name = "f" + std::to_string(n++);
    symbol.address = start;
    symbol.kind = donkey::SymbolKind::Function;
    symbol.exported = true;
    image.symbols.push_back(symbol);
  }
  return {std::move(data), std::move(image)};
}

/// `.gnu.version_r` bytes: one Verneed for the file at string offset `file`, with one Vernaux per
/// (index, name offset) pair.
std::vector<std::byte> version_needs(std::uint32_t file,
                                     std::vector<std::pair<std::uint16_t, std::uint32_t>> entries) {
  std::vector<std::byte> out;
  auto put16 = [&](std::uint16_t v) {
    out.push_back(static_cast<std::byte>(v & 0xffU));
    out.push_back(static_cast<std::byte>(v >> 8U));
  };
  auto put32 = [&](std::uint32_t v) {
    for (int i = 0; i < 4; ++i) {
      out.push_back(static_cast<std::byte>((v >> (8 * i)) & 0xffU));
    }
  };
  put16(1);
  put16(static_cast<std::uint16_t>(entries.size()));
  put32(file);
  put32(16);  // aux
  put32(0);   // next
  for (std::size_t i = 0; i < entries.size(); ++i) {
    put32(0);  // hash
    put16(0);  // flags
    put16(entries[i].first);
    put32(entries[i].second);
    put32(i + 1 < entries.size() ? 16 : 0);
  }
  return out;
}

std::vector<std::byte> strings(const std::string& text) {
  std::vector<std::byte> out;
  for (const char c : text) {
    out.push_back(static_cast<std::byte>(c));
  }
  out.push_back(std::byte{0});
  return out;
}

}  // namespace

// --- The version reader -------------------------------------------------------------------------

TEST(ElfVersions, ReadsTheVersionNeedsOfOneFile) {
  // "\0libc.so.6\0GLIBC_2.2.5\0GLIBC_2.34"
  const auto names = strings(std::string("\0libc.so.6\0GLIBC_2.2.5\0GLIBC_2.34", 33));
  const auto needs = donkey::read_version_needs(version_needs(1, {{3, 11}, {2, 23}}), names);
  ASSERT_TRUE(needs.has_value()) << needs.diagnostic().message;
  ASSERT_EQ(needs.value().by_index.size(), 2U);
  EXPECT_EQ(needs.value().by_index.at(3).file, "libc.so.6");
  EXPECT_EQ(needs.value().by_index.at(3).version, "GLIBC_2.2.5");
  EXPECT_EQ(needs.value().by_index.at(2).version, "GLIBC_2.34");
}

TEST(ElfVersions, RefusesBrokenTables) {
  const auto names = strings(std::string("\0libc.so.6\0GLIBC_2.2.5", 22));
  // An entry past the end of the section.
  auto truncated = version_needs(1, {{2, 11}});
  truncated.resize(truncated.size() - 4);
  EXPECT_EQ(donkey::read_version_needs(truncated, names).diagnostic().code,
            "elf.version_needs.truncated");
  // The reserved indexes 0 and 1.
  EXPECT_EQ(donkey::read_version_needs(version_needs(1, {{1, 11}}), names).diagnostic().code,
            "elf.version_needs.index");
  // Two entries with one index.
  EXPECT_EQ(
      donkey::read_version_needs(version_needs(1, {{2, 11}, {2, 11}}), names).diagnostic().code,
      "elf.version_needs.duplicate");
  // A name outside the string table.
  EXPECT_EQ(donkey::read_version_needs(version_needs(1, {{2, 400}}), names).diagnostic().code,
            "elf.version_needs.name");
  // A Verneed whose next offset lands on its own Vernaux, which was already read: a loop.
  auto self = version_needs(1, {{2, 11}});
  self[12] = std::byte{0x10};  // next = 16
  EXPECT_EQ(donkey::read_version_needs(self, names).diagnostic().code, "elf.version_needs.loop");
  // The entry limit.
  EXPECT_EQ(
      donkey::read_version_needs(version_needs(1, {{2, 11}, {3, 11}}), names, 2).diagnostic().code,
      "elf.version_needs.limit");
  // The last Vernaux the count allows links on (next = 16, past the 32-byte table).
  auto dangling = version_needs(1, {{2, 11}});
  dangling[28] = std::byte{0x10};
  EXPECT_EQ(donkey::read_version_needs(dangling, names).diagnostic().code,
            "elf.version_needs.count");
  // A Vernaux at offset 12 overlaps the last four bytes of its Verneed (28 bytes in all).
  auto overlap = version_needs(1, {{2, 11}});
  overlap[8] = std::byte{12};  // aux = 12
  std::copy(overlap.begin() + 16, overlap.begin() + 32, overlap.begin() + 12);
  overlap.resize(28);
  EXPECT_EQ(donkey::read_version_needs(overlap, names).diagnostic().code, "elf.version_needs.loop");
}

// readelf -V on stubs_x86_64: abort's version index names GLIBC_2.2.5 of libc.so.6.
TEST(ElfVersions, NamesTheProviderOfEachVersionedImport) {
  auto loaded = donkey::load_binary(fixture("stubs", "stubs_x86_64"));
  ASSERT_TRUE(loaded.has_value());
  const auto versions = donkey::read_import_versions(loaded.value().image, loaded.value().data);
  ASSERT_TRUE(versions.has_value()) << versions.diagnostic().message;
  ASSERT_TRUE(versions.value().contains("abort"));
  EXPECT_EQ(versions.value().at("abort").file, "libc.so.6");
  EXPECT_EQ(versions.value().at("abort").version, "GLIBC_2.2.5");
}

namespace {

const donkey::Section* section_of(const donkey::BinaryImage& image, const char* name) {
  for (const donkey::Section& section : image.sections) {
    if (section.name == name) {
      return &section;
    }
  }
  return nullptr;
}

}  // namespace

// A `.gnu.version` that ends before an import's entry is an error, not a shorter map: a missing
// entry would read as unversioned and let the DT_NEEDED rule mark the name.
TEST(ElfVersions, ATruncatedSymbolVersionTableIsAnError) {
  auto loaded = donkey::load_binary(fixture("stubs", "stubs_x86_64"));
  ASSERT_TRUE(loaded.has_value());
  donkey::BinaryImage image = loaded.value().image;
  for (donkey::Section& section : image.sections) {
    if (section.name == ".gnu.version") {
      section.file_size = 2;  // the null symbol's entry only
    }
  }
  const auto versions = donkey::read_import_versions(image, loaded.value().data);
  ASSERT_FALSE(versions.has_value());
  EXPECT_EQ(versions.diagnostic().code, "elf.version_symbols.truncated");
}

// An import whose `.gnu.version` index is 1 (global, unversioned) carries no version evidence.
TEST(ElfVersions, AnUnversionedImportIsNotListed) {
  auto loaded = donkey::load_binary(fixture("stubs", "stubs_x86_64"));
  ASSERT_TRUE(loaded.has_value());
  const donkey::Section* versym = section_of(loaded.value().image, ".gnu.version");
  ASSERT_NE(versym, nullptr);
  std::vector<std::byte> data(loaded.value().data.begin(), loaded.value().data.end());
  // Every entry becomes index 1.
  for (std::uint64_t at = 2; at + 2 <= versym->file_size; at += 2) {
    data[versym->file_offset + at] = std::byte{1};
    data[versym->file_offset + at + 1] = std::byte{0};
  }
  const auto versions = donkey::read_import_versions(loaded.value().image, data);
  ASSERT_TRUE(versions.has_value()) << versions.diagnostic().message;
  EXPECT_FALSE(versions.value().contains("abort"));
}

// One versioned and one unversioned undefined import of the same name: the name carries no
// version evidence. stubs_x86_64's `puts` import is renamed `abort` (its st_name points at
// abort's string) and made unversioned (index 1); the versioned `abort` stays as it was.
TEST(ElfVersions, ANameAlsoImportedUnversionedHasNoVersion) {
  auto loaded = donkey::load_binary(fixture("stubs", "stubs_x86_64"));
  ASSERT_TRUE(loaded.has_value());
  const donkey::BinaryImage& image = loaded.value().image;
  const donkey::Section* versym = section_of(image, ".gnu.version");
  const donkey::Section* dynsym = section_of(image, ".dynsym");
  const donkey::Section* dynstr = section_of(image, ".dynstr");
  ASSERT_NE(versym, nullptr);
  ASSERT_NE(dynsym, nullptr);
  ASSERT_NE(dynstr, nullptr);
  std::vector<std::byte> data(loaded.value().data.begin(), loaded.value().data.end());
  const auto read32 = [&](std::uint64_t at) {
    std::uint32_t value = 0;
    for (int byte = 3; byte >= 0; --byte) {
      value = (value << 8U) | std::to_integer<std::uint32_t>(data[at + byte]);
    }
    return value;
  };
  const auto name_of = [&](std::uint32_t offset) {
    std::string name;
    for (std::uint64_t at = dynstr->file_offset + offset;
         at < dynstr->file_offset + dynstr->file_size && data[at] != std::byte{0}; ++at) {
      name.push_back(static_cast<char>(std::to_integer<unsigned>(data[at])));
    }
    return name;
  };
  std::uint64_t abort_entry = 0;
  std::uint64_t puts_entry = 0;
  for (std::uint64_t entry = 1; (entry + 1) * 24 <= dynsym->file_size; ++entry) {
    const std::string name = name_of(read32(dynsym->file_offset + entry * 24));
    if (name == "abort") {
      abort_entry = entry;
    } else if (name == "puts") {
      puts_entry = entry;
    }
  }
  ASSERT_NE(abort_entry, 0U);
  ASSERT_NE(puts_entry, 0U);
  {
    const auto before = donkey::read_import_versions(image, data);
    ASSERT_TRUE(before.has_value()) << before.diagnostic().message;
    ASSERT_TRUE(before.value().contains("abort"));
  }
  for (std::uint64_t byte = 0; byte < 4; ++byte) {
    data[dynsym->file_offset + puts_entry * 24 + byte] =
        data[dynsym->file_offset + abort_entry * 24 + byte];
  }
  data[versym->file_offset + puts_entry * 2] = std::byte{1};
  data[versym->file_offset + puts_entry * 2 + 1] = std::byte{0};
  const auto versions = donkey::read_import_versions(image, data);
  ASSERT_TRUE(versions.has_value()) << versions.diagnostic().message;
  EXPECT_FALSE(versions.value().contains("abort"));
}

// --- The fixed list and its binding -------------------------------------------------------------

TEST(Analysis, NoReturnNamesComeOnlyFromTheFixedList) {
  EXPECT_TRUE(donkey::is_known_no_return_name("abort"));
  EXPECT_TRUE(donkey::is_known_no_return_name("__stack_chk_fail"));
  EXPECT_TRUE(donkey::is_known_no_return_name("ExitProcess"));
  // error() returns when its status is 0.
  EXPECT_FALSE(donkey::is_known_no_return_name("error"));
  EXPECT_FALSE(donkey::is_known_no_return_name("error_at_line"));
  EXPECT_FALSE(donkey::is_known_no_return_name("frobnicate"));
  EXPECT_FALSE(donkey::is_known_no_return_name("RaiseException"));
  EXPECT_TRUE(donkey::is_runtime_library("libc.so.6"));
  EXPECT_TRUE(donkey::is_runtime_library("libc.musl-x86_64.so.1"));
  EXPECT_TRUE(donkey::is_runtime_library("KERNEL32.dll"));
  EXPECT_FALSE(donkey::is_runtime_library("libmyexit.so.1"));
}

// stubs_x86_64: `1060 <abort@plt>` is marked with its evidence; `1070 <puts@plt>` is not.
TEST(Analysis, AVersionedRuntimeImportIsMarkedWithItsEvidence) {
  const Analyzed analyzed = analyze_fixture("stubs_x86_64");
  const donkey::Function* abort_stub = function_at(analyzed.analysis, 0x1060);
  ASSERT_NE(abort_stub, nullptr);
  EXPECT_TRUE(abort_stub->no_return);
  // The evidence: the version the import asks for, the library the loader binds it to, and the
  // file that library was found in (the fixture sysroot's stand-in libc).
  EXPECT_EQ(abort_stub->no_return_reason,
            "known-name:abort version:GLIBC_2.2.5 bound:libc.so.6 path:" +
                fixture("loadscope", "sysroot-x86_64") + "/lib/x86_64-linux-gnu/libc.so.6");
  const donkey::Function* puts_stub = function_at(analyzed.analysis, 0x1070);
  ASSERT_NE(puts_stub, nullptr);
  EXPECT_FALSE(puts_stub->no_return);
}

// The case a version need alone gets wrong (tests/fixtures/loadscope, PROVENANCE.md there):
// steal_consumer imports exit@GLIBC_2.2.5 from libc.so.6 and needs libsteal.so.1 first. When the
// libsteal.so.1 it runs with defines an unversioned exit, glibc's loader binds the call there (the
// fixture's oracle: under LD_LIBRARY_PATH=steal the program prints "libsteal exit(1) returned"),
// so the call is not marked. With the libsteal.so.1 it was linked against (no exit), the call
// binds to libc.so.6 and is marked.
TEST(Analysis, AVersionedImportBoundToAnEarlierUnversionedDefinitionIsNotMarked) {
  const Analyzed stolen = analyze_fixture("steal_consumer", "loadscope", {"steal"});
  const auto exit_stub =
      std::find_if(stolen.analysis.functions.begin(), stolen.analysis.functions.end(),
                   [](const donkey::Function& f) { return f.import_name == "exit"; });
  ASSERT_NE(exit_stub, stolen.analysis.functions.end());
  EXPECT_FALSE(exit_stub->no_return);
  EXPECT_TRUE(stolen.analysis.no_return.empty());

  const Analyzed clean = analyze_fixture("steal_consumer", "loadscope", {"clean"});
  const auto clean_stub =
      std::find_if(clean.analysis.functions.begin(), clean.analysis.functions.end(),
                   [](const donkey::Function& f) { return f.import_name == "exit"; });
  ASSERT_NE(clean_stub, clean.analysis.functions.end());
  EXPECT_TRUE(clean_stub->no_return);
  EXPECT_NE(clean_stub->no_return_reason.find("bound:libc.so.6"), std::string::npos)
      << clean_stub->no_return_reason;
}

// A shared library's references bind first in the global scope of the program that loads it
// (glibc's _dl_lookup_symbol_x: the program's search list, then the library's local scope). So the
// library alone proves nothing: without the program its abort call is not marked, and the analysis
// says why. With the program it is loaded by, the call binds to the C library and is marked.
TEST(Analysis, ALibrarysImportIsBoundOnlyInTheScopeOfItsProgram) {
  const Analyzed alone = analyze_fixture("libaborts.so.1", "loadscope");
  EXPECT_TRUE(alone.analysis.no_return.empty());
  const auto diagnostic = std::find_if(
      alone.analysis.diagnostics.begin(), alone.analysis.diagnostics.end(),
      [](const donkey::Diagnostic& d) { return d.code == "analysis.no_return_unverified"; });
  ASSERT_NE(diagnostic, alone.analysis.diagnostics.end());
  EXPECT_NE(diagnostic->message.find("abort: a shared library's references bind first in the "
                                     "scope of the program that loads it"),
            std::string::npos)
      << diagnostic->message;

  auto loaded = donkey::load_binary(fixture("loadscope", "libaborts.so.1"));
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  AnalysisOptions options;
  options.library_search = fixture_libraries(donkey::Architecture::X86_64);
  options.library_search.paths.push_back(fixture("loadscope", "clean"));
  options.library_search.program = fixture("loadscope", "steal_consumer");
  auto analysis = donkey::analyze(loaded.value().image, loaded.value().data, options);
  ASSERT_TRUE(analysis.has_value()) << analysis.diagnostic().message;
  const auto abort_stub =
      std::find_if(analysis.value().functions.begin(), analysis.value().functions.end(),
                   [](const donkey::Function& f) { return f.import_name == "abort"; });
  ASSERT_NE(abort_stub, analysis.value().functions.end());
  EXPECT_TRUE(abort_stub->no_return);
  EXPECT_NE(abort_stub->no_return_reason.find("version:GLIBC_2.2.5 bound:libc.so.6"),
            std::string::npos)
      << abort_stub->no_return_reason;
}

// A library the walk cannot find before any definition leaves the binding unknown: no mark, and
// the analysis says which import and why.
TEST(Analysis, AnImportWhoseLibrariesCannotBeFoundIsNotMarked) {
  const Analyzed analyzed = analyze_fixture("steal_consumer", "loadscope");
  EXPECT_TRUE(analyzed.analysis.no_return.empty());
  const auto diagnostic = std::find_if(
      analyzed.analysis.diagnostics.begin(), analyzed.analysis.diagnostics.end(),
      [](const donkey::Diagnostic& d) { return d.code == "analysis.no_return_unverified"; });
  ASSERT_NE(diagnostic, analyzed.analysis.diagnostics.end());
  EXPECT_NE(diagnostic->message.find("exit: libsteal.so.1 was not found"), std::string::npos)
      << diagnostic->message;
}

// AArch64: the same proof with the AArch64 stand-in libc (GLIBC_2.17).
TEST(Analysis, AnAArch64VersionedRuntimeImportIsMarked) {
  const Analyzed analyzed = analyze_fixture("stubs_aarch64");
  const auto abort_stub =
      std::find_if(analyzed.analysis.functions.begin(), analyzed.analysis.functions.end(),
                   [](const donkey::Function& f) { return f.import_name == "abort"; });
  ASSERT_NE(abort_stub, analyzed.analysis.functions.end());
  EXPECT_TRUE(abort_stub->no_return);
  EXPECT_NE(abort_stub->no_return_reason.find("version:GLIBC_2.17 bound:libc.so.6"),
            std::string::npos)
      << abort_stub->no_return_reason;
}

// The scope in the loader's order, from the sysroot and the library path: the executable, then
// DT_NEEDED breadth first (libsteal.so.1 from the library path, libc.so.6 from the sysroot's
// multiarch directory). A versioned reference binds to the first definition it accepts; an
// unversioned one to a definition of index 0 to 2 (libc's exit@@GLIBC_2.2.5 is index 2).
TEST(ElfLoadScope, FindsLibrariesInTheLoadersOrderAndBindsByGlibcRules) {
  auto loaded = donkey::load_binary(fixture("loadscope", "steal_consumer"));
  ASSERT_TRUE(loaded.has_value());
  donkey::ElfLibrarySearch search = fixture_libraries(donkey::Architecture::X86_64);
  search.paths.push_back(fixture("loadscope", "steal"));
  const donkey::ElfLoadScope scope =
      donkey::ElfLoadScope::build(loaded.value().image, loaded.value().data, search);
  ASSERT_EQ(scope.libraries().size(), 3U);
  EXPECT_EQ(scope.libraries()[1].name, "libsteal.so.1");
  EXPECT_EQ(scope.libraries()[1].path, fixture("loadscope", "steal") + "/libsteal.so.1");
  EXPECT_EQ(scope.libraries()[2].soname, "libc.so.6");
  const donkey::ElfBinding versioned = scope.lookup("exit", "GLIBC_2.2.5");
  ASSERT_EQ(versioned.outcome, donkey::ElfBinding::Outcome::Bound);
  EXPECT_EQ(versioned.library, 1U);  // libsteal's unversioned exit satisfies it
  const donkey::ElfBinding puts = scope.lookup("puts", "GLIBC_2.2.5");
  ASSERT_EQ(puts.outcome, donkey::ElfBinding::Outcome::Bound);
  EXPECT_EQ(puts.library, 2U);
  const donkey::ElfBinding unversioned = scope.lookup("abort", "");
  ASSERT_EQ(unversioned.outcome, donkey::ElfBinding::Outcome::Bound);
  EXPECT_EQ(unversioned.library, 2U);
  EXPECT_EQ(scope.lookup("no_such_name", "").outcome, donkey::ElfBinding::Outcome::NotDefined);
  // A version the stand-in libc does not define is not satisfied by its versioned definition.
  EXPECT_EQ(scope.lookup("abort", "GLIBC_9.9").outcome, donkey::ElfBinding::Outcome::NotDefined);
}

// exit_consumer imports an unversioned `exit` and needs libmyexit.so.1 (which exports an `exit`
// that returns) before libc.so.6: two needed libraries can provide the name, one of them not a
// runtime library, so it is not marked. objdump: `1150: call 1050 <exit@plt>`, then
// `1155: lea 0x7(%rbx),%eax`, which stays in the function with its fall-through edge.
TEST(Analysis, ANoReturnNameFromAnotherLibraryKeepsItsFallThrough) {
  const Analyzed analyzed = analyze_fixture("exit_consumer");
  const donkey::Function* stub = function_at(analyzed.analysis, 0x1050);
  ASSERT_NE(stub, nullptr);
  EXPECT_EQ(stub->name, "exit@plt");
  EXPECT_FALSE(stub->no_return);
  const donkey::Function* caller = function_at(analyzed.analysis, 0x1149);
  ASSERT_NE(caller, nullptr);
  EXPECT_FALSE(caller->no_return);
  // The call does not end a block: 0x1149 to 0x115a is one block, so the add and ret after the
  // call stay on the caller's path.
  EXPECT_EQ(caller->end_address, 0x115aU);
  EXPECT_EQ(caller->block_count, 1U);
}

TEST(Analysis, ANoReturnNameExportedByTwoNeededLibrariesIsNotMarked) {
  // The same fixture, read through the binding function directly: the name is on the list, its
  // import is unversioned, and DT_NEEDED names a library that is not a runtime library.
  auto loaded = donkey::load_binary(fixture("stubs", "exit_consumer"));
  ASSERT_TRUE(loaded.has_value());
  std::vector<std::string> unverified;
  const auto marks = donkey::bind_no_return_imports(
      loaded.value().image, loaded.value().data, {{0x1050, "exit"}}, {},
      fixture_libraries(donkey::Architecture::X86_64), &unverified);
  EXPECT_TRUE(marks.empty());
  // Proven, not unknown: both libraries are in the sysroot, and libmyexit.so.1 comes first.
  EXPECT_TRUE(unverified.empty());
}

// --- CFG ----------------------------------------------------------------------------------------

// f0 (0x1000): call 0x1010; mov eax, 1; ret.  f1 (0x1010): ret, marked no-return by the caller.
// The bytes after the call are not f0's: no other path reaches them.
TEST(Cfg, NoReturnCallEndsTheBlock) {
  auto [data, image] = raw_image(
      {{0x0, {0xe8, 0x0b, 0x00, 0x00, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3}}, {0x10, {0xc3}}},
      0x11, {0x1000, 0x1010});
  AnalysisOptions options;
  options.no_return_targets.insert(0x1010);
  auto result = donkey::analyze(image, data, options);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  const donkey::Function* f0 = function_at(result.value(), 0x1000);
  ASSERT_NE(f0, nullptr);
  EXPECT_EQ(f0->end_address, 0x1005U);
  EXPECT_EQ(f0->block_count, 1U);
  EXPECT_FALSE(has_edge_from(result.value(), 0x1000));
  // Without the mark the bytes after the call are f0's.
  auto plain = donkey::analyze(image, data);
  ASSERT_TRUE(plain.has_value());
  EXPECT_EQ(function_ref(plain.value(), 0x1000).end_address, 0x100bU);
}

// f0 (0x1000): test edi, edi; je 0x100b; call 0x1010; 0x100b: ret.  The ret after the call is
// reached by the je, so it stays in f0, but the call has no fall-through edge to it.
TEST(Cfg, BytesReachedByAnotherPathStayInTheFunction) {
  auto [data, image] =
      raw_image({{0x0, {0x85, 0xff, 0x74, 0x07, 0xe8, 0x07, 0x00, 0x00, 0x00, 0x90, 0x90, 0xc3}},
                 {0x10, {0xc3}}},
                0x11, {0x1000, 0x1010});
  AnalysisOptions options;
  options.no_return_targets.insert(0x1010);
  auto result = donkey::analyze(image, data, options);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  const donkey::Function* f0 = function_at(result.value(), 0x1000);
  ASSERT_NE(f0, nullptr);
  EXPECT_EQ(f0->end_address, 0x100cU);
  EXPECT_FALSE(f0->no_return);  // the je path returns
  EXPECT_FALSE(has_edge(result.value(), 0x1004, 0x1009));
  EXPECT_TRUE(has_edge(result.value(), 0x1002, 0x100b));
}

// Propagation from proven marks only. 0x1040 is marked by the caller. f0 (0x1000) only calls it:
// no-return. f1 (0x1010) calls f0 and then returns: no-return too, found in the next round,
// once f0's mark cuts its fall-through. f2 (0x1020) has a path that returns: not marked.
TEST(Analysis, PropagationUsesOnlyProvenMarks) {
  auto [data, image] = raw_image(
      {{0x00, {0xe8, 0x3b, 0x00, 0x00, 0x00, 0xc3}},              // f0: call 0x1040; ret
       {0x10, {0xe8, 0xeb, 0xff, 0xff, 0xff, 0x31, 0xc0, 0xc3}},  // f1: call 0x1000; xor; ret
       {0x20, {0x85, 0xff, 0x74, 0x05, 0xe8, 0x17, 0x00, 0x00, 0x00, 0xc3}},  // f2
       {0x40, {0xc3}}},
      0x41, {0x1000, 0x1010, 0x1020, 0x1040});
  AnalysisOptions options;
  options.no_return_targets.insert(0x1040);
  auto result = donkey::analyze(image, data, options);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  EXPECT_TRUE(function_ref(result.value(), 0x1000).no_return);
  EXPECT_EQ(function_ref(result.value(), 0x1000).no_return_reason,
            "propagated:every path ends in a call that does not return");
  EXPECT_TRUE(function_ref(result.value(), 0x1010).no_return);
  EXPECT_FALSE(function_ref(result.value(), 0x1020).no_return);
  // The mark is not taken from the target's own `ret`: 0x1040 is the caller's assumption, and
  // the analysis does not mark it itself.
  EXPECT_FALSE(function_ref(result.value(), 0x1040).no_return);
  // Off: nothing is marked.
  options.no_return_analysis = false;
  options.no_return_targets.clear();
  auto off = donkey::analyze(image, data, options);
  ASSERT_TRUE(off.has_value());
  EXPECT_FALSE(function_ref(off.value(), 0x1000).no_return);
}

// --- IR -----------------------------------------------------------------------------------------

// stubs_x86_64, objdump: `1169: endbr64; ... 1179: call 1060 <abort@plt>`, the path for a
// negative argument. The call is the last real statement of its block, followed by an
// unreachable return, and the pseudocode prints no `return` after it.
TEST(Ir, NoReturnCallHasNoSuccessorAndNoReturnStatement) {
  const Analyzed analyzed = analyze_fixture("stubs_x86_64");
  const donkey::Function* check = function_at(analyzed.analysis, 0x1169);
  ASSERT_NE(check, nullptr);
  auto lifted = donkey::lift_function(analyzed.binary.image, analyzed.analysis, *check);
  ASSERT_TRUE(lifted.has_value()) << lifted.diagnostic().message;
  bool found = false;
  for (const donkey::IrBlock& block : lifted.value().blocks) {
    for (std::size_t i = 0; i < block.statements.size(); ++i) {
      if (block.statements[i].op != donkey::IrOp::Call || !block.statements[i].no_return) {
        continue;
      }
      found = true;
      ASSERT_EQ(i + 2, block.statements.size());
      EXPECT_EQ(block.statements[i + 1].op, donkey::IrOp::Return);
      EXPECT_TRUE(block.statements[i + 1].unreachable);
    }
  }
  EXPECT_TRUE(found);
  auto text = donkey::format_pseudocode(lifted.value());
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  const std::size_t at = text.value().find("abort();");
  ASSERT_NE(at, std::string::npos) << text.value();
  const std::size_t line_end = text.value().find('\n', at);
  const std::string next_line =
      text.value().substr(line_end + 1, text.value().find('\n', line_end + 1) - line_end - 1);
  EXPECT_EQ(next_line.find("return"), std::string::npos) << text.value();
  EXPECT_EQ(text.value().find("the returned register is not determined"), std::string::npos)
      << text.value();
  EXPECT_EQ(text.value().find("some return paths carry no value"), std::string::npos)
      << text.value();
}

namespace {

/// Whether `lifted` holds a no-return call to `target` that ends its block, followed by the
/// unreachable return and nothing else.
bool ends_at_no_return_call(const donkey::IrFunction& lifted, std::uint64_t target) {
  for (const donkey::IrBlock& block : lifted.blocks) {
    const std::size_t n = block.statements.size();
    if (n < 2) {
      continue;
    }
    const donkey::IrStatement& call = block.statements[n - 2];
    const donkey::IrStatement& end = block.statements[n - 1];
    if (call.op == donkey::IrOp::Call && call.a.constant == target && call.no_return &&
        end.op == donkey::IrOp::Return && end.unreachable) {
      return true;
    }
  }
  return false;
}

}  // namespace

// x86-64, f0 (0x1000): test edi, edi; je 0x1010; mov eax, 1; ret. The je leaves the function for
// f1 (0x1010), which the caller marks no-return: the exit block that calls f1 ends at the call.
TEST(Ir, AConditionalTailCallToANoReturnFunctionEndsAtTheCall) {
  auto [data, image] = raw_image(
      {{0x0, {0x85, 0xff, 0x74, 0x0c, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3}}, {0x10, {0xc3}}}, 0x11,
      {0x1000, 0x1010});
  AnalysisOptions options;
  options.no_return_targets.insert(0x1010);
  auto result = donkey::analyze(image, data, options);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  auto lifted = donkey::lift_function(image, result.value(), function_ref(result.value(), 0x1000));
  ASSERT_TRUE(lifted.has_value()) << lifted.diagnostic().message;
  EXPECT_TRUE(ends_at_no_return_call(lifted.value(), 0x1010));
  ASSERT_TRUE(donkey::verify_ir(lifted.value()).has_value());
}

// AArch64, f0 (0x1000): b 0x1010, a tail jump to f1, which the caller marks no-return.
TEST(Ir, AnAArch64TailJumpToANoReturnFunctionEndsAtTheCall) {
  auto [data, image] = raw_image(
      {{0x0, {0x04, 0x00, 0x00, 0x14}}, {0x10, {0xc0, 0x03, 0x5f, 0xd6}}}, 0x14, {0x1000, 0x1010});
  image.architecture = donkey::Architecture::AArch64;
  AnalysisOptions options;
  options.no_return_targets.insert(0x1010);
  auto result = donkey::analyze(image, data, options);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  auto lifted = donkey::lift_function(image, result.value(), function_ref(result.value(), 0x1000));
  ASSERT_TRUE(lifted.has_value()) << lifted.diagnostic().message;
  EXPECT_TRUE(ends_at_no_return_call(lifted.value(), 0x1010));
  ASSERT_TRUE(donkey::verify_ir(lifted.value()).has_value());
}

TEST(Ir, VerifierRejectsANoReturnCallWithASuccessor) {
  donkey::IrFunction function;
  function.address = 0x1000;
  donkey::IrBlock block;
  block.address = 0x1000;
  donkey::IrStatement call;
  call.op = donkey::IrOp::Call;
  call.width = 8;
  call.a = donkey::IrOperand::constant_value(0x2000, 8);
  call.no_return = true;
  block.statements.push_back(call);
  donkey::IrStatement branch;
  branch.op = donkey::IrOp::Branch;
  branch.width = 8;
  branch.a = donkey::IrOperand::block_ref(1);
  block.statements.push_back(branch);
  function.blocks.push_back(block);
  donkey::IrBlock next;
  next.address = 0x1010;
  donkey::IrStatement ret;
  ret.op = donkey::IrOp::Return;
  ret.width = 8;
  next.statements.push_back(ret);
  function.blocks.push_back(next);
  EXPECT_EQ(donkey::verify_ir(function).diagnostic().code, "ir.no_return_call_not_last");

  // An unreachable return that follows no such call.
  donkey::IrFunction lone;
  lone.address = 0x1000;
  donkey::IrBlock only;
  only.address = 0x1000;
  donkey::IrStatement unreachable = ret;
  unreachable.unreachable = true;
  only.statements.push_back(unreachable);
  lone.blocks.push_back(only);
  EXPECT_EQ(donkey::verify_ir(lone).diagnostic().code, "ir.unreachable_return_without_call");

  // The well-formed pair is accepted.
  function.blocks[0].statements[1] = unreachable;
  function.blocks.pop_back();
  EXPECT_TRUE(donkey::verify_ir(function).has_value());
}

// Owner decision 3: the returning paths are compared, the path through the no-return call is
// not. check(5) returns 10 on the compiled code (objdump: `lea (%rdi,%rdi,1),%eax`); check(-1)
// reaches abort, and the evaluator stops with ir.eval_no_return instead of inventing a value.
TEST(Ir, NoReturnPathsAreNotCompared) {
  const Analyzed analyzed = analyze_fixture("stubs_x86_64");
  const donkey::Function* check = function_at(analyzed.analysis, 0x1169);
  ASSERT_NE(check, nullptr);
  auto lifted = donkey::lift_function(analyzed.binary.image, analyzed.analysis, *check);
  ASSERT_TRUE(lifted.has_value()) << lifted.diagnostic().message;
  donkey::IrEvalMemory memory(analyzed.binary.image, analyzed.binary.data);
  const std::uint64_t five[] = {5};
  auto returned = donkey::evaluate_ir(lifted.value(), five, memory);
  ASSERT_TRUE(returned.has_value()) << returned.diagnostic().message;
  EXPECT_EQ(returned.value().return_value & 0xffffffffU, 10U);
  const std::uint64_t negative[] = {0xffffffffU};
  donkey::IrEvalMemory fresh(analyzed.binary.image, analyzed.binary.data);
  auto stopped = donkey::evaluate_ir(lifted.value(), negative, fresh);
  ASSERT_FALSE(stopped.has_value());
  EXPECT_EQ(stopped.diagnostic().code, "ir.eval_no_return");
}

namespace {

/// if (rdi == 0) { abort(); } return rax; with abort a no-return call.
donkey::IrFunction no_return_arm_function() {
  donkey::IrFunction function;
  function.address = 0x1000;
  function.name = "checked";
  donkey::IrBlock test;
  test.address = 0x1000;
  donkey::IrStatement compare;
  compare.op = donkey::IrOp::Compare;
  compare.a = donkey::IrOperand::register_ref("rdi", 8);
  compare.b = donkey::IrOperand::constant_value(0, 8);
  compare.condition = donkey::IrCondition::NotEqual;
  compare.width = 8;
  test.statements.push_back(compare);
  donkey::IrStatement branch;
  branch.op = donkey::IrOp::CondBranch;
  branch.condition = donkey::IrCondition::NotEqual;
  branch.a = donkey::IrOperand::register_ref("rax", 8);
  branch.b = donkey::IrOperand::block_ref(2);
  branch.width = 8;
  test.statements.push_back(branch);
  function.blocks.push_back(test);
  donkey::IrBlock fail;
  fail.address = 0x1008;
  donkey::IrStatement call;
  call.op = donkey::IrOp::Call;
  call.width = 8;
  call.a = donkey::IrOperand::constant_value(0x2000, 8);
  call.no_return = true;
  fail.statements.push_back(call);
  donkey::IrStatement end;
  end.op = donkey::IrOp::Return;
  end.width = 8;
  end.unreachable = true;
  fail.statements.push_back(end);
  function.blocks.push_back(fail);
  donkey::IrBlock ok;
  ok.address = 0x1010;
  donkey::IrStatement ret;
  ret.op = donkey::IrOp::Return;
  ret.width = 8;
  ret.a = donkey::IrOperand::register_ref("rax", 8);
  ok.statements.push_back(ret);
  function.blocks.push_back(ok);
  function.call_names[0x2000] = "abort";
  return function;
}

}  // namespace

// The unreachable end of a no-return block prints nothing but is still the block's end for the
// control-flow check, in the layout structurer and in the goto structurer (a regression: without
// the tag the check saw the block fall through, and refused every candidate).
TEST(Ir, ANoReturnBlockIsStructured) {
  const donkey::IrFunction function = no_return_arm_function();
  const auto verified = donkey::verify_ir(function);
  ASSERT_TRUE(verified.has_value())
      << verified.diagnostic().code << ": " << verified.diagnostic().message;
  const auto text = donkey::format_pseudocode(function);
  ASSERT_TRUE(text.has_value()) << text.diagnostic().message;
  EXPECT_EQ(text.value().find("labeled blocks"), std::string::npos) << text.value();
  EXPECT_NE(text.value().find("abort();"), std::string::npos) << text.value();
  const donkey::StructureVerdict verdict = donkey::classify_structure(function);
  EXPECT_EQ(verdict.cls, donkey::StructureClass::Structured) << verdict.reason;
  EXPECT_EQ(verdict.oracle_rejections, 0U) << verdict.oracle_detail;
  // The goto structurer, called on its own, is accepted by the check too.
  const auto gotos = donkey::detail::structure_with_gotos(function, nullptr);
  ASSERT_TRUE(gotos.has_value());
  const auto mismatch = donkey::detail::check_structured_control_flow(function, gotos->lines);
  EXPECT_FALSE(mismatch.has_value()) << mismatch.value_or("");
}

// Owner decision 3: Complete needs at least one returning path. f0 (0x1000) is only `call 0x1010`,
// and 0x1010 is marked no-return by the caller: f0 has no path that returns, so it stays Partial,
// whatever else its lift resolved.
TEST(Ir, AFunctionWithNoReturningPathStaysPartial) {
  auto [data, image] =
      raw_image({{0x0, {0xe8, 0x0b, 0x00, 0x00, 0x00}}, {0x10, {0xc3}}}, 0x11, {0x1000, 0x1010});
  AnalysisOptions options;
  options.no_return_targets.insert(0x1010);
  auto result = donkey::analyze(image, data, options);
  ASSERT_TRUE(result.has_value()) << result.diagnostic().message;
  const donkey::Function* f0 = function_at(result.value(), 0x1000);
  ASSERT_NE(f0, nullptr);
  auto lifted = donkey::lift_function(image, result.value(), *f0);
  ASSERT_TRUE(lifted.has_value()) << lifted.diagnostic().message;
  EXPECT_TRUE(lifted.value().partial);
  bool noted = false;
  for (const std::string& note : lifted.value().notes) {
    noted = noted || note.find("no path returns") != std::string::npos;
  }
  EXPECT_TRUE(noted);
}

// glibc's lookup rules on a library with two versions of a name
// (tests/fixtures/loadscope/libvers.so.1: the hidden exit@V2 at index 3 and the default exit@@V3 at
// index 4). An unversioned reference takes the only non-hidden versioned definition; a versioned
// one takes its own version, hidden or not; a version the library does not define for the name is
// not satisfied, and lookup goes on to the next library. A library that was not found stops the
// lookup: where the name binds is unknown.
TEST(ElfLoadScope, LooksUpVersionsByGlibcRules) {
  auto vers = donkey::load_binary(fixture("loadscope", "libvers.so.1"));
  auto libc =
      donkey::load_binary(fixture("loadscope", "sysroot-x86_64/lib/x86_64-linux-gnu/libc.so.6"));
  ASSERT_TRUE(vers.has_value());
  ASSERT_TRUE(libc.has_value());
  const std::vector<donkey::ElfLoadScope::Input> inputs = {
      {"executable", nullptr, {}},
      {"libvers.so.1", &vers.value().image, vers.value().data},
      {"libc.so.6", &libc.value().image, libc.value().data},
  };
  const donkey::ElfLoadScope scope = donkey::ElfLoadScope::from_images(inputs);
  EXPECT_EQ(scope.lookup("exit", "").library, 1U);
  EXPECT_EQ(scope.lookup("exit", "V2").library, 1U);
  EXPECT_EQ(scope.lookup("exit", "V3").library, 1U);
  // libvers has no exit@GLIBC_2.2.5 and its exits are versioned: the reference goes on to libc.
  const donkey::ElfBinding glibc = scope.lookup("exit", "GLIBC_2.2.5");
  ASSERT_EQ(glibc.outcome, donkey::ElfBinding::Outcome::Bound);
  EXPECT_EQ(glibc.library, 2U);

  const std::vector<donkey::ElfLoadScope::Input> missing = {
      {"executable", nullptr, {}},
      {"libgone.so.1", nullptr, {}},
      {"libc.so.6", &libc.value().image, libc.value().data},
  };
  const donkey::ElfLoadScope unknown = donkey::ElfLoadScope::from_images(missing);
  const donkey::ElfBinding blocked = unknown.lookup("exit", "GLIBC_2.2.5");
  EXPECT_EQ(blocked.outcome, donkey::ElfBinding::Outcome::Unknown);
  EXPECT_EQ(blocked.reason, "libgone.so.1 was not found");
}

// ---------------------------------------------------------------------------------------------
// The load scope's search, case by case against glibc's own loader. Each oracle is `LD_DEBUG=libs`
// on the build host with the same files (tests/fixtures/loadscope/PROVENANCE.md). Where the loader
// would choose by something this model does not know, the lookup is Unknown, never a guess.

namespace {

namespace fs = std::filesystem;

/// A scratch directory for one test, removed when the test ends.
class Scratch {
 public:
  Scratch() {
    const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
    path_ = fs::temp_directory_path() /
            (std::string("donkey-scope-") + info->test_suite_name() + "-" + info->name());
    std::error_code error;
    fs::remove_all(path_, error);
    fs::create_directories(path_);
  }
  ~Scratch() {
    std::error_code error;
    fs::remove_all(path_, error);
  }
  Scratch(const Scratch&) = delete;
  Scratch& operator=(const Scratch&) = delete;
  [[nodiscard]] const fs::path& path() const { return path_; }
  /// Copies a fixture file to `relative` under the scratch directory.
  fs::path place(const std::string& fixture_file, const std::string& relative) const {
    const fs::path to = path_ / relative;
    fs::create_directories(to.parent_path());
    fs::copy_file(fixture("loadscope", fixture_file), to, fs::copy_options::overwrite_existing);
    return to;
  }
  fs::path write(const std::string& relative, const std::vector<std::byte>& bytes) const {
    const fs::path to = path_ / relative;
    fs::create_directories(to.parent_path());
    std::ofstream out(to, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    return to;
  }
  fs::path write(const std::string& relative, const std::string& text) const {
    std::vector<std::byte> bytes;
    for (const char c : text) {
      bytes.push_back(static_cast<std::byte>(c));
    }
    return write(relative, bytes);
  }

 private:
  fs::path path_;
};

constexpr const char* kLibc = "sysroot-x86_64/lib/x86_64-linux-gnu/libc.so.6";

/// A sysroot with the stand-in libc in its multiarch directory.
void place_libc(const Scratch& root) {
  root.place(kLibc, "lib/x86_64-linux-gnu/libc.so.6");
}

donkey::ElfLoadScope scope_of(const fs::path& executable, const donkey::ElfLibrarySearch& search) {
  auto loaded = donkey::load_binary(executable.string());
  EXPECT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  return donkey::ElfLoadScope::build(loaded.value().image, loaded.value().data, search);
}

donkey::ElfLibrarySearch under(const Scratch& root) {
  donkey::ElfLibrarySearch search;
  search.sysroot = root.path().string();
  return search;
}

std::string generic(const fs::path& path) {
  return path.generic_string();
}

bool contains(const std::string& text, const std::string& part) {
  return text.find(part) != std::string::npos;
}

void put_u32(std::vector<std::byte>& out, std::uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    out.push_back(static_cast<std::byte>((value >> (8 * i)) & 0xFFU));
  }
}

struct CacheEntry {
  std::string name;
  std::string path;
  std::uint32_t flags = 0x0303;  // FLAG_ELF_LIBC6 | FLAG_X8664_LIB64
  std::uint64_t hwcap = 0;
};

/// An ld.so.cache in glibc's format `glibc-ld.so.cache1.1` (ldconfig's layout: the header, the
/// entries, then the strings, every offset from the start of the header).
std::vector<std::byte> loader_cache(const std::vector<CacheEntry>& entries) {
  const std::string magic = "glibc-ld.so.cache1.1";
  std::string strings;
  std::vector<std::pair<std::uint32_t, std::uint32_t>> offsets;
  const std::uint32_t base = 48 + 24 * static_cast<std::uint32_t>(entries.size());
  for (const CacheEntry& entry : entries) {
    const auto key = base + static_cast<std::uint32_t>(strings.size());
    strings += entry.name + '\0';
    const auto value = base + static_cast<std::uint32_t>(strings.size());
    strings += entry.path + '\0';
    offsets.emplace_back(key, value);
  }
  std::vector<std::byte> out;
  for (const char c : magic) {
    out.push_back(static_cast<std::byte>(c));
  }
  put_u32(out, static_cast<std::uint32_t>(entries.size()));
  put_u32(out, static_cast<std::uint32_t>(strings.size()));
  out.push_back(std::byte{2});  // little-endian
  out.insert(out.end(), 3, std::byte{0});
  put_u32(out, 0);  // no extension
  for (int i = 0; i < 3; ++i) {
    put_u32(out, 0);
  }
  for (std::size_t i = 0; i < entries.size(); ++i) {
    put_u32(out, entries[i].flags);
    put_u32(out, offsets[i].first);
    put_u32(out, offsets[i].second);
    put_u32(out, 0);
    put_u32(out, static_cast<std::uint32_t>(entries[i].hwcap));
    put_u32(out, static_cast<std::uint32_t>(entries[i].hwcap >> 32U));
  }
  for (const char c : strings) {
    out.push_back(static_cast<std::byte>(c));
  }
  return out;
}

std::vector<std::byte> file_bytes(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  std::vector<std::byte> bytes;
  char c = 0;
  while (in.get(c)) {
    bytes.push_back(static_cast<std::byte>(c));
  }
  return bytes;
}

bool make_link(const fs::path& link, const std::string& target) {
  std::error_code error;
  fs::create_directories(link.parent_path(), error);
  fs::create_symlink(target, link, error);
  return !error;
}

}  // namespace

// Oracle: libb.so.1 has no search path; the loader finds its libsteal.so.1 through the DT_RPATH of
// liba.so.1, which loaded it ("search path=.../chain/inner (RPATH from file chain/liba.so.1)").
TEST(ElfLoadScope, InheritsTheRpathOfTheObjectsThatLoadedTheRequester) {
  donkey::ElfLibrarySearch search = fixture_libraries(donkey::Architecture::X86_64);
  search.paths.push_back(fixture("loadscope", "chain"));
  const donkey::ElfLoadScope scope = scope_of(fixture("loadscope", "chain/chain_consumer"), search);
  ASSERT_EQ(scope.libraries().size(), 5U);
  EXPECT_EQ(scope.libraries()[1].name, "liba.so.1");
  EXPECT_EQ(scope.libraries()[2].name, "libc.so.6");
  EXPECT_EQ(scope.libraries()[3].path, fixture("loadscope", "chain/inner/libb.so.1"));
  EXPECT_EQ(scope.libraries()[4].path, fixture("loadscope", "chain/inner/libsteal.so.1"));
  // Every library was found and read, so a name none defines is known not to be defined.
  EXPECT_EQ(scope.lookup("no_such_name", "").outcome, donkey::ElfBinding::Outcome::NotDefined);
}

// A shared library is looked up in the program's global scope first, then in its own local scope.
// steal/libsteal.so.1 defines an unversioned exit. Rooted at the library, exit binds to its own
// definition; loaded by steal_consumer (whose global scope is the program, the libsteal.so.1 it
// was linked with, then libc.so.6), exit binds to libc.so.6, before the library's own copy.
TEST(ElfLoadScope, ALibraryIsLookedUpInItsProgramsScopeFirst) {
  donkey::ElfLibrarySearch search = fixture_libraries(donkey::Architecture::X86_64);
  search.paths.push_back(fixture("loadscope", "clean"));
  const std::string library = fixture("loadscope", "steal/libsteal.so.1");

  // Without the program nothing is known: the program comes first and is not given.
  const donkey::ElfLoadScope alone = scope_of(library, search);
  EXPECT_EQ(alone.image_index(), 1U);
  const donkey::ElfBinding unknown = alone.lookup("exit", "");
  EXPECT_EQ(unknown.outcome, donkey::ElfBinding::Outcome::Unknown);
  EXPECT_NE(unknown.reason.find("no program was given"), std::string::npos) << unknown.reason;

  search.program = fixture("loadscope", "steal_consumer");
  const donkey::ElfLoadScope scope = scope_of(library, search);
  // The program, its libsteal.so.1 and libc.so.6, then the library. The library's own need,
  // libc.so.6, is the one the program already loaded: it is not read again.
  ASSERT_EQ(scope.libraries().size(), 4U);
  EXPECT_EQ(scope.libraries()[1].path, fixture("loadscope", "clean/libsteal.so.1"));
  EXPECT_EQ(scope.libraries()[2].name, "libc.so.6");
  EXPECT_EQ(scope.image_index(), 3U);
  EXPECT_EQ(scope.libraries()[3].path, library);
  const donkey::ElfBinding exit_binding = scope.lookup("exit", "");
  ASSERT_EQ(exit_binding.outcome, donkey::ElfBinding::Outcome::Bound) << exit_binding.reason;
  EXPECT_EQ(exit_binding.library, 2U);  // libc.so.6 of the global scope, not the library's exit
  // The library defines steal_marker too, but the program's libsteal.so.1 comes first.
  const donkey::ElfBinding marker = scope.lookup("steal_marker", "");
  ASSERT_EQ(marker.outcome, donkey::ElfBinding::Outcome::Bound) << marker.reason;
  EXPECT_EQ(marker.library, 1U);

  // A program that is itself a shared library is refused.
  search.program = fixture("loadscope", "chain/liba.so.1");
  const donkey::ElfBinding refused = scope_of(library, search).lookup("exit", "");
  EXPECT_EQ(refused.outcome, donkey::ElfBinding::Outcome::Unknown);
  EXPECT_NE(refused.reason.find("is a shared library, not a program"), std::string::npos)
      << refused.reason;
}

// A library's local scope follows glibc's dlopen (tests/fixtures/loadscope/PROVENANCE.md, "plugin",
// where glibc's loader is the oracle). plugin/program has DT_RPATH $ORIGIN/a and needs
// libdep.so.1, which it finds in a/ (dep_a only).
namespace {

donkey::ElfLibrarySearch plugin_search() {
  donkey::ElfLibrarySearch search;
  search.system_directories = false;  // everything is found through the fixtures' own paths
  search.program = fixture("loadscope", "plugin/program");
  return search;
}

}  // namespace

// libplugin_runpath.so.1 (DT_RUNPATH $ORIGIN/b) needs libdep.so.1. glibc gives it the libdep.so.1
// the program already loaded, and never opens b/libdep.so.1, the only one that defines `marker`.
TEST(ElfLoadScope, ALibrarysNeedTheProgramAlreadyLoadedIsNotSearchedAgain) {
  const donkey::ElfLoadScope scope =
      scope_of(fixture("loadscope", "plugin/libplugin_runpath.so.1"), plugin_search());
  for (const donkey::ElfScopeLibrary& library : scope.libraries()) {
    EXPECT_EQ(library.path.find("/b/"), std::string::npos) << library.path;
  }
  EXPECT_EQ(scope.lookup("marker", "").outcome, donkey::ElfBinding::Outcome::NotDefined);
  const donkey::ElfBinding dep = scope.lookup("dep_a", "");
  ASSERT_EQ(dep.outcome, donkey::ElfBinding::Outcome::Bound) << dep.reason;
  EXPECT_EQ(scope.libraries()[dep.library].path, fixture("loadscope", "plugin/a/libdep.so.1"));
  // A name only the library defines is found in its local scope, after the global scope.
  const donkey::ElfBinding own = scope.lookup("plugin_runpath", "");
  ASSERT_EQ(own.outcome, donkey::ElfBinding::Outcome::Bound) << own.reason;
  EXPECT_EQ(own.library, scope.image_index());
}

// libplugin_rpath.so.1 has no search path and needs libhelper.so.1, which only the program's
// DT_RPATH directory holds: glibc finds it there ("RPATH from file" the executable). When a library
// of the program's scope has a DT_RPATH of its own, the object that called dlopen could pass that
// on too, and which object that is is not known: the search is Unknown.
TEST(ElfLoadScope, ALibrarysSearchTakesTheExecutablesRpath) {
  const donkey::ElfLoadScope scope =
      scope_of(fixture("loadscope", "plugin/libplugin_rpath.so.1"), plugin_search());
  const donkey::ElfBinding helper = scope.lookup("helper", "");
  ASSERT_EQ(helper.outcome, donkey::ElfBinding::Outcome::Bound) << helper.reason;
  EXPECT_EQ(scope.libraries()[helper.library].path,
            fixture("loadscope", "plugin/a/libhelper.so.1"));

  const Scratch root;
  const fs::path program = root.place("plugin/program", "program");
  root.place("plugin/rpath/libdep.so.1", "a/libdep.so.1");  // DT_RPATH /opt/vendor
  root.place("plugin/a/libhelper.so.1", "a/libhelper.so.1");
  const fs::path plugin = root.place("plugin/libplugin_rpath.so.1", "libplugin_rpath.so.1");
  donkey::ElfLibrarySearch search = plugin_search();
  search.program = program.string();
  const donkey::ElfBinding unknown = scope_of(plugin, search).lookup("helper", "");
  EXPECT_EQ(unknown.outcome, donkey::ElfBinding::Outcome::Unknown);
  EXPECT_NE(unknown.reason.find("loads the library with dlopen is not known"), std::string::npos)
      << unknown.reason;
}

// libplugin_symbolic.so.1 is linked with -Bsymbolic and defines dep_a itself: its own definition
// comes first (glibc's oracle: plugin_symbolic() returns 5, its own dep_a, where the program's
// gives 1). The DT_RUNPATH plugin, without DT_SYMBOLIC, binds dep_a to the program's libdep.so.1.
TEST(ElfLoadScope, ASymbolicLibraryLooksItselfUpFirst) {
  const donkey::ElfLoadScope symbolic =
      scope_of(fixture("loadscope", "plugin/libplugin_symbolic.so.1"), plugin_search());
  const donkey::ElfBinding own = symbolic.lookup("dep_a", "");
  ASSERT_EQ(own.outcome, donkey::ElfBinding::Outcome::Bound) << own.reason;
  EXPECT_EQ(own.library, symbolic.image_index());
  const donkey::ElfLoadScope plain =
      scope_of(fixture("loadscope", "plugin/libplugin_runpath.so.1"), plugin_search());
  EXPECT_NE(plain.lookup("dep_a", "").library, plain.image_index());
}

// The program's scope and the library's local scope share one limit: with room for the program and
// its libdep.so.1 only, the library's own need is not read, and a name it would define is Unknown.
TEST(ElfLoadScope, AProgramAndItsLibraryShareTheLibraryLimit) {
  donkey::ElfLibrarySearch search = plugin_search();
  search.library_limit = 2;
  const donkey::ElfLoadScope scope =
      scope_of(fixture("loadscope", "plugin/libplugin_rpath.so.1"), search);
  const donkey::ElfBinding helper = scope.lookup("helper", "");
  EXPECT_EQ(helper.outcome, donkey::ElfBinding::Outcome::Unknown);
  EXPECT_NE(helper.reason.find("more libraries than the limit"), std::string::npos)
      << helper.reason;
}

// The limit counts every object of the scope, the program included: steal_consumer needs
// libsteal.so.1 and libc.so.6, and with a limit of 2 only libsteal.so.1 is read. `exit`, which
// only libc.so.6 defines, is then not known.
TEST(ElfLoadScope, TheLibraryLimitCountsTheProgram) {
  donkey::ElfLibrarySearch search = fixture_libraries(donkey::Architecture::X86_64);
  search.paths.push_back(fixture("loadscope", "clean"));
  search.library_limit = 2;
  const donkey::ElfLoadScope scope = scope_of(fixture("loadscope", "steal_consumer"), search);
  ASSERT_EQ(scope.libraries().size(), 3U);  // the program, libsteal.so.1 and the limit's marker
  EXPECT_EQ(scope.libraries()[1].path, fixture("loadscope", "clean/libsteal.so.1"));
  const donkey::ElfBinding exit_binding = scope.lookup("exit", "GLIBC_2.2.5");
  EXPECT_EQ(exit_binding.outcome, donkey::ElfBinding::Outcome::Unknown);
  EXPECT_NE(exit_binding.reason.find("more libraries than the limit"), std::string::npos)
      << exit_binding.reason;
  search.library_limit = 3;
  EXPECT_EQ(scope_of(fixture("loadscope", "steal_consumer"), search)
                .lookup("exit", "GLIBC_2.2.5")
                .outcome,
            donkey::ElfBinding::Outcome::Bound);
}

// A program the caller already holds is used as it is, not read again by its path: here the path
// names a file that does not exist.
TEST(ElfLoadScope, AProgramInMemoryIsNotReadAgain) {
  auto program = donkey::load_binary(fixture("loadscope", "plugin/program"));
  ASSERT_TRUE(program.has_value()) << program.diagnostic().message;
  donkey::ElfLibrarySearch search = plugin_search();
  search.program = fixture("loadscope", "plugin/no-such-program");
  search.program_image = &program.value().image;
  search.program_data = program.value().data;
  const donkey::ElfLoadScope scope =
      scope_of(fixture("loadscope", "plugin/libplugin_rpath.so.1"), search);
  EXPECT_EQ(scope.lookup("helper", "").outcome, donkey::ElfBinding::Outcome::Bound);
}

// $ORIGIN of an executable inside the sysroot is a path of the target: its RUNPATH
// $ORIGIN/../private is read under the sysroot once, not twice. The directory's own name contains
// the text "$ORIGIN": the expansion is not scanned again (it would never end).
TEST(ElfLoadScope, ExpandsOriginOnceAndDoesNotApplyTheSysrootTwice) {
  const Scratch root;
  place_libc(root);
  const fs::path executable = root.place("origin_consumer", "srv/x$ORIGIN/bin/origin_consumer");
  root.place("clean/libsteal.so.1", "srv/x$ORIGIN/private/libsteal.so.1");
  const donkey::ElfLoadScope scope = scope_of(executable, under(root));
  ASSERT_EQ(scope.libraries().size(), 3U);
  const std::string& found = scope.libraries()[1].path;
  EXPECT_EQ(found, generic(root.path() / "srv/x$ORIGIN/bin/../private/libsteal.so.1"));
  const donkey::ElfBinding exit_binding = scope.lookup("exit", "GLIBC_2.2.5");
  ASSERT_EQ(exit_binding.outcome, donkey::ElfBinding::Outcome::Bound) << exit_binding.reason;
  EXPECT_EQ(exit_binding.library, 2U);  // the linked libsteal has no exit
}

// Oracle: DT_RPATH "/opt/missing::/opt/base" searches "/opt/missing", then the loader's working
// directory (the empty entry), then "/opt/base". Which directory that is is not known.
TEST(ElfLoadScope, AnEmptyRpathEntryIsTheLoadersWorkingDirectory) {
  const donkey::ElfLoadScope scope = scope_of(fixture("loadscope", "empty_entry_consumer"),
                                              fixture_libraries(donkey::Architecture::X86_64));
  const donkey::ElfBinding binding = scope.lookup("exit", "GLIBC_2.2.5");
  ASSERT_EQ(binding.outcome, donkey::ElfBinding::Outcome::Unknown);
  EXPECT_TRUE(contains(binding.reason, "working directory")) << binding.reason;
}

// glibc consults /etc/ld.so.cache after DT_RUNPATH and before the default directories: the copy
// the cache names is the one loaded, wherever /etc/ld.so.conf now points. An entry for particular
// hardware, an entry for another machine and a cache that cannot be read are handled as the
// loader would, or left Unknown.
TEST(ElfLoadScope, ReadsTheTargetsLoaderCache) {
  const Scratch root;
  place_libc(root);
  root.place("steal/libsteal.so.1", "opt/cached/libsteal.so.1");
  root.place("clean/libsteal.so.1", "usr/lib/x86_64-linux-gnu/libsteal.so.1");
  const fs::path consumer = fixture("loadscope", "steal_consumer");

  root.write("etc/ld.so.cache", loader_cache({{"libsteal.so.1", "/opt/cached/libsteal.so.1"}}));
  {
    const donkey::ElfLoadScope scope = scope_of(consumer, under(root));
    ASSERT_GE(scope.libraries().size(), 2U);
    EXPECT_EQ(scope.libraries()[1].path, generic(root.path() / "opt/cached/libsteal.so.1"));
    EXPECT_EQ(scope.lookup("exit", "GLIBC_2.2.5").library, 1U);  // the cached copy's exit
  }
  // An entry for another machine (AArch64's flags) is not used: the default directory is.
  root.write("etc/ld.so.cache",
             loader_cache({{"libsteal.so.1", "/opt/cached/libsteal.so.1", 0x0a03}}));
  {
    const donkey::ElfLoadScope scope = scope_of(consumer, under(root));
    ASSERT_GE(scope.libraries().size(), 2U);
    EXPECT_EQ(scope.libraries()[1].path,
              generic(root.path() / "usr/lib/x86_64-linux-gnu/libsteal.so.1"));
  }
  // An entry for particular hardware: which entry the loader takes depends on the processor.
  root.write(
      "etc/ld.so.cache",
      loader_cache({{"libsteal.so.1", "/opt/cached/libsteal.so.1", 0x0303, std::uint64_t{1} << 62U},
                    {"libsteal.so.1", "/usr/lib/x86_64-linux-gnu/libsteal.so.1"}}));
  {
    const donkey::ElfBinding binding =
        scope_of(consumer, under(root)).lookup("exit", "GLIBC_2.2.5");
    EXPECT_EQ(binding.outcome, donkey::ElfBinding::Outcome::Unknown);
    EXPECT_TRUE(contains(binding.reason, "particular hardware")) << binding.reason;
  }
  // A cache this reader refuses: not a guess at what the loader does with it.
  root.write("etc/ld.so.cache", std::string("glibc-ld.so.cache1.1 cut short"));
  EXPECT_EQ(scope_of(consumer, under(root)).lookup("exit", "GLIBC_2.2.5").outcome,
            donkey::ElfBinding::Outcome::Unknown);
}

TEST(ElfLoadScope, ReadsTheCacheFormatAndRefusesBrokenOnes) {
  const auto bytes = loader_cache({{"libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6"},
                                   {"libm.so.6", "/lib/x86_64-linux-gnu/libm.so.6", 0x0303, 5}});
  auto entries = donkey::read_loader_cache(bytes);
  ASSERT_TRUE(entries.has_value()) << entries.diagnostic().message;
  ASSERT_EQ(entries.value().size(), 2U);
  EXPECT_EQ(entries.value()[0].name, "libc.so.6");
  EXPECT_EQ(entries.value()[0].path, "/lib/x86_64-linux-gnu/libc.so.6");
  EXPECT_EQ(entries.value()[0].flags, 0x0303);
  EXPECT_EQ(entries.value()[1].hwcap, 5U);
  // Cut inside the entries, and an entry whose name lies outside the file.
  const std::vector<std::byte> cut(bytes.begin(), bytes.begin() + 60);
  EXPECT_FALSE(donkey::read_loader_cache(cut).has_value());
  std::vector<std::byte> outside = bytes;
  outside[48 + 4] = std::byte{0xFF};
  outside[48 + 5] = std::byte{0xFF};
  EXPECT_FALSE(donkey::read_loader_cache(outside).has_value());
  // Another format, and a big-endian cache.
  EXPECT_FALSE(donkey::read_loader_cache(std::vector<std::byte>(64, std::byte{0})).has_value());
  std::vector<std::byte> big = bytes;
  big[28] = std::byte{3};
  EXPECT_FALSE(donkey::read_loader_cache(big).has_value());
}

// Oracle: before a directory the loader tries its glibc-hwcaps/x86-64-v4, -v3 and -v2
// subdirectories. A copy there is taken on a processor of that level, so it is not known which.
TEST(ElfLoadScope, ACopyForParticularHardwareLeavesTheBindingUnknown) {
  const fs::path consumer = fixture("loadscope", "steal_consumer");
  {
    const Scratch root;
    place_libc(root);
    root.place("clean/libsteal.so.1", "lib/x86_64-linux-gnu/libsteal.so.1");
    root.place("steal/libsteal.so.1", "lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3/libsteal.so.1");
    const donkey::ElfBinding binding =
        scope_of(consumer, under(root)).lookup("exit", "GLIBC_2.2.5");
    EXPECT_EQ(binding.outcome, donkey::ElfBinding::Outcome::Unknown);
    EXPECT_TRUE(contains(binding.reason, "glibc-hwcaps")) << binding.reason;
  }
  {
    // A legacy capability subdirectory (glibc before 2.37).
    const Scratch root;
    place_libc(root);
    root.place("clean/libsteal.so.1", "lib/x86_64-linux-gnu/libsteal.so.1");
    root.place("steal/libsteal.so.1", "lib/x86_64-linux-gnu/haswell/libsteal.so.1");
    EXPECT_EQ(scope_of(consumer, under(root)).lookup("exit", "GLIBC_2.2.5").outcome,
              donkey::ElfBinding::Outcome::Unknown);
  }
}

// Which default directories the loader searches, and in which order, is fixed when its glibc is
// built. A name found as two different files in two of them is not known; the same file reached
// through a link (merged /usr) is.
TEST(ElfLoadScope, ANameInTwoDefaultDirectoriesIsKnownOnlyWhenTheyAreOneFile) {
  const Scratch root;
  place_libc(root);
  root.place("steal/libsteal.so.1", "lib/x86_64-linux-gnu/libsteal.so.1");
  root.place("clean/libsteal.so.1", "usr/lib/libsteal.so.1");
  const fs::path consumer = fixture("loadscope", "steal_consumer");
  const donkey::ElfBinding two = scope_of(consumer, under(root)).lookup("exit", "GLIBC_2.2.5");
  EXPECT_EQ(two.outcome, donkey::ElfBinding::Outcome::Unknown);
  EXPECT_TRUE(contains(two.reason, "two default directories")) << two.reason;
  fs::remove(root.path() / "usr/lib/libsteal.so.1");
  if (!make_link(root.path() / "usr/lib/libsteal.so.1", "/lib/x86_64-linux-gnu/libsteal.so.1")) {
    GTEST_SKIP() << "symbolic links cannot be made here";
  }
  const donkey::ElfBinding one = scope_of(consumer, under(root)).lookup("exit", "GLIBC_2.2.5");
  ASSERT_EQ(one.outcome, donkey::ElfBinding::Outcome::Bound) << one.reason;
  EXPECT_EQ(one.library, 1U);
}

// An absolute link in the sysroot points into the target, not at this machine: it is followed
// under the sysroot. A link to a file this machine has and the target lacks finds nothing.
TEST(ElfLoadScope, FollowsLinksInsideTheSysroot) {
  const Scratch root;
  place_libc(root);
  root.place("steal/libsteal.so.1", "opt/real/libsteal.so.1");
  if (!make_link(root.path() / "lib/x86_64-linux-gnu/libsteal.so.1", "/opt/real/libsteal.so.1")) {
    GTEST_SKIP() << "symbolic links cannot be made here";
  }
  const fs::path consumer = fixture("loadscope", "steal_consumer");
  {
    const donkey::ElfLoadScope scope = scope_of(consumer, under(root));
    ASSERT_GE(scope.libraries().size(), 2U);
    EXPECT_EQ(scope.libraries()[1].path,
              generic(root.path() / "lib/x86_64-linux-gnu/libsteal.so.1"));
    EXPECT_EQ(scope.lookup("exit", "GLIBC_2.2.5").library, 1U);
  }
  // The test program itself is a file of this machine, at an absolute path the sysroot lacks.
  fs::remove(root.path() / "lib/x86_64-linux-gnu/libsteal.so.1");
  const std::string host_file = fs::absolute(consumer).generic_string();
  ASSERT_TRUE(make_link(root.path() / "lib/x86_64-linux-gnu/libsteal.so.1", host_file));
  const donkey::ElfBinding binding = scope_of(consumer, under(root)).lookup("exit", "GLIBC_2.2.5");
  EXPECT_EQ(binding.outcome, donkey::ElfBinding::Outcome::Unknown);
  EXPECT_TRUE(contains(binding.reason, "was not found")) << binding.reason;
}

// A file of another machine is skipped, as the loader skips it. A file the loader would take (its
// header matches) and this reader cannot parse leaves the binding Unknown: a later copy is not
// proven.
TEST(ElfLoadScope, AFileTheReaderRefusesIsNotPassedBy) {
  const fs::path consumer = fixture("loadscope", "steal_consumer");
  const Scratch root;
  place_libc(root);
  root.place("steal/libsteal.so.1", "lib/x86_64-linux-gnu/libsteal.so.1");
  root.place("sysroot-aarch64/lib/aarch64-linux-gnu/libc.so.6", "first/libsteal.so.1");
  donkey::ElfLibrarySearch search = under(root);
  search.paths.push_back((root.path() / "first").string());
  {
    const donkey::ElfLoadScope scope = scope_of(consumer, search);
    ASSERT_GE(scope.libraries().size(), 2U);
    EXPECT_EQ(scope.libraries()[1].path,
              generic(root.path() / "lib/x86_64-linux-gnu/libsteal.so.1"));
  }
  std::ifstream in(fixture("loadscope", "steal/libsteal.so.1"), std::ios::binary);
  std::vector<std::byte> head(256);
  in.read(reinterpret_cast<char*>(head.data()), static_cast<std::streamsize>(head.size()));
  root.write("first/libsteal.so.1", head);  // an x86-64 header, cut short
  const donkey::ElfBinding binding = scope_of(consumer, search).lookup("exit", "GLIBC_2.2.5");
  EXPECT_EQ(binding.outcome, donkey::ElfBinding::Outcome::Unknown);
  EXPECT_TRUE(contains(binding.reason, "could not be parsed")) << binding.reason;
}

// ld.so.preload separates names by white space or `:`; `#` starts a comment to the end of the line.
TEST(ElfLoadScope, ReadsPreloadNamesAsTheLoaderDoes) {
  const Scratch root;
  place_libc(root);
  root.place("clean/libsteal.so.1", "lib/x86_64-linux-gnu/libsteal.so.1");
  root.place("hidden/libhidden.so.1", "opt/pre/libpre.so.1");
  root.place("libvers.so.1", "opt/pre/libpre2.so.1");
  root.write("etc/ld.so.preload",
             std::string("# preloads for the test\n/opt/pre/libpre.so.1:/opt/pre/libpre2.so.1 "
                         "# two of them\n"));
  const donkey::ElfLoadScope scope = scope_of(fixture("loadscope", "steal_consumer"), under(root));
  ASSERT_EQ(scope.libraries().size(), 5U);
  EXPECT_EQ(scope.libraries()[1].name, "/opt/pre/libpre.so.1");
  EXPECT_TRUE(scope.libraries()[1].preloaded);
  EXPECT_EQ(scope.libraries()[2].name, "/opt/pre/libpre2.so.1");
  EXPECT_TRUE(scope.libraries()[2].preloaded);
  EXPECT_EQ(scope.libraries()[3].name, "libsteal.so.1");
  // The preloads come first: libpre2 (libvers) takes an unversioned exit before libc.
  EXPECT_EQ(scope.lookup("exit", "").library, 2U);
}

// A version need with the hidden flag accepts only its own version: an earlier library's
// unversioned exit (libsteal, which has symbol versions) is passed by, and libc's exit@GLIBC_2.2.5
// is taken. Without the flag the unversioned exit is taken.
TEST(ElfLoadScope, AHiddenVersionNeedPassesAnUnversionedDefinition) {
  auto steal = donkey::load_binary(fixture("loadscope", "steal/libsteal.so.1"));
  auto libc = donkey::load_binary(fixture("loadscope", kLibc));
  ASSERT_TRUE(steal.has_value());
  ASSERT_TRUE(libc.has_value());
  const std::vector<donkey::ElfLoadScope::Input> inputs = {
      {"executable", nullptr, {}},
      {"libsteal.so.1", &steal.value().image, steal.value().data},
      {"libc.so.6", &libc.value().image, libc.value().data},
  };
  const donkey::ElfLoadScope scope = donkey::ElfLoadScope::from_images(inputs);
  EXPECT_EQ(scope.lookup("exit", "GLIBC_2.2.5", false).library, 1U);
  EXPECT_EQ(scope.lookup("exit", "GLIBC_2.2.5", true).library, 2U);
}

// libhidden.so.1 defines only the hidden exit@V2 (an index above the base). An explicit V2 binds
// there; an unversioned reference does not take a hidden definition and goes on to libc.
TEST(ElfLoadScope, AHiddenOnlyDefinitionIsTakenOnlyByItsVersion) {
  auto hidden = donkey::load_binary(fixture("loadscope", "hidden/libhidden.so.1"));
  auto libc = donkey::load_binary(fixture("loadscope", kLibc));
  ASSERT_TRUE(hidden.has_value());
  ASSERT_TRUE(libc.has_value());
  const std::vector<donkey::ElfLoadScope::Input> inputs = {
      {"executable", nullptr, {}},
      {"libhidden.so.1", &hidden.value().image, hidden.value().data},
      {"libc.so.6", &libc.value().image, libc.value().data},
  };
  const donkey::ElfLoadScope scope = donkey::ElfLoadScope::from_images(inputs);
  EXPECT_EQ(scope.lookup("exit", "V2").library, 1U);
  const donkey::ElfBinding unversioned = scope.lookup("exit", "");
  ASSERT_EQ(unversioned.outcome, donkey::ElfBinding::Outcome::Bound);
  EXPECT_EQ(unversioned.library, 2U);
}

// The loader reads DT_NEEDED from PT_DYNAMIC. A name it would read that this reader cannot (here
// an offset past the string table) may be a library before the provider: the lookup is Unknown.
TEST(ElfLoadScope, ADynamicTableThatCannotBeReadInFullStopsTheLookup) {
  const Scratch root;
  place_libc(root);
  root.place("clean/libsteal.so.1", "lib/x86_64-linux-gnu/libsteal.so.1");
  std::vector<std::byte> bytes = file_bytes(fixture("loadscope", "steal_consumer"));
  constexpr std::size_t kDynamic = 0x2da8;  // `readelf -l steal_consumer`: PT_DYNAMIC's offset
  ASSERT_GT(bytes.size(), kDynamic + 16);
  ASSERT_EQ(static_cast<unsigned>(bytes[kDynamic]), 1U);  // DT_NEEDED libsteal.so.1
  bytes[kDynamic + 8 + 3] = std::byte{0x7F};              // its name: far past DT_STRSZ
  const fs::path broken = root.write("broken_consumer", bytes);
  const donkey::ElfBinding binding = scope_of(broken, under(root)).lookup("exit", "GLIBC_2.2.5");
  EXPECT_EQ(binding.outcome, donkey::ElfBinding::Outcome::Unknown);
  EXPECT_TRUE(contains(binding.reason, "dynamic table")) << binding.reason;
}

// The loader reads symbol versions through DT_VERSYM and DT_VERNEED, not section names. When the
// version need section cannot be found by name, an import's version index is unresolved (not
// unversioned), and the call is not marked.
TEST(ElfVersions, AVersionNeedTheLoaderReadsButTheSectionsHideIsUnresolved) {
  std::vector<std::byte> bytes = file_bytes(fixture("stubs", "stubs_x86_64"));
  const std::string name(".gnu.version_r");
  std::size_t renamed = 0;
  for (std::size_t at = 0; at + name.size() < bytes.size(); ++at) {
    bool match = bytes[at + name.size()] == std::byte{0};
    for (std::size_t i = 0; match && i < name.size(); ++i) {
      match = static_cast<char>(bytes[at + i]) == name[i];
    }
    if (match) {
      bytes[at + 10] = std::byte{'X'};  // .gnu.versiXn_r
      ++renamed;
    }
  }
  ASSERT_EQ(renamed, 1U);
  auto image = donkey::parse_binary(bytes, "stubs_x86_64");
  ASSERT_TRUE(image.has_value());
  auto references = donkey::read_import_references(image.value(), bytes);
  ASSERT_TRUE(references.has_value()) << references.diagnostic().message;
  bool abort_unresolved = false;
  for (const donkey::ElfImportReference& reference : references.value()) {
    if (reference.name == "abort") {
      abort_unresolved = reference.unresolved && reference.version.empty();
    }
  }
  EXPECT_TRUE(abort_unresolved);
  AnalysisOptions options;
  options.library_search = fixture_libraries(donkey::Architecture::X86_64);
  auto analysis = donkey::analyze(image.value(), bytes, options);
  ASSERT_TRUE(analysis.has_value());
  EXPECT_TRUE(analysis.value().no_return.empty());
  EXPECT_TRUE(analysis.value().partial);
}

// A library that calls itself libc.so.6 (its SONAME) but was loaded as libsteal.so.1 is not taken
// for the C library: its own name is no evidence of what it is. The loader does bind exit there
// (and libc.so.6, needed later, matches it by SONAME and is not loaded again).
TEST(Analysis, ALibraryThatIsTheCLibraryOnlyByItsSonameIsNotTrusted) {
  const Scratch root;
  place_libc(root);
  root.place(kLibc, "opt/impostor/libsteal.so.1");
  auto loaded = donkey::load_binary(fixture("loadscope", "steal_consumer"));
  ASSERT_TRUE(loaded.has_value());
  AnalysisOptions options;
  options.library_search = under(root);
  options.library_search.paths.push_back((root.path() / "opt/impostor").string());
  auto analysis = donkey::analyze(loaded.value().image, loaded.value().data, options);
  ASSERT_TRUE(analysis.has_value());
  EXPECT_TRUE(analysis.value().no_return.empty());
}

// A library left out when the queue is full stays out, and so does every library queued after it,
// even once the queue has room again. chain_consumer needs liba.so.1 then libc.so.6; with room for
// one, libc.so.6 is left out. Were liba's own needs (libb, then libsteal with an unversioned exit)
// queued later, exit would bind to libsteal, ahead of the libc the loader takes first.
TEST(ElfLoadScope, ALibraryLeftOutOfAFullQueueKeepsEveryLaterOneOut) {
  donkey::ElfLibrarySearch search = fixture_libraries(donkey::Architecture::X86_64);
  search.paths.push_back(fixture("loadscope", "chain"));
  search.queue_limit = 1;
  const donkey::ElfLoadScope scope = scope_of(fixture("loadscope", "chain/chain_consumer"), search);
  ASSERT_EQ(scope.libraries().size(), 3U);  // the executable, liba.so.1, then the unknown rest
  EXPECT_EQ(scope.libraries()[1].name, "liba.so.1");
  const donkey::ElfBinding binding = scope.lookup("exit", "GLIBC_2.2.5");
  EXPECT_EQ(binding.outcome, donkey::ElfBinding::Outcome::Unknown);
  EXPECT_TRUE(contains(binding.reason, "limit")) << binding.reason;
}

// The hardware-capability check resolves its paths as the library's own are: an absolute link
// under a sysroot's glibc-hwcaps is followed inside the sysroot, where the override exists.
TEST(ElfLoadScope, AHardwareCopyBehindALinkInTheSysrootLeavesTheBindingUnknown) {
  const Scratch root;
  place_libc(root);
  root.place("clean/libsteal.so.1", "lib/x86_64-linux-gnu/libsteal.so.1");
  root.place("steal/libsteal.so.1", "opt/v3/libsteal.so.1");
  if (!make_link(root.path() / "lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3", "/opt/v3")) {
    GTEST_SKIP() << "symbolic links cannot be made here";
  }
  const donkey::ElfBinding binding =
      scope_of(fixture("loadscope", "steal_consumer"), under(root)).lookup("exit", "GLIBC_2.2.5");
  EXPECT_EQ(binding.outcome, donkey::ElfBinding::Outcome::Unknown);
  EXPECT_TRUE(contains(binding.reason, "glibc-hwcaps/x86-64-v3")) << binding.reason;
}

namespace {

/// Renames every section called `from` to `to` (same length) in `bytes`; returns how many.
std::size_t rename_section(std::vector<std::byte>& bytes, const std::string& from,
                           const std::string& to) {
  std::size_t renamed = 0;
  for (std::size_t at = 0; at + from.size() < bytes.size(); ++at) {
    bool match =
        bytes[at + from.size()] == std::byte{0} && (at == 0 || bytes[at - 1] == std::byte{0});
    for (std::size_t i = 0; match && i < from.size(); ++i) {
      match = static_cast<char>(bytes[at + i]) == from[i];
    }
    if (match) {
      for (std::size_t i = 0; i < to.size(); ++i) {
        bytes[at + i] = static_cast<std::byte>(to[i]);
      }
      ++renamed;
    }
  }
  return renamed;
}

std::uint64_t read_le(const std::vector<std::byte>& bytes, std::size_t at, std::size_t size) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < size; ++i) {
    value |= static_cast<std::uint64_t>(bytes[at + i]) << (8 * i);
  }
  return value;
}

}  // namespace

// The loader reads a library's needs through PT_DYNAMIC: with its `.dynamic` section renamed,
// liba.so.1 still needs libb.so.1, and the scope still finds it.
TEST(ElfLoadScope, ALibraryWhoseDynamicSectionIsRenamedStillGivesItsNeeds) {
  const Scratch root;
  std::vector<std::byte> liba = file_bytes(fixture("loadscope", "chain/liba.so.1"));
  ASSERT_EQ(rename_section(liba, ".dynamic", ".dynamiX"), 1U);
  root.write("libs/liba.so.1", liba);
  fs::create_directories(root.path() / "libs/inner");
  fs::copy_file(fixture("loadscope", "chain/inner/libb.so.1"),
                root.path() / "libs/inner/libb.so.1");
  fs::copy_file(fixture("loadscope", "chain/inner/libsteal.so.1"),
                root.path() / "libs/inner/libsteal.so.1");
  donkey::ElfLibrarySearch search = fixture_libraries(donkey::Architecture::X86_64);
  search.paths.push_back((root.path() / "libs").string());
  const donkey::ElfLoadScope scope = scope_of(fixture("loadscope", "chain/chain_consumer"), search);
  ASSERT_EQ(scope.libraries().size(), 5U);
  EXPECT_EQ(scope.libraries()[3].name, "libb.so.1");
  EXPECT_EQ(scope.libraries()[4].name, "libsteal.so.1");
}

// An image with program headers and no PT_DYNAMIC is not dynamically linked for the loader,
// whatever its sections say: it needs nothing.
TEST(ElfLoadScope, ProgramHeadersWithoutPtDynamicNeedNothing) {
  std::vector<std::byte> bytes = file_bytes(fixture("loadscope", "steal_consumer"));
  const std::uint64_t phoff = read_le(bytes, 32, 8);
  const std::uint64_t phentsize = read_le(bytes, 54, 2);
  const std::uint64_t phnum = read_le(bytes, 56, 2);
  std::size_t changed = 0;
  for (std::uint64_t i = 0; i < phnum; ++i) {
    const std::size_t at = static_cast<std::size_t>(phoff + i * phentsize);
    if (read_le(bytes, at, 4) == 2) {  // PT_DYNAMIC becomes PT_NULL
      bytes[at] = std::byte{0};
      ++changed;
    }
  }
  ASSERT_EQ(changed, 1U);
  auto image = donkey::parse_binary(bytes, "no_pt_dynamic");
  ASSERT_TRUE(image.has_value());
  const donkey::ElfLibraryNames names = donkey::read_library_names(image.value(), bytes);
  EXPECT_FALSE(names.dynamic);
  EXPECT_TRUE(names.needed.empty());
  EXPECT_TRUE(names.complete);
}
