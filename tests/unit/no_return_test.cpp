// No-return calls (G24-T3): the version reader, the fixed list and its provider binding, the CFG
// and lifter effects, propagation, the verifier rules and the evaluator. Fixtures: see
// tests/fixtures/stubs/PROVENANCE.md; the oracle for each address is `objdump -d` on the same file.

#include <gtest/gtest.h>

#include <algorithm>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/analysis/no_return.h"
#include "donkey/binary/elf_load_scope.h"
#include "donkey/binary/elf_versions.h"
#include "donkey/binary/image.h"
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
// so the call is not marked and its fall-through stays. With the libsteal.so.1 it was linked
// against (no exit), the call binds to libc.so.6 and is marked.
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
