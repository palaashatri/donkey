// Applying a type library (G22-T3): merging its types into a project table, binding each import to
// the library file that defines it, and applying a prototype only where the library describes that
// file, for the image's ABI.

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/core/sha256.h"
#include "donkey/project/cdecl.h"
#include "donkey/project/project.h"
#include "donkey/project/typelib.h"
#include "donkey/project/typelib_apply.h"
#include "donkey/project/types.h"

namespace {

/// The header of a hand-written test library: name and ABI first, then the fixed keys.
std::string library_header(const std::string& name, const std::string& abi_lines) {
  return "donkey-typelib 1\n"
         "library: " +
         name +
         "\n"
         "library_version: 1\n" +
         abi_lines;
}

const char* kSysvAbi =
    "platform: linux\n"
    "architecture: x86_64\n"
    "abi: sysv\n"
    "data_model: LP64\n"
    "pointer_size: 8\n"
    "long_size: 8\n"
    "char_is_signed: true\n";

const char* kWin64Abi =
    "platform: windows\n"
    "architecture: x86_64\n"
    "abi: win64\n"
    "data_model: LLP64\n"
    "pointer_size: 8\n"
    "long_size: 4\n"
    "char_is_signed: true\n";

const char* kLibrary =
    "source: unit test\n"
    "source_sha256: 0000000000000000000000000000000000000000000000000000000000000000\n"
    "licence: MIT\n"
    "licence_file: LICENSE\n"
    "licence_sha256: 1111111111111111111111111111111111111111111111111111111111111111\n"
    "generator: hand-written 1\n"
    "generator_command: none\n"
    "preprocessor: none\n"
    "created: 2026-11-17\n";

std::string library_text(const std::string& body, const std::string& name = "apply-test",
                         const std::string& abi = kSysvAbi,
                         const std::vector<std::string>& provides = {}) {
  donkey::TypeTable empty;
  auto parsed = donkey::parse_c_declarations(body, empty);
  EXPECT_TRUE(parsed.has_value()) << parsed.diagnostic().message;
  // body_sha256 and the declarations count, as the generator computes them.
  std::string text = library_header(name, abi) + kLibrary;
  text += "body_sha256: " +
          donkey::Sha256::hex(std::span<const std::byte>(
              reinterpret_cast<const std::byte*>(body.data()), body.size())) +
          "\n";
  text += "declarations: " + std::to_string(parsed.value().size()) + "\n";
  for (const std::string& file : provides) {
    text += "provides: " + file + "\n";
  }
  return text + "\n" + body;
}

donkey::TypeLibrary library_of(const std::string& body, const donkey::TypeTable& known) {
  auto library = donkey::read_type_library(library_text(body), known);
  EXPECT_TRUE(library.has_value()) << library.diagnostic().message;
  return library.value();
}

/// A project database in the temporary directory, removed with its SQLite sidecars.
class TempProject {
 public:
  TempProject() {
    std::random_device random;
    path_ = std::filesystem::temp_directory_path() /
            ("donkey-typelib-apply-" + std::to_string(random()) + "-" +
             std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".db");
  }
  ~TempProject() {
    std::error_code ignored;
    for (const char* suffix : {"", "-wal", "-shm", "-journal"}) {
      std::filesystem::remove(path_.string() + suffix, ignored);
    }
  }
  TempProject(const TempProject&) = delete;
  TempProject& operator=(const TempProject&) = delete;
  [[nodiscard]] std::string str() const { return path_.string(); }

 private:
  std::filesystem::path path_;
};

std::string fixture(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/" + name;
}

donkey::TypeLibrary musl_library() {
  auto library = donkey::load_type_library(fixture("../../typelibs/musl-1.2.4-x86_64-linux.dtl"));
  EXPECT_TRUE(library.has_value()) << library.diagnostic().message;
  return library.value();
}

/// An image in a new project, with `library` loaded into it, and the image's import sites bound
/// in `search`.
struct OpenedProject {
  donkey::Project project;
  std::int64_t image_id = 0;
  std::vector<donkey::ImportSite> sites;
  donkey::ImageAbi abi;
};

std::optional<OpenedProject> open_with_library(const std::string& path, const std::string& image,
                                               const donkey::TypeLibrary& library,
                                               const donkey::ElfLibrarySearch& search = {}) {
  auto loaded = donkey::load_binary(fixture(image));
  EXPECT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  if (!loaded) {
    return std::nullopt;
  }
  donkey::AnalysisOptions options;
  options.library_search = search;
  auto analysis = donkey::analyze(loaded.value().image, loaded.value().data, options);
  EXPECT_TRUE(analysis.has_value());
  auto project = donkey::Project::create(path);
  EXPECT_TRUE(project.has_value()) << project.diagnostic().message;
  if (!analysis || !project) {
    return std::nullopt;
  }
  auto imported = project.value().import(loaded.value(), analysis.value());
  EXPECT_TRUE(imported.has_value()) << imported.diagnostic().message;
  if (!imported) {
    return std::nullopt;
  }
  donkey::TypeLibraryRecord record;
  record.library = library.library;
  record.library_version = library.library_version;
  record.architecture = library.architecture;
  record.platform = library.platform;
  record.abi = library.abi;
  record.data_model = library.data_model;
  record.provides = library.provides;
  record.body_sha256 = library.body_sha256;
  auto stored = project.value().load_type_library(
      record,
      [&](const donkey::TypeTable& types,
          std::int64_t id) -> donkey::Result<donkey::TypeLibraryLoad> {
        auto merged = donkey::merge_type_library(types, library, id);
        if (!merged) {
          return merged.diagnostic();
        }
        return donkey::TypeLibraryLoad{merged.value().table, merged.value().added,
                                       merged.value().collisions.size()};
      });
  EXPECT_TRUE(stored.has_value()) << stored.diagnostic().message;
  if (!stored) {
    return std::nullopt;
  }
  OpenedProject out{
      std::move(project.value()), imported.value(),
      donkey::import_sites(loaded.value().image, loaded.value().data, analysis.value(), search),
      donkey::image_abi(donkey::format_name(loaded.value().image.format),
                        donkey::architecture_name(loaded.value().image.architecture),
                        loaded.value().image.bits)};
  return out;
}

donkey::ElfLibrarySearch musl_sysroot() {
  donkey::ElfLibrarySearch search;
  search.sysroot = fixture("loadscope/musl/sysroot-x86_64");
  return search;
}

donkey::ElfLibrarySearch glibc_sysroot() {
  donkey::ElfLibrarySearch search;
  search.sysroot = fixture("loadscope/sysroot-x86_64");
  return search;
}

const donkey::LibraryPrototypeApplication* entry_named(
    const std::vector<donkey::LibraryPrototypeApplication>& entries, const std::string& name) {
  for (const auto& entry : entries) {
    if (entry.import == name) {
      return &entry;
    }
  }
  return nullptr;
}

donkey::ImportSite site(const std::string& name, std::vector<std::string> versions = {""}) {
  donkey::ImportSite out;
  out.name = name;
  out.versions = std::move(versions);
  return out;
}

}  // namespace

TEST(TypeLibApply, MergeAddsLibraryTypesWithFreshIds) {
  const donkey::TypeTable empty;
  const auto library = library_of(
      "struct point { int32_t x; int32_t y; };\nint32_t norm(const struct point *p);\n", empty);
  auto merge = donkey::merge_type_library(empty, library, 7);
  ASSERT_TRUE(merge.has_value()) << merge.diagnostic().message;
  EXPECT_GT(merge.value().added, 0U);
  EXPECT_TRUE(merge.value().collisions.empty());
  ASSERT_TRUE(merge.value().ordinary.contains("norm"));
  const auto* norm = merge.value().table.find(merge.value().ordinary.at("norm"));
  ASSERT_NE(norm, nullptr);
  EXPECT_EQ(norm->kind, donkey::TypeKind::Function);
  EXPECT_EQ(norm->provenance, donkey::TypeProvenance::Library);
  EXPECT_EQ(norm->library, 7);  // the record that brought it
}

// A user type with the library's name wins: the library's is not added, references move to the
// user's, and the collision is listed, with `differs` when the layouts do not match.
TEST(TypeLibApply, UserAndDebugTypesWinOverALibrary) {
  donkey::TypeTable user;
  auto declared = donkey::parse_c_declarations("struct point { int64_t x; };\n", user);
  ASSERT_TRUE(declared.has_value());
  for (const auto& type : declared.value()) {
    user.put(type);
  }
  const auto library = library_of(
      "struct point { int32_t x; int32_t y; };\nint32_t norm(const struct point *p);\n", user);
  auto merge = donkey::merge_type_library(user, library);
  ASSERT_TRUE(merge.has_value()) << merge.diagnostic().message;
  ASSERT_EQ(merge.value().collisions.size(), 1U);
  EXPECT_EQ(merge.value().collisions[0].name, "point");
  EXPECT_TRUE(merge.value().collisions[0].differs);
  // The user's struct keeps its layout: 8 bytes, one member.
  const auto* point = merge.value().table.find(merge.value().tags.at("point"));
  ASSERT_NE(point, nullptr);
  EXPECT_EQ(point->provenance, donkey::TypeProvenance::User);
  EXPECT_EQ(point->fields.size(), 1U);
}

TEST(TypeLibApply, SameNameSameLayoutIsAnEqualCollision) {
  donkey::TypeTable user;
  auto declared = donkey::parse_c_declarations("struct point { int32_t x; int32_t y; };\n", user);
  ASSERT_TRUE(declared.has_value());
  for (const auto& type : declared.value()) {
    user.put(type);
  }
  const auto same = library_of("struct point { int32_t x; int32_t y; };\n", user);
  auto merge = donkey::merge_type_library(user, same);
  ASSERT_TRUE(merge.has_value());
  ASSERT_EQ(merge.value().collisions.size(), 1U);
  EXPECT_FALSE(merge.value().collisions[0].differs);
}

// Collisions compare what the types refer to, not just sizes: two typedefs of one size with
// different targets differ, and so do two structs whose members have different types of one size.
TEST(TypeLibApply, CollisionsCompareTargetsAndMemberTypes) {
  donkey::TypeTable user;
  auto declared = donkey::parse_c_declarations(
      "typedef int handle;\nstruct pair { int a; float b; };\ntypedef struct pair same_t;\n", user);
  ASSERT_TRUE(declared.has_value()) << declared.diagnostic().message;
  for (const auto& type : declared.value()) {
    user.put(type);
  }
  const auto library = library_of(
      "typedef unsigned int handle;\nstruct pair { int a; int b; };\n"
      "struct other { int a; float b; };\ntypedef struct other same_t;\n",
      user);
  auto merge = donkey::merge_type_library(user, library);
  ASSERT_TRUE(merge.has_value()) << merge.diagnostic().message;
  std::map<std::string, bool> differs;
  for (const auto& collision : merge.value().collisions) {
    differs[collision.name] = collision.differs;
  }
  EXPECT_TRUE(differs.at("handle"));  // int, unsigned int
  EXPECT_TRUE(differs.at("pair"));    // float, int: one size
  // same_t names `struct pair` in the project and `struct other` in the library: equal shapes,
  // reached through different ids, are the same.
  EXPECT_FALSE(differs.at("same_t"));
}

// A tag declared in a prototype is not a file-scope name: it neither takes a project tag's place
// nor is taken by one.
TEST(TypeLibApply, PrototypeTagsDoNotCollide) {
  donkey::TypeTable user;
  auto declared =
      donkey::parse_c_declarations("struct item { int n; };\nint user(struct point *p);\n", user);
  ASSERT_TRUE(declared.has_value()) << declared.diagnostic().message;
  for (const auto& type : declared.value()) {
    user.put(type);
  }
  // The library's prototype-local `struct item` is its own type, and its file-scope `struct
  // point` is not the project's prototype-local one.
  const auto library =
      library_of("int f(struct item { char n; } *p);\nstruct point { int x; };\n", user);
  auto merge = donkey::merge_type_library(user, library);
  ASSERT_TRUE(merge.has_value()) << merge.diagnostic().message;
  EXPECT_TRUE(merge.value().collisions.empty());
  ASSERT_TRUE(merge.value().tags.contains("point"));
  const auto* point = merge.value().table.find(merge.value().tags.at("point"));
  ASSERT_NE(point, nullptr);
  EXPECT_EQ(point->provenance, donkey::TypeProvenance::Library);
  EXPECT_EQ(point->size, 4U);
  const auto* f = merge.value().table.find(merge.value().ordinary.at("f"));
  ASSERT_NE(f, nullptr);
  EXPECT_EQ(donkey::c_declaration(merge.value().table, f->id, "f"), "int f(struct item *p)");
  const auto* parameter = merge.value().table.find(f->fields.at(0).type);
  ASSERT_NE(parameter, nullptr);
  const auto* item = merge.value().table.find(parameter->target);
  ASSERT_NE(item, nullptr);
  EXPECT_EQ(item->provenance, donkey::TypeProvenance::Library);  // not the project's struct item
  EXPECT_EQ(item->size, 1U);
}

// `typedef struct { ... } item;` names the record with an ordinary name: it prints as `item`, and
// it collides with a project typedef of that name, not with a tag.
TEST(TypeLibApply, ATypedefNamedRecordIsAnOrdinaryName) {
  donkey::TypeTable user;
  auto declared = donkey::parse_c_declarations("struct item { long n; };\n", user);
  ASSERT_TRUE(declared.has_value());
  for (const auto& type : declared.value()) {
    user.put(type);
  }
  const auto library = library_of("typedef struct { int n; } item;\nint f(item *p);\n", user);
  auto merge = donkey::merge_type_library(user, library);
  ASSERT_TRUE(merge.has_value()) << merge.diagnostic().message;
  EXPECT_TRUE(merge.value().collisions.empty());
  const auto* f = merge.value().table.find(merge.value().ordinary.at("f"));
  ASSERT_NE(f, nullptr);
  EXPECT_EQ(donkey::c_declaration(merge.value().table, f->id, "f"), "int f(item *p)");
}

TEST(TypeLibApply, VersionedNameMatchesTheUnversionedLibraryName) {
  const donkey::TypeTable empty;
  auto merge = donkey::merge_type_library(
      empty,
      library_of("void *memcpy(void *, const void *, size_t);\nint puts(const char *);\n", empty));
  ASSERT_TRUE(merge.has_value());
  const auto matched = donkey::match_import_prototypes(
      {site("memcpy", {"GLIBC_2.14"}), site("puts"), site("frobnicate")}, merge.value());
  ASSERT_EQ(matched.size(), 3U);
  EXPECT_EQ(matched[0].prototype, merge.value().ordinary.at("memcpy"));
  EXPECT_EQ(matched[1].prototype, merge.value().ordinary.at("puts"));
  EXPECT_EQ(matched[2].reason, "no prototype");
  EXPECT_EQ(donkey::import_match_name("memcpy@@GLIBC_2.14"), "memcpy");
  EXPECT_EQ(donkey::import_match_name("_puts", true), "puts");
}

// Two versions of one name come from the dynamic symbols, not from the stub's bare name.
TEST(TypeLibApply, AmbiguousVersionsApplyNothing) {
  const donkey::TypeTable empty;
  auto merge = donkey::merge_type_library(
      empty, library_of("void *memcpy(void *, const void *, size_t);\n", empty));
  ASSERT_TRUE(merge.has_value());
  const auto matched =
      donkey::match_import_prototypes({site("memcpy", {"GLIBC_2.2.5", "GLIBC_2.14"}),
                                       site("memcpy", {"GLIBC_2.2.5", "GLIBC_2.14"})},
                                      merge.value());
  EXPECT_EQ(matched[0].reason, "ambiguous");
  EXPECT_EQ(matched[1].reason, "ambiguous");
  EXPECT_EQ(matched[0].prototype.value(), 0U);
}

// An import by ordinal (the import directory says so) is never matched; a function whose name
// only starts like one is matched as any other name.
TEST(TypeLibApply, OrdinalImportIsNotMatched) {
  const donkey::TypeTable empty;
  auto merge = donkey::merge_type_library(
      empty, library_of("int ordinal_7(void);\nint ordinal_lookup(void);\n", empty));
  ASSERT_TRUE(merge.has_value());
  donkey::ImportSite by_ordinal = site("ordinal_7");
  by_ordinal.by_ordinal = true;
  const auto matched =
      donkey::match_import_prototypes({by_ordinal, site("ordinal_lookup")}, merge.value());
  EXPECT_EQ(matched[0].reason, "ordinal import");
  EXPECT_TRUE(matched[1].prototype.valid()) << matched[1].reason;
}

// Only 64-bit images have an ABI a library describes: an x32 ELF image (x86-64, ELFCLASS32) has
// none, so nothing applies to it.
TEST(TypeLibApply, AnX32ImageHasNoLibraryAbi) {
  EXPECT_EQ(donkey::image_abi("ELF", "x86_64", 64).abi, "sysv");
  EXPECT_EQ(donkey::image_abi("ELF", "x86_64", 64).data_model, "LP64");
  EXPECT_TRUE(donkey::image_abi("ELF", "x86_64", 32).abi.empty());
  EXPECT_EQ(donkey::image_abi("PE", "x86_64", 64).abi, "win64");
  EXPECT_TRUE(donkey::image_abi("PE", "x86", 32).abi.empty());
}

// Only a function type the library brought matches: a user function that kept the name on a
// collision is not a library prototype, even passed in a merge result.
TEST(TypeLibApply, TheMatcherNeedsLibraryProvenance) {
  donkey::TypeTable user;
  auto declared = donkey::parse_c_declarations("int puts(char *s);\n", user);
  ASSERT_TRUE(declared.has_value());
  for (const auto& type : declared.value()) {
    user.put(type);
  }
  auto merge = donkey::merge_type_library(user, library_of("int puts(const char *s);\n", user));
  ASSERT_TRUE(merge.has_value());
  ASSERT_EQ(merge.value().collisions.size(), 1U);
  const auto matched = donkey::match_import_prototypes({site("puts")}, merge.value());
  EXPECT_EQ(matched[0].reason, "no prototype");
}

// The shipped musl library merges into an empty table, and the imports of a C program match it.
TEST(TypeLibApply, MuslLibraryGivesPrototypesToCommonImports) {
  const donkey::TypeLibrary library = musl_library();
  // musl's loader, by its file name (no SONAME, as musl-gcc's sysroot has it) and by Alpine's
  // SONAME.
  EXPECT_EQ(library.provides,
            (std::vector<std::string>{"ld-musl-x86_64.so.1", "libc.musl-x86_64.so.1"}));
  auto merge = donkey::merge_type_library(donkey::TypeTable{}, library);
  ASSERT_TRUE(merge.has_value()) << merge.diagnostic().message;
  const auto matched =
      donkey::match_import_prototypes({site("puts", {"GLIBC_2.2.5"}), site("abort"), site("malloc"),
                                       site("strlen"), site("__cxa_finalize")},
                                      merge.value());
  EXPECT_NE(matched[0].prototype.value(), 0U);
  EXPECT_NE(matched[1].prototype.value(), 0U);
  EXPECT_NE(matched[2].prototype.value(), 0U);
  EXPECT_NE(matched[3].prototype.value(), 0U);
  EXPECT_EQ(matched[4].reason, "no prototype");  // not a public musl function
}

// The ledger's done-when for T3: a program linked against musl gets the musl prototypes of
// `puts` and `abort` as Library applications, because both bind to musl's loader, the file the
// library describes. `__cxa_finalize` (not a public musl function) gets none.
TEST(TypeLib, AppliesALibraryPrototypeToAnImportedName) {
  TempProject temp;
  auto opened = open_with_library(temp.str(), "loadscope/musl/stubs_musl_x86_64", musl_library(),
                                  musl_sysroot());
  ASSERT_TRUE(opened.has_value());
  auto applied = donkey::apply_library_prototypes(opened->project, opened->image_id, opened->sites,
                                                  opened->abi);
  ASSERT_TRUE(applied.has_value()) << applied.diagnostic().message;
  auto table = opened->project.types();
  ASSERT_TRUE(table.has_value());
  const auto* puts = entry_named(applied.value(), "puts");
  ASSERT_NE(puts, nullptr);
  ASSERT_TRUE(puts->prototype.valid()) << puts->reason;
  EXPECT_EQ(puts->library, "musl-libc 1.2.4");
  EXPECT_EQ(donkey::c_declaration(table.value(), puts->prototype, "puts"), "int puts(char *)");
  const auto* abort_entry = entry_named(applied.value(), "abort");
  ASSERT_NE(abort_entry, nullptr);
  EXPECT_EQ(donkey::c_declaration(table.value(), abort_entry->prototype, "abort"),
            "void abort(void)");
  auto stored = opened->project.type_applications(opened->image_id);
  ASSERT_TRUE(stored.has_value());
  std::size_t library_applications = 0;
  for (const donkey::TypeApplication& application : stored.value()) {
    EXPECT_EQ(application.kind, donkey::TypeApplicationKind::FunctionPrototype);
    EXPECT_EQ(application.source, donkey::TypeProvenance::Library);
    ++library_applications;
  }
  EXPECT_EQ(library_applications, 2U);
  for (const auto& entry : applied.value()) {
    if (entry.import != "puts" && entry.import != "abort") {
      EXPECT_FALSE(entry.prototype.valid()) << entry.import;
    }
  }
}

// A glibc program's imports bind to libc.so.6, which the musl library does not describe: musl's
// prototypes are not glibc's (strerror_r returns int in one and char * in the other), so none is
// applied.
TEST(TypeLib, ALibraryDoesNotApplyToAnotherCLibrary) {
  TempProject temp;
  auto opened =
      open_with_library(temp.str(), "stubs/stubs_x86_64", musl_library(), glibc_sysroot());
  ASSERT_TRUE(opened.has_value());
  auto applied = donkey::apply_library_prototypes(opened->project, opened->image_id, opened->sites,
                                                  opened->abi);
  ASSERT_TRUE(applied.has_value()) << applied.diagnostic().message;
  const auto* puts = entry_named(applied.value(), "puts");
  ASSERT_NE(puts, nullptr);
  EXPECT_FALSE(puts->prototype.valid());
  EXPECT_EQ(puts->reason, "bound to libc.so.6, which musl-libc 1.2.4 does not describe");
  auto stored = opened->project.type_applications(opened->image_id);
  ASSERT_TRUE(stored.has_value());
  EXPECT_TRUE(stored.value().empty());
}

// Where the loader's libraries cannot be found, the provider is not shown, and nothing applies.
TEST(TypeLib, AnUnshownProviderAppliesNothing) {
  TempProject temp;
  donkey::ElfLibrarySearch nowhere;
  nowhere.sysroot = fixture("loadscope/clean");  // no loader, no libc
  auto opened =
      open_with_library(temp.str(), "loadscope/musl/stubs_musl_x86_64", musl_library(), nowhere);
  ASSERT_TRUE(opened.has_value());
  auto applied = donkey::apply_library_prototypes(opened->project, opened->image_id, opened->sites,
                                                  opened->abi);
  ASSERT_TRUE(applied.has_value());
  const auto* puts = entry_named(applied.value(), "puts");
  ASSERT_NE(puts, nullptr);
  EXPECT_FALSE(puts->prototype.valid());
  EXPECT_EQ(puts->reason.rfind("provider not shown: ", 0), 0U) << puts->reason;
}

// A PE image: each import names its DLL, and a Win64 library that provides msvcrt.dll applies to
// the MinGW fixture's msvcrt thunks. A System V library does not fit the image's ABI.
TEST(TypeLib, AppliesAWin64LibraryToPeImportThunks) {
  TempProject temp;
  donkey::TypeTable empty;
  auto win64 = donkey::read_type_library(
      library_text("int puts(const char *s);\nvoid abort(void);\nlong labs(long n);\n",
                   "msvcrt-test", kWin64Abi, {"msvcrt.dll"}),
      empty);
  ASSERT_TRUE(win64.has_value()) << win64.diagnostic().message;
  auto opened = open_with_library(temp.str(), "stubs/stubs_x86_64.exe", win64.value());
  ASSERT_TRUE(opened.has_value());
  EXPECT_EQ(opened->abi.abi, "win64");
  auto applied = donkey::apply_library_prototypes(opened->project, opened->image_id, opened->sites,
                                                  opened->abi);
  ASSERT_TRUE(applied.has_value()) << applied.diagnostic().message;
  auto table = opened->project.types();
  ASSERT_TRUE(table.has_value());
  const auto* puts = entry_named(applied.value(), "puts");
  ASSERT_NE(puts, nullptr);
  ASSERT_TRUE(puts->prototype.valid()) << puts->reason;
  EXPECT_EQ(donkey::c_declaration(table.value(), puts->prototype, "puts"), "int puts(char *s)");
  const auto* abort_entry = entry_named(applied.value(), "abort");
  ASSERT_NE(abort_entry, nullptr);
  ASSERT_TRUE(abort_entry->prototype.valid()) << abort_entry->reason;
  auto stored = opened->project.type_applications(opened->image_id);
  ASSERT_TRUE(stored.has_value());
  ASSERT_EQ(stored.value().size(), 2U);  // puts and abort
  // Each stored application is a library prototype, at its thunk, of the type the step applied.
  for (const donkey::TypeApplication& application : stored.value()) {
    EXPECT_EQ(application.kind, donkey::TypeApplicationKind::FunctionPrototype);
    EXPECT_EQ(application.source, donkey::TypeProvenance::Library);
    const auto* entry = application.address == puts->address          ? puts
                        : application.address == abort_entry->address ? abort_entry
                                                                      : nullptr;
    ASSERT_NE(entry, nullptr) << application.address;
    EXPECT_EQ(application.type_id, entry->prototype);
  }

  TempProject other;
  auto sysv = donkey::read_type_library(
      library_text("int puts(const char *s);\n", "sysv-test", kSysvAbi, {"msvcrt.dll"}), empty);
  ASSERT_TRUE(sysv.has_value());
  auto mismatched = open_with_library(other.str(), "stubs/stubs_x86_64.exe", sysv.value());
  ASSERT_TRUE(mismatched.has_value());
  auto refused = donkey::apply_library_prototypes(mismatched->project, mismatched->image_id,
                                                  mismatched->sites, mismatched->abi);
  ASSERT_TRUE(refused.has_value());
  const auto* refused_puts = entry_named(refused.value(), "puts");
  ASSERT_NE(refused_puts, nullptr);
  EXPECT_FALSE(refused_puts->prototype.valid());
  EXPECT_EQ(refused_puts->reason,
            "sysv-test 1 is for x86_64 sysv LP64, the image is x86_64 win64 LLP64");
}

// A user prototype at a stub is kept when the library is applied, and a user edit after the
// library replaces the library application.
TEST(TypeLib, AUserPrototypeWinsOverTheLibraryInBothOrders) {
  TempProject temp;
  auto opened = open_with_library(temp.str(), "loadscope/musl/stubs_musl_x86_64", musl_library(),
                                  musl_sysroot());
  ASSERT_TRUE(opened.has_value());
  std::uint64_t puts_at = 0;
  std::uint64_t abort_at = 0;
  for (const auto& entry : opened->sites) {
    puts_at = entry.name == "puts" ? entry.address : puts_at;
    abort_at = entry.name == "abort" ? entry.address : abort_at;
  }
  ASSERT_NE(puts_at, 0U);
  ASSERT_NE(abort_at, 0U);
  auto table = opened->project.types();
  ASSERT_TRUE(table.has_value());
  auto declared = donkey::parse_c_declarations("int my_puts(char *s);\n", table.value());
  ASSERT_TRUE(declared.has_value()) << declared.diagnostic().message;
  donkey::TypeTable with_user = table.value();
  donkey::TypeId user_id{};
  for (const donkey::TypeDefinition& type : declared.value()) {
    with_user.put(type);
    if (type.name == "my_puts") {
      user_id = type.id;
    }
  }
  ASSERT_TRUE(opened->project.replace_types(with_user).has_value());
  ASSERT_TRUE(opened->project
                  .set_type_application(opened->image_id,
                                        donkey::TypeApplicationKind::FunctionPrototype, puts_at,
                                        user_id)
                  .has_value());
  auto applied = donkey::apply_library_prototypes(opened->project, opened->image_id, opened->sites,
                                                  opened->abi);
  ASSERT_TRUE(applied.has_value());
  const auto* puts = entry_named(applied.value(), "puts");
  ASSERT_NE(puts, nullptr);
  EXPECT_FALSE(puts->prototype.valid());
  EXPECT_EQ(puts->reason, "kept: user");
  const auto* abort_entry = entry_named(applied.value(), "abort");
  ASSERT_NE(abort_entry, nullptr);
  EXPECT_TRUE(abort_entry->prototype.valid());
  // The user's edit replaces abort's library prototype.
  ASSERT_TRUE(opened->project
                  .set_type_application(opened->image_id,
                                        donkey::TypeApplicationKind::FunctionPrototype, abort_at,
                                        user_id)
                  .has_value());
  auto stored = opened->project.type_applications(opened->image_id);
  ASSERT_TRUE(stored.has_value());
  ASSERT_EQ(stored.value().size(), 2U);
  for (const donkey::TypeApplication& application : stored.value()) {
    EXPECT_EQ(application.type_id, user_id);
    EXPECT_EQ(application.source, donkey::TypeProvenance::User);
  }
  // Applying the library again changes nothing.
  applied = donkey::apply_library_prototypes(opened->project, opened->image_id, opened->sites,
                                             opened->abi);
  ASSERT_TRUE(applied.has_value());
  abort_entry = entry_named(applied.value(), "abort");
  ASSERT_NE(abort_entry, nullptr);
  EXPECT_EQ(abort_entry->reason, "kept: user");
}

// Only function types the library brought are library prototypes: a user type named like an
// import is not applied as one.
TEST(TypeLibApply, OnlyLibraryFunctionTypesArePrototypes) {
  donkey::TypeTable table;
  auto declared = donkey::parse_c_declarations("int puts(char *s);\n", table);
  ASSERT_TRUE(declared.has_value());
  for (const donkey::TypeDefinition& type : declared.value()) {
    table.put(type);
  }
  const donkey::TypeLibraryMerge prototypes = donkey::library_prototypes(table);
  EXPECT_TRUE(prototypes.ordinary.empty());
  const auto matched = donkey::match_import_prototypes({site("puts")}, prototypes);
  EXPECT_EQ(matched[0].reason, "no prototype");
}

// A load is one transaction: a merge that fails leaves neither types nor a record, and a second
// load of the same library is refused before its merge runs.
TEST(TypeLib, ALoadStoresItsTypesAndRecordTogether) {
  TempProject temp;
  auto project = donkey::Project::create(temp.str());
  ASSERT_TRUE(project.has_value());
  donkey::TypeLibraryRecord record;
  record.library = "atomic";
  record.library_version = "1";
  record.architecture = "x86_64";
  record.platform = "linux";
  record.abi = "sysv";
  record.data_model = "LP64";
  record.provides = {"libatomic-test.so.1"};
  record.body_sha256 = std::string(64, '0');
  auto failed = project.value().load_type_library(
      record,
      [](const donkey::TypeTable&, std::int64_t) -> donkey::Result<donkey::TypeLibraryLoad> {
        return donkey::Diagnostic::make(donkey::Status::InvalidInput, "test.refused", "refused");
      });
  ASSERT_FALSE(failed.has_value());
  EXPECT_EQ(failed.diagnostic().code, "test.refused");
  auto none = project.value().type_libraries();
  ASSERT_TRUE(none.has_value());
  EXPECT_TRUE(none.value().empty());

  const donkey::TypeLibrary library = library_of("int f(void);\n", donkey::TypeTable{});
  const auto merge = [&](const donkey::TypeTable& types,
                         std::int64_t id) -> donkey::Result<donkey::TypeLibraryLoad> {
    auto merged = donkey::merge_type_library(types, library, id);
    if (!merged) {
      return merged.diagnostic();
    }
    return donkey::TypeLibraryLoad{merged.value().table, merged.value().added,
                                   merged.value().collisions.size()};
  };
  auto loaded = project.value().load_type_library(record, merge);
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  auto listed = project.value().type_libraries();
  ASSERT_TRUE(listed.has_value());
  ASSERT_EQ(listed.value().size(), 1U);
  EXPECT_EQ(listed.value()[0].id, loaded.value());
  EXPECT_EQ(listed.value()[0].provides, record.provides);
  EXPECT_EQ(listed.value()[0].abi, "sysv");
  EXPECT_GT(listed.value()[0].added_types, 0U);
  auto types = project.value().types();
  ASSERT_TRUE(types.has_value());
  const std::size_t stored = types.value().list().size();
  bool merged_again = false;
  auto twice =
      project.value().load_type_library(record, [&](const donkey::TypeTable& t, std::int64_t id) {
        merged_again = true;
        return merge(t, id);
      });
  ASSERT_FALSE(twice.has_value());
  EXPECT_EQ(twice.diagnostic().code, "project.type_library_loaded");
  EXPECT_FALSE(merged_again);
  auto after = project.value().types();
  ASSERT_TRUE(after.has_value());
  EXPECT_EQ(after.value().list().size(), stored);
}

TEST(Types, CDeclarationPrintsCDeclarators) {
  donkey::TypeTable table;
  auto declared = donkey::parse_c_declarations(
      "struct point { int x; int y; };\n"
      "int sum(struct point *p, int n);\n"
      "int printf(char *format, ...);\n"
      "void reset(void);\n"
      "long table_of(char *names[4]);\n",
      table);
  ASSERT_TRUE(declared.has_value()) << declared.diagnostic().message;
  for (const donkey::TypeDefinition& type : declared.value()) {
    table.put(type);
  }
  const auto id_of = [&](const char* name) {
    for (const donkey::TypeDefinition& type : table.list()) {
      if (type.name == name && type.kind == donkey::TypeKind::Function) {
        return type.id;
      }
    }
    return donkey::TypeId{};
  };
  EXPECT_EQ(donkey::c_declaration(table, id_of("sum"), "sum"), "int sum(struct point *p, int n)");
  EXPECT_EQ(donkey::c_declaration(table, id_of("printf"), "printf"),
            "int printf(char *format, ...)");
  EXPECT_EQ(donkey::c_declaration(table, id_of("reset"), "reset"), "void reset(void)");
  const std::string array_parameter = donkey::c_declaration(table, id_of("table_of"), "table_of");
  // C adjusts an array parameter to a pointer; either spelling is the same type.
  EXPECT_TRUE(array_parameter == "long table_of(char *names[4])" ||
              array_parameter == "long table_of(char **names)")
      << array_parameter;
  EXPECT_EQ(donkey::c_declaration(table, donkey::TypeId{999'999}, "x"), "? x");
}

// Two libraries that declare one name each keep their own prototype; the apply step takes the one
// whose library provides the DLL the import names. (The MinGW fixture imports puts from
// msvcrt.dll; a library for another DLL is loaded first.)
TEST(TypeLib, EachLibraryKeepsItsOwnPrototypeOfAName) {
  TempProject temp;
  donkey::TypeTable empty;
  auto other = donkey::read_type_library(
      library_text("long puts(long n);\n", "other-dll", kWin64Abi, {"other.dll"}), empty);
  ASSERT_TRUE(other.has_value()) << other.diagnostic().message;
  auto opened = open_with_library(temp.str(), "stubs/stubs_x86_64.exe", other.value());
  ASSERT_TRUE(opened.has_value());
  auto msvcrt = donkey::read_type_library(
      library_text("int puts(const char *s);\n", "msvcrt-test", kWin64Abi, {"msvcrt.dll"}), empty);
  ASSERT_TRUE(msvcrt.has_value()) << msvcrt.diagnostic().message;
  donkey::TypeLibraryRecord record;
  record.library = msvcrt.value().library;
  record.library_version = msvcrt.value().library_version;
  record.architecture = msvcrt.value().architecture;
  record.platform = msvcrt.value().platform;
  record.abi = msvcrt.value().abi;
  record.data_model = msvcrt.value().data_model;
  record.provides = msvcrt.value().provides;
  record.body_sha256 = msvcrt.value().body_sha256;
  auto second = opened->project.load_type_library(
      record,
      [&](const donkey::TypeTable& types,
          std::int64_t id) -> donkey::Result<donkey::TypeLibraryLoad> {
        auto merged = donkey::merge_type_library(types, msvcrt.value(), id);
        if (!merged) {
          return merged.diagnostic();
        }
        EXPECT_TRUE(merged.value().collisions.empty());  // another library's puts is not one
        return donkey::TypeLibraryLoad{merged.value().table, merged.value().added,
                                       merged.value().collisions.size()};
      });
  ASSERT_TRUE(second.has_value()) << second.diagnostic().message;
  auto applied = donkey::apply_library_prototypes(opened->project, opened->image_id, opened->sites,
                                                  opened->abi);
  ASSERT_TRUE(applied.has_value()) << applied.diagnostic().message;
  auto table = opened->project.types();
  ASSERT_TRUE(table.has_value());
  const auto* puts = entry_named(applied.value(), "puts");
  ASSERT_NE(puts, nullptr);
  ASSERT_TRUE(puts->prototype.valid()) << puts->reason;
  EXPECT_EQ(puts->library, "msvcrt-test 1");
  EXPECT_EQ(donkey::c_declaration(table.value(), puts->prototype, "puts"), "int puts(char *s)");
}

// A library type built on a name the project defines differently is not added: a prototype whose
// parameter is the library's `double` item_t would otherwise take the project's integer one.
TEST(TypeLibApply, ATypeBuiltOnADifferentCollisionIsNotAdded) {
  donkey::TypeTable user;
  auto declared = donkey::parse_c_declarations("typedef unsigned long item_t;\n", user);
  ASSERT_TRUE(declared.has_value());
  for (const auto& type : declared.value()) {
    user.put(type);
  }
  const auto library = library_of(
      "typedef double item_t;\ndouble measure(item_t x);\nstruct box { item_t v; };\n"
      "int plain(int n);\n",
      user);
  auto merge = donkey::merge_type_library(user, library);
  ASSERT_TRUE(merge.has_value()) << merge.diagnostic().message;
  ASSERT_EQ(merge.value().collisions.size(), 1U);
  EXPECT_TRUE(merge.value().collisions[0].differs);
  EXPECT_FALSE(merge.value().ordinary.contains("measure"));
  EXPECT_FALSE(merge.value().tags.contains("box"));
  EXPECT_TRUE(merge.value().ordinary.contains("plain"));
  std::set<std::string> dependent(merge.value().dependent.begin(), merge.value().dependent.end());
  EXPECT_TRUE(dependent.contains("measure"));
  EXPECT_TRUE(dependent.contains("box"));
  const auto matched = donkey::match_import_prototypes({site("measure")}, merge.value());
  EXPECT_EQ(matched[0].reason, "no prototype");
}

// Comparing two collisions that share subtrees visits each pair once: a chain of records whose two
// members both point at the previous record is compared in linear time, not exponential.
// The comparison of a long chain (each record points to the one before it) stops at a fixed
// depth instead of recursing as deep as the chain: past it, the two are not shown to be the same.
TEST(TypeLibApply, CollisionComparisonDepthIsBounded) {
  std::string text = "struct t0 { int v; };\n";
  for (int level = 1; level <= 400; ++level) {
    text += "struct t" + std::to_string(level) + " { struct t" + std::to_string(level - 1) +
            " *p; };\n";
  }
  donkey::TypeTable user;
  auto declared = donkey::parse_c_declarations(text, user);
  ASSERT_TRUE(declared.has_value()) << declared.diagnostic().message;
  for (const auto& type : declared.value()) {
    user.put(type);
  }
  auto merge = donkey::merge_type_library(user, library_of(text, user));
  ASSERT_TRUE(merge.has_value()) << merge.diagnostic().message;
  std::map<std::string, bool> differs;
  for (const auto& collision : merge.value().collisions) {
    differs[collision.name] = collision.differs;
  }
  EXPECT_FALSE(differs.at("t10"));
  EXPECT_TRUE(differs.at("t400"));
}

TEST(TypeLibApply, CollisionComparisonIsBounded) {
  std::string text = "struct r0 { int v; };\n";
  for (int level = 1; level <= 40; ++level) {
    text += "struct r" + std::to_string(level) + " { struct r" + std::to_string(level - 1) +
            " *a; struct r" + std::to_string(level - 1) + " *b; };\n";
  }
  donkey::TypeTable user;
  auto declared = donkey::parse_c_declarations(text, user);
  ASSERT_TRUE(declared.has_value()) << declared.diagnostic().message;
  for (const auto& type : declared.value()) {
    user.put(type);
  }
  const auto library = library_of(text, user);
  const auto started = std::chrono::steady_clock::now();
  auto merge = donkey::merge_type_library(user, library);
  const auto elapsed = std::chrono::steady_clock::now() - started;
  ASSERT_TRUE(merge.has_value()) << merge.diagnostic().message;
  EXPECT_EQ(merge.value().collisions.size(), 41U);
  for (const auto& collision : merge.value().collisions) {
    EXPECT_FALSE(collision.differs) << collision.name;
  }
  EXPECT_LT(elapsed, std::chrono::seconds(5));
}

// The register form a call takes (G22-T4): integers, enums and pointers through typedefs, and a
// result typedef'd to void is void; a float or a struct parameter or result has no form.
TEST(TypeLibApply, RegisterPrototypeFollowsTypedefs) {
  donkey::TypeTable table;
  auto declared = donkey::parse_c_declarations(
      "typedef void V;\ntypedef int I;\nV quit(I, char *);\nI count(long);\n"
      "double half(double);\nstruct s { int a; };\nint take(struct s);\n",
      table);
  ASSERT_TRUE(declared.has_value()) << declared.diagnostic().message;
  for (const auto& type : declared.value()) {
    table.put(type);
  }
  // list() returns a copy, so the functions are taken by value.
  const auto function = [&](const std::string& name) -> donkey::TypeDefinition {
    for (const auto& type : table.list()) {
      if (type.kind == donkey::TypeKind::Function && type.name == name) {
        return type;
      }
    }
    ADD_FAILURE() << name;
    return {};
  };
  const auto quit = donkey::register_prototype(table, function("quit"));
  ASSERT_TRUE(quit.has_value());
  EXPECT_EQ(quit->parameter_widths, (std::vector<std::uint8_t>{4, 8}));
  EXPECT_EQ(quit->return_width, 0);
  const auto count = donkey::register_prototype(table, function("count"));
  ASSERT_TRUE(count.has_value());
  EXPECT_EQ(count->parameter_widths, (std::vector<std::uint8_t>{8}));
  EXPECT_EQ(count->return_width, 4);
  EXPECT_FALSE(donkey::register_prototype(table, function("half")).has_value());
  EXPECT_FALSE(donkey::register_prototype(table, function("take")).has_value());
}
