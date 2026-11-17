// Applying a type library (G22-T3, first part): merging its types into a project table and
// matching imported names to its prototypes.

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <optional>
#include <random>
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

const char* kLibrary =
    "donkey-typelib 1\n"
    "library: apply-test\n"
    "library_version: 1\n"
    "platform: linux\n"
    "architecture: x86_64\n"
    "abi: sysv\n"
    "data_model: LP64\n"
    "pointer_size: 8\n"
    "long_size: 8\n"
    "char_is_signed: true\n"
    "source: unit test\n"
    "source_sha256: 0000000000000000000000000000000000000000000000000000000000000000\n"
    "licence: MIT\n"
    "licence_file: LICENSE\n"
    "licence_sha256: 1111111111111111111111111111111111111111111111111111111111111111\n"
    "generator: hand-written 1\n"
    "generator_command: none\n"
    "preprocessor: none\n"
    "created: 2026-11-17\n";

std::string library_text(const std::string& body) {
  donkey::TypeTable empty;
  auto parsed = donkey::parse_c_declarations(body, empty);
  EXPECT_TRUE(parsed.has_value()) << parsed.diagnostic().message;
  // body_sha256 and the declarations count, as the generator computes them.
  std::string text = kLibrary;
  text += "body_sha256: " +
          donkey::Sha256::hex(std::span<const std::byte>(
              reinterpret_cast<const std::byte*>(body.data()), body.size())) +
          "\n";
  text += "declarations: " + std::to_string(parsed.value().size()) + "\n\n" + body;
  return text;
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

/// stubs_x86_64 in a new project, with the musl library merged into its type table, and the
/// image's import sites: `1050 <__cxa_finalize@plt>`, `1060 <abort@plt>`, `1070 <puts@plt>`.
struct MuslProject {
  donkey::Project project;
  std::int64_t image_id = 0;
  std::vector<donkey::ImportSite> sites;
};

std::optional<MuslProject> musl_project(const std::string& path) {
  auto loaded = donkey::load_binary(std::string(DONKEY_FIXTURE_DIR) + "/stubs/stubs_x86_64");
  EXPECT_TRUE(loaded.has_value());
  auto analysis = donkey::analyze(loaded.value().image, loaded.value().data);
  EXPECT_TRUE(analysis.has_value());
  auto project = donkey::Project::create(path);
  EXPECT_TRUE(project.has_value()) << project.diagnostic().message;
  if (!loaded || !analysis || !project) {
    return std::nullopt;
  }
  auto imported = project.value().import(loaded.value(), analysis.value());
  EXPECT_TRUE(imported.has_value()) << imported.diagnostic().message;
  auto library = donkey::load_type_library(std::string(DONKEY_FIXTURE_DIR) +
                                           "/../../typelibs/musl-1.2.4-x86_64-linux.dtl");
  EXPECT_TRUE(library.has_value());
  if (!imported || !library) {
    return std::nullopt;
  }
  auto merged = donkey::merge_type_library(donkey::TypeTable{}, library.value());
  EXPECT_TRUE(merged.has_value());
  if (!merged || !project.value().replace_types(merged.value().table)) {
    return std::nullopt;
  }
  MuslProject out{std::move(project.value()), imported.value(), {}};
  for (const donkey::Function& function : analysis.value().functions) {
    if (!function.import_name.empty()) {
      out.sites.push_back({function.import_name, function.address});
    }
  }
  return out;
}

const donkey::LibraryPrototypeApplication* entry_at(
    const std::vector<donkey::LibraryPrototypeApplication>& entries, std::uint64_t address) {
  for (const auto& entry : entries) {
    if (entry.address == address) {
      return &entry;
    }
  }
  return nullptr;
}

}  // namespace

TEST(TypeLibApply, MergeAddsLibraryTypesWithFreshIds) {
  const donkey::TypeTable empty;
  const auto library = library_of(
      "struct point { int32_t x; int32_t y; };\nint32_t norm(const struct point *p);\n", empty);
  auto merge = donkey::merge_type_library(empty, library);
  ASSERT_TRUE(merge.has_value()) << merge.diagnostic().message;
  EXPECT_GT(merge.value().added, 0U);
  EXPECT_TRUE(merge.value().collisions.empty());
  ASSERT_TRUE(merge.value().ordinary.contains("norm"));
  const auto* norm = merge.value().table.find(merge.value().ordinary.at("norm"));
  ASSERT_NE(norm, nullptr);
  EXPECT_EQ(norm->kind, donkey::TypeKind::Function);
  EXPECT_EQ(norm->provenance, donkey::TypeProvenance::Library);
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

TEST(TypeLibApply, SameNameDifferentLayoutIsACollision) {
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

TEST(TypeLibApply, VersionedNameMatchesTheUnversionedLibraryName) {
  const donkey::TypeTable empty;
  auto merge = donkey::merge_type_library(
      empty,
      library_of("void *memcpy(void *, const void *, size_t);\nint puts(const char *);\n", empty));
  ASSERT_TRUE(merge.has_value());
  const auto matched =
      donkey::match_import_prototypes({"memcpy@GLIBC_2.14", "puts", "frobnicate"}, merge.value());
  ASSERT_EQ(matched.size(), 3U);
  EXPECT_EQ(matched[0].prototype, merge.value().ordinary.at("memcpy"));
  EXPECT_EQ(matched[1].prototype, merge.value().ordinary.at("puts"));
  EXPECT_EQ(matched[2].reason, "no prototype");
  EXPECT_EQ(donkey::import_match_name("memcpy@@GLIBC_2.14"), "memcpy");
  EXPECT_EQ(donkey::import_match_name("_puts", true), "puts");
}

TEST(TypeLibApply, AmbiguousVersionsApplyNothing) {
  const donkey::TypeTable empty;
  auto merge = donkey::merge_type_library(
      empty, library_of("void *memcpy(void *, const void *, size_t);\n", empty));
  ASSERT_TRUE(merge.has_value());
  const auto matched =
      donkey::match_import_prototypes({"memcpy@GLIBC_2.2.5", "memcpy@GLIBC_2.14"}, merge.value());
  EXPECT_EQ(matched[0].reason, "ambiguous");
  EXPECT_EQ(matched[1].reason, "ambiguous");
  EXPECT_EQ(matched[0].prototype.value(), 0U);
}

TEST(TypeLibApply, OrdinalImportIsNotMatched) {
  const donkey::TypeTable empty;
  auto merge = donkey::merge_type_library(empty, library_of("int ordinal_7(void);\n", empty));
  ASSERT_TRUE(merge.has_value());
  const auto matched = donkey::match_import_prototypes({"ordinal_7"}, merge.value());
  EXPECT_EQ(matched[0].reason, "ordinal import");
}

// The shipped musl library merges into an empty table, and the imports of a C program match it.
TEST(TypeLibApply, MuslLibraryGivesPrototypesToCommonImports) {
  auto library = donkey::load_type_library(std::string(DONKEY_FIXTURE_DIR) +
                                           "/../../typelibs/musl-1.2.4-x86_64-linux.dtl");
  ASSERT_TRUE(library.has_value()) << library.diagnostic().message;
  auto merge = donkey::merge_type_library(donkey::TypeTable{}, library.value());
  ASSERT_TRUE(merge.has_value()) << merge.diagnostic().message;
  const auto matched = donkey::match_import_prototypes(
      {"puts@GLIBC_2.2.5", "abort", "malloc", "strlen", "__cxa_finalize"}, merge.value());
  EXPECT_NE(matched[0].prototype.value(), 0U);
  EXPECT_NE(matched[1].prototype.value(), 0U);
  EXPECT_NE(matched[2].prototype.value(), 0U);
  EXPECT_NE(matched[3].prototype.value(), 0U);
  EXPECT_EQ(matched[4].reason, "no prototype");  // not a public musl function
}

// The ledger's done-when for T3: the fixture's `puts` and `abort` stubs get their musl prototypes
// as Library applications; `__cxa_finalize` (not a public musl function) gets none.
TEST(TypeLib, AppliesALibraryPrototypeToAnImportedName) {
  TempProject temp;
  auto opened = musl_project(temp.str());
  ASSERT_TRUE(opened.has_value());
  ASSERT_EQ(opened->sites.size(), 3U);
  auto applied = donkey::apply_library_prototypes(opened->project, opened->image_id, opened->sites);
  ASSERT_TRUE(applied.has_value()) << applied.diagnostic().message;
  auto table = opened->project.types();
  ASSERT_TRUE(table.has_value());
  const auto* puts = entry_at(applied.value(), 0x1070);
  ASSERT_NE(puts, nullptr);
  ASSERT_TRUE(puts->prototype.valid()) << puts->reason;
  EXPECT_EQ(donkey::c_declaration(table.value(), puts->prototype, "puts"), "int puts(char *)");
  const auto* abort_entry = entry_at(applied.value(), 0x1060);
  ASSERT_NE(abort_entry, nullptr);
  EXPECT_EQ(donkey::c_declaration(table.value(), abort_entry->prototype, "abort"),
            "void abort(void)");
  const auto* finalize = entry_at(applied.value(), 0x1050);
  ASSERT_NE(finalize, nullptr);
  EXPECT_FALSE(finalize->prototype.valid());
  EXPECT_EQ(finalize->reason, "no prototype");
  auto stored = opened->project.type_applications(opened->image_id);
  ASSERT_TRUE(stored.has_value());
  ASSERT_EQ(stored.value().size(), 2U);
  for (const donkey::TypeApplication& application : stored.value()) {
    EXPECT_EQ(application.kind, donkey::TypeApplicationKind::FunctionPrototype);
    EXPECT_EQ(application.source, donkey::TypeProvenance::Library);
  }
}

// A user prototype at a stub is kept when the library is applied, and a user edit after the
// library replaces the library application.
TEST(TypeLib, AUserPrototypeWinsOverTheLibraryInBothOrders) {
  TempProject temp;
  auto opened = musl_project(temp.str());
  ASSERT_TRUE(opened.has_value());
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
                                        donkey::TypeApplicationKind::FunctionPrototype, 0x1070,
                                        user_id)
                  .has_value());
  auto applied = donkey::apply_library_prototypes(opened->project, opened->image_id, opened->sites);
  ASSERT_TRUE(applied.has_value());
  const auto* puts = entry_at(applied.value(), 0x1070);
  ASSERT_NE(puts, nullptr);
  EXPECT_FALSE(puts->prototype.valid());
  EXPECT_EQ(puts->reason, "kept: user");
  const auto* abort_entry = entry_at(applied.value(), 0x1060);
  ASSERT_NE(abort_entry, nullptr);
  EXPECT_TRUE(abort_entry->prototype.valid());
  // The user's edit replaces abort's library prototype.
  ASSERT_TRUE(opened->project
                  .set_type_application(opened->image_id,
                                        donkey::TypeApplicationKind::FunctionPrototype, 0x1060,
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
  applied = donkey::apply_library_prototypes(opened->project, opened->image_id, opened->sites);
  ASSERT_TRUE(applied.has_value());
  abort_entry = entry_at(applied.value(), 0x1060);
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
  const auto matched = donkey::match_import_prototypes({"puts"}, prototypes);
  EXPECT_EQ(matched[0].reason, "no prototype");
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
