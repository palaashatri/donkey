#include <gtest/gtest.h>
#include <sqlite3.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <utility>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/project/project.h"

namespace {

using donkey::AnalysisResult;
using donkey::LoadedBinary;
using donkey::Project;

std::string fixture_path(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/binaries/" + name;
}

/// Unique database path that removes itself and its SQLite sidecars.
class TempPath {
 public:
  explicit TempPath(const std::string& name) {
    static std::uint64_t counter = 0;
    path_ = std::filesystem::temp_directory_path() /
            ("donkey-" + name + "-" + std::to_string(++counter) + ".db");
  }
  ~TempPath() { remove(); }
  TempPath(const TempPath&) = delete;
  TempPath& operator=(const TempPath&) = delete;

  [[nodiscard]] std::string str() const { return path_.string(); }

  void remove() const {
    std::error_code ignored;
    std::filesystem::remove(path_, ignored);
    std::filesystem::remove(path_.string() + "-wal", ignored);
    std::filesystem::remove(path_.string() + "-shm", ignored);
  }

 private:
  std::filesystem::path path_;
};

LoadedBinary load_elf() {
  auto loaded = donkey::load_binary(fixture_path("tiny-elf-x86_64"));
  EXPECT_TRUE(loaded.has_value());
  return loaded.has_value() ? std::move(loaded.value()) : LoadedBinary{};
}

TEST(Project, CreatesReopensAndPersistsImage) {
  TempPath path("persist");
  auto loaded = load_elf();
  auto analysis = donkey::analyze(loaded.image, loaded.data);
  ASSERT_TRUE(analysis.has_value());

  {
    auto created = Project::create(path.str());
    ASSERT_TRUE(created.has_value())
        << created.diagnostic().code << ": " << created.diagnostic().message;
    EXPECT_EQ(created.value().schema_version(), donkey::kProjectSchemaVersion);
    auto id = created.value().import(loaded, analysis.value());
    ASSERT_TRUE(id.has_value()) << id.diagnostic().message;
    EXPECT_GT(id.value(), 0);
    auto integrity = created.value().check_integrity();
    ASSERT_TRUE(integrity.has_value());
    EXPECT_TRUE(integrity.value());
  }

  auto reopened = Project::open(path.str());
  ASSERT_TRUE(reopened.has_value()) << reopened.diagnostic().message;
  auto images = reopened.value().images();
  ASSERT_TRUE(images.has_value()) << images.diagnostic().message;
  ASSERT_EQ(images.value().size(), 1U);

  const auto& image = images.value().front();
  EXPECT_EQ(image.sha256, loaded.image.sha256);
  EXPECT_EQ(image.format, "ELF");
  EXPECT_EQ(image.architecture, "x86_64");
  EXPECT_EQ(image.bits, 64U);
  EXPECT_EQ(image.entry_point, 0x400100U);
  EXPECT_GE(image.sections, 5U);
  EXPECT_EQ(image.functions, 2U);
  EXPECT_FALSE(image.analysis_partial);

  auto integrity = reopened.value().check_integrity();
  ASSERT_TRUE(integrity.has_value());
  EXPECT_TRUE(integrity.value());
}

TEST(Project, ReimportReplacesDerivedRows) {
  TempPath path("reimport");
  auto loaded = load_elf();
  auto analysis = donkey::analyze(loaded.image, loaded.data);
  ASSERT_TRUE(analysis.has_value());

  auto project = Project::create(path.str());
  ASSERT_TRUE(project.has_value());
  ASSERT_TRUE(project.value().import(loaded, analysis.value()).has_value());
  ASSERT_TRUE(project.value().import(loaded, analysis.value()).has_value());

  auto images = project.value().images();
  ASSERT_TRUE(images.has_value());
  ASSERT_EQ(images.value().size(), 1U);
  EXPECT_EQ(images.value().front().functions, 2U);
}

TEST(Project, PersistsAnnotationsAcrossReopen) {
  TempPath path("annotations-persist");
  auto loaded = load_elf();
  auto analysis = donkey::analyze(loaded.image, loaded.data);
  ASSERT_TRUE(analysis.has_value());

  std::int64_t image_id = 0;
  {
    auto project = Project::create(path.str());
    ASSERT_TRUE(project.has_value());
    auto imported = project.value().import(loaded, analysis.value());
    ASSERT_TRUE(imported.has_value()) << imported.diagnostic().message;
    image_id = imported.value();

    auto rename = project.value().set_annotation(image_id, donkey::AnnotationKind::Rename, 0x400100,
                                                 "entry_point");
    ASSERT_TRUE(rename.has_value()) << rename.diagnostic().message;
    auto comment = project.value().set_annotation(image_id, donkey::AnnotationKind::Comment,
                                                  0x400104, "calls the helper");
    ASSERT_TRUE(comment.has_value()) << comment.diagnostic().message;
  }

  auto reopened = Project::open(path.str());
  ASSERT_TRUE(reopened.has_value()) << reopened.diagnostic().message;
  auto found = reopened.value().annotations(image_id);
  ASSERT_TRUE(found.has_value()) << found.diagnostic().message;
  ASSERT_EQ(found.value().size(), 2U);
  EXPECT_EQ(found.value()[0].kind, donkey::AnnotationKind::Rename);
  EXPECT_EQ(found.value()[0].address, 0x400100U);
  EXPECT_EQ(found.value()[0].text, "entry_point");
  EXPECT_EQ(found.value()[1].kind, donkey::AnnotationKind::Comment);
  EXPECT_EQ(found.value()[1].text, "calls the helper");

  auto images = reopened.value().images();
  ASSERT_TRUE(images.has_value());
  ASSERT_EQ(images.value().size(), 1U);
  EXPECT_EQ(images.value().front().annotations, 2U);
}

TEST(Project, AnnotationsSurviveReimportAndCanBeCleared) {
  TempPath path("annotations-reimport");
  auto loaded = load_elf();
  auto analysis = donkey::analyze(loaded.image, loaded.data);
  ASSERT_TRUE(analysis.has_value());

  auto project = Project::create(path.str());
  ASSERT_TRUE(project.has_value());
  auto imported = project.value().import(loaded, analysis.value());
  ASSERT_TRUE(imported.has_value());
  const std::int64_t image_id = imported.value();

  ASSERT_TRUE(project.value()
                  .set_annotation(image_id, donkey::AnnotationKind::Rename, 0x400100, "main")
                  .has_value());
  // Re-import replaces derived rows but must not drop user annotations.
  ASSERT_TRUE(project.value().import(loaded, analysis.value()).has_value());
  auto after = project.value().annotations(image_id);
  ASSERT_TRUE(after.has_value());
  ASSERT_EQ(after.value().size(), 1U);
  EXPECT_EQ(after.value().front().text, "main");

  // Empty text clears through set_annotation.
  ASSERT_TRUE(project.value()
                  .set_annotation(image_id, donkey::AnnotationKind::Rename, 0x400100, "")
                  .has_value());
  auto cleared = project.value().annotations(image_id);
  ASSERT_TRUE(cleared.has_value());
  EXPECT_TRUE(cleared.value().empty());

  // Clearing an absent annotation is still success.
  EXPECT_TRUE(project.value()
                  .clear_annotation(image_id, donkey::AnnotationKind::Comment, 0x400100)
                  .has_value());
}

TEST(Project, RejectsAnnotationsForMissingImageAndOverlongText) {
  TempPath path("annotations-invalid");
  auto project = Project::create(path.str());
  ASSERT_TRUE(project.has_value());

  auto missing = project.value().set_annotation(42, donkey::AnnotationKind::Rename, 0x1000, "x");
  ASSERT_FALSE(missing.has_value());
  EXPECT_EQ(missing.diagnostic().code, "project.image_not_found");

  auto loaded = load_elf();
  auto analysis = donkey::analyze(loaded.image, loaded.data);
  ASSERT_TRUE(analysis.has_value());
  auto imported = project.value().import(loaded, analysis.value());
  ASSERT_TRUE(imported.has_value());

  const std::string too_long(5000, 'x');
  auto overlong = project.value().set_annotation(imported.value(), donkey::AnnotationKind::Comment,
                                                 0x400100, too_long);
  ASSERT_FALSE(overlong.has_value());
  EXPECT_EQ(overlong.diagnostic().code, "project.annotation_too_long");
}

TEST(Project, MigratesVersionOneDatabaseForward) {
  TempPath path("migrate-v1");
  auto loaded = load_elf();
  auto analysis = donkey::analyze(loaded.image, loaded.data);
  ASSERT_TRUE(analysis.has_value());

  std::int64_t image_id = 0;
  {
    auto project = Project::create(path.str());
    ASSERT_TRUE(project.has_value());
    auto imported = project.value().import(loaded, analysis.value());
    ASSERT_TRUE(imported.has_value());
    image_id = imported.value();
  }

  // Turn the database back into a v1 project: drop the v2 table and reset the
  // version. Reopening must recreate annotations and keep existing images.
  {
    sqlite3* db = nullptr;
    ASSERT_EQ(sqlite3_open_v2(path.str().c_str(), &db, SQLITE_OPEN_READWRITE, nullptr), SQLITE_OK);
    ASSERT_EQ(sqlite3_exec(db, "DROP TABLE annotations", nullptr, nullptr, nullptr), SQLITE_OK);
    ASSERT_EQ(sqlite3_exec(db, "PRAGMA user_version=1", nullptr, nullptr, nullptr), SQLITE_OK);
    sqlite3_close(db);
  }

  auto reopened = Project::open(path.str());
  ASSERT_TRUE(reopened.has_value()) << reopened.diagnostic().message;
  EXPECT_EQ(reopened.value().schema_version(), 2);
  auto images = reopened.value().images();
  ASSERT_TRUE(images.has_value());
  ASSERT_EQ(images.value().size(), 1U);
  EXPECT_EQ(images.value().front().id, image_id);
  EXPECT_TRUE(reopened.value()
                  .set_annotation(image_id, donkey::AnnotationKind::Rename, 0x400100, "entry")
                  .has_value());
}

TEST(Project, FailedImportRollsBackEverything) {
  TempPath path("rollback");
  {
    auto loaded = load_elf();
    auto analysis = donkey::analyze(loaded.image, loaded.data);
    ASSERT_TRUE(analysis.has_value());

    // A section address that cannot be represented forces a failure after the
    // transaction has inserted the image row.
    loaded.image.sections.front().address = std::numeric_limits<std::uint64_t>::max();

    auto project = Project::create(path.str());
    ASSERT_TRUE(project.has_value());
    auto imported = project.value().import(loaded, analysis.value());
    ASSERT_FALSE(imported.has_value());
    EXPECT_EQ(imported.diagnostic().code, "project.value_out_of_range");

    auto images = project.value().images();
    ASSERT_TRUE(images.has_value());
    EXPECT_TRUE(images.value().empty());

    auto integrity = project.value().check_integrity();
    ASSERT_TRUE(integrity.has_value());
    EXPECT_TRUE(integrity.value());
  }
}

TEST(Project, RejectsCorruptDatabaseFile) {
  TempPath path("corrupt");
  {
    std::ofstream file(path.str(), std::ios::binary);
    file << "this is not a SQLite database";
  }
  auto project = Project::open(path.str());
  ASSERT_FALSE(project.has_value());
  EXPECT_EQ(project.diagnostic().status, donkey::Status::CorruptProject)
      << project.diagnostic().code << ": " << project.diagnostic().message;
}

TEST(Project, RejectsMissingDatabaseFile) {
  TempPath path("missing");
  auto project = Project::open(path.str());
  ASSERT_FALSE(project.has_value());
  EXPECT_EQ(project.diagnostic().code, "project.open_failed");
}

TEST(Project, RejectsNewerSchemaWithoutTouchingIt) {
  TempPath path("newer");
  {
    auto project = Project::create(path.str());
    ASSERT_TRUE(project.has_value());
  }

  sqlite3* raw = nullptr;
  ASSERT_EQ(sqlite3_open(path.str().c_str(), &raw), SQLITE_OK);
  ASSERT_EQ(sqlite3_exec(raw, "PRAGMA user_version=99", nullptr, nullptr, nullptr), SQLITE_OK);
  sqlite3_close(raw);

  auto project = Project::open(path.str());
  ASSERT_FALSE(project.has_value());
  EXPECT_EQ(project.diagnostic().code, "project.schema_too_new");
  EXPECT_EQ(project.diagnostic().status, donkey::Status::Unsupported);
}

}  // namespace
