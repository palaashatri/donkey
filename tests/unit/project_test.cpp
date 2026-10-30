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

TEST(Project, ReplaceAnnotationsRewritesSnapshotAtomically) {
  TempPath path("annotations-replace");
  auto loaded = load_elf();
  auto analysis = donkey::analyze(loaded.image, loaded.data);
  ASSERT_TRUE(analysis.has_value());

  auto project = Project::create(path.str());
  ASSERT_TRUE(project.has_value());
  auto imported = project.value().import(loaded, analysis.value());
  ASSERT_TRUE(imported.has_value());
  const std::int64_t image_id = imported.value();

  ASSERT_TRUE(project.value()
                  .set_annotation(image_id, donkey::AnnotationKind::Rename, 0x400100, "old")
                  .has_value());

  std::vector<donkey::Annotation> rows;
  rows.push_back(donkey::Annotation{donkey::AnnotationKind::Rename, 0x400109, "helper"});
  rows.push_back(donkey::Annotation{donkey::AnnotationKind::Comment, 0x400104, "called once"});
  ASSERT_TRUE(project.value().replace_annotations(image_id, rows).has_value());

  auto after = project.value().annotations(image_id);
  ASSERT_TRUE(after.has_value());
  ASSERT_EQ(after.value().size(), 2U);
  // Ordered by address, so the comment at 0x400104 comes before the rename.
  EXPECT_EQ(after.value()[0].kind, donkey::AnnotationKind::Comment);
  EXPECT_EQ(after.value()[0].address, 0x400104U);
  EXPECT_EQ(after.value()[1].address, 0x400109U);
  EXPECT_EQ(after.value()[1].text, "helper");

  // An empty snapshot clears every annotation.
  ASSERT_TRUE(project.value().replace_annotations(image_id, {}).has_value());
  auto emptied = project.value().annotations(image_id);
  ASSERT_TRUE(emptied.has_value());
  EXPECT_TRUE(emptied.value().empty());
}

TEST(Project, ReplaceAnnotationsRejectsMissingImageAndOverlongText) {
  TempPath path("annotations-replace-invalid");
  auto project = Project::create(path.str());
  ASSERT_TRUE(project.has_value());

  std::vector<donkey::Annotation> rows;
  rows.push_back(donkey::Annotation{donkey::AnnotationKind::Rename, 0x1000, "x"});
  auto missing = project.value().replace_annotations(7, rows);
  ASSERT_FALSE(missing.has_value());
  EXPECT_EQ(missing.diagnostic().code, "project.image_not_found");

  auto loaded = load_elf();
  auto analysis = donkey::analyze(loaded.image, loaded.data);
  ASSERT_TRUE(analysis.has_value());
  auto imported = project.value().import(loaded, analysis.value());
  ASSERT_TRUE(imported.has_value());

  std::vector<donkey::Annotation> too_long_rows;
  too_long_rows.push_back(
      donkey::Annotation{donkey::AnnotationKind::Comment, 0x400100, std::string(5000, 'x')});
  auto overlong = project.value().replace_annotations(imported.value(), too_long_rows);
  ASSERT_FALSE(overlong.has_value());
  EXPECT_EQ(overlong.diagnostic().code, "project.annotation_too_long");

  // The rejected call must not have cleared the existing snapshot.
  ASSERT_TRUE(
      project.value()
          .set_annotation(imported.value(), donkey::AnnotationKind::Rename, 0x400100, "entry")
          .has_value());
  auto rejected = project.value().replace_annotations(imported.value(), too_long_rows);
  ASSERT_FALSE(rejected.has_value());
  auto kept = project.value().annotations(imported.value());
  ASSERT_TRUE(kept.has_value());
  ASSERT_EQ(kept.value().size(), 1U);
  EXPECT_EQ(kept.value().front().text, "entry");
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
  EXPECT_EQ(reopened.value().schema_version(), 3);
  auto images = reopened.value().images();
  ASSERT_TRUE(images.has_value());
  ASSERT_EQ(images.value().size(), 1U);
  EXPECT_EQ(images.value().front().id, image_id);
  EXPECT_TRUE(reopened.value()
                  .set_annotation(image_id, donkey::AnnotationKind::Rename, 0x400100, "entry")
                  .has_value());
}

TEST(Project, MigratesVersionTwoDatabaseToVersionThree) {
  TempPath path("migrate-v2-v3");
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

    auto rename =
        project.value().set_annotation(image_id, donkey::AnnotationKind::Rename, 0x400100, "entry");
    ASSERT_TRUE(rename.has_value());
  }

  // Downgrade table to v2 constraint and version:
  {
    sqlite3* db = nullptr;
    ASSERT_EQ(sqlite3_open_v2(path.str().c_str(), &db, SQLITE_OPEN_READWRITE, nullptr), SQLITE_OK);
    ASSERT_EQ(sqlite3_exec(db, "ALTER TABLE annotations RENAME TO annotations_v3_temp", nullptr,
                           nullptr, nullptr),
              SQLITE_OK);
    const char* v2_schema =
        "CREATE TABLE annotations ("
        "  image_id   INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,"
        "  kind       TEXT    NOT NULL CHECK (kind IN ('rename', 'comment')),"
        "  address    INTEGER NOT NULL,"
        "  text       TEXT    NOT NULL,"
        "  updated_at TEXT    NOT NULL DEFAULT (datetime('now')),"
        "  PRIMARY KEY (image_id, kind, address)"
        ");";
    ASSERT_EQ(sqlite3_exec(db, v2_schema, nullptr, nullptr, nullptr), SQLITE_OK);
    ASSERT_EQ(sqlite3_exec(db, "INSERT INTO annotations SELECT * FROM annotations_v3_temp", nullptr,
                           nullptr, nullptr),
              SQLITE_OK);
    ASSERT_EQ(sqlite3_exec(db, "DROP TABLE annotations_v3_temp", nullptr, nullptr, nullptr),
              SQLITE_OK);
    ASSERT_EQ(sqlite3_exec(db, "PRAGMA user_version=2", nullptr, nullptr, nullptr), SQLITE_OK);
    sqlite3_close(db);
  }

  // Opening must migrate from v2 to v3, preserve existing annotations, and allow Bookmark
  auto reopened = Project::open(path.str());
  ASSERT_TRUE(reopened.has_value()) << reopened.diagnostic().message;
  EXPECT_EQ(reopened.value().schema_version(), 3);
  auto annotations = reopened.value().annotations(image_id);
  ASSERT_TRUE(annotations.has_value());
  ASSERT_EQ(annotations.value().size(), 1U);
  EXPECT_EQ(annotations.value()[0].kind, donkey::AnnotationKind::Rename);
  EXPECT_EQ(annotations.value()[0].text, "entry");

  // Adding a bookmark must succeed now in v3:
  auto bookmark = reopened.value().set_annotation(image_id, donkey::AnnotationKind::Bookmark,
                                                  0x400100, "entry_mark");
  ASSERT_TRUE(bookmark.has_value()) << bookmark.diagnostic().message;
  auto annotations_after = reopened.value().annotations(image_id);
  ASSERT_TRUE(annotations_after.has_value());
  ASSERT_EQ(annotations_after.value().size(), 2U);
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

TEST(Project, BacksUpAndRestoresAnnotations) {
  TempPath source("backup-source");
  TempPath destination("restore-destination");
  TempPath backup("backup-file");
  auto loaded = load_elf();
  auto analysis = donkey::analyze(loaded.image, loaded.data);
  ASSERT_TRUE(analysis.has_value()) << analysis.diagnostic().message;

  std::int64_t image_id = 0;
  {
    auto project = Project::create(source.str());
    ASSERT_TRUE(project.has_value()) << project.diagnostic().message;
    auto imported = project.value().import(loaded, analysis.value());
    ASSERT_TRUE(imported.has_value()) << imported.diagnostic().message;
    image_id = imported.value();
    auto set = project.value().set_annotation(image_id, donkey::AnnotationKind::Rename, 0x400100,
                                              "entry_point");
    ASSERT_TRUE(set.has_value()) << set.diagnostic().message;
  }

  {
    auto project = Project::open(source.str());
    ASSERT_TRUE(project.has_value()) << project.diagnostic().message;
    auto written = project.value().backup(backup.str());
    ASSERT_TRUE(written.has_value())
        << written.diagnostic().code << ": " << written.diagnostic().message;

    // Without --force an existing destination is preserved.
    auto refused = project.value().backup(backup.str());
    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(refused.diagnostic().code, "project.backup_exists");

    auto forced = project.value().backup(backup.str(), true);
    ASSERT_TRUE(forced.has_value()) << forced.diagnostic().message;
  }

  {
    auto project = Project::open(backup.str());
    ASSERT_TRUE(project.has_value()) << project.diagnostic().message;
    auto integrity = project.value().check_integrity();
    ASSERT_TRUE(integrity.has_value());
    EXPECT_TRUE(integrity.value());
    auto annotations = project.value().annotations(image_id);
    ASSERT_TRUE(annotations.has_value()) << annotations.diagnostic().message;
    ASSERT_EQ(annotations.value().size(), 1U);
    EXPECT_EQ(annotations.value().front().text, "entry_point");
  }

  // A destination with different annotations is overwritten by the backup.
  {
    auto project = Project::create(destination.str());
    ASSERT_TRUE(project.has_value()) << project.diagnostic().message;
    auto imported = project.value().import(loaded, analysis.value());
    ASSERT_TRUE(imported.has_value()) << imported.diagnostic().message;
    auto set = project.value().set_annotation(imported.value(), donkey::AnnotationKind::Comment,
                                              0x400100, "stale");
    ASSERT_TRUE(set.has_value()) << set.diagnostic().message;
  }
  auto restored = Project::restore(destination.str(), backup.str());
  ASSERT_TRUE(restored.has_value())
      << restored.diagnostic().code << ": " << restored.diagnostic().message;

  auto project = Project::open(destination.str());
  ASSERT_TRUE(project.has_value()) << project.diagnostic().message;
  auto integrity = project.value().check_integrity();
  ASSERT_TRUE(integrity.has_value());
  EXPECT_TRUE(integrity.value());
  auto annotations = project.value().annotations(image_id);
  ASSERT_TRUE(annotations.has_value()) << annotations.diagnostic().message;
  ASSERT_EQ(annotations.value().size(), 1U);
  EXPECT_EQ(annotations.value().front().kind, donkey::AnnotationKind::Rename);
  EXPECT_EQ(annotations.value().front().text, "entry_point");
}

TEST(Project, RestoreReplacesCorruptDestinationFile) {
  TempPath source("restore-corrupt-source");
  TempPath destination("restore-corrupt-destination");
  TempPath backup("restore-corrupt-backup");
  auto loaded = load_elf();
  auto analysis = donkey::analyze(loaded.image, loaded.data);
  ASSERT_TRUE(analysis.has_value()) << analysis.diagnostic().message;

  {
    auto project = Project::create(source.str());
    ASSERT_TRUE(project.has_value()) << project.diagnostic().message;
    auto imported = project.value().import(loaded, analysis.value());
    ASSERT_TRUE(imported.has_value()) << imported.diagnostic().message;
    auto written = project.value().backup(backup.str());
    ASSERT_TRUE(written.has_value()) << written.diagnostic().message;
  }

  {
    std::ofstream file(destination.str(), std::ios::binary | std::ios::trunc);
    file << "this is not a SQLite database";
  }

  auto restored = Project::restore(destination.str(), backup.str());
  ASSERT_TRUE(restored.has_value())
      << restored.diagnostic().code << ": " << restored.diagnostic().message;

  auto project = Project::open(destination.str());
  ASSERT_TRUE(project.has_value()) << project.diagnostic().message;
  auto images = project.value().images();
  ASSERT_TRUE(images.has_value()) << images.diagnostic().message;
  ASSERT_EQ(images.value().size(), 1U);
  EXPECT_EQ(images.value().front().sha256, loaded.image.sha256);
}

TEST(Project, RestoreRejectsInvalidBackups) {
  TempPath database("restore-invalid-db");
  TempPath garbage("restore-invalid-backup");
  TempPath newer("restore-newer-backup");

  auto missing = Project::restore(database.str(), garbage.str() + ".missing");
  ASSERT_FALSE(missing.has_value());
  EXPECT_EQ(missing.diagnostic().code, "project.backup_missing");

  {
    std::ofstream file(garbage.str(), std::ios::binary | std::ios::trunc);
    file << "this is not a SQLite database";
  }
  auto bad = Project::restore(database.str(), garbage.str());
  ASSERT_FALSE(bad.has_value());
  EXPECT_EQ(bad.diagnostic().status, donkey::Status::CorruptProject)
      << bad.diagnostic().code << ": " << bad.diagnostic().message;

  {
    auto project = Project::create(newer.str());
    ASSERT_TRUE(project.has_value()) << project.diagnostic().message;
  }
  sqlite3* raw = nullptr;
  ASSERT_EQ(sqlite3_open(newer.str().c_str(), &raw), SQLITE_OK);
  ASSERT_EQ(sqlite3_exec(raw, "PRAGMA user_version=99", nullptr, nullptr, nullptr), SQLITE_OK);
  sqlite3_close(raw);

  auto too_new = Project::restore(database.str(), newer.str());
  ASSERT_FALSE(too_new.has_value());
  EXPECT_EQ(too_new.diagnostic().status, donkey::Status::Unsupported);
  EXPECT_EQ(too_new.diagnostic().code, "project.backup_schema");
}

}  // namespace
