#include <gtest/gtest.h>
#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/project/cdecl.h"
#include "donkey/project/project.h"
#include "test_io.h"

namespace {

using donkey::AnalysisResult;
using donkey::LoadedBinary;
using donkey::Project;

std::string fixture_path(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/binaries/" + name;
}

std::uint64_t current_process_id() {
#if defined(_WIN32)
  return static_cast<std::uint64_t>(GetCurrentProcessId());
#else
  return static_cast<std::uint64_t>(getpid());
#endif
}

/// Unique database path that removes itself and its SQLite sidecars.
class TempPath {
 public:
  explicit TempPath(const std::string& name) {
    // CTest runs each test in its own process, possibly in parallel, so the
    // name must be unique across processes, not only within one.
    static std::uint64_t counter = 0;
    const auto unique = std::to_string(current_process_id()) + "-" +
                        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    path_ = std::filesystem::temp_directory_path() /
            ("donkey-" + name + "-" + unique + "-" + std::to_string(++counter) + ".db");
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
    ASSERT_EQ(
        sqlite3_exec(
            db,
            "DROP TABLE IF EXISTS type_applications; DROP TABLE IF EXISTS type_enumerators; DROP "
            "TABLE IF EXISTS type_fields; DROP TABLE IF EXISTS types; DROP TABLE IF EXISTS "
            "local_names; PRAGMA user_version=1",
            nullptr, nullptr, nullptr),
        SQLITE_OK);
    sqlite3_close(db);
  }

  auto reopened = Project::open(path.str());
  ASSERT_TRUE(reopened.has_value()) << reopened.diagnostic().message;
  EXPECT_EQ(reopened.value().schema_version(), donkey::kProjectSchemaVersion);
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
    ASSERT_EQ(
        sqlite3_exec(
            db,
            "DROP TABLE IF EXISTS type_applications; DROP TABLE IF EXISTS type_enumerators; DROP "
            "TABLE IF EXISTS type_fields; DROP TABLE IF EXISTS types; DROP TABLE IF EXISTS "
            "local_names; PRAGMA user_version=2",
            nullptr, nullptr, nullptr),
        SQLITE_OK);
    sqlite3_close(db);
  }

  // Opening must migrate from v2 to v3, preserve existing annotations, and allow Bookmark
  auto reopened = Project::open(path.str());
  ASSERT_TRUE(reopened.has_value()) << reopened.diagnostic().message;
  EXPECT_EQ(reopened.value().schema_version(), donkey::kProjectSchemaVersion);
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

TEST(Project, RestoreHonorsCancellationBeforeReplacingDatabase) {
  TempPath source("restore-cancel-source");
  TempPath destination("restore-cancel-destination");
  TempPath backup("restore-cancel-backup");
  auto loaded = load_elf();
  auto analysis = donkey::analyze(loaded.image, loaded.data);
  ASSERT_TRUE(analysis.has_value());

  {
    auto project = Project::create(source.str());
    ASSERT_TRUE(project.has_value());
    ASSERT_TRUE(project.value().import(loaded, analysis.value()).has_value());
    ASSERT_TRUE(project.value().backup(backup.str()).has_value());
  }

  {
    std::ofstream file(destination.str(), std::ios::binary | std::ios::trunc);
    file << "original destination content";
  }

  donkey::CancellationToken token;
  token.cancel();

  auto restored = Project::restore(destination.str(), backup.str(), token);
  ASSERT_FALSE(restored.has_value());
  EXPECT_EQ(restored.diagnostic().code, "io.cancelled");

  std::ifstream check(destination.str());
  std::string content;
  std::getline(check, content);
  EXPECT_EQ(content, "original destination content");

  EXPECT_FALSE(std::filesystem::exists(destination.str() + ".restore-tmp"));
}

// Covers only the restore path's cleanup when its commit step fails; the real
// replacement routine is exercised by the Replace* tests below.
TEST(Project, RestoreRemovesTemporaryCopyWhenCommitHookFails) {
  TempPath source("restore-fail-source");
  TempPath destination("restore-fail-destination");
  TempPath backup("restore-fail-backup");
  auto loaded = load_elf();
  auto analysis = donkey::analyze(loaded.image, loaded.data);
  ASSERT_TRUE(analysis.has_value());

  {
    auto project = Project::create(source.str());
    ASSERT_TRUE(project.has_value());
    ASSERT_TRUE(project.value().import(loaded, analysis.value()).has_value());
    ASSERT_TRUE(project.value().backup(backup.str()).has_value());
  }

  const std::string orig_db_content = "original destination database content";
  const std::string orig_wal_content = "original wal sidecar content";
  const std::string orig_shm_content = "original shm sidecar content";

  {
    std::ofstream db_file(destination.str(), std::ios::binary | std::ios::trunc);
    db_file << orig_db_content;
    std::ofstream wal_file(destination.str() + "-wal", std::ios::binary | std::ios::trunc);
    wal_file << orig_wal_content;
    std::ofstream shm_file(destination.str() + "-shm", std::ios::binary | std::ios::trunc);
    shm_file << orig_shm_content;
  }

  // Inject failure at commit phase
  auto failing_commit = [](const std::string&, const std::string&) -> donkey::Result<void> {
    return donkey::make_error<void>(donkey::Status::InternalError, "injected.commit_failure",
                                    "injected filesystem failure during commit");
  };

  auto restored = Project::restore(destination.str(), backup.str(), {}, failing_commit);
  ASSERT_FALSE(restored.has_value());
  EXPECT_EQ(restored.diagnostic().code, "injected.commit_failure");

  // Verify byte-for-byte preservation of original database and sidecars
  {
    std::ifstream check_db(destination.str());
    std::string content;
    std::getline(check_db, content);
    EXPECT_EQ(content, orig_db_content);

    std::ifstream check_wal(destination.str() + "-wal");
    std::getline(check_wal, content);
    EXPECT_EQ(content, orig_wal_content);

    std::ifstream check_shm(destination.str() + "-shm");
    std::getline(check_shm, content);
    EXPECT_EQ(content, orig_shm_content);
  }

  EXPECT_FALSE(std::filesystem::exists(destination.str() + ".restore-tmp"));

  std::error_code ec;
  std::filesystem::remove(destination.str() + "-wal", ec);
  std::filesystem::remove(destination.str() + "-shm", ec);
}

// ---------------------------------------------------------------------------
// Real replacement routine: exclusivity, sidecars and interruption.
// ---------------------------------------------------------------------------

using donkey::Annotation;
using donkey::AnnotationKind;
using donkey::ReplaceStage;

[[maybe_unused]] std::uintmax_t file_size_or_zero(const std::string& path) {
  std::error_code ec;
  const auto size = std::filesystem::file_size(path, ec);
  return ec ? 0 : size;
}

std::string read_bytes(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  return donkey_test::read_stream<std::string>(in);
}

/// Create a project at `path` holding the ELF fixture and one comment.
std::int64_t make_project(const std::string& path, const std::string& comment) {
  auto loaded = load_elf();
  auto analysis = donkey::analyze(loaded.image, loaded.data);
  EXPECT_TRUE(analysis.has_value());
  auto project = Project::create(path);
  EXPECT_TRUE(project.has_value());
  auto id = project.value().import(loaded, analysis.value());
  EXPECT_TRUE(id.has_value());
  EXPECT_TRUE(project.value()
                  .replace_annotations(id.value(), {{AnnotationKind::Comment, 0x10, comment}})
                  .has_value());
  return id.value();
}

/// All annotation texts of the single image, sorted, or {"<unreadable>"}.
std::vector<std::string> annotation_texts(const std::string& path) {
  auto project = Project::open(path);
  if (!project) {
    return {"<unreadable: " + project.diagnostic().code + ">"};
  }
  auto integrity = project.value().check_integrity();
  if (!integrity || !integrity.value()) {
    return {"<integrity failure>"};
  }
  auto images = project.value().images();
  if (!images || images.value().size() != 1) {
    return {"<bad image count>"};
  }
  auto annotations = project.value().annotations(images.value().front().id);
  if (!annotations) {
    return {"<no annotations>"};
  }
  std::vector<std::string> texts;
  for (const Annotation& annotation : annotations.value()) {
    texts.push_back(annotation.text);
  }
  std::sort(texts.begin(), texts.end());
  return texts;
}

#if !defined(_WIN32)
/// Commit one more annotation and kill the process before the connection is
/// closed, so the committed transaction exists only in `path`-wal.
void commit_into_wal_and_die(const std::string& path, std::int64_t image_id,
                             const std::string& comment, const std::string& wal_comment) {
  const pid_t child = fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    auto project = Project::open(path);
    if (!project) {
      _exit(2);
    }
    const bool ok =
        project.value()
            .replace_annotations(image_id, {{AnnotationKind::Comment, 0x10, comment},
                                            {AnnotationKind::Comment, 0x20, wal_comment}})
            .has_value();
    _exit(ok ? 0 : 3);
  }
  int status = 0;
  ASSERT_EQ(waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  ASSERT_EQ(WEXITSTATUS(status), 0);
}
#endif

TEST(Project, ReplaceRefusesWhileAnotherConnectionIsOpen) {
  TempPath destination("replace-busy-destination");
  TempPath replacement("replace-busy-replacement");
  make_project(destination.str(), "old");
  make_project(replacement.str(), "new");

  auto holder = Project::open(destination.str());
  ASSERT_TRUE(holder.has_value());
  auto replaced = Project::replace_file_atomically(replacement.str(), destination.str());
  ASSERT_FALSE(replaced.has_value());
  EXPECT_EQ(replaced.diagnostic().code, "project.replace_busy") << replaced.diagnostic().message;
  EXPECT_TRUE(std::filesystem::exists(replacement.str()));
  holder = donkey::make_error<Project>(donkey::Status::InvalidInput, "closed", "closed");

  EXPECT_EQ(annotation_texts(destination.str()), std::vector<std::string>{"old"});
}

TEST(Project, ReplaceKeepsUnreadableDatabaseThatHasAWal) {
  TempPath destination("replace-garbage-destination");
  TempPath replacement("replace-garbage-replacement");
  make_project(replacement.str(), "new");
  {
    std::ofstream db(destination.str(), std::ios::binary | std::ios::trunc);
    db << "not a database";
    std::ofstream wal(destination.str() + "-wal", std::ios::binary | std::ios::trunc);
    wal << "not a wal";
  }
  auto replaced = Project::replace_file_atomically(replacement.str(), destination.str());
  ASSERT_FALSE(replaced.has_value());
  EXPECT_EQ(read_bytes(destination.str()), "not a database");
  EXPECT_EQ(read_bytes(destination.str() + "-wal"), "not a wal");
}

TEST(Project, ReplaceFoldsCommittedWalBeforeSwappingFiles) {
#if defined(_WIN32)
  GTEST_SKIP() << "needs fork() to leave committed frames in a WAL";
#else
  TempPath destination("replace-wal-destination");
  TempPath backup("replace-wal-backup");
  const auto id = make_project(destination.str(), "old");
  make_project(backup.str(), "new");
  commit_into_wal_and_die(destination.str(), id, "old", "old-in-wal");
  ASSERT_GT(file_size_or_zero(destination.str() + "-wal"), 0U);

  auto restored = Project::restore(destination.str(), backup.str());
  ASSERT_TRUE(restored.has_value()) << restored.diagnostic().message;
  EXPECT_FALSE(std::filesystem::exists(destination.str() + "-wal"));
  EXPECT_EQ(annotation_texts(destination.str()), std::vector<std::string>{"new"});
#endif
}

/// Run a restore of `backup` over `destination` that dies at `stage`. On POSIX
/// the restore runs in a forked child that calls _exit() at the boundary, so
/// no destructor or cleanup runs; elsewhere the hook aborts the routine.
void interrupted_restore(const std::string& destination, const std::string& backup,
                         ReplaceStage stage) {
#if !defined(_WIN32)
  const pid_t child = fork();
  ASSERT_GE(child, 0);
  if (child == 0) {
    Project::set_replace_fault_hook_for_testing([stage](ReplaceStage at) {
      if (at == stage) {
        _exit(0);
      }
      return false;
    });
    (void)Project::restore(destination, backup);
    _exit(1);  // The fault point was never reached.
  }
  int status = 0;
  ASSERT_EQ(waitpid(child, &status, 0), child);
  ASSERT_TRUE(WIFEXITED(status));
  ASSERT_EQ(WEXITSTATUS(status), 0) << "fault point not reached";
#else
  Project::set_replace_fault_hook_for_testing([stage](ReplaceStage at) { return at == stage; });
  auto restored = Project::restore(destination, backup);
  Project::set_replace_fault_hook_for_testing({});
  ASSERT_FALSE(restored.has_value());
  EXPECT_EQ(restored.diagnostic().code, "project.replace_interrupted");
#endif
}

class InterruptedReplace : public ::testing::TestWithParam<ReplaceStage> {};

TEST_P(InterruptedReplace, LeavesEitherCompleteOldOrCompleteNewDatabase) {
  const ReplaceStage stage = GetParam();
  TempPath destination("interrupt-destination");
  TempPath backup("interrupt-backup");
  const auto id = make_project(destination.str(), "old");
  make_project(backup.str(), "new");
  const std::string backup_bytes = read_bytes(backup.str());

  std::vector<std::string> expected_old{"old"};
#if !defined(_WIN32)
  // The old database's newest committed transaction lives only in its WAL.
  commit_into_wal_and_die(destination.str(), id, "old", "old-in-wal");
  ASSERT_GT(file_size_or_zero(destination.str() + "-wal"), 0U);
  expected_old = {"old", "old-in-wal"};
#else
  (void)id;
#endif

  interrupted_restore(destination.str(), backup.str(), stage);

  // "Restart": a fresh open must see one complete database.
  const auto texts = annotation_texts(destination.str());
  if (stage == ReplaceStage::Renamed) {
    EXPECT_EQ(texts, std::vector<std::string>{"new"});
  } else {
    EXPECT_EQ(texts, expected_old);
  }
  // The backup itself is never touched, and a retry completes the restore.
  EXPECT_EQ(read_bytes(backup.str()), backup_bytes);
  auto retried = Project::restore(destination.str(), backup.str());
  ASSERT_TRUE(retried.has_value()) << retried.diagnostic().message;
  EXPECT_EQ(annotation_texts(destination.str()), std::vector<std::string>{"new"});
  EXPECT_FALSE(std::filesystem::exists(destination.str() + ".restore-tmp"));
}

INSTANTIATE_TEST_SUITE_P(Stages, InterruptedReplace,
                         ::testing::Values(ReplaceStage::Quiesced, ReplaceStage::Synced,
                                           ReplaceStage::Renamed));

TEST(Project, BackupRefusesToOverwriteItsOwnDatabase) {
  TempPath path("backup-self");
  make_project(path.str(), "keep");
  const std::string before = read_bytes(path.str());
  {
    auto project = Project::open(path.str());
    ASSERT_TRUE(project.has_value());
    for (const bool overwrite : {false, true}) {
      auto same = project.value().backup(path.str(), overwrite);
      ASSERT_FALSE(same.has_value());
      EXPECT_EQ(same.diagnostic().code, "project.backup_is_source");
    }
    const std::filesystem::path p(path.str());
    auto dotted = project.value().backup((p.parent_path() / "." / p.filename()).string(), true);
    ASSERT_FALSE(dotted.has_value());
    EXPECT_EQ(dotted.diagnostic().code, "project.backup_is_source");

    std::error_code ec;
    const std::string hard = path.str() + ".hardlink";
    std::filesystem::create_hard_link(path.str(), hard, ec);
    if (!ec) {
      auto linked = project.value().backup(hard, true);
      ASSERT_FALSE(linked.has_value());
      EXPECT_EQ(linked.diagnostic().code, "project.backup_is_source");
      std::filesystem::remove(hard, ec);
    }
    const std::string sym = path.str() + ".symlink";
    std::filesystem::create_symlink(path.str(), sym, ec);
    if (!ec) {
      auto linked = project.value().backup(sym, true);
      ASSERT_FALSE(linked.has_value());
      EXPECT_EQ(linked.diagnostic().code, "project.backup_is_source");
      std::filesystem::remove(sym, ec);
    }
  }
  EXPECT_EQ(annotation_texts(path.str()), std::vector<std::string>{"keep"});
}

TEST(Project, RestoreChecksCancellationBeforeCreatingTemporaryCopy) {
  TempPath destination("restore-early-cancel");
  TempPath backup("restore-early-cancel-backup");
  make_project(destination.str(), "old");
  make_project(backup.str(), "new");
  donkey::CancellationToken token;
  token.cancel();
  bool hook_called = false;
  auto restored = Project::restore(destination.str(), backup.str(), token,
                                   [&](const std::string&, const std::string&) {
                                     hook_called = true;
                                     return donkey::Result<void>();
                                   });
  ASSERT_FALSE(restored.has_value());
  EXPECT_EQ(restored.diagnostic().code, "io.cancelled");
  EXPECT_FALSE(hook_called);
  EXPECT_FALSE(std::filesystem::exists(destination.str() + ".restore-tmp"));
}

TEST(Project, MigratesSchemaV3AnnotationsToV4AndAcceptsFunctionEdits) {
  TempPath path("migrate-v3");
  const std::int64_t image_id = make_project(path.str(), "kept");
  // Recreate the exact v3 annotations table (narrower CHECK) with a row.
  {
    sqlite3* db = nullptr;
    ASSERT_EQ(sqlite3_open_v2(path.str().c_str(), &db, SQLITE_OPEN_READWRITE, nullptr), SQLITE_OK);
    ASSERT_EQ(
        sqlite3_exec(
            db,
            "DROP TABLE annotations;"
            "CREATE TABLE annotations ("
            "  image_id INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,"
            "  kind TEXT NOT NULL CHECK (kind IN ('rename', 'comment', 'bookmark')),"
            "  address INTEGER NOT NULL, text TEXT NOT NULL,"
            "  updated_at TEXT NOT NULL DEFAULT (datetime('now')),"
            "  PRIMARY KEY (image_id, kind, address));"
            "INSERT INTO annotations(image_id, kind, address, text) "
            "  VALUES (1, 'comment', 16, 'kept'), (1, 'bookmark', 32, 'mark');"
            "DROP TABLE IF EXISTS type_applications; DROP TABLE IF EXISTS type_enumerators; DROP "
            "TABLE IF EXISTS type_fields; DROP TABLE IF EXISTS types; DROP TABLE IF EXISTS "
            "local_names; PRAGMA user_version=3;",
            nullptr, nullptr, nullptr),
        SQLITE_OK);
    // The old constraint really rejects the new kind.
    EXPECT_NE(sqlite3_exec(db,
                           "INSERT INTO annotations(image_id, kind, address, text) "
                           "VALUES (1, 'function', 48, 'define')",
                           nullptr, nullptr, nullptr),
              SQLITE_OK);
    sqlite3_close(db);
  }
  {
    auto project = Project::open(path.str());
    ASSERT_TRUE(project.has_value()) << project.diagnostic().message;
    EXPECT_EQ(project.value().schema_version(), 7);
    auto stored = project.value().annotations(image_id);
    ASSERT_TRUE(stored.has_value());
    ASSERT_EQ(stored.value().size(), 2U);
    ASSERT_TRUE(
        project.value()
            .replace_annotations(image_id, {{AnnotationKind::Comment, 16, "kept"},
                                            {AnnotationKind::FunctionStart, 0x1060, "define"}})
            .has_value());
    auto integrity = project.value().check_integrity();
    ASSERT_TRUE(integrity.has_value());
    EXPECT_TRUE(integrity.value());
  }
  auto reopened = Project::open(path.str());
  ASSERT_TRUE(reopened.has_value());
  auto stored = reopened.value().annotations(image_id);
  ASSERT_TRUE(stored.has_value());
  bool found = false;
  for (const Annotation& annotation : stored.value()) {
    if (annotation.kind == AnnotationKind::FunctionStart) {
      EXPECT_EQ(annotation.address, 0x1060U);
      EXPECT_EQ(annotation.text, "define");
      found = true;
    }
  }
  EXPECT_TRUE(found);
}

// ---- Types (G05-T1) ---------------------------------------------------------

namespace {

donkey::TypeDefinition scalar(donkey::TypeId id, donkey::TypeKind kind, const char* name,
                              std::uint64_t size, bool is_signed = false) {
  donkey::TypeDefinition definition;
  definition.id = id;
  definition.kind = kind;
  definition.name = name;
  definition.size = size;
  definition.is_signed = is_signed;
  return definition;
}

donkey::TypeDefinition record(donkey::TypeId id, donkey::TypeKind kind, const char* name,
                              std::uint64_t size, std::vector<donkey::TypeField> fields) {
  donkey::TypeDefinition definition = scalar(id, kind, name, size);
  definition.fields = std::move(fields);
  return definition;
}

donkey::TypeField member(const char* name, std::uint64_t offset, donkey::TypeId type) {
  donkey::TypeField field;
  field.name = name;
  field.offset = offset;
  field.type = type;
  return field;
}

}  // namespace

TEST(Types, RoundTripThroughTheProject) {
  TempPath path("types-round-trip");
  auto loaded = load_elf();
  auto analysis = donkey::analyze(loaded.image, loaded.data);
  ASSERT_TRUE(analysis.has_value());

  const donkey::TypeId int32(1);
  const donkey::TypeId point(2);
  const donkey::TypeId point_pointer(3);
  const donkey::TypeId color(4);
  donkey::TypeTable table;
  table.put(scalar(int32, donkey::TypeKind::Integer, "int", 4, true));
  table.put(record(point, donkey::TypeKind::Struct, "point", 8,
                   {member("x", 0, int32), member("y", 4, int32)}));
  donkey::TypeDefinition pointer = scalar(point_pointer, donkey::TypeKind::Pointer, "", 8);
  pointer.target = point;
  table.put(std::move(pointer));
  donkey::TypeDefinition colour = scalar(color, donkey::TypeKind::Enum, "color", 4);
  colour.enumerators = {donkey::TypeEnumerator{"RED", 0}, donkey::TypeEnumerator{"GREEN", 1}};
  table.put(std::move(colour));
  const donkey::TypeId function(5);
  donkey::TypeDefinition signature = scalar(function, donkey::TypeKind::Function, "", 0);
  signature.target = int32;
  table.put(std::move(signature));

  std::int64_t image_id = 0;
  {
    auto project = Project::create(path.str());
    ASSERT_TRUE(project.has_value());
    auto imported = project.value().import(loaded, analysis.value());
    ASSERT_TRUE(imported.has_value());
    image_id = imported.value();
    ASSERT_TRUE(project.value().replace_types(table).has_value());
    ASSERT_TRUE(project.value()
                    .set_type_application(image_id, donkey::TypeApplicationKind::FunctionPrototype,
                                          0x400100, function)
                    .has_value());
  }

  auto reopened = Project::open(path.str());
  ASSERT_TRUE(reopened.has_value()) << reopened.diagnostic().message;
  auto stored = reopened.value().types();
  ASSERT_TRUE(stored.has_value()) << stored.diagnostic().message;
  ASSERT_EQ(stored.value().size(), 5U);
  const donkey::TypeDefinition* read_point = stored.value().find(point);
  ASSERT_NE(read_point, nullptr);
  EXPECT_EQ(read_point->name, "point");
  ASSERT_EQ(read_point->fields.size(), 2U);
  EXPECT_EQ(read_point->fields[1].name, "y");
  EXPECT_EQ(read_point->fields[1].offset, 4U);
  EXPECT_EQ(read_point->fields[1].type, int32);
  const donkey::TypeDefinition* read_color = stored.value().find(color);
  ASSERT_NE(read_color, nullptr);
  ASSERT_EQ(read_color->enumerators.size(), 2U);
  EXPECT_EQ(read_color->enumerators[1].name, "GREEN");
  EXPECT_EQ(read_color->enumerators[1].value, 1);
  EXPECT_EQ(stored.value().find(point_pointer)->target, point);
  EXPECT_TRUE(stored.value().validate().has_value());

  auto applications = reopened.value().type_applications(image_id);
  ASSERT_TRUE(applications.has_value());
  ASSERT_EQ(applications.value().size(), 1U);
  EXPECT_EQ(applications.value()[0].address, 0x400100U);
  EXPECT_EQ(applications.value()[0].type_id, function);
  EXPECT_EQ(applications.value()[0].type_id, function);
}

TEST(Types, MigratesFromSchemaV4) {
  TempPath path("types-migrate-v4");
  {
    auto project = Project::create(path.str());
    ASSERT_TRUE(project.has_value());
    EXPECT_EQ(project.value().schema_version(), 7);
  }
  // A v4 project has no type tables; drop them and set the version back to 4.
  {
    sqlite3* db = nullptr;
    ASSERT_EQ(sqlite3_open_v2(path.str().c_str(), &db, SQLITE_OPEN_READWRITE, nullptr), SQLITE_OK);
    ASSERT_EQ(sqlite3_exec(db,
                           "DROP TABLE type_applications; DROP TABLE type_enumerators; "
                           "DROP TABLE type_fields; DROP TABLE types; DROP TABLE IF EXISTS "
                           "local_names; PRAGMA user_version=4;",
                           nullptr, nullptr, nullptr),
              SQLITE_OK);
    sqlite3_close(db);
  }
  auto reopened = Project::open(path.str());
  ASSERT_TRUE(reopened.has_value()) << reopened.diagnostic().message;
  EXPECT_EQ(reopened.value().schema_version(), 7);
  auto empty = reopened.value().types();
  ASSERT_TRUE(empty.has_value());
  EXPECT_EQ(empty.value().size(), 0U);
  // The migrated project accepts type writes.
  donkey::TypeTable table;
  table.put(scalar(donkey::TypeId(1), donkey::TypeKind::Integer, "int", 4, true));
  EXPECT_TRUE(reopened.value().replace_types(table).has_value());
}

TEST(Types, RejectsCyclesWithoutPointer) {
  // A struct that holds itself by value has no size.
  donkey::TypeTable direct;
  direct.put(record(donkey::TypeId(1), donkey::TypeKind::Struct, "self", 8,
                    {member("next", 0, donkey::TypeId(1))}));
  auto refused = direct.validate();
  ASSERT_FALSE(refused.has_value());
  EXPECT_EQ(refused.diagnostic().code, "type.contains_itself");

  // Two structs that hold each other by value.
  donkey::TypeTable mutual;
  mutual.put(record(donkey::TypeId(1), donkey::TypeKind::Struct, "a", 8,
                    {member("b", 0, donkey::TypeId(2))}));
  mutual.put(record(donkey::TypeId(2), donkey::TypeKind::Struct, "b", 8,
                    {member("a", 0, donkey::TypeId(1))}));
  EXPECT_EQ(mutual.validate().diagnostic().code, "type.contains_itself");

  // The same shape through a pointer is a list, and is allowed.
  donkey::TypeTable linked;
  linked.put(record(donkey::TypeId(1), donkey::TypeKind::Struct, "node", 16,
                    {member("value", 0, donkey::TypeId(2)), member("next", 8, donkey::TypeId(3))}));
  linked.put(scalar(donkey::TypeId(2), donkey::TypeKind::Integer, "long", 8, true));
  donkey::TypeDefinition next = scalar(donkey::TypeId(3), donkey::TypeKind::Pointer, "", 8);
  next.target = donkey::TypeId(1);
  linked.put(std::move(next));
  EXPECT_TRUE(linked.validate().has_value());
}

TEST(Types, SizeAndAlignmentFollowTheAbi) {
  const donkey::TypeId c_char(1);
  const donkey::TypeId c_int(2);
  donkey::TypeTable table;
  table.put(scalar(c_char, donkey::TypeKind::Integer, "char", 1, true));
  table.put(scalar(c_int, donkey::TypeKind::Integer, "int", 4, true));

  // struct { char c; int i; }: the int sits at 4, so the struct is 8 bytes, aligned to 4.
  table.put(record(donkey::TypeId(3), donkey::TypeKind::Struct, "pair", 8,
                   {member("c", 0, c_char), member("i", 4, c_int)}));
  EXPECT_EQ(table.size_of(donkey::TypeId(3)).value(), 8U);
  EXPECT_EQ(table.alignment_of(donkey::TypeId(3)).value(), 4U);

  // An array of three of them: 24 bytes, still aligned to 4.
  donkey::TypeDefinition array = scalar(donkey::TypeId(4), donkey::TypeKind::Array, "", 0);
  array.target = donkey::TypeId(3);
  array.count = 3;
  table.put(std::move(array));
  EXPECT_EQ(table.size_of(donkey::TypeId(4)).value(), 24U);
  EXPECT_EQ(table.alignment_of(donkey::TypeId(4)).value(), 4U);

  // A union is as large as its largest member, and every member sits at 0.
  donkey::TypeTable unions = table;
  unions.put(record(donkey::TypeId(5), donkey::TypeKind::Union, "either", 4,
                    {member("c", 0, c_char), member("i", 0, c_int)}));
  EXPECT_EQ(unions.size_of(donkey::TypeId(5)).value(), 4U);

  // A stored size that is not the padded end of the members is refused.
  donkey::TypeTable wrong = table;
  wrong.put(record(donkey::TypeId(6), donkey::TypeKind::Struct, "short", 5,
                   {member("c", 0, c_char), member("i", 4, c_int)}));
  EXPECT_EQ(wrong.validate().diagnostic().code, "type.size_mismatch");

  // An int at offset 2 is misaligned.
  donkey::TypeTable misaligned = table;
  misaligned.put(record(donkey::TypeId(7), donkey::TypeKind::Struct, "gap", 8,
                        {member("c", 0, c_char), member("i", 2, c_int)}));
  EXPECT_EQ(misaligned.validate().diagnostic().code, "type.misaligned_field");

  // Integers, pointers and enums have ABI sizes only.
  donkey::TypeTable sizes;
  sizes.put(scalar(donkey::TypeId(1), donkey::TypeKind::Integer, "int24", 3, true));
  EXPECT_EQ(sizes.validate().diagnostic().code, "type.bad_integer_size");
  donkey::TypeTable pointers;
  pointers.put(scalar(donkey::TypeId(1), donkey::TypeKind::Pointer, "", 6));
  EXPECT_EQ(pointers.validate().diagnostic().code, "type.bad_pointer_size");

  // A function has no size by value.
  donkey::TypeTable functions;
  donkey::TypeDefinition function = scalar(donkey::TypeId(1), donkey::TypeKind::Function, "", 0);
  functions.put(std::move(function));
  EXPECT_FALSE(functions.size_of(donkey::TypeId(1)).has_value());
}

namespace {

const donkey::TypeDefinition* named_type(const std::vector<donkey::TypeDefinition>& types,
                                         const std::string& name) {
  for (const donkey::TypeDefinition& type : types) {
    if (type.name == name) {
      return &type;
    }
  }
  return nullptr;
}

const donkey::TypeDefinition* type_by_id(const std::vector<donkey::TypeDefinition>& types,
                                         donkey::TypeId id) {
  for (const donkey::TypeDefinition& type : types) {
    if (type.id == id) {
      return &type;
    }
  }
  return nullptr;
}

/// Parses `text` and checks that it is refused with `code`, and that the message
/// begins with `location` (for example "line 1, column 18: ").
void expect_located_error(std::string_view text, const char* code, std::string_view location) {
  const auto result = donkey::parse_c_declarations(text, donkey::TypeTable{});
  ASSERT_FALSE(result.has_value()) << text;
  EXPECT_EQ(result.diagnostic().code, code) << text;
  EXPECT_TRUE(std::string_view(result.diagnostic().message).starts_with(location))
      << result.diagnostic().message;
}

}  // namespace

TEST(Types, ParsesCDeclarations) {
  const char* text = R"(
typedef unsigned char u8;
struct point { int32_t x; int32_t y; };
struct record { uint8_t tag; struct point at; double weight; char name[5]; };
union value { uint32_t word; float real; };
enum mode { MODE_A, MODE_B = 4, MODE_C };
typedef struct { uint16_t lo, hi; } pair;
struct list { struct list *next; int count; };
int64_t sum(const struct point *points, size_t count, ...);
void reset(void);
)";
  const auto parsed = donkey::parse_c_declarations(text, donkey::TypeTable{});
  ASSERT_TRUE(parsed.has_value()) << parsed.diagnostic().message;
  const std::vector<donkey::TypeDefinition>& types = parsed.value();

  // Ids start where the empty table left off, one per declared type.
  ASSERT_FALSE(types.empty());
  EXPECT_EQ(types.front().id.value(), 1U);
  EXPECT_EQ(types.front().provenance, donkey::TypeProvenance::User);

  // struct point: two int32_t members.
  const auto* point = named_type(types, "point");
  ASSERT_NE(point, nullptr);
  EXPECT_EQ(point->kind, donkey::TypeKind::Struct);
  EXPECT_EQ(point->size, 8U);
  ASSERT_EQ(point->fields.size(), 2U);
  EXPECT_EQ(point->fields[1].offset, 4U);

  // struct record: tag at 0, the point at 4 (align 4), weight at 16 (align 8), name at
  // 24. The members end at 29, padded to 32 for the 8-byte alignment of the double.
  const auto* record = named_type(types, "record");
  ASSERT_NE(record, nullptr);
  EXPECT_EQ(record->size, 32U);
  ASSERT_EQ(record->fields.size(), 4U);
  EXPECT_EQ(record->fields[1].offset, 4U);
  EXPECT_EQ(record->fields[2].offset, 16U);
  EXPECT_EQ(record->fields[3].offset, 24U);

  const auto* value = named_type(types, "value");
  ASSERT_NE(value, nullptr);
  EXPECT_EQ(value->kind, donkey::TypeKind::Union);
  EXPECT_EQ(value->size, 4U);
  EXPECT_EQ(value->fields[1].offset, 0U);

  const auto* mode = named_type(types, "mode");
  ASSERT_NE(mode, nullptr);
  EXPECT_EQ(mode->kind, donkey::TypeKind::Enum);
  ASSERT_EQ(mode->enumerators.size(), 3U);
  EXPECT_EQ(mode->enumerators[1].value, 4);
  EXPECT_EQ(mode->enumerators[2].value, 5);

  // An untagged struct takes the typedef's name.
  const auto* pair = named_type(types, "pair");
  ASSERT_NE(pair, nullptr);
  EXPECT_EQ(pair->kind, donkey::TypeKind::Struct);
  EXPECT_EQ(pair->size, 4U);
  ASSERT_EQ(pair->fields.size(), 2U);
  EXPECT_EQ(pair->fields[1].offset, 2U);

  // A pointer to the struct being defined refers back to it.
  const auto* list = named_type(types, "list");
  ASSERT_NE(list, nullptr);
  EXPECT_EQ(list->size, 16U);
  const auto* next = type_by_id(types, list->fields[0].type);
  ASSERT_NE(next, nullptr);
  EXPECT_EQ(next->kind, donkey::TypeKind::Pointer);
  EXPECT_EQ(next->target, list->id);

  // A prototype: a variadic function of a struct pointer and a size_t, returning
  // int64_t. A void return has no target.
  const auto* sum = named_type(types, "sum");
  ASSERT_NE(sum, nullptr);
  EXPECT_EQ(sum->kind, donkey::TypeKind::Function);
  EXPECT_TRUE(sum->variadic);
  ASSERT_EQ(sum->fields.size(), 2U);
  const auto* returned = type_by_id(types, sum->target);
  ASSERT_NE(returned, nullptr);
  EXPECT_EQ(returned->name, "int64_t");
  EXPECT_EQ(returned->size, 8U);
  EXPECT_TRUE(returned->is_signed);
  const auto* first_parameter = type_by_id(types, sum->fields[0].type);
  ASSERT_NE(first_parameter, nullptr);
  EXPECT_EQ(first_parameter->kind, donkey::TypeKind::Pointer);
  EXPECT_EQ(first_parameter->target, point->id);
  const auto* reset = named_type(types, "reset");
  ASSERT_NE(reset, nullptr);
  EXPECT_FALSE(reset->variadic);
  EXPECT_TRUE(reset->fields.empty());
  EXPECT_EQ(type_by_id(types, reset->target), nullptr);

  // The whole result passes the type store's checks.
  donkey::TypeTable table;
  for (const donkey::TypeDefinition& type : types) {
    table.put(type);
  }
  EXPECT_TRUE(table.validate().has_value());

  // A second parse sees the first one's types. The int32_t it needs is reused, not
  // declared again.
  donkey::TypeTable known = table;
  const auto second = donkey::parse_c_declarations(
      "typedef struct point point_t; struct pair2 { point_t p; int32_t extra; };", known);
  ASSERT_TRUE(second.has_value()) << second.diagnostic().message;
  const auto* pair2 = named_type(second.value(), "pair2");
  ASSERT_NE(pair2, nullptr);
  EXPECT_EQ(pair2->size, 12U);
  EXPECT_EQ(named_type(second.value(), "int32_t"), nullptr);

  // The ILP32 model: 4-byte pointers and long, and an unsigned plain char.
  donkey::CDeclarationOptions ilp32;
  ilp32.pointer_size = 4;
  ilp32.long_size = 4;
  ilp32.char_is_signed = false;
  const auto narrow = donkey::parse_c_declarations("struct s { long a; char *p; char c; };",
                                                   donkey::TypeTable{}, ilp32);
  ASSERT_TRUE(narrow.has_value()) << narrow.diagnostic().message;
  const auto* s = named_type(narrow.value(), "s");
  ASSERT_NE(s, nullptr);
  EXPECT_EQ(s->size, 12U);
  EXPECT_EQ(s->fields[1].offset, 4U);
  const auto* plain_char = type_by_id(narrow.value(), s->fields[2].type);
  ASSERT_NE(plain_char, nullptr);
  EXPECT_FALSE(plain_char->is_signed);
}

TEST(Types, ParserErrorsAreLocated) {
  expect_located_error("struct s { int x }", "cdecl.unexpected_token", "line 1, column 18: ");
  expect_located_error("typedef int T;\n  #define X 1\n", "cdecl.preprocessor",
                       "line 2, column 3: ");
  expect_located_error("/* abc\n  def", "cdecl.unterminated_comment", "line 1, column 1: ");
  expect_located_error("typedef int T $;", "cdecl.bad_character", "line 1, column 15: ");
  expect_located_error("foo x;", "cdecl.unknown_type", "line 1, column 1: ");
  expect_located_error("struct s { int a[]; };", "cdecl.array_size_required",
                       "line 1, column 17: ");
  expect_located_error("struct s { int a : 3; };", "cdecl.bitfield_unsupported",
                       "line 1, column 18: ");
  expect_located_error("struct s { int a; }; struct s { int b; };", "cdecl.redefinition",
                       "line 1, column 29: ");
  expect_located_error("struct s {", "cdecl.unexpected_token", "line 1, column 11: ");
  expect_located_error("struct list2 { struct nope n; };", "cdecl.incomplete_type",
                       "line 1, column 28: ");
  expect_located_error("enum e { A = 3000000000 };", "cdecl.enum_value_range",
                       "line 1, column 14: ");
  expect_located_error("typedef char c[99999999999999999999];", "cdecl.number_too_large",
                       "line 1, column 16: ");
  expect_located_error(std::string("typedef int ") + std::string(65, '*') + "p;", "cdecl.nesting",
                       "line 1, column 77: ");
  // An array of arrays whose total size does not fit in 64 bits is refused by the
  // type store's whole-table check.
  expect_located_error("typedef long long huge[9223372036854775807][4];", "cdecl.invalid_type", "");

  const std::string huge(donkey::kMaxCDeclarationBytes + 1, ' ');
  const auto too_large = donkey::parse_c_declarations(huge, donkey::TypeTable{});
  ASSERT_FALSE(too_large.has_value());
  EXPECT_EQ(too_large.diagnostic().status, donkey::Status::ResourceLimit);
  EXPECT_EQ(too_large.diagnostic().code, "cdecl.too_large");

  donkey::CDeclarationOptions bad;
  bad.pointer_size = 3;
  const auto refused = donkey::parse_c_declarations("int x;", donkey::TypeTable{}, bad);
  ASSERT_FALSE(refused.has_value());
  EXPECT_EQ(refused.diagnostic().code, "cdecl.bad_options");
}

TEST(Types, DwarfStructsMatchTheirByteSize) {
  auto loaded = donkey::load_binary(DONKEY_TEST_DEBUGGEE_PATH);
  ASSERT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  auto info = donkey::read_debug_info(loaded.value().image, loaded.value().data);
  if (!info && info.diagnostic().code == "dwarf.not_present") {
    GTEST_SKIP() << "the toolchain put no DWARF in the debuggee";
  }
  ASSERT_TRUE(info.has_value()) << info.diagnostic().code;
  const donkey::TypeTable table = donkey::types_from_debug_info(info.value());
  const auto valid = table.validate();
  std::size_t checked = 0;
  // Every struct and union the reader found, with its size, so that a failure says what was read.
  std::string seen;
  for (const auto& [offset, source] : info.value().types) {
    if (source.kind != donkey::DebugTypeKind::Struct &&
        source.kind != donkey::DebugTypeKind::Union) {
      continue;
    }
    seen += " " + source.name + "(" + std::to_string(source.byte_size) + ")";
    if (source.byte_size == 0) {
      continue;  // a declaration only: no size to compare
    }
    const donkey::TypeId id(offset + 1);
    auto size = table.size_of(id);
    ASSERT_TRUE(size.has_value()) << source.name << ": " << size.diagnostic().message;
    EXPECT_EQ(size.value(), source.byte_size) << source.name;
    ++checked;
  }
  EXPECT_GT(checked, 0U) << "the debuggee has structs to check; " << info.value().types.size()
                         << " debug types were read; struct and union sizes seen:" << seen;
}

}  // namespace

// The DataRange text is "<element size>:<count>", canonical and bounded: no signs, no leading
// zeros, sizes 0, 1, 2, 4 or 8, and at most 16 MiB covered.
TEST(Project, DataRangeTextIsCanonicalAndBounded) {
  std::uint64_t element_size = 0;
  std::uint64_t count = 0;
  EXPECT_TRUE(donkey::parse_data_range_text("0:1", element_size, count));
  EXPECT_EQ(element_size, 0U);
  EXPECT_EQ(count, 1U);
  EXPECT_TRUE(donkey::parse_data_range_text("8:2097152", element_size, count));
  EXPECT_EQ(element_size, 8U);
  EXPECT_EQ(count, 2097152U);
  EXPECT_EQ(donkey::format_data_range_text(8, 2097152), "8:2097152");
  EXPECT_EQ(donkey::format_data_range_text(0, 5), "0:5");
  for (const char* bad : {"", "3:2", "1:0", "1:", ":4", "01:4", "+1:4", "1:-4", "1 :4", "1:4:5",
                          "8:2097153", "0:16777217", "16:1", "1:99999999999999999999"}) {
    EXPECT_FALSE(donkey::parse_data_range_text(bad, element_size, count)) << bad;
  }
}

// G12-T1: a code start and data ranges are stored, come back in order after a reopen, and text
// that does not fit the kind is refused with a code, never stored.
// G12-T2: a string is a DataRange whose text is "string:<bytes>", the terminator included. It is
// read as an array of one-byte elements, and it is stored and read back like any other range.
// A string of zero bytes, a bad number, or a size past the limit is refused.
TEST(Project, ParsesAndStoresStringRangesAndRefusesBadStringText) {
  std::uint64_t element_size = 9;
  std::uint64_t count = 9;
  donkey::StringEncoding encoding = donkey::StringEncoding::None;
  EXPECT_TRUE(donkey::parse_data_extent("string:12", element_size, count, encoding));
  EXPECT_EQ(encoding, donkey::StringEncoding::Bytes);
  EXPECT_EQ(element_size, 1U);
  EXPECT_EQ(count, 12U);
  EXPECT_TRUE(donkey::parse_data_extent("4:16", element_size, count, encoding));
  EXPECT_EQ(encoding, donkey::StringEncoding::None);
  EXPECT_EQ(element_size, 4U);
  EXPECT_EQ(count, 16U);
  EXPECT_EQ(donkey::format_string_range_text(12), "string:12");
  for (const char* bad : {"string:0", "string:", "string:01", "string:-1", "string:17000000",
                          "string:1x", "string"}) {
    EXPECT_FALSE(donkey::parse_data_extent(bad, element_size, count, encoding)) << bad;
  }

  // G12-T2: "string16:<bytes>" is UTF-16LE with its two-byte terminator. It reads as 2-byte
  // elements, so analysis treats it as an array of code units. The byte count must be even and
  // at least 2, and within the same bound as every data range.
  EXPECT_TRUE(donkey::parse_data_extent("string16:14", element_size, count, encoding));
  EXPECT_EQ(encoding, donkey::StringEncoding::Utf16Le);
  EXPECT_EQ(element_size, 2U);
  EXPECT_EQ(count, 7U);
  EXPECT_TRUE(donkey::parse_data_extent("string16:2", element_size, count, encoding));
  EXPECT_EQ(count, 1U);
  EXPECT_TRUE(donkey::parse_data_extent("string16:16777216", element_size, count, encoding));
  EXPECT_EQ(donkey::format_utf16_range_text(14), "string16:14");
  for (const char* bad : {"string16:0", "string16:", "string16:3", "string16:15", "string16:x",
                          "string16:16777218", "string16:-2"}) {
    EXPECT_FALSE(donkey::parse_data_extent(bad, element_size, count, encoding)) << bad;
  }

  TempPath path("string-kind");
  const std::int64_t image_id = make_project(path.str(), "kept");
  auto project = Project::open(path.str());
  ASSERT_TRUE(project.has_value()) << project.diagnostic().message;
  EXPECT_TRUE(
      project.value()
          .set_annotation(image_id, donkey::AnnotationKind::DataRange, 0x400180, "string:12")
          .has_value());
  EXPECT_FALSE(
      project.value()
          .set_annotation(image_id, donkey::AnnotationKind::DataRange, 0x400190, "string:0")
          .has_value());
  auto reopened = Project::open(path.str());
  ASSERT_TRUE(reopened.has_value()) << reopened.diagnostic().message;
  auto rows = reopened.value().annotations(image_id);
  ASSERT_TRUE(rows.has_value()) << rows.diagnostic().message;
  EXPECT_NE(std::find_if(rows.value().begin(), rows.value().end(),
                         [](const donkey::Annotation& row) {
                           return row.address == 0x400180 && row.text == "string:12";
                         }),
            rows.value().end());
}

TEST(Project, StoresCodeStartsAndDataRangesAndRefusesOtherText) {
  TempPath path("code-data-kinds");
  const std::int64_t image_id = make_project(path.str(), "kept");
  auto project = Project::open(path.str());
  ASSERT_TRUE(project.has_value()) << project.diagnostic().message;

  EXPECT_TRUE(project.value()
                  .set_annotation(image_id, donkey::AnnotationKind::CodeStart, 0x400109, "code")
                  .has_value());
  EXPECT_TRUE(project.value()
                  .set_annotation(image_id, donkey::AnnotationKind::DataRange, 0x40010c, "1:4")
                  .has_value());
  EXPECT_TRUE(project.value()
                  .set_annotation(image_id, donkey::AnnotationKind::DataRange, 0x400200, "0:8")
                  .has_value());

  const std::pair<donkey::AnnotationKind, const char*> refused[] = {
      {donkey::AnnotationKind::CodeStart, "yes"},
      {donkey::AnnotationKind::DataRange, "3:2"},
      {donkey::AnnotationKind::DataRange, "8:2097153"},
  };
  for (const auto& [kind, text] : refused) {
    auto result = project.value().set_annotation(image_id, kind, 0x400300, text);
    ASSERT_FALSE(result.has_value()) << text;
    EXPECT_EQ(result.diagnostic().code, "project.annotation_text_invalid") << text;
  }

  // A batch with one bad row is refused as a whole, so the good row is not written either.
  const std::vector<donkey::Annotation> batch{
      {donkey::AnnotationKind::CodeStart, 0x400500, "code"},
      {donkey::AnnotationKind::DataRange, 0x400504, "4:0"},
  };
  auto replaced = project.value().replace_annotations(image_id, batch);
  ASSERT_FALSE(replaced.has_value());
  EXPECT_EQ(replaced.diagnostic().code, "project.annotation_text_invalid");

  auto reopened = Project::open(path.str());
  ASSERT_TRUE(reopened.has_value()) << reopened.diagnostic().message;
  auto rows = reopened.value().annotations(image_id);
  ASSERT_TRUE(rows.has_value()) << rows.diagnostic().message;
  std::vector<std::string> seen;
  for (const donkey::Annotation& row : rows.value()) {
    seen.push_back(std::string(donkey::annotation_kind_name(row.kind)) + "@" +
                   std::to_string(row.address) + "=" + row.text);
  }
  // The helper stores its own comment at 0x10; the three below are the ones this test added.
  EXPECT_EQ(seen.size(), 4U);
  EXPECT_NE(std::find(seen.begin(), seen.end(), "comment@16=kept"), seen.end());
  EXPECT_NE(std::find(seen.begin(), seen.end(), "code@4194569=code"), seen.end());
  EXPECT_NE(std::find(seen.begin(), seen.end(), "data@4194572=1:4"), seen.end());
  EXPECT_NE(std::find(seen.begin(), seen.end(), "data@4194816=0:8"), seen.end());
}

// A flexible array member is the last member of a struct and adds no size: its element sets the
// alignment, and the struct ends where the members before it end. Anywhere else it is refused.
TEST(Types, FlexibleArrayMembersAddNoSize) {
  donkey::TypeTable table;
  table.put(scalar(donkey::TypeId(1), donkey::TypeKind::Integer, "char", 1, true));
  table.put(scalar(donkey::TypeId(2), donkey::TypeKind::Integer, "int", 4, true));
  donkey::TypeDefinition open = scalar(donkey::TypeId(3), donkey::TypeKind::Array, "", 0);
  open.target = donkey::TypeId(2);
  open.count_known = false;
  table.put(std::move(open));

  // struct { int n; int data[]; }: 4 bytes, aligned to 4.
  donkey::TypeTable counted = table;
  counted.put(record(donkey::TypeId(4), donkey::TypeKind::Struct, "counted", 4,
                     {member("n", 0, donkey::TypeId(2)), member("data", 4, donkey::TypeId(3))}));
  EXPECT_TRUE(counted.validate().has_value());
  EXPECT_EQ(counted.size_of(donkey::TypeId(4)).value(), 4U);
  EXPECT_EQ(counted.alignment_of(donkey::TypeId(4)).value(), 4U);

  // struct { char c; int data[]; } with the array at 2 is misaligned for its int elements.
  donkey::TypeTable misaligned = table;
  misaligned.put(record(donkey::TypeId(5), donkey::TypeKind::Struct, "gap", 4,
                        {member("c", 0, donkey::TypeId(1)), member("data", 2, donkey::TypeId(3))}));
  EXPECT_EQ(misaligned.validate().diagnostic().code, "type.misaligned_field");

  // The flexible array must be the last member.
  donkey::TypeTable middle = table;
  middle.put(record(donkey::TypeId(6), donkey::TypeKind::Struct, "middle", 8,
                    {member("data", 0, donkey::TypeId(3)), member("n", 4, donkey::TypeId(2))}));
  EXPECT_EQ(middle.validate().diagnostic().code, "type.flexible_member_not_last");

  // Alone, the array of unknown bound is not a type with a size; it validates, and asking for its
  // size fails. As the element of a complete array it is refused by value.
  EXPECT_TRUE(table.validate().has_value());
  const auto size = table.size_of(donkey::TypeId(3));
  ASSERT_FALSE(size.has_value());
  EXPECT_EQ(size.diagnostic().code, "type.incomplete_array");
  donkey::TypeTable nested = table;
  donkey::TypeDefinition outer = scalar(donkey::TypeId(7), donkey::TypeKind::Array, "", 0);
  outer.target = donkey::TypeId(3);
  outer.count = 2;
  nested.put(std::move(outer));
  EXPECT_EQ(nested.validate().diagnostic().code, "type.incomplete_array");
}

// A scalar may be aligned to less than its size, as an eight-byte integer is in a 32-bit unit. The
// alignment must be a power of two, and no larger than the size.
TEST(Types, ScalarAlignmentIsAtMostItsSize) {
  donkey::TypeTable table;
  table.put(scalar(donkey::TypeId(1), donkey::TypeKind::Integer, "char", 1, true));
  donkey::TypeDefinition wide =
      scalar(donkey::TypeId(2), donkey::TypeKind::Integer, "long long", 8, true);
  wide.alignment = 4;
  table.put(std::move(wide));
  // struct { char c; long long x; } with x at 4: 12 bytes, aligned to 4.
  table.put(record(donkey::TypeId(3), donkey::TypeKind::Struct, "pair", 12,
                   {member("c", 0, donkey::TypeId(1)), member("x", 4, donkey::TypeId(2))}));
  EXPECT_TRUE(table.validate().has_value());
  EXPECT_EQ(table.alignment_of(donkey::TypeId(2)).value(), 4U);
  EXPECT_EQ(table.size_of(donkey::TypeId(3)).value(), 12U);
  EXPECT_EQ(table.alignment_of(donkey::TypeId(3)).value(), 4U);

  donkey::TypeTable above = table;
  donkey::TypeDefinition too_aligned =
      scalar(donkey::TypeId(4), donkey::TypeKind::Integer, "int", 4, true);
  too_aligned.alignment = 8;
  above.put(std::move(too_aligned));
  EXPECT_EQ(above.validate().diagnostic().code, "type.bad_alignment");

  donkey::TypeTable odd = table;
  donkey::TypeDefinition three =
      scalar(donkey::TypeId(4), donkey::TypeKind::Integer, "int", 4, true);
  three.alignment = 3;
  odd.put(std::move(three));
  EXPECT_EQ(odd.validate().diagnostic().code, "type.bad_alignment");
}

// DWARF gives an array with no bound the flag that makes it a flexible array member, and a zero
// bound stays a complete array of no elements. An eight-byte base type keeps its alignment of four.
TEST(Types, DwarfUnboundedArraysAndAlignmentsCarryThrough) {
  donkey::DebugInfo info;
  donkey::DebugType int_type;
  int_type.kind = donkey::DebugTypeKind::Base;
  int_type.name = "int";
  int_type.byte_size = 4;
  int_type.encoding = 5;
  info.types[0x10] = int_type;
  donkey::DebugType wide;
  wide.kind = donkey::DebugTypeKind::Base;
  wide.name = "long long";
  wide.byte_size = 8;
  wide.encoding = 5;
  wide.alignment = 4;
  info.types[0x18] = wide;
  donkey::DebugType open;
  open.kind = donkey::DebugTypeKind::Array;
  open.target = 0x10;
  open.bound_known = false;
  info.types[0x20] = open;
  donkey::DebugType empty;
  empty.kind = donkey::DebugTypeKind::Array;
  empty.target = 0x10;
  info.types[0x28] = empty;

  const donkey::TypeTable table = donkey::types_from_debug_info(info);
  const donkey::TypeDefinition* flexible = table.find(donkey::TypeId(0x21));
  ASSERT_NE(flexible, nullptr);
  EXPECT_FALSE(flexible->count_known);
  const donkey::TypeDefinition* zero_length = table.find(donkey::TypeId(0x29));
  ASSERT_NE(zero_length, nullptr);
  EXPECT_TRUE(zero_length->count_known);
  EXPECT_EQ(zero_length->count, 0U);
  ASSERT_NE(table.find(donkey::TypeId(0x19)), nullptr);
  EXPECT_EQ(table.find(donkey::TypeId(0x19))->alignment, 4U);
  EXPECT_TRUE(table.validate().has_value());
}

// The unknown bound and the alignment are stored, so a reopened project gives the same layout.
TEST(Types, FlexibleArraysAndScalarAlignmentsSurviveTheProject) {
  TempPath path("types-flexible");
  auto loaded = load_elf();
  auto analysis = donkey::analyze(loaded.image, loaded.data);
  ASSERT_TRUE(analysis.has_value());

  const donkey::TypeId int32(1);
  const donkey::TypeId wide(2);
  const donkey::TypeId flexible(3);
  const donkey::TypeId counted(4);
  donkey::TypeTable table;
  table.put(scalar(int32, donkey::TypeKind::Integer, "int", 4, true));
  donkey::TypeDefinition eight = scalar(wide, donkey::TypeKind::Integer, "long long", 8, true);
  eight.alignment = 4;
  table.put(std::move(eight));
  donkey::TypeDefinition open = scalar(flexible, donkey::TypeKind::Array, "", 0);
  open.target = int32;
  open.count_known = false;
  table.put(std::move(open));
  table.put(record(counted, donkey::TypeKind::Struct, "counted", 4,
                   {member("n", 0, int32), member("data", 4, flexible)}));

  {
    auto project = Project::create(path.str());
    ASSERT_TRUE(project.has_value());
    auto imported = project.value().import(loaded, analysis.value());
    ASSERT_TRUE(imported.has_value());
    ASSERT_TRUE(project.value().replace_types(table).has_value());
  }

  auto reopened = Project::open(path.str());
  ASSERT_TRUE(reopened.has_value()) << reopened.diagnostic().message;
  auto stored = reopened.value().types();
  ASSERT_TRUE(stored.has_value()) << stored.diagnostic().message;
  const donkey::TypeDefinition* read_open = stored.value().find(flexible);
  ASSERT_NE(read_open, nullptr);
  EXPECT_FALSE(read_open->count_known);
  ASSERT_NE(stored.value().find(wide), nullptr);
  EXPECT_EQ(stored.value().find(wide)->alignment, 4U);
  EXPECT_EQ(stored.value().alignment_of(counted).value(), 4U);
  EXPECT_TRUE(stored.value().validate().has_value());
}

// The formal parameters of a DWARF subroutine type come through as the function's fields, with
// their types, so a prototype read from DWARF keeps its signature.
TEST(Types, DwarfSubroutineTypesKeepTheirParameters) {
  donkey::DebugInfo info;
  donkey::DebugType int_type;
  int_type.kind = donkey::DebugTypeKind::Base;
  int_type.name = "int";
  int_type.byte_size = 4;
  int_type.encoding = 5;
  info.types[0x10] = int_type;
  donkey::DebugType signature;
  signature.kind = donkey::DebugTypeKind::Function;
  signature.target = 0x10;
  signature.members = {donkey::DebugMember{"a", 0x10, 0}, donkey::DebugMember{"b", 0x10, 0}};
  info.types[0x20] = signature;
  const donkey::TypeTable table = donkey::types_from_debug_info(info);
  const donkey::TypeDefinition* function = table.find(donkey::TypeId(0x21));
  ASSERT_NE(function, nullptr);
  ASSERT_EQ(function->fields.size(), 2U);
  EXPECT_EQ(function->fields[1].name, "b");
  EXPECT_EQ(function->fields[1].type, donkey::TypeId(0x11));
  EXPECT_TRUE(table.names_function(donkey::TypeId(0x21)));
  EXPECT_FALSE(table.names_function(donkey::TypeId(0x11)));
}

// The v5 fixture was saved by the v5 build (tests/fixtures/projects/PROVENANCE.md): one image with
// a rename, a comment and a bookmark at 0x400109. Opening it must migrate to v6, keep all three,
// and accept the new kinds.
TEST(Project, MigratesSchemaV5AnnotationsToV6AndKeepsThem) {
  TempPath path("migrate-v5");
  std::error_code copy_error;
  std::filesystem::copy_file(std::string(DONKEY_FIXTURE_DIR) + "/projects/schema-v5.db", path.str(),
                             std::filesystem::copy_options::overwrite_existing, copy_error);
  ASSERT_FALSE(copy_error) << copy_error.message();

  auto project = Project::open(path.str());
  ASSERT_TRUE(project.has_value()) << project.diagnostic().message;
  EXPECT_EQ(project.value().schema_version(), 7);
  auto images = project.value().images();
  ASSERT_TRUE(images.has_value());
  ASSERT_EQ(images.value().size(), 1U);
  const std::int64_t image_id = images.value()[0].id;

  auto kept = project.value().annotations(image_id);
  ASSERT_TRUE(kept.has_value()) << kept.diagnostic().message;
  ASSERT_EQ(kept.value().size(), 3U);
  bool rename = false;
  bool comment = false;
  bool bookmark = false;
  for (const donkey::Annotation& row : kept.value()) {
    rename = rename || (row.kind == donkey::AnnotationKind::Rename && row.text == "entry_main");
    comment =
        comment || (row.kind == donkey::AnnotationKind::Comment && row.text == "reviewed in v5");
    bookmark = bookmark || (row.kind == donkey::AnnotationKind::Bookmark && row.text == "keep");
  }
  EXPECT_TRUE(rename && comment && bookmark);

  // The rebuilt table accepts the new kinds, and they survive a reopen.
  ASSERT_TRUE(project.value()
                  .set_annotation(image_id, donkey::AnnotationKind::CodeStart, 0x400109, "code")
                  .has_value());
  ASSERT_TRUE(project.value()
                  .set_annotation(image_id, donkey::AnnotationKind::DataRange, 0x40010c, "1:4")
                  .has_value());
  auto reopened = Project::open(path.str());
  ASSERT_TRUE(reopened.has_value()) << reopened.diagnostic().message;
  EXPECT_EQ(reopened.value().schema_version(), 7);
  auto rows = reopened.value().annotations(image_id);
  ASSERT_TRUE(rows.has_value());
  EXPECT_EQ(rows.value().size(), 5U);
}

// Version 7 adds the local_names table and nothing else. A version 6 database is therefore one
// without that table, and opening it must add the table and keep every annotation.
TEST(Project, MigratesVersionSixDatabaseToVersionSevenAndKeepsItsAnnotations) {
  TempPath path("migrate-v6-v7");
  std::error_code copy_error;
  std::filesystem::copy_file(std::string(DONKEY_FIXTURE_DIR) + "/projects/schema-v5.db", path.str(),
                             std::filesystem::copy_options::overwrite_existing, copy_error);
  ASSERT_FALSE(copy_error) << copy_error.message();

  std::int64_t image_id = 0;
  {
    auto project = Project::open(path.str());
    ASSERT_TRUE(project.has_value()) << project.diagnostic().message;
    EXPECT_EQ(project.value().schema_version(), 7);
    auto images = project.value().images();
    ASSERT_TRUE(images.has_value());
    ASSERT_EQ(images.value().size(), 1U);
    image_id = images.value()[0].id;
  }

  // Make the file a version 6 database again.
  {
    sqlite3* raw = nullptr;
    ASSERT_EQ(sqlite3_open_v2(path.str().c_str(), &raw, SQLITE_OPEN_READWRITE, nullptr), SQLITE_OK);
    ASSERT_EQ(sqlite3_exec(raw, "DROP TABLE local_names; PRAGMA user_version=6", nullptr, nullptr,
                           nullptr),
              SQLITE_OK);
    sqlite3_close(raw);
  }

  auto migrated = Project::open(path.str());
  ASSERT_TRUE(migrated.has_value()) << migrated.diagnostic().message;
  EXPECT_EQ(migrated.value().schema_version(), 7);
  auto rows = migrated.value().annotations(image_id);
  ASSERT_TRUE(rows.has_value());
  EXPECT_EQ(rows.value().size(), 3U);
  auto names = migrated.value().local_names(image_id);
  ASSERT_TRUE(names.has_value()) << names.diagnostic().message;
  EXPECT_TRUE(names.value().empty());
  EXPECT_TRUE(
      migrated.value().set_local_name(image_id, 0x400100, "frame:rbp:-8", "total").has_value());
}

TEST(Project, StoresLocalNamesAndRefusesBadKeysAndNames) {
  TempPath path("local-names");
  std::error_code copy_error;
  std::filesystem::copy_file(std::string(DONKEY_FIXTURE_DIR) + "/projects/schema-v5.db", path.str(),
                             std::filesystem::copy_options::overwrite_existing, copy_error);
  ASSERT_FALSE(copy_error) << copy_error.message();
  auto project = Project::open(path.str());
  ASSERT_TRUE(project.has_value()) << project.diagnostic().message;
  auto images = project.value().images();
  ASSERT_TRUE(images.has_value());
  const std::int64_t image_id = images.value()[0].id;

  ASSERT_TRUE(
      project.value().set_local_name(image_id, 0x400100, "frame:rbp:-8", "total").has_value());
  ASSERT_TRUE(project.value().set_local_name(image_id, 0x400100, "arg:0", "count").has_value());
  // A later name for the same key replaces the first.
  ASSERT_TRUE(project.value().set_local_name(image_id, 0x400100, "arg:0", "items").has_value());

  for (const char* variable : {"arg:", "arg:x", "arg:1024", "frame:rbp", "frame:rbp:08",
                               "frame:rbp:-0", "frame::8", "frame:r-p:8", "local:1"}) {
    EXPECT_FALSE(project.value().set_local_name(image_id, 0x400100, variable, "name").has_value())
        << variable;
    EXPECT_FALSE(donkey::local_variable_key_valid(variable)) << variable;
  }
  for (const char* name : {"1x", "a b", "a-b"}) {
    const auto refused = project.value().set_local_name(image_id, 0x400100, "arg:0", name);
    ASSERT_FALSE(refused.has_value()) << name;
    EXPECT_EQ(refused.diagnostic().code, "project.local_name_invalid");
  }
  const std::string too_long(129, 'a');
  EXPECT_FALSE(project.value().set_local_name(image_id, 0x400100, "arg:0", too_long).has_value());
  EXPECT_TRUE(donkey::local_variable_key_valid("frame:rsp:-1048576"));
  EXPECT_TRUE(donkey::local_variable_key_valid("arg:0"));

  const auto unknown_image = project.value().set_local_name(999, 0x400100, "arg:0", "x");
  ASSERT_FALSE(unknown_image.has_value());
  EXPECT_EQ(unknown_image.diagnostic().code, "project.image_not_found");
  EXPECT_FALSE(project.value().set_local_name(image_id, ~0ULL, "arg:0", "x").has_value());

  auto listed = project.value().local_names(image_id);
  ASSERT_TRUE(listed.has_value()) << listed.diagnostic().message;
  ASSERT_EQ(listed.value().size(), 2U);
  EXPECT_EQ(listed.value()[0].variable, "arg:0");
  EXPECT_EQ(listed.value()[0].name, "items");
  EXPECT_EQ(listed.value()[1].variable, "frame:rbp:-8");
  EXPECT_EQ(listed.value()[1].name, "total");

  // An empty name clears the entry; clearing an absent one succeeds.
  ASSERT_TRUE(project.value().set_local_name(image_id, 0x400100, "arg:0", "").has_value());
  ASSERT_TRUE(project.value().set_local_name(image_id, 0x400100, "arg:0", "").has_value());

  // The names survive a reopen.
  project = Project::open(path.str());
  ASSERT_TRUE(project.has_value()) << project.diagnostic().message;
  auto reopened = project.value().local_names(image_id);
  ASSERT_TRUE(reopened.has_value());
  ASSERT_EQ(reopened.value().size(), 1U);
  EXPECT_EQ(reopened.value()[0].variable, "frame:rbp:-8");
  EXPECT_EQ(reopened.value()[0].function_address, 0x400100U);
}

// G12-T3: the session saves its whole set of local names at once. The replacement is complete and
// atomic: a repeated (function, key) pair is refused, and the names already stored stay.
TEST(Project, ReplacesEveryLocalNameAtOnceAndKeepsThePreviousSetWhenRefused) {
  TempPath path("replace-local-names");
  std::error_code copy_error;
  std::filesystem::copy_file(std::string(DONKEY_FIXTURE_DIR) + "/projects/schema-v5.db", path.str(),
                             std::filesystem::copy_options::overwrite_existing, copy_error);
  ASSERT_FALSE(copy_error) << copy_error.message();
  auto project = Project::open(path.str());
  ASSERT_TRUE(project.has_value()) << project.diagnostic().message;
  auto images = project.value().images();
  ASSERT_TRUE(images.has_value());
  const std::int64_t image_id = images.value()[0].id;

  ASSERT_TRUE(
      project.value()
          .replace_local_names(image_id, {donkey::LocalName{0x400100, "arg:0", "count"},
                                          donkey::LocalName{0x400100, "frame:rbp:-8", "total"}})
          .has_value());
  auto first = project.value().local_names(image_id);
  ASSERT_TRUE(first.has_value());
  EXPECT_EQ(first.value().size(), 2U);

  // A second set replaces the first entirely: the entry not repeated is gone.
  ASSERT_TRUE(project.value()
                  .replace_local_names(image_id, {donkey::LocalName{0x400100, "arg:0", "items"}})
                  .has_value());
  auto second = project.value().local_names(image_id);
  ASSERT_TRUE(second.has_value());
  ASSERT_EQ(second.value().size(), 1U);
  EXPECT_EQ(second.value()[0].name, "items");

  // A repeated pair is refused, and the set stored before the call is kept as it was.
  const auto refused = project.value().replace_local_names(
      image_id,
      {donkey::LocalName{0x400100, "arg:0", "a"}, donkey::LocalName{0x400100, "arg:0", "b"}});
  EXPECT_FALSE(refused.has_value());
  auto kept = project.value().local_names(image_id);
  ASSERT_TRUE(kept.has_value());
  ASSERT_EQ(kept.value().size(), 1U);
  EXPECT_EQ(kept.value()[0].name, "items");

  // A malformed key is refused before anything is written.
  EXPECT_FALSE(project.value()
                   .replace_local_names(image_id, {donkey::LocalName{0x400100, "local:1", "x"}})
                   .has_value());
  EXPECT_FALSE(project.value()
                   .replace_local_names(image_id + 99, {donkey::LocalName{0x400100, "arg:0", "x"}})
                   .has_value());

  // Empty set clears everything.
  ASSERT_TRUE(project.value().replace_local_names(image_id, {}).has_value());
  auto cleared = project.value().local_names(image_id);
  ASSERT_TRUE(cleared.has_value());
  EXPECT_TRUE(cleared.value().empty());
}
