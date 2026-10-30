#include <gtest/gtest.h>
#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <string>
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
#include "donkey/project/project.h"

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

std::uintmax_t file_size_or_zero(const std::string& path) {
  std::error_code ec;
  const auto size = std::filesystem::file_size(path, ec);
  return ec ? 0 : size;
}

std::string read_bytes(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
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

}  // namespace
