#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/project/project.h"
#include "session.h"

namespace {

using donkey::Project;
using donkey::ui::Session;

std::string fixture_path(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/binaries/" + name;
}

/// Unique database path that removes itself and its SQLite sidecars.
class TempPath {
 public:
  explicit TempPath(const std::string& name) {
    static std::uint64_t counter = 0;
    path_ = std::filesystem::temp_directory_path() /
            ("donkey-session-" + name + "-" + std::to_string(++counter) + ".db");
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

donkey::LoadedBinary load_fixture(const std::string& name) {
  auto loaded = donkey::load_binary(fixture_path(name));
  EXPECT_TRUE(loaded.has_value()) << loaded.diagnostic().message;
  return loaded.has_value() ? std::move(loaded.value()) : donkey::LoadedBinary{};
}

/// Spins until the session's worker thread reports idle. The worker owns all
/// file and database I/O, so tests must never read its results before it
/// publishes them.
bool wait_idle(Session& session, int timeout_ms = 20000) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  while (session.busy()) {
    if (std::chrono::steady_clock::now() > deadline) {
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  return true;
}

/// Creates a project with the ELF fixture plus a rename and a comment, which is
/// the state the desktop shell would have after a few edits.
void create_project_with_annotations(const std::string& path) {
  auto loaded = load_fixture("tiny-elf-x86_64");
  auto analysis = donkey::analyze(loaded.image, loaded.data);
  ASSERT_TRUE(analysis.has_value()) << analysis.diagnostic().message;

  auto project = Project::create(path);
  ASSERT_TRUE(project.has_value()) << project.diagnostic().message;
  auto image_id = project.value().import(loaded, analysis.value());
  ASSERT_TRUE(image_id.has_value()) << image_id.diagnostic().message;
  ASSERT_TRUE(
      project.value()
          .set_annotation(image_id.value(), donkey::AnnotationKind::Rename, 0x400100, "entry_point")
          .has_value());
  ASSERT_TRUE(project.value()
                  .set_annotation(image_id.value(), donkey::AnnotationKind::Comment, 0x400104,
                                  "calls helper")
                  .has_value());
}

TEST(Session, OpenProjectPublishesDocumentAndAnnotations) {
  TempPath path("open");
  create_project_with_annotations(path.str());

  Session session;
  session.open_project(path.str());
  ASSERT_TRUE(wait_idle(session)) << "worker did not finish";
  ASSERT_FALSE(session.take_error().has_value()) << "project open failed";

  const auto document = session.document();
  ASSERT_NE(document, nullptr);
  EXPECT_EQ(document->loaded.image.entry_point, 0x400100U);
  EXPECT_FALSE(document->analysis.functions.empty());

  const auto annotations = session.annotations();
  ASSERT_NE(annotations, nullptr);
  ASSERT_NE(annotations->rename_at(0x400100), nullptr);
  EXPECT_EQ(*annotations->rename_at(0x400100), "entry_point");
  ASSERT_NE(annotations->comment_at(0x400104), nullptr);
  EXPECT_EQ(*annotations->comment_at(0x400104), "calls helper");

  EXPECT_TRUE(session.has_project());
  EXPECT_EQ(session.project_path(), path.str());
  EXPECT_FALSE(session.dirty());
}

TEST(Session, SaveProjectPersistsInMemoryAnnotationEdits) {
  TempPath path("save");
  create_project_with_annotations(path.str());

  Session session;
  session.open_project(path.str());
  ASSERT_TRUE(wait_idle(session));
  ASSERT_FALSE(session.take_error().has_value());

  // Edit through the same API the annotation modal uses.
  session.set_annotation(donkey::AnnotationKind::Comment, 0x400104, "edited in the shell");
  session.set_annotation(donkey::AnnotationKind::Rename, 0x400109, "helper");
  EXPECT_TRUE(session.dirty());
  EXPECT_EQ(*session.annotations()->comment_at(0x400104), "edited in the shell");

  session.save_project(path.str());
  ASSERT_TRUE(wait_idle(session));
  ASSERT_FALSE(session.take_error().has_value()) << "project save failed";
  EXPECT_FALSE(session.dirty());

  auto reopened = Project::open(path.str());
  ASSERT_TRUE(reopened.has_value()) << reopened.diagnostic().message;
  auto images = reopened.value().images();
  ASSERT_TRUE(images.has_value());
  ASSERT_EQ(images.value().size(), 1U);
  auto annotations = reopened.value().annotations(images.value().front().id);
  ASSERT_TRUE(annotations.has_value());

  bool saw_comment = false;
  bool saw_rename = false;
  for (const donkey::Annotation& annotation : annotations.value()) {
    if (annotation.kind == donkey::AnnotationKind::Comment) {
      EXPECT_EQ(annotation.address, 0x400104U);
      EXPECT_EQ(annotation.text, "edited in the shell");
      saw_comment = true;
    } else if (annotation.address == 0x400109) {
      EXPECT_EQ(annotation.text, "helper");
      saw_rename = true;
    } else {
      // The original rename must survive a save.
      EXPECT_EQ(annotation.address, 0x400100U);
      EXPECT_EQ(annotation.text, "entry_point");
    }
  }
  EXPECT_TRUE(saw_comment);
  EXPECT_TRUE(saw_rename);
}

TEST(Session, SaveThenReopenSeesTheSameAnnotations) {
  TempPath path("roundtrip");
  create_project_with_annotations(path.str());

  {
    Session session;
    session.open_project(path.str());
    ASSERT_TRUE(wait_idle(session));
    session.set_annotation(donkey::AnnotationKind::Comment, 0x400100, "entry comment");
    session.save_project(path.str());
    ASSERT_TRUE(wait_idle(session));
    ASSERT_FALSE(session.take_error().has_value());
  }

  Session session;
  session.open_project(path.str());
  ASSERT_TRUE(wait_idle(session));
  ASSERT_FALSE(session.take_error().has_value());
  ASSERT_NE(session.annotations()->comment_at(0x400100), nullptr);
  EXPECT_EQ(*session.annotations()->comment_at(0x400100), "entry comment");
  EXPECT_EQ(*session.annotations()->rename_at(0x400100), "entry_point");
}

TEST(Session, OpenProjectReportsMissingImageFile) {
  TempPath path("missing-image");
  auto loaded = load_fixture("tiny-elf-x86_64");
  auto analysis = donkey::analyze(loaded.image, loaded.data);
  ASSERT_TRUE(analysis.has_value());
  loaded.image.path = "/definitely/not/here/tiny-elf";

  auto project = Project::create(path.str());
  ASSERT_TRUE(project.has_value());
  ASSERT_TRUE(project.value().import(loaded, analysis.value()).has_value());

  Session session;
  session.open_project(path.str());
  ASSERT_TRUE(wait_idle(session));
  const auto error = session.take_error();
  ASSERT_TRUE(error.has_value());
  EXPECT_NE(error->find("could not load"), std::string::npos) << *error;
  EXPECT_EQ(session.document(), nullptr);
}

TEST(Session, OpenProjectRejectsMultipleImages) {
  TempPath path("multi-image");
  {
    auto elf = load_fixture("tiny-elf-x86_64");
    auto elf_analysis = donkey::analyze(elf.image, elf.data);
    ASSERT_TRUE(elf_analysis.has_value());
    auto pe = load_fixture("tiny-pe-x86_64.exe");
    auto pe_analysis = donkey::analyze(pe.image, pe.data);
    ASSERT_TRUE(pe_analysis.has_value());

    auto project = Project::create(path.str());
    ASSERT_TRUE(project.has_value());
    ASSERT_TRUE(project.value().import(elf, elf_analysis.value()).has_value());
    ASSERT_TRUE(project.value().import(pe, pe_analysis.value()).has_value());
  }

  Session session;
  session.open_project(path.str());
  ASSERT_TRUE(wait_idle(session));
  const auto error = session.take_error();
  ASSERT_TRUE(error.has_value());
  EXPECT_NE(error->find("project.multi_image_unsupported"), std::string::npos) << *error;
}

TEST(Session, OpeningAPlainBinaryClearsTheProjectAssociation) {
  TempPath path("plain-open");
  create_project_with_annotations(path.str());

  Session session;
  session.open_project(path.str());
  ASSERT_TRUE(wait_idle(session));
  ASSERT_TRUE(session.has_project());

  session.open(fixture_path("tiny-pe-x86_64.exe"));
  ASSERT_TRUE(wait_idle(session));
  ASSERT_FALSE(session.take_error().has_value());
  EXPECT_FALSE(session.has_project());
  EXPECT_TRUE(session.annotations()->renames.empty());
  EXPECT_TRUE(session.annotations()->comments.empty());
}

TEST(Session, BackupAndRestoreProjectRoundTripsAnnotationsAndClearsDirtyState) {
  TempPath project_path("backup-source");
  TempPath backup_path("backup-copy");
  create_project_with_annotations(project_path.str());

  Session session;
  session.open_project(project_path.str());
  ASSERT_TRUE(wait_idle(session));
  ASSERT_FALSE(session.take_error().has_value());

  session.backup_project(backup_path.str());
  ASSERT_TRUE(wait_idle(session));
  ASSERT_FALSE(session.take_error().has_value()) << "backup failed";

  // Mutate and save the live project so both disk and memory diverge from the backup.
  session.set_annotation(donkey::AnnotationKind::Rename, 0x400100, "mutated_entry");
  session.set_annotation(donkey::AnnotationKind::Comment, 0x400104, "");
  session.save_project(project_path.str());
  ASSERT_TRUE(wait_idle(session));
  ASSERT_FALSE(session.take_error().has_value());
  ASSERT_NE(session.annotations()->rename_at(0x400100), nullptr);
  EXPECT_EQ(*session.annotations()->rename_at(0x400100), "mutated_entry");
  EXPECT_EQ(session.annotations()->comment_at(0x400104), nullptr);

  // Also stage an unsaved in-memory edit before restoring.
  session.set_annotation(donkey::AnnotationKind::Comment, 0x400109, "unsaved note");
  EXPECT_TRUE(session.dirty());

  session.restore_project(backup_path.str());
  ASSERT_TRUE(wait_idle(session));
  ASSERT_FALSE(session.take_error().has_value()) << "restore failed";
  EXPECT_FALSE(session.dirty());

  const auto restored = session.annotations();
  ASSERT_NE(restored, nullptr);
  ASSERT_NE(restored->rename_at(0x400100), nullptr);
  EXPECT_EQ(*restored->rename_at(0x400100), "entry_point");
  ASSERT_NE(restored->comment_at(0x400104), nullptr);
  EXPECT_EQ(*restored->comment_at(0x400104), "calls helper");
  EXPECT_EQ(restored->comment_at(0x400109), nullptr);
}

TEST(Session, RestoreProjectRejectsCorruptBackupAndPreservesLiveSession) {
  TempPath project_path("restore-live");
  TempPath corrupt_backup("restore-corrupt");
  create_project_with_annotations(project_path.str());
  {
    std::ofstream out(corrupt_backup.str(), std::ios::binary);
    out << "not a sqlite database";
  }

  Session session;
  session.open_project(project_path.str());
  ASSERT_TRUE(wait_idle(session));
  ASSERT_FALSE(session.take_error().has_value());

  session.restore_project(corrupt_backup.str());
  ASSERT_TRUE(wait_idle(session));
  const auto error = session.take_error();
  ASSERT_TRUE(error.has_value());
  EXPECT_NE(error->find("project.schema_read_failed"), std::string::npos) << *error;

  // The live document and annotations must remain intact after a rejected restore.
  ASSERT_NE(session.document(), nullptr);
  ASSERT_NE(session.annotations()->rename_at(0x400100), nullptr);
  EXPECT_EQ(*session.annotations()->rename_at(0x400100), "entry_point");
}

TEST(Session, BackupAndRestoreRequireOpenProject) {
  TempPath backup_path("no-project-backup");
  Session session;

  session.backup_project(backup_path.str());
  const auto backup_error = session.take_error();
  ASSERT_TRUE(backup_error.has_value());
  EXPECT_NE(backup_error->find("project.not_open"), std::string::npos) << *backup_error;

  session.restore_project(backup_path.str());
  const auto restore_error = session.take_error();
  ASSERT_TRUE(restore_error.has_value());
  EXPECT_NE(restore_error->find("project.not_open"), std::string::npos) << *restore_error;
}

}  // namespace
