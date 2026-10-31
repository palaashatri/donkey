#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/core/navigation.h"
#include "donkey/project/project.h"
#include "session.h"
#include "test_io.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace {

using donkey::Project;
using donkey::ui::Session;

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
            ("donkey-session-" + name + "-" + unique + "-" + std::to_string(++counter) + ".db");
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

/// Annotation text, or a marker when the annotation is missing, so a failing
/// expectation reports a value instead of dereferencing null.
std::string text_of(const std::string* text) {
  return text != nullptr ? *text : std::string("<missing>");
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
  EXPECT_EQ(text_of(annotations->rename_at(0x400100)), "entry_point");
  ASSERT_NE(annotations->comment_at(0x400104), nullptr);
  EXPECT_EQ(text_of(annotations->comment_at(0x400104)), "calls helper");

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
  EXPECT_EQ(text_of(session.annotations()->comment_at(0x400104)), "edited in the shell");

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
  EXPECT_EQ(text_of(session.annotations()->comment_at(0x400100)), "entry comment");
  EXPECT_EQ(text_of(session.annotations()->rename_at(0x400100)), "entry_point");
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
  EXPECT_EQ(text_of(session.annotations()->rename_at(0x400100)), "mutated_entry");
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
  EXPECT_EQ(text_of(restored->rename_at(0x400100)), "entry_point");
  ASSERT_NE(restored->comment_at(0x400104), nullptr);
  EXPECT_EQ(text_of(restored->comment_at(0x400104)), "calls helper");
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
  EXPECT_EQ(text_of(session.annotations()->rename_at(0x400100)), "entry_point");
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

TEST(Session, UndoAndRedoEdits) {
  Session session;
  session.open(fixture_path("tiny-elf-x86_64"));
  ASSERT_TRUE(wait_idle(session));

  EXPECT_FALSE(session.can_undo());
  EXPECT_FALSE(session.can_redo());

  // Set a rename
  session.set_annotation(donkey::AnnotationKind::Rename, 0x400100, "my_main");
  EXPECT_TRUE(session.can_undo());
  EXPECT_FALSE(session.can_redo());
  EXPECT_EQ(text_of(session.annotations()->rename_at(0x400100)), "my_main");

  // Set a comment
  session.set_annotation(donkey::AnnotationKind::Comment, 0x400100, "first line");
  EXPECT_EQ(text_of(session.annotations()->comment_at(0x400100)), "first line");

  // Toggle bookmark
  session.toggle_bookmark(0x400100, "entry");
  EXPECT_TRUE(session.annotations()->has_bookmark(0x400100));
  EXPECT_EQ(text_of(session.annotations()->bookmark_at(0x400100)), "entry");

  // Undo bookmark
  EXPECT_TRUE(session.undo());
  EXPECT_FALSE(session.annotations()->has_bookmark(0x400100));
  EXPECT_TRUE(session.can_redo());

  // Redo bookmark
  EXPECT_TRUE(session.redo());
  EXPECT_TRUE(session.annotations()->has_bookmark(0x400100));

  // Undo bookmark and comment
  EXPECT_TRUE(session.undo());  // undo bookmark
  EXPECT_TRUE(session.undo());  // undo comment
  EXPECT_EQ(session.annotations()->comment_at(0x400100), nullptr);
  EXPECT_EQ(text_of(session.annotations()->rename_at(0x400100)), "my_main");

  // Undo rename
  EXPECT_TRUE(session.undo());
  EXPECT_EQ(session.annotations()->rename_at(0x400100), nullptr);
  EXPECT_FALSE(session.can_undo());

  // Redo all three
  EXPECT_TRUE(session.redo());
  EXPECT_EQ(text_of(session.annotations()->rename_at(0x400100)), "my_main");
  EXPECT_TRUE(session.redo());
  EXPECT_EQ(text_of(session.annotations()->comment_at(0x400100)), "first line");
  EXPECT_TRUE(session.redo());
  EXPECT_TRUE(session.annotations()->has_bookmark(0x400100));
  EXPECT_FALSE(session.can_redo());
}

TEST(Session, NavigationHistory) {
  donkey::NavigationHistory nav;
  EXPECT_FALSE(nav.can_nav_back());
  EXPECT_FALSE(nav.can_nav_forward());

  nav.navigate_to(0x1000);
  EXPECT_EQ(nav.current_address(), 0x1000U);
  EXPECT_FALSE(nav.can_nav_back());

  nav.navigate_to(0x2000);
  EXPECT_EQ(nav.current_address(), 0x2000U);
  EXPECT_TRUE(nav.can_nav_back());
  EXPECT_FALSE(nav.can_nav_forward());

  nav.navigate_to(0x3000);
  EXPECT_EQ(nav.current_address(), 0x3000U);
  EXPECT_TRUE(nav.can_nav_back());

  // Back to 0x2000
  auto back1 = nav.nav_back();
  ASSERT_TRUE(back1.has_value());
  EXPECT_EQ(*back1, 0x2000U);
  EXPECT_TRUE(nav.can_nav_back());
  EXPECT_TRUE(nav.can_nav_forward());

  // Back to 0x1000
  auto back2 = nav.nav_back();
  ASSERT_TRUE(back2.has_value());
  EXPECT_EQ(*back2, 0x1000U);
  EXPECT_FALSE(nav.can_nav_back());
  EXPECT_TRUE(nav.can_nav_forward());

  // Forward to 0x2000
  auto fwd1 = nav.nav_forward();
  ASSERT_TRUE(fwd1.has_value());
  EXPECT_EQ(*fwd1, 0x2000U);

  // New navigation branches off forward history
  nav.navigate_to(0x4000);
  EXPECT_EQ(nav.current_address(), 0x4000U);
  EXPECT_FALSE(nav.can_nav_forward());
  EXPECT_TRUE(nav.can_nav_back());

  auto back3 = nav.nav_back();
  ASSERT_TRUE(back3.has_value());
  EXPECT_EQ(*back3, 0x2000U);
}

TEST(Session, CancellationStopsRunningTask) {
  Session session;
  session.open(fixture_path("tiny-elf-x86_64"));
  // Immediate cancel
  session.cancel();
  ASSERT_TRUE(wait_idle(session));
  // Session must either finish or fail cleanly with Cancelled without crash or hung thread
  EXPECT_FALSE(session.busy());
}

TEST(Session, SupersededWorkerDoesNotPublishFailure) {
  Session session;
  session.open(fixture_path("tiny-elf-x86_64"));
  session.cancel();
  session.open(fixture_path("tiny-pe-x86_64.exe"));
  ASSERT_TRUE(wait_idle(session));

  EXPECT_FALSE(session.busy());
  EXPECT_FALSE(session.take_error().has_value());
  auto doc = session.document();
  ASSERT_NE(doc, nullptr);
  EXPECT_EQ(doc->loaded.image.path, fixture_path("tiny-pe-x86_64.exe"));
}

TEST(Session, RapidInterleavedOpenCancelOpenMaintainsConsistentState) {
  Session session;
  for (int i = 0; i < 20; ++i) {
    session.open(fixture_path("tiny-elf-x86_64"));
    session.cancel();
    session.open(fixture_path("tiny-pe-x86_64.exe"));
  }
  ASSERT_TRUE(wait_idle(session));

  EXPECT_FALSE(session.busy());
  EXPECT_FALSE(session.take_error().has_value());
  auto doc = session.document();
  ASSERT_NE(doc, nullptr);
  EXPECT_EQ(doc->loaded.image.path, fixture_path("tiny-pe-x86_64.exe"));
}

TEST(Session, SupersededRestoreAtCommitBoundaryDoesNotMutateDatabase) {
  TempPath db_path("session-restore-supersede");
  TempPath backup_path("session-restore-backup");
  TempPath other_source("session-other-source");

  // Project A has ELF
  {
    Session s;
    s.open(fixture_path("tiny-elf-x86_64"));
    ASSERT_TRUE(wait_idle(s));
    s.save_project(db_path.str());
    ASSERT_TRUE(wait_idle(s));
  }

  // Backup has PE
  {
    Session s;
    s.open(fixture_path("tiny-pe-x86_64.exe"));
    ASSERT_TRUE(wait_idle(s));
    s.save_project(other_source.str());
    ASSERT_TRUE(wait_idle(s));
    s.backup_project(backup_path.str());
    ASSERT_TRUE(wait_idle(s));
  }

  std::string orig_db_content;
  {
    std::ifstream in(db_path.str(), std::ios::binary);
    orig_db_content = donkey_test::read_stream<std::string>(in);
  }

  Session session;
  session.open_project(db_path.str());
  ASSERT_TRUE(wait_idle(session));

  // Trigger restore into db_path, then immediately supersede it with open()
  session.restore_project(backup_path.str());
  session.open(fixture_path("tiny-macho-arm64"));
  ASSERT_TRUE(wait_idle(session));

  EXPECT_FALSE(session.busy());
  EXPECT_FALSE(session.take_error().has_value());
  auto doc = session.document();
  ASSERT_NE(doc, nullptr);
  EXPECT_EQ(doc->loaded.image.path, fixture_path("tiny-macho-arm64"));

  // Verify that on-disk db_path was not mutated by the superseded restore
  {
    std::ifstream in(db_path.str(), std::ios::binary);
    const std::string current_content = donkey_test::read_stream<std::string>(in);
    EXPECT_EQ(current_content, orig_db_content);
  }
}

TEST(Session, ReapsCompletedRetiredWorkersDuringNormalOperation) {
  Session session;
  // Trigger several worker tasks that get retired
  for (int i = 0; i < 5; ++i) {
    session.open(fixture_path("tiny-elf-x86_64"));
  }
  ASSERT_TRUE(wait_idle(session));

  // Starting a new task calls retire_worker() which reaps finished retired workers
  session.open(fixture_path("tiny-pe-x86_64.exe"));
  ASSERT_TRUE(wait_idle(session));

  EXPECT_FALSE(session.busy());
  EXPECT_FALSE(session.take_error().has_value());
  auto doc = session.document();
  ASSERT_NE(doc, nullptr);
  EXPECT_EQ(doc->loaded.image.path, fixture_path("tiny-pe-x86_64.exe"));
}

TEST(Session, CancelAfterRestoreCommitReportsCompletedRestore) {
  TempPath db_path("session-post-commit");
  TempPath backup_path("session-post-commit-backup");

  Session session;
  session.open(fixture_path("tiny-elf-x86_64"));
  ASSERT_TRUE(wait_idle(session));
  const auto document = session.document();
  ASSERT_NE(document, nullptr);
  const std::uint64_t address = document->loaded.image.entry_point;
  session.set_annotation(donkey::AnnotationKind::Rename, address, "from_backup");
  session.save_project(db_path.str());
  ASSERT_TRUE(wait_idle(session));
  session.backup_project(backup_path.str());
  ASSERT_TRUE(wait_idle(session));
  ASSERT_FALSE(session.take_error().has_value());
  session.set_annotation(donkey::AnnotationKind::Rename, address, "after_backup");
  session.save_project(db_path.str());
  ASSERT_TRUE(wait_idle(session));

  // Cancel deterministically in the window after the database replacement
  // has committed but before the image is reloaded.
  bool hook_ran = false;
  session.set_restore_post_commit_hook_for_testing([&]() {
    hook_ran = true;
    session.cancel();
  });
  session.restore_project(backup_path.str());
  ASSERT_TRUE(wait_idle(session));
  session.set_restore_post_commit_hook_for_testing({});

  ASSERT_TRUE(hook_ran);
  const auto error = session.take_error();
  EXPECT_FALSE(error.has_value()) << *error;
  EXPECT_NE(session.status().find("Restored project from"), std::string::npos) << session.status();
  EXPECT_EQ(session.status().find("Operation cancelled"), std::string::npos);
  EXPECT_TRUE(session.has_project());
  EXPECT_FALSE(session.dirty());
  const auto annotations = session.annotations();
  ASSERT_NE(annotations->rename_at(address), nullptr);
  EXPECT_EQ(text_of(annotations->rename_at(address)), "from_backup");
  // The open document is the restored project's image, so it stays.
  ASSERT_NE(session.document(), nullptr);
  EXPECT_EQ(session.path(), fixture_path("tiny-elf-x86_64"));

  // And the database on disk really holds the backup.
  auto project = Project::open(db_path.str());
  ASSERT_TRUE(project.has_value());
  auto images = project.value().images();
  ASSERT_TRUE(images.has_value());
  ASSERT_EQ(images.value().size(), 1U);
  auto stored = project.value().annotations(images.value().front().id);
  ASSERT_TRUE(stored.has_value());
  ASSERT_EQ(stored.value().size(), 1U);
  EXPECT_EQ(stored.value().front().text, "from_backup");
}

TEST(Session, BackupOverOpenProjectIsRejected) {
  TempPath db_path("session-backup-self");
  Session session;
  session.open(fixture_path("tiny-elf-x86_64"));
  ASSERT_TRUE(wait_idle(session));
  session.save_project(db_path.str());
  ASSERT_TRUE(wait_idle(session));
  session.backup_project(db_path.str(), true);
  ASSERT_TRUE(wait_idle(session));
  const auto error = session.take_error();
  ASSERT_TRUE(error.has_value());
  EXPECT_NE(error->find("project.backup_is_source"), std::string::npos) << *error;
  EXPECT_TRUE(Project::open(db_path.str()).has_value());
}

bool has_function(const Session& session, std::uint64_t address) {
  const auto document = session.document();
  if (document == nullptr) {
    return false;
  }
  for (const auto& function : document->analysis.functions) {
    if (function.address == address) {
      return true;
    }
  }
  return false;
}

TEST(Session, FunctionBoundaryEditsReanalyseUndoAndPersist) {
  TempPath db_path("session-function-edits");
  Session session;
  session.open(DONKEY_TEST_DEBUGGEE_PATH);
  ASSERT_TRUE(wait_idle(session));
  const auto document = session.document();
  ASSERT_NE(document, nullptr);

  // An instruction inside main that is not a function start, and a
  // discovered function to remove.
  std::uint64_t main_address = 0;
  std::uint64_t tick_address = 0;
  for (const auto& function : document->analysis.functions) {
    // Mach-O symbols carry a leading underscore.
    if (function.name == "main" || function.name == "_main") {
      main_address = function.address;
    } else if (function.name == "donkey_debuggee_tick" ||
               function.name == "_donkey_debuggee_tick") {
      tick_address = function.address;
    }
  }
  ASSERT_NE(main_address, 0U);
  ASSERT_NE(tick_address, 0U);
  std::uint64_t inside = 0;
  for (const auto& instruction : document->analysis.instructions) {
    if (instruction.address > main_address + 4 && !has_function(session, instruction.address)) {
      inside = instruction.address;
      break;
    }
  }
  ASSERT_NE(inside, 0U);

  session.set_function_edit(inside, "define");
  ASSERT_TRUE(wait_idle(session));
  EXPECT_TRUE(has_function(session, inside));
  EXPECT_NE(session.document(), document) << "analysis must be recomputed, not reused";
  EXPECT_TRUE(session.dirty());

  session.set_function_edit(tick_address, "remove");
  ASSERT_TRUE(wait_idle(session));
  // A user removal wins over discovery, even for a call target.
  EXPECT_FALSE(has_function(session, tick_address));
  ASSERT_NE(session.annotations()->function_edit_at(tick_address), nullptr);

  ASSERT_TRUE(session.undo());  // undo the removal
  ASSERT_TRUE(wait_idle(session));
  EXPECT_EQ(session.annotations()->function_edit_at(tick_address), nullptr);
  EXPECT_TRUE(has_function(session, tick_address));
  ASSERT_TRUE(session.undo());  // undo the definition
  ASSERT_TRUE(wait_idle(session));
  EXPECT_FALSE(has_function(session, inside));
  ASSERT_TRUE(session.redo());
  ASSERT_TRUE(wait_idle(session));
  EXPECT_TRUE(has_function(session, inside));

  session.save_project(db_path.str());
  ASSERT_TRUE(wait_idle(session));
  ASSERT_FALSE(session.take_error().has_value());

  Session reopened;
  reopened.open_project(db_path.str());
  ASSERT_TRUE(wait_idle(reopened));
  ASSERT_FALSE(reopened.take_error().has_value());
  EXPECT_TRUE(has_function(reopened, inside)) << "the edit must survive save and reopen";
  ASSERT_NE(reopened.annotations()->function_edit_at(inside), nullptr);
  EXPECT_EQ(*reopened.annotations()->function_edit_at(inside), "define");
}

}  // namespace
