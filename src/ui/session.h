#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/debug_info.h"
#include "donkey/binary/image.h"
#include "donkey/core/cancellation.h"
#include "donkey/project/project.h"

namespace donkey::ui {

/// A fully parsed image plus its analysis. Immutable once published, so the
/// render thread can read it without holding the session lock.
struct Document {
  LoadedBinary loaded;
  AnalysisResult analysis;
  /// DWARF read from the file (null when it has none or it was unreadable;
  /// `debug_info_note` says which). Names from it only fill functions that
  /// have no symbol name, and never replace a user rename.
  std::shared_ptr<const DebugInfo> debug_info;
  std::string debug_info_note;
};

/// Address-keyed user annotations. Snapshots are immutable and swapped under
/// the session lock, so the render thread never sees a half-applied edit.
struct Annotations {
  std::unordered_map<std::uint64_t, std::string> renames;
  std::unordered_map<std::uint64_t, std::string> comments;
  std::unordered_map<std::uint64_t, std::string> bookmarks;
  /// User function-boundary edits: "define" adds a start, "remove" drops a
  /// discovered one. Changing them re-runs analysis.
  std::unordered_map<std::uint64_t, std::string> functions;

  [[nodiscard]] const std::string* rename_at(std::uint64_t address) const {
    const auto it = renames.find(address);
    return it == renames.end() ? nullptr : &it->second;
  }
  [[nodiscard]] const std::string* comment_at(std::uint64_t address) const {
    const auto it = comments.find(address);
    return it == comments.end() ? nullptr : &it->second;
  }
  [[nodiscard]] const std::string* bookmark_at(std::uint64_t address) const {
    const auto it = bookmarks.find(address);
    return it == bookmarks.end() ? nullptr : &it->second;
  }
  [[nodiscard]] const std::string* function_edit_at(std::uint64_t address) const {
    const auto it = functions.find(address);
    return it == functions.end() ? nullptr : &it->second;
  }
  [[nodiscard]] bool has_bookmark(std::uint64_t address) const {
    return bookmarks.contains(address);
  }
};

struct AnnotationEdit {
  AnnotationKind kind = AnnotationKind::Rename;
  std::uint64_t address = 0;
  std::string old_text;
  std::string new_text;
};

/// Loads, analyses and persists files on a worker thread. The render thread
/// never reads a file, runs analysis or writes SQL itself.
class Session {
 public:
  Session() = default;
  ~Session();

  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;

  /// Start loading `path`. The previous worker (if any) is cancelled and
  /// retired while the new one starts; it may finish asynchronously, and its
  /// results are discarded because its generation is obsolete. The desktop
  /// shell still disables its menu items while `busy()`.
  void open(const std::string& path);

  /// Open a project database, load the single image it references and its
  /// persisted annotations. Projects with zero or several images are rejected
  /// because the workspace shows one document at a time.
  void open_project(const std::string& path);

  /// Import the current document into a project database and replace that
  /// image's annotations with the current in-memory snapshot.
  void save_project(const std::string& path);

  /// Write a self-contained SQLite backup of the currently open project to
  /// `destination` on the worker thread.
  void backup_project(const std::string& destination, bool overwrite = true);

  /// Replace the currently open project database with `backup_path` after
  /// validating the backup, then reload the restored document and annotations
  /// on the worker thread. Cancellation is honoured up to the atomic database
  /// replacement; after it the restore is reported as completed, and a later
  /// cancel only stops the image reload.
  void restore_project(const std::string& backup_path);

  /// Test-only: runs on the restore worker immediately after the database
  /// replacement has committed.
  void set_restore_post_commit_hook_for_testing(std::function<void()> hook);

  /// Test-only: runs on the open() worker before the file is read, so a test
  /// can stand in for slow storage. It receives the operation's token.
  void set_load_hook_for_testing(std::function<void(const CancellationToken&)> hook);

  /// Request cooperative cancellation of any running worker task.
  void cancel();
  [[nodiscard]] bool is_cancelled() const;

  [[nodiscard]] bool busy() const noexcept { return busy_.load(); }
  [[nodiscard]] std::optional<std::string> take_error();
  [[nodiscard]] std::shared_ptr<const Document> document() const;
  [[nodiscard]] std::shared_ptr<const Annotations> annotations() const;
  [[nodiscard]] std::string path() const;
  [[nodiscard]] std::string status() const;

  [[nodiscard]] bool has_project() const;
  [[nodiscard]] std::string project_path() const;
  [[nodiscard]] bool dirty() const;

  /// Replace or clear one annotation in memory and mark the project dirty.
  /// Persistence happens on the next explicit save.
  void set_annotation(AnnotationKind kind, std::uint64_t address, const std::string& text);

  /// Define a function starting at `address`, remove the discovered one, or
  /// (with an empty action) drop the edit. Re-runs analysis on the worker.
  void set_function_edit(std::uint64_t address, const std::string& action);

  /// True when a function-boundary edit is waiting for the worker to be free.
  [[nodiscard]] bool reanalysis_pending() const;
  /// Re-analyse the open document with the current function edits. Deferred
  /// (see reanalysis_pending) while another operation runs.
  void reanalyze();

  /// Toggle bookmark at address. Clears it if already present.
  void toggle_bookmark(std::uint64_t address, const std::string& note = "Bookmark");

  /// Undo / redo support for annotation edits.
  bool undo();
  bool redo();
  [[nodiscard]] bool can_undo() const;
  [[nodiscard]] bool can_redo() const;

 private:
  struct RetiredWorker {
    std::thread thread;
    std::shared_ptr<std::atomic<bool>> done;
  };

  void retire_worker();
  void reap_retired_workers();
  void after_annotation_change(AnnotationKind kind);
  std::function<void(std::uint64_t, std::uint64_t)> progress_reporter(std::uint64_t generation);
  bool wait_for_retired_workers(const CancellationToken& token);
  void fail(std::uint64_t generation, const std::string& message, const std::string& status);
  void publish_project(std::string path, std::int64_t image_id);
  void apply_annotation_edit_locked(AnnotationKind kind, std::uint64_t address,
                                    const std::string& text, bool record_undo);

  mutable std::mutex mutex_;
  std::shared_ptr<const Document> document_;
  std::shared_ptr<const Annotations> annotations_ = std::make_shared<Annotations>();
  std::optional<std::string> error_;
  std::string path_;
  std::string status_ = "No file open";
  std::string project_path_;
  std::int64_t image_id_ = 0;
  bool dirty_ = false;
  std::atomic<bool> busy_{false};
  std::thread worker_;
  std::shared_ptr<std::atomic<bool>> current_worker_done_;
  std::vector<RetiredWorker> retired_workers_;
  std::atomic<std::uint64_t> generation_{0};
  std::function<void()> restore_post_commit_hook_;
  std::function<void(const CancellationToken&)> load_hook_;
  bool reanalysis_pending_ = false;

  CancellationToken current_cancellation_;
  std::vector<AnnotationEdit> undo_stack_;
  std::vector<AnnotationEdit> redo_stack_;
};

}  // namespace donkey::ui
