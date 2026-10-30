#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/core/cancellation.h"
#include "donkey/project/project.h"

namespace donkey::ui {

/// A fully parsed image plus its analysis. Immutable once published, so the
/// render thread can read it without holding the session lock.
struct Document {
  LoadedBinary loaded;
  AnalysisResult analysis;
};

/// Address-keyed user annotations. Snapshots are immutable and swapped under
/// the session lock, so the render thread never sees a half-applied edit.
struct Annotations {
  std::unordered_map<std::uint64_t, std::string> renames;
  std::unordered_map<std::uint64_t, std::string> comments;
  std::unordered_map<std::uint64_t, std::string> bookmarks;

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

  /// Start loading `path`. The previous worker (if any) is joined first, so
  /// re-entrant calls block the caller rather than running two loads at once.
  /// Callers must not invoke this while `busy()` (the desktop shell disables
  /// its menu items accordingly).
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
  /// on the worker thread.
  void restore_project(const std::string& backup_path);

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

  /// Toggle bookmark at address. Clears it if already present.
  void toggle_bookmark(std::uint64_t address, const std::string& note = "Bookmark");

  /// Undo / redo support for annotation edits.
  bool undo();
  bool redo();
  [[nodiscard]] bool can_undo() const;
  [[nodiscard]] bool can_redo() const;

 private:
  void join_worker();
  void fail(const std::string& message, const std::string& status);
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
  std::atomic<std::uint64_t> generation_{0};

  CancellationToken current_cancellation_;
  std::vector<AnnotationEdit> undo_stack_;
  std::vector<AnnotationEdit> redo_stack_;
};

}  // namespace donkey::ui
