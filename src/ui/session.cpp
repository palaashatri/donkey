#include "session.h"

#include <chrono>
#include <cstdint>
#include <utility>
#include <vector>

namespace donkey::ui {
namespace {

constexpr std::size_t kMaxInstructions = 200'000;
constexpr std::size_t kMaxStrings = 50'000;

AnalysisOptions analysis_options() {
  AnalysisOptions options;
  options.max_instructions = kMaxInstructions;
  options.max_strings = kMaxStrings;
  return options;
}

std::shared_ptr<Annotations> annotations_from(const std::vector<Annotation>& rows) {
  auto annotations = std::make_shared<Annotations>();
  for (const Annotation& annotation : rows) {
    switch (annotation.kind) {
      case AnnotationKind::Rename:
        annotations->renames[annotation.address] = annotation.text;
        break;
      case AnnotationKind::Comment:
        annotations->comments[annotation.address] = annotation.text;
        break;
      case AnnotationKind::Bookmark:
        annotations->bookmarks[annotation.address] = annotation.text;
        break;
      case AnnotationKind::FunctionStart:
        annotations->functions[annotation.address] = annotation.text;
        break;
    }
  }
  return annotations;
}

std::vector<Annotation> rows_from(const Annotations& annotations) {
  std::vector<Annotation> rows;
  rows.reserve(annotations.renames.size() + annotations.comments.size() +
               annotations.bookmarks.size() + annotations.functions.size());
  for (const auto& [address, text] : annotations.renames) {
    rows.push_back(Annotation{AnnotationKind::Rename, address, text});
  }
  for (const auto& [address, text] : annotations.comments) {
    rows.push_back(Annotation{AnnotationKind::Comment, address, text});
  }
  for (const auto& [address, text] : annotations.bookmarks) {
    rows.push_back(Annotation{AnnotationKind::Bookmark, address, text});
  }
  for (const auto& [address, text] : annotations.functions) {
    rows.push_back(Annotation{AnnotationKind::FunctionStart, address, text});
  }
  return rows;
}

/// Analysis options with the user's function-boundary edits applied.
AnalysisOptions analysis_options_for(const Annotations& annotations) {
  AnalysisOptions options = analysis_options();
  for (const auto& [address, action] : annotations.functions) {
    if (action == "define") {
      options.user_function_starts.push_back(address);
    } else if (action == "remove") {
      options.removed_function_starts.push_back(address);
    }
  }
  return options;
}

struct WorkerDoneGuard {
  std::shared_ptr<std::atomic<bool>> flag;
  ~WorkerDoneGuard() {
    if (flag) {
      flag->store(true);
    }
  }
};

}  // namespace

Session::~Session() {
  cancel();
  if (worker_.joinable()) {
    worker_.join();
  }
  std::vector<RetiredWorker> retired;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    retired = std::move(retired_workers_);
  }
  for (auto& rw : retired) {
    if (rw.thread.joinable()) {
      rw.thread.join();
    }
  }
}

void Session::reap_retired_workers() {
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto it = retired_workers_.begin(); it != retired_workers_.end();) {
    if (it->done && it->done->load()) {
      if (it->thread.joinable()) {
        it->thread.join();
      }
      it = retired_workers_.erase(it);
    } else {
      ++it;
    }
  }
}

void Session::retire_worker() {
  cancel();
  if (worker_.joinable()) {
    std::lock_guard<std::mutex> lock(mutex_);
    retired_workers_.push_back({std::move(worker_), current_worker_done_});
  }
  reap_retired_workers();
}

void Session::fail(std::uint64_t generation, const std::string& message,
                   const std::string& status) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (generation != generation_.load()) {
    return;
  }
  error_ = message;
  status_ = status;
  busy_.store(false);
}

std::function<void(std::uint64_t, std::uint64_t)> Session::progress_reporter(
    std::uint64_t generation) {
  // Updates the status line at most once per whole percent.
  auto last = std::make_shared<int>(-1);
  return [this, generation, last](std::uint64_t done, std::uint64_t total) {
    if (total == 0) {
      return;
    }
    const int percent = static_cast<int>((done * 100) / total);
    if (percent == *last) {
      return;
    }
    *last = percent;
    std::lock_guard<std::mutex> lock(mutex_);
    if (generation != generation_.load()) {
      return;
    }
    const auto paren = status_.rfind(" (");
    const std::string base =
        paren != std::string::npos && status_.back() == ')' ? status_.substr(0, paren) : status_;
    status_ = base + " (" + std::to_string(percent) + "%)";
  };
}

void Session::publish_project(std::string path, std::int64_t image_id) {
  std::lock_guard<std::mutex> lock(mutex_);
  project_path_ = std::move(path);
  image_id_ = image_id;
  dirty_ = false;
}

void Session::open(const std::string& path) {
  retire_worker();
  const std::uint64_t generation = generation_.fetch_add(1) + 1;
  CancellationToken token;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    current_cancellation_ = token;
    undo_stack_.clear();
    redo_stack_.clear();
    path_ = path;
    status_ = "Loading " + path;
    error_.reset();
  }
  busy_.store(true);
  auto done = std::make_shared<std::atomic<bool>>(false);
  {
    std::lock_guard<std::mutex> lock(mutex_);
    current_worker_done_ = done;
  }
  std::function<void(const CancellationToken&)> load_hook;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    load_hook = load_hook_;
  }
  worker_ = std::thread([this, path, generation, token, done, load_hook]() {
    WorkerDoneGuard done_guard{done};
    if (load_hook) {
      load_hook(token);
    }
    LoadOptions load_opts;
    load_opts.cancellation_token = token;
    load_opts.progress = progress_reporter(generation);
    auto loaded = load_binary(path, load_opts);
    if (generation_.load() != generation) {
      return;
    }
    if (token.is_cancelled()) {
      fail(generation, "Operation cancelled", "Cancelled");
      return;
    }
    if (!loaded) {
      fail(generation, loaded.diagnostic().message + " [" + loaded.diagnostic().code + "]",
           "Failed to load " + path);
      return;
    }

    AnalysisOptions options = analysis_options();
    options.cancellation_token = token;
    auto analysis = analyze(loaded.value().image, loaded.value().data, options);
    if (token.is_cancelled()) {
      fail(generation, "Operation cancelled", "Cancelled");
      return;
    }
    if (!analysis) {
      fail(generation, analysis.diagnostic().message + " [" + analysis.diagnostic().code + "]",
           "Failed to analyse " + path);
      return;
    }

    auto document = std::make_shared<Document>();
    document->loaded = std::move(loaded.value());
    document->analysis = std::move(analysis.value());

    std::lock_guard<std::mutex> lock(mutex_);
    if (generation_.load() == generation) {
      document_ = std::move(document);
      // A plain binary is no longer attached to the previously open project.
      project_path_.clear();
      image_id_ = 0;
      dirty_ = false;
      annotations_ = std::make_shared<Annotations>();
      status_ = "Loaded " + path;
      busy_.store(false);
    }
  });
}

void Session::open_project(const std::string& path) {
  retire_worker();
  const std::uint64_t generation = generation_.fetch_add(1) + 1;
  CancellationToken token;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    current_cancellation_ = token;
    undo_stack_.clear();
    redo_stack_.clear();
    status_ = "Opening project " + path;
    error_.reset();
  }
  busy_.store(true);
  auto done = std::make_shared<std::atomic<bool>>(false);
  {
    std::lock_guard<std::mutex> lock(mutex_);
    current_worker_done_ = done;
  }
  worker_ = std::thread([this, path, generation, token, done]() {
    WorkerDoneGuard done_guard{done};
    // Read everything the project owns first, then close the database before
    // the (slower) binary load and analysis. busy_ is only cleared after the
    // connection is released, so an observer that sees "idle" knows the
    // database is no longer held.
    std::string image_path;
    std::int64_t image_id = 0;
    std::vector<Annotation> stored;
    std::string failure;
    std::string failure_status;
    {
      auto project = Project::open(path);
      if (token.is_cancelled()) {
        fail(generation, "Operation cancelled", "Cancelled");
        return;
      }
      if (!project) {
        failure = project.diagnostic().message + " [" + project.diagnostic().code + "]";
        failure_status = "Failed to open project " + path;
      } else {
        auto images = project.value().images();
        if (!images) {
          failure = images.diagnostic().message + " [" + images.diagnostic().code + "]";
          failure_status = "Failed to read project " + path;
        } else if (images.value().size() != 1) {
          failure =
              "project.multi_image_unsupported: the workspace shows one image at a time, "
              "this project has " +
              std::to_string(images.value().size());
          failure_status = "Failed to open project " + path;
        } else {
          image_path = images.value().front().path;
          image_id = images.value().front().id;
          auto annotations = project.value().annotations(image_id);
          if (!annotations) {
            failure = annotations.diagnostic().message + " [" + annotations.diagnostic().code + "]";
            failure_status = "Failed to read annotations";
          } else {
            stored = std::move(annotations.value());
          }
        }
      }
    }
    if (token.is_cancelled()) {
      fail(generation, "Operation cancelled", "Cancelled");
      return;
    }
    if (!failure.empty()) {
      fail(generation, failure, failure_status);
      return;
    }

    LoadOptions load_opts;
    load_opts.cancellation_token = token;
    load_opts.progress = progress_reporter(generation);
    auto loaded = load_binary(image_path, load_opts);
    if (token.is_cancelled()) {
      fail(generation, "Operation cancelled", "Cancelled");
      return;
    }
    if (!loaded) {
      fail(generation,
           "could not load '" + image_path + "': " + loaded.diagnostic().message + " [" +
               loaded.diagnostic().code + "]",
           "Failed to load project image");
      return;
    }
    auto annotations = annotations_from(stored);
    AnalysisOptions options = analysis_options_for(*annotations);
    options.cancellation_token = token;
    auto analysis = analyze(loaded.value().image, loaded.value().data, options);
    if (token.is_cancelled()) {
      fail(generation, "Operation cancelled", "Cancelled");
      return;
    }
    if (!analysis) {
      fail(generation, analysis.diagnostic().message + " [" + analysis.diagnostic().code + "]",
           "Failed to analyse project image");
      return;
    }

    auto document = std::make_shared<Document>();
    document->loaded = std::move(loaded.value());
    document->analysis = std::move(analysis.value());

    std::lock_guard<std::mutex> lock(mutex_);
    if (generation_.load() == generation) {
      document_ = std::move(document);
      annotations_ = std::move(annotations);
      path_ = image_path;
      project_path_ = path;
      image_id_ = image_id;
      dirty_ = false;
      status_ = "Opened project " + path;
      busy_.store(false);
    }
  });
}

void Session::save_project(const std::string& path) {
  retire_worker();
  std::shared_ptr<const Document> document;
  std::shared_ptr<const Annotations> annotations;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    document = document_;
    annotations = annotations_;
  }
  if (!document) {
    std::lock_guard<std::mutex> lock(mutex_);
    error_ = "no document to save";
    status_ = "Nothing to save";
    return;
  }

  const std::uint64_t generation = generation_.fetch_add(1) + 1;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    status_ = "Saving project " + path;
    error_.reset();
  }
  busy_.store(true);
  auto done = std::make_shared<std::atomic<bool>>(false);
  {
    std::lock_guard<std::mutex> lock(mutex_);
    current_worker_done_ = done;
  }
  worker_ = std::thread([this, path, document, annotations, generation, done]() {
    WorkerDoneGuard done_guard{done};
    // Everything that touches the database happens in this scope so the
    // connection (and its WAL checkpoint) is released before busy_ is cleared.
    std::string failure;
    std::int64_t saved_image_id = 0;
    {
      auto project = Project::create(path);
      if (generation_.load() != generation) {
        return;
      }
      if (!project) {
        failure = project.diagnostic().message + " [" + project.diagnostic().code + "]";
      } else {
        auto image_id = project.value().import(document->loaded, document->analysis);
        if (!image_id) {
          failure = image_id.diagnostic().message + " [" + image_id.diagnostic().code + "]";
        } else {
          const std::vector<Annotation> rows = rows_from(*annotations);
          auto replaced = project.value().replace_annotations(image_id.value(), rows);
          if (!replaced) {
            failure = replaced.diagnostic().message + " [" + replaced.diagnostic().code + "]";
          } else {
            auto integrity = project.value().check_integrity();
            if (!integrity) {
              failure = integrity.diagnostic().message + " [" + integrity.diagnostic().code + "]";
            } else if (!integrity.value()) {
              failure = "integrity check failed";
            } else {
              saved_image_id = image_id.value();
            }
          }
        }
      }
    }
    if (!failure.empty()) {
      fail(generation, failure, "Failed to save project " + path);
      return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (generation_.load() == generation) {
      project_path_ = path;
      image_id_ = saved_image_id;
      dirty_ = false;
      status_ = "Saved project " + path;
      busy_.store(false);
    }
  });
}

void Session::backup_project(const std::string& destination, bool overwrite) {
  retire_worker();
  std::string source_path;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    source_path = project_path_;
  }
  if (source_path.empty()) {
    std::lock_guard<std::mutex> lock(mutex_);
    error_ = "no open project to back up [project.not_open]";
    status_ = "No open project";
    return;
  }
  if (destination.empty()) {
    std::lock_guard<std::mutex> lock(mutex_);
    error_ = "backup destination path is empty [project.backup_failed]";
    status_ = "Failed to back up project";
    return;
  }

  const std::uint64_t generation = generation_.fetch_add(1) + 1;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    status_ = "Backing up project to " + destination;
    error_.reset();
  }
  busy_.store(true);
  auto done = std::make_shared<std::atomic<bool>>(false);
  {
    std::lock_guard<std::mutex> lock(mutex_);
    current_worker_done_ = done;
  }
  worker_ = std::thread([this, source_path, destination, overwrite, generation, done]() {
    WorkerDoneGuard done_guard{done};
    std::string failure;
    {
      auto project = Project::open(source_path);
      if (generation_.load() != generation) {
        return;
      }
      if (!project) {
        failure = project.diagnostic().message + " [" + project.diagnostic().code + "]";
      } else {
        auto backed_up = project.value().backup(destination, overwrite);
        if (!backed_up) {
          failure = backed_up.diagnostic().message + " [" + backed_up.diagnostic().code + "]";
        }
      }
    }
    if (!failure.empty()) {
      fail(generation, failure, "Failed to back up project to " + destination);
      return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (generation_.load() == generation) {
      status_ = "Backed up project to " + destination;
      busy_.store(false);
    }
  });
}

void Session::restore_project(const std::string& backup_path) {
  retire_worker();
  std::string target_path;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    target_path = project_path_;
  }
  if (target_path.empty()) {
    std::lock_guard<std::mutex> lock(mutex_);
    error_ = "no open project to restore into [project.not_open]";
    status_ = "No open project";
    return;
  }
  if (backup_path.empty()) {
    std::lock_guard<std::mutex> lock(mutex_);
    error_ = "backup path is empty [project.backup_missing]";
    status_ = "Failed to restore project";
    return;
  }

  const std::uint64_t generation = generation_.fetch_add(1) + 1;
  CancellationToken token;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    current_cancellation_ = token;
    status_ = "Restoring project from " + backup_path;
    error_.reset();
  }
  busy_.store(true);
  auto done = std::make_shared<std::atomic<bool>>(false);
  {
    std::lock_guard<std::mutex> lock(mutex_);
    current_worker_done_ = done;
  }
  worker_ = std::thread([this, target_path, backup_path, generation, token, done]() {
    WorkerDoneGuard done_guard{done};
    if (generation_.load() != generation) {
      return;
    }
    if (token.is_cancelled()) {
      fail(generation, "Operation cancelled", "Cancelled");
      return;
    }
    // Earlier workers were cancelled but may still hold the project open; the
    // replacement needs exclusive access, so wait for them to finish.
    if (!wait_for_retired_workers(token)) {
      if (token.is_cancelled()) {
        fail(generation, "Operation cancelled", "Cancelled");
      } else {
        fail(generation, "a previous project operation is still running [project.replace_busy]",
             "Failed to restore project from " + backup_path);
      }
      return;
    }

    auto commit_hook = [this, generation](const std::string& temp,
                                          const std::string& dest) -> Result<void> {
      // Holding the lock makes "not superseded, not cancelled" and the rename
      // one step: cancel() and new operations wait until the commit is done.
      std::lock_guard<std::mutex> lock(mutex_);
      if (generation != generation_.load() || current_cancellation_.is_cancelled()) {
        return make_error<void>(Status::Cancelled, "io.cancelled",
                                "restore was superseded or cancelled before commit");
      }
      return Project::replace_file_atomically(temp, dest);
    };

    auto restored = Project::restore(target_path, backup_path, token, commit_hook);
    if (!restored) {
      if (restored.diagnostic().status == Status::Cancelled) {
        fail(generation, "Operation cancelled", "Cancelled");
      } else {
        fail(generation, restored.diagnostic().message + " [" + restored.diagnostic().code + "]",
             "Failed to restore project from " + backup_path);
      }
      return;
    }

    // Point of no return: the database on disk now holds the backup. From here
    // on the outcome is reported as a completed restore, whatever happens to
    // the cancellation token. Only the image reload below is cancellable.
    if (restore_post_commit_hook_) {
      restore_post_commit_hook_();
    }
    const std::string restored_status = "Restored project from " + backup_path;

    std::string image_path;
    std::int64_t image_id = 0;
    std::vector<Annotation> stored;
    std::string failure;
    {
      auto project = Project::open(target_path);
      if (!project) {
        failure = project.diagnostic().message + " [" + project.diagnostic().code + "]";
      } else {
        auto images = project.value().images();
        if (!images) {
          failure = images.diagnostic().message + " [" + images.diagnostic().code + "]";
        } else if (images.value().size() != 1) {
          failure = "the workspace shows one image at a time, this project has " +
                    std::to_string(images.value().size()) + " [project.multi_image_unsupported]";
        } else {
          image_path = images.value().front().path;
          image_id = images.value().front().id;
          auto annotations = project.value().annotations(image_id);
          if (!annotations) {
            failure = annotations.diagnostic().message + " [" + annotations.diagnostic().code + "]";
          } else {
            stored = std::move(annotations.value());
          }
        }
      }
    }

    auto annotations = annotations_from(stored);

    {
      // A newer operation started after the commit owns the workspace; it
      // decides what is shown. The restore itself is complete on disk.
      std::lock_guard<std::mutex> lock(mutex_);
      if (generation_.load() != generation) {
        return;
      }
      project_path_ = target_path;
      dirty_ = false;
      undo_stack_.clear();
      redo_stack_.clear();
      if (!failure.empty()) {
        // The in-memory annotations belong to the replaced database; showing
        // them as the restored project's would be wrong.
        annotations_ = std::make_shared<Annotations>();
        image_id_ = 0;
        error_ = "the project was restored, but reading it back failed: " + failure;
        status_ = restored_status + "; reading it back failed";
        busy_.store(false);
        return;
      }
      annotations_ = annotations;
      image_id_ = image_id;
      status_ = restored_status + "; reloading " + image_path;
    }

    LoadOptions load_opts;
    load_opts.cancellation_token = token;
    load_opts.progress = progress_reporter(generation);
    auto loaded = load_binary(image_path, load_opts);
    std::optional<AnalysisResult> analysis;
    std::string load_failure;
    if (!token.is_cancelled()) {
      if (!loaded) {
        load_failure = "could not load '" + image_path + "': " + loaded.diagnostic().message +
                       " [" + loaded.diagnostic().code + "]";
      } else {
        AnalysisOptions options = analysis_options_for(*annotations);
        options.cancellation_token = token;
        auto analysed = analyze(loaded.value().image, loaded.value().data, options);
        if (analysed) {
          analysis = std::move(analysed.value());
        } else if (!token.is_cancelled()) {
          load_failure = analysed.diagnostic().message + " [" + analysed.diagnostic().code + "]";
        }
      }
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (generation_.load() != generation) {
      return;
    }
    if (analysis.has_value()) {
      auto document = std::make_shared<Document>();
      document->loaded = std::move(loaded.value());
      document->analysis = std::move(*analysis);
      document_ = std::move(document);
      path_ = image_path;
      status_ = restored_status;
    } else {
      // Keep the open document only if it is the restored project's image.
      if (path_ != image_path) {
        document_.reset();
        path_ = image_path;
      }
      if (load_failure.empty()) {
        status_ = restored_status + "; image reload cancelled";
      } else {
        error_ = "the project was restored, but its image could not be reloaded: " + load_failure;
        status_ = restored_status + "; image reload failed";
      }
    }
    busy_.store(false);
  });
}

bool Session::wait_for_retired_workers(const CancellationToken& token) {
  using namespace std::chrono_literals;
  const auto deadline = std::chrono::steady_clock::now() + 10s;
  while (std::chrono::steady_clock::now() < deadline) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      bool all_done = true;
      for (const RetiredWorker& retired : retired_workers_) {
        if (retired.done && !retired.done->load()) {
          all_done = false;
          break;
        }
      }
      if (all_done) {
        return true;
      }
    }
    if (token.is_cancelled()) {
      return false;
    }
    std::this_thread::sleep_for(5ms);
  }
  return false;
}

void Session::set_load_hook_for_testing(std::function<void(const CancellationToken&)> hook) {
  std::lock_guard<std::mutex> lock(mutex_);
  load_hook_ = std::move(hook);
}

void Session::set_restore_post_commit_hook_for_testing(std::function<void()> hook) {
  restore_post_commit_hook_ = std::move(hook);
}

std::optional<std::string> Session::take_error() {
  std::lock_guard<std::mutex> lock(mutex_);
  auto error = std::move(error_);
  error_.reset();
  return error;
}

std::shared_ptr<const Document> Session::document() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return document_;
}

std::shared_ptr<const Annotations> Session::annotations() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return annotations_;
}

std::string Session::path() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return path_;
}

std::string Session::status() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return status_;
}

bool Session::has_project() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return !project_path_.empty();
}

std::string Session::project_path() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return project_path_;
}

bool Session::dirty() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return dirty_;
}

void Session::cancel() {
  std::lock_guard<std::mutex> lock(mutex_);
  current_cancellation_.cancel();
}

bool Session::is_cancelled() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return current_cancellation_.is_cancelled();
}

void Session::apply_annotation_edit_locked(AnnotationKind kind, std::uint64_t address,
                                           const std::string& text, bool record_undo) {
  std::string old_text;
  if (kind == AnnotationKind::Rename) {
    if (const auto* s = annotations_->rename_at(address)) {
      old_text = *s;
    }
  } else if (kind == AnnotationKind::Comment) {
    if (const auto* s = annotations_->comment_at(address)) {
      old_text = *s;
    }
  } else if (kind == AnnotationKind::Bookmark) {
    if (const auto* s = annotations_->bookmark_at(address)) {
      old_text = *s;
    }
  } else if (kind == AnnotationKind::FunctionStart) {
    if (const auto* s = annotations_->function_edit_at(address)) {
      old_text = *s;
    }
  }

  if (old_text == text) {
    return;
  }

  if (record_undo) {
    undo_stack_.push_back(AnnotationEdit{kind, address, old_text, text});
    redo_stack_.clear();
  }

  auto next = std::make_shared<Annotations>(*annotations_);
  auto& target = kind == AnnotationKind::Rename     ? next->renames
                 : kind == AnnotationKind::Comment  ? next->comments
                 : kind == AnnotationKind::Bookmark ? next->bookmarks
                                                    : next->functions;
  if (text.empty()) {
    target.erase(address);
  } else {
    target[address] = text;
  }
  annotations_ = std::move(next);
  dirty_ = true;
}

void Session::set_annotation(AnnotationKind kind, std::uint64_t address, const std::string& text) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    apply_annotation_edit_locked(kind, address, text, true);
  }
  after_annotation_change(kind);
}

void Session::set_function_edit(std::uint64_t address, const std::string& action) {
  set_annotation(AnnotationKind::FunctionStart, address, action);
}

void Session::after_annotation_change(AnnotationKind kind) {
  // Function boundaries change the analysis; every other annotation is
  // display-only.
  if (kind == AnnotationKind::FunctionStart) {
    reanalyze();
  }
}

bool Session::reanalysis_pending() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return reanalysis_pending_;
}

void Session::reanalyze() {
  std::shared_ptr<const Document> current;
  std::shared_ptr<const Annotations> annotations;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (busy_.load()) {
      // Never cancel a load or save for this; the workspace retries when
      // the worker is free.
      reanalysis_pending_ = true;
      return;
    }
    reanalysis_pending_ = false;
    current = document_;
    annotations = annotations_;
  }
  if (current == nullptr) {
    return;
  }
  retire_worker();
  const std::uint64_t generation = generation_.fetch_add(1) + 1;
  CancellationToken token;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    current_cancellation_ = token;
    status_ =
        "Re-analysing with " + std::to_string(annotations->functions.size()) + " function edit(s)";
    error_.reset();
  }
  busy_.store(true);
  auto done = std::make_shared<std::atomic<bool>>(false);
  {
    std::lock_guard<std::mutex> lock(mutex_);
    current_worker_done_ = done;
  }
  worker_ = std::thread([this, current, annotations, generation, token, done]() {
    WorkerDoneGuard done_guard{done};
    AnalysisOptions options = analysis_options_for(*annotations);
    options.cancellation_token = token;
    auto analysis = analyze(current->loaded.image, current->loaded.data, options);
    if (generation_.load() != generation) {
      return;
    }
    if (token.is_cancelled()) {
      fail(generation, "Operation cancelled", "Cancelled");
      return;
    }
    if (!analysis) {
      fail(generation, analysis.diagnostic().message + " [" + analysis.diagnostic().code + "]",
           "Failed to re-analyse");
      return;
    }
    // The loaded bytes are shared, not copied (ByteBuffer storage).
    auto document = std::make_shared<Document>();
    document->loaded = current->loaded;
    document->analysis = std::move(analysis.value());
    std::lock_guard<std::mutex> lock(mutex_);
    if (generation_.load() == generation) {
      document_ = std::move(document);
      status_ =
          "Re-analysed (" + std::to_string(document_->analysis.functions.size()) + " functions)";
      busy_.store(false);
    }
  });
}

void Session::toggle_bookmark(std::uint64_t address, const std::string& note) {
  std::lock_guard<std::mutex> lock(mutex_);
  const bool exists = annotations_->has_bookmark(address);
  apply_annotation_edit_locked(AnnotationKind::Bookmark, address, exists ? "" : note, true);
}

bool Session::undo() {
  std::unique_lock<std::mutex> lock(mutex_);
  if (undo_stack_.empty()) {
    return false;
  }
  AnnotationEdit edit = std::move(undo_stack_.back());
  undo_stack_.pop_back();
  apply_annotation_edit_locked(edit.kind, edit.address, edit.old_text, false);
  const AnnotationKind kind = edit.kind;
  redo_stack_.push_back(std::move(edit));
  lock.unlock();
  after_annotation_change(kind);
  return true;
}

bool Session::redo() {
  std::unique_lock<std::mutex> lock(mutex_);
  if (redo_stack_.empty()) {
    return false;
  }
  AnnotationEdit edit = std::move(redo_stack_.back());
  redo_stack_.pop_back();
  apply_annotation_edit_locked(edit.kind, edit.address, edit.new_text, false);
  const AnnotationKind kind = edit.kind;
  undo_stack_.push_back(std::move(edit));
  lock.unlock();
  after_annotation_change(kind);
  return true;
}

bool Session::can_undo() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return !undo_stack_.empty();
}

bool Session::can_redo() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return !redo_stack_.empty();
}

}  // namespace donkey::ui
