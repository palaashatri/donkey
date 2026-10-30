#include "session.h"

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

}  // namespace

Session::~Session() {
  join_worker();
}

void Session::join_worker() {
  if (worker_.joinable()) {
    worker_.join();
  }
}

void Session::fail(const std::string& message, const std::string& status) {
  std::lock_guard<std::mutex> lock(mutex_);
  error_ = message;
  status_ = status;
  busy_.store(false);
}

void Session::publish_project(std::string path, std::int64_t image_id) {
  std::lock_guard<std::mutex> lock(mutex_);
  project_path_ = std::move(path);
  image_id_ = image_id;
  dirty_ = false;
}

void Session::open(const std::string& path) {
  join_worker();
  const std::uint64_t generation = generation_.fetch_add(1) + 1;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    path_ = path;
    status_ = "Loading " + path;
    error_.reset();
  }
  busy_.store(true);
  worker_ = std::thread([this, path, generation]() {
    auto loaded = load_binary(path);
    if (generation_.load() != generation) {
      return;
    }
    if (!loaded) {
      fail(loaded.diagnostic().message + " [" + loaded.diagnostic().code + "]",
           "Failed to load " + path);
      return;
    }

    auto analysis = analyze(loaded.value().image, loaded.value().data, analysis_options());
    if (generation_.load() != generation) {
      return;
    }
    if (!analysis) {
      fail(analysis.diagnostic().message + " [" + analysis.diagnostic().code + "]",
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
  join_worker();
  const std::uint64_t generation = generation_.fetch_add(1) + 1;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    status_ = "Opening project " + path;
    error_.reset();
  }
  busy_.store(true);
  worker_ = std::thread([this, path, generation]() {
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
      if (generation_.load() != generation) {
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
    if (generation_.load() != generation) {
      return;
    }
    if (!failure.empty()) {
      fail(failure, failure_status);
      return;
    }

    auto loaded = load_binary(image_path);
    if (generation_.load() != generation) {
      return;
    }
    if (!loaded) {
      fail("could not load '" + image_path + "': " + loaded.diagnostic().message + " [" +
               loaded.diagnostic().code + "]",
           "Failed to load project image");
      return;
    }
    auto analysis = analyze(loaded.value().image, loaded.value().data, analysis_options());
    if (generation_.load() != generation) {
      return;
    }
    if (!analysis) {
      fail(analysis.diagnostic().message + " [" + analysis.diagnostic().code + "]",
           "Failed to analyse project image");
      return;
    }

    auto annotations = std::make_shared<Annotations>();
    for (const Annotation& annotation : stored) {
      if (annotation.kind == AnnotationKind::Rename) {
        annotations->renames[annotation.address] = annotation.text;
      } else {
        annotations->comments[annotation.address] = annotation.text;
      }
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
  join_worker();
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
  worker_ = std::thread([this, path, document, annotations, generation]() {
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
          std::vector<Annotation> rows;
          rows.reserve(annotations->renames.size() + annotations->comments.size());
          for (const auto& [address, text] : annotations->renames) {
            rows.push_back(Annotation{AnnotationKind::Rename, address, text});
          }
          for (const auto& [address, text] : annotations->comments) {
            rows.push_back(Annotation{AnnotationKind::Comment, address, text});
          }
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
    if (generation_.load() != generation) {
      return;
    }
    if (!failure.empty()) {
      fail(failure, "Failed to save project " + path);
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
  join_worker();
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
  worker_ = std::thread([this, source_path, destination, overwrite, generation]() {
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
    if (generation_.load() != generation) {
      return;
    }
    if (!failure.empty()) {
      fail(failure, "Failed to back up project to " + destination);
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
  join_worker();
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
  {
    std::lock_guard<std::mutex> lock(mutex_);
    status_ = "Restoring project from " + backup_path;
    error_.reset();
  }
  busy_.store(true);
  worker_ = std::thread([this, target_path, backup_path, generation]() {
    auto restored = Project::restore(target_path, backup_path);
    if (generation_.load() != generation) {
      return;
    }
    if (!restored) {
      fail(restored.diagnostic().message + " [" + restored.diagnostic().code + "]",
           "Failed to restore project from " + backup_path);
      return;
    }

    std::string image_path;
    std::int64_t image_id = 0;
    std::vector<Annotation> stored;
    std::string failure;
    std::string failure_status;
    {
      auto project = Project::open(target_path);
      if (generation_.load() != generation) {
        return;
      }
      if (!project) {
        failure = project.diagnostic().message + " [" + project.diagnostic().code + "]";
        failure_status = "Failed to open restored project " + target_path;
      } else {
        auto images = project.value().images();
        if (!images) {
          failure = images.diagnostic().message + " [" + images.diagnostic().code + "]";
          failure_status = "Failed to read restored project " + target_path;
        } else if (images.value().size() != 1) {
          failure =
              "project.multi_image_unsupported: the workspace shows one image at a time, "
              "this project has " +
              std::to_string(images.value().size());
          failure_status = "Failed to open restored project " + target_path;
        } else {
          image_path = images.value().front().path;
          image_id = images.value().front().id;
          auto annotations = project.value().annotations(image_id);
          if (!annotations) {
            failure = annotations.diagnostic().message + " [" + annotations.diagnostic().code + "]";
            failure_status = "Failed to read restored annotations";
          } else {
            stored = std::move(annotations.value());
          }
        }
      }
    }
    if (generation_.load() != generation) {
      return;
    }
    if (!failure.empty()) {
      fail(failure, failure_status);
      return;
    }

    auto loaded = load_binary(image_path);
    if (generation_.load() != generation) {
      return;
    }
    if (!loaded) {
      fail("could not load '" + image_path + "': " + loaded.diagnostic().message + " [" +
               loaded.diagnostic().code + "]",
           "Failed to load restored project image");
      return;
    }
    auto analysis = analyze(loaded.value().image, loaded.value().data, analysis_options());
    if (generation_.load() != generation) {
      return;
    }
    if (!analysis) {
      fail(analysis.diagnostic().message + " [" + analysis.diagnostic().code + "]",
           "Failed to analyse restored project image");
      return;
    }

    auto annotations = std::make_shared<Annotations>();
    for (const Annotation& annotation : stored) {
      if (annotation.kind == AnnotationKind::Rename) {
        annotations->renames[annotation.address] = annotation.text;
      } else {
        annotations->comments[annotation.address] = annotation.text;
      }
    }

    auto document = std::make_shared<Document>();
    document->loaded = std::move(loaded.value());
    document->analysis = std::move(analysis.value());

    std::lock_guard<std::mutex> lock(mutex_);
    if (generation_.load() == generation) {
      document_ = std::move(document);
      annotations_ = std::move(annotations);
      path_ = image_path;
      project_path_ = target_path;
      image_id_ = image_id;
      dirty_ = false;
      status_ = "Restored project from " + backup_path;
      busy_.store(false);
    }
  });
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

void Session::set_annotation(AnnotationKind kind, std::uint64_t address, const std::string& text) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto next = std::make_shared<Annotations>(*annotations_);
  auto& target = kind == AnnotationKind::Rename ? next->renames : next->comments;
  if (text.empty()) {
    target.erase(address);
  } else {
    target[address] = text;
  }
  annotations_ = std::move(next);
  dirty_ = true;
}

}  // namespace donkey::ui
