#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/core/cancellation.h"
#include "donkey/core/result.h"

namespace donkey {

/// Storage schema version written to `PRAGMA user_version`. It is independent
/// of the analysis engine version.
constexpr int kProjectSchemaVersion = 3;

/// User annotations keyed by image address. They are stored separately from
/// derived analysis rows so re-importing a binary keeps them.
enum class AnnotationKind : std::uint8_t { Rename = 0, Comment = 1, Bookmark = 2 };
const char* annotation_kind_name(AnnotationKind kind) noexcept;

struct Annotation {
  AnnotationKind kind = AnnotationKind::Rename;
  std::uint64_t address = 0;
  std::string text;
};

struct ProjectImage {
  std::int64_t id = 0;
  std::string path;
  std::string sha256;
  std::string format;
  std::string architecture;
  unsigned bits = 0;
  std::uint64_t image_base = 0;
  std::uint64_t entry_point = 0;
  std::uint64_t file_size = 0;
  std::size_t sections = 0;
  std::size_t functions = 0;
  std::size_t annotations = 0;
  bool analysis_partial = false;
};

/// SQLite-backed project storage. Every mutation is transactional and the
/// storage schema is migrated forward with `PRAGMA user_version`. The original
/// binary is referenced by path and SHA-256, never copied silently.
class Project {
 public:
  Project() = default;
  ~Project();
  Project(Project&& other) noexcept;
  Project& operator=(Project&& other) noexcept;
  Project(const Project&) = delete;
  Project& operator=(const Project&) = delete;

  /// Open an existing project database and migrate it forward if needed.
  [[nodiscard]] static Result<Project> open(const std::string& path);
  /// Create the database when absent, then behave like `open`.
  [[nodiscard]] static Result<Project> create(const std::string& path);

  [[nodiscard]] bool is_open() const noexcept;
  [[nodiscard]] const std::string& path() const noexcept;
  [[nodiscard]] int schema_version() const noexcept;

  /// Insert or update one image and its derived sections, functions and
  /// analysis summary in a single transaction. Re-importing the same SHA-256
  /// replaces the previous derived rows instead of duplicating them.
  [[nodiscard]] Result<std::int64_t> import(const LoadedBinary& loaded,
                                            const AnalysisResult& analysis);

  [[nodiscard]] Result<std::vector<ProjectImage>> images() const;

  /// Set or replace a user annotation. Empty text clears the annotation.
  /// Annotations are keyed by image address and survive re-import.
  [[nodiscard]] Result<void> set_annotation(std::int64_t image_id, AnnotationKind kind,
                                            std::uint64_t address, const std::string& text);

  /// Remove one annotation. Removing an absent annotation succeeds.
  [[nodiscard]] Result<void> clear_annotation(std::int64_t image_id, AnnotationKind kind,
                                              std::uint64_t address);

  /// Persisted annotations for one image, ordered by address then kind.
  [[nodiscard]] Result<std::vector<Annotation>> annotations(std::int64_t image_id) const;

  /// Replace every annotation for one image in a single transaction. Used by
  /// the desktop shell to flush its in-memory annotation snapshot.
  [[nodiscard]] Result<void> replace_annotations(std::int64_t image_id,
                                                 const std::vector<Annotation>& annotations);

  /// Runs `PRAGMA integrity_check` and `PRAGMA foreign_key_check`.
  [[nodiscard]] Result<bool> check_integrity() const;

  /// Write a consistent, self-contained copy of the open project to
  /// `destination` using SQLite's online backup API (so WAL content is
  /// included). The copy is written to a temporary file first and renamed into
  /// place, so a failed backup never damages an existing destination. Refuses
  /// to replace an existing file unless `overwrite` is true.
  [[nodiscard]] Result<void> backup(const std::string& destination, bool overwrite = false) const;

  /// Replace `database_path` with `backup_path` after validating that the
  /// backup is a readable project with a supported schema and passing
  /// `PRAGMA integrity_check`. The replacement is written to a temporary file
  /// and renamed into place. The destination must not have an active SQLite
  /// connection open while it is replaced.
  [[nodiscard]] static Result<void> restore(const std::string& database_path,
                                            const std::string& backup_path,
                                            const CancellationToken& cancellation_token = {});

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace donkey
