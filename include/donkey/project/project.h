#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/core/result.h"

namespace donkey {

/// Storage schema version written to `PRAGMA user_version`. It is independent
/// of the analysis engine version.
constexpr int kProjectSchemaVersion = 1;

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
  /// Runs `PRAGMA integrity_check` and `PRAGMA foreign_key_check`.
  [[nodiscard]] Result<bool> check_integrity() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace donkey
