#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/core/cancellation.h"
#include "donkey/core/result.h"
#include "donkey/project/types.h"

namespace donkey {

/// Storage schema version written to `PRAGMA user_version`. It is independent
/// of the analysis engine version.
constexpr int kProjectSchemaVersion = 7;

/// User annotations keyed by image address. They are stored separately from
/// derived analysis rows so re-importing a binary keeps them.
/// FunctionStart records a user edit of function boundaries at `address`:
/// text "define" adds a function start, "remove" deletes a discovered one.
/// CodeStart (G12-T1) makes `address` a code start; its text must be "code".
/// DataRange (G12-T1) makes the bytes at `address` data, not code; its text is
/// "<element size>:<count>" (see parse_data_range_text). Element size 0 is undefined
/// bytes, so a range of size 0 is how the user undefines code that analysis found.
enum class AnnotationKind : std::uint8_t {
  Rename = 0,
  Comment = 1,
  Bookmark = 2,
  FunctionStart = 3,
  CodeStart = 4,
  DataRange = 5
};
const char* annotation_kind_name(AnnotationKind kind) noexcept;

/// Largest byte length one DataRange may cover (element size times count, or count when the
/// element size is 0). A larger range is refused, so a single annotation cannot make the
/// analysis skip an unbounded part of the binary by accident.
inline constexpr std::uint64_t kMaxDataRangeBytes = 16ULL * 1024ULL * 1024ULL;

/// Parses a DataRange text "<element size>:<count>". The element size must be 0, 1, 2, 4 or
/// 8, the count at least 1, and the byte length within kMaxDataRangeBytes. Returns false on
/// any other text, so the caller reports the annotation as invalid rather than guessing.
[[nodiscard]] bool parse_data_range_text(const std::string& text, std::uint64_t& element_size,
                                         std::uint64_t& count) noexcept;
/// The canonical DataRange text for an element size and count.
[[nodiscard]] std::string format_data_range_text(std::uint64_t element_size, std::uint64_t count);

/// Parses either DataRange form (G12-T2): "<element size>:<count>" as above, or "string:<bytes>",
/// a NUL-terminated string of that many bytes including the terminator, read as an array of
/// one-byte elements (`is_string` is then true, element size 1, count bytes). The byte length is
/// within kMaxDataRangeBytes, and the bytes are at least 1.
[[nodiscard]] bool parse_data_extent(const std::string& text, std::uint64_t& element_size,
                                     std::uint64_t& count, bool& is_string) noexcept;
/// The canonical DataRange text for a string of `bytes` bytes, terminator included.
[[nodiscard]] std::string format_string_range_text(std::uint64_t bytes);

struct Annotation {
  AnnotationKind kind = AnnotationKind::Rename;
  std::uint64_t address = 0;
  std::string text;
};

/// A user name for one local of one function (G12-T3). `variable` is the local's key in the
/// function's IR: "arg:<index>" for a parameter, or "frame:<base register>:<offset>" for a frame
/// slot, where the offset is signed decimal. The key is checked for shape here. Whether it still
/// names a local after re-analysis is decided when the name is applied, so a name whose key no
/// longer exists is kept but has no effect.
struct LocalName {
  std::uint64_t function_address = 0;
  std::string variable;
  std::string name;
};

/// True when `variable` has the shape of a local key (see LocalName).
[[nodiscard]] bool local_variable_key_valid(const std::string& variable) noexcept;

/// Where a type is applied (G05-T3 uses these): a function prototype at its entry, or a
/// data slot (a stack slot or a global) at its address.
enum class TypeApplicationKind : std::uint8_t { FunctionPrototype = 0, DataSlot = 1 };

struct TypeApplication {
  TypeApplicationKind kind = TypeApplicationKind::FunctionPrototype;
  std::uint64_t address = 0;
  TypeId type_id{};
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
/// Boundaries inside `Project::replace_file_atomically`, exposed so tests can
/// inject a simulated crash at each one.
enum class ReplaceStage : std::uint8_t {
  Quiesced = 0,  ///< target WAL folded, nothing renamed yet
  Synced = 1,    ///< replacement flushed, rename not yet issued
  Renamed = 2,   ///< rename done, directory entry not yet flushed
};
using ReplaceFaultHook = std::function<bool(ReplaceStage)>;

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

  /// Set or replace the user name of one local of the function at `function_address` (G12-T3).
  /// Empty text clears the name. The key must have the shape of a LocalName variable, and the
  /// name must be a C identifier of at most 128 bytes.
  [[nodiscard]] Result<void> set_local_name(std::int64_t image_id, std::uint64_t function_address,
                                            const std::string& variable, const std::string& name);

  /// Every user local name for one image, ordered by function address then key.
  [[nodiscard]] Result<std::vector<LocalName>> local_names(std::int64_t image_id) const;

  /// Every type in the project's type store (G05-T1), validated as a whole.
  [[nodiscard]] Result<TypeTable> types() const;

  /// Replace the whole type store in one transaction. The table is validated first; an
  /// invalid table is refused and nothing changes. A type removed from the table takes
  /// its applications with it.
  [[nodiscard]] Result<void> replace_types(const TypeTable& table);

  /// Type applications for one image, ordered by address.
  [[nodiscard]] Result<std::vector<TypeApplication>> type_applications(std::int64_t image_id) const;

  /// Apply a type to an address of an image. A type id of zero removes the application.
  [[nodiscard]] Result<void> set_type_application(std::int64_t image_id, TypeApplicationKind kind,
                                                  std::uint64_t address, TypeId type_id);

  /// Runs `PRAGMA integrity_check` and `PRAGMA foreign_key_check`.
  [[nodiscard]] Result<bool> check_integrity() const;

  /// Write a consistent, self-contained copy of the open project to
  /// `destination` using SQLite's online backup API (so WAL content is
  /// included). The copy is written to a temporary file first and renamed into
  /// place, so a failed backup never damages an existing destination. Refuses
  /// to replace an existing file unless `overwrite` is true, and always
  /// refuses a destination that is the open database itself (including
  /// through symlinks or hard links) with `project.backup_is_source`.
  [[nodiscard]] Result<void> backup(const std::string& destination, bool overwrite = false) const;

  /// Replace the database at `target_path` with the self-contained file at
  /// `temp_path` (same volume). The target's WAL is folded into it first,
  /// which fails with `project.replace_busy` if any other connection still
  /// has it open; then one atomic rename swaps the files. An interruption at
  /// any point leaves either the complete old database or the complete new
  /// one. On failure `temp_path` is left for the caller to remove.
  [[nodiscard]] static Result<void> replace_file_atomically(const std::string& temp_path,
                                                            const std::string& target_path);

  /// Test-only: called at each boundary of `replace_file_atomically`; when it
  /// returns true the replacement stops there with no cleanup, as if the
  /// process had died. Pass an empty function to remove it.
  static void set_replace_fault_hook_for_testing(ReplaceFaultHook hook);

  using RestoreCommitHook =
      std::function<Result<void>(const std::string& temp_path, const std::string& target_path)>;

  /// Replace `database_path` with `backup_path` after validating that the
  /// backup is a readable project with a supported schema and passing
  /// `PRAGMA integrity_check`. The replacement is written to a temporary file
  /// and atomically renamed into place. The destination must not have an active SQLite
  /// connection open while it is replaced.
  [[nodiscard]] static Result<void> restore(const std::string& database_path,
                                            const std::string& backup_path,
                                            const CancellationToken& cancellation_token = {},
                                            RestoreCommitHook commit_hook = nullptr);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace donkey
