#include "donkey/project/project.h"

#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <utility>

#include <sqlite3.h>

#include "donkey/core/version.h"

namespace donkey {

const char* annotation_kind_name(AnnotationKind kind) noexcept {
  switch (kind) {
    case AnnotationKind::Rename:
      return "rename";
    case AnnotationKind::Comment:
      return "comment";
  }
  return "unknown";
}

namespace {

constexpr const char* kSchemaV1 = R"sql(
CREATE TABLE images (
  id            INTEGER PRIMARY KEY,
  path          TEXT    NOT NULL,
  sha256        TEXT    NOT NULL UNIQUE,
  format        TEXT    NOT NULL,
  architecture  TEXT    NOT NULL,
  bits          INTEGER NOT NULL,
  endian        TEXT    NOT NULL,
  image_base    INTEGER NOT NULL,
  entry_point   INTEGER NOT NULL,
  file_size     INTEGER NOT NULL,
  imported_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE sections (
  id        INTEGER PRIMARY KEY,
  image_id  INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,
  ordinal   INTEGER NOT NULL,
  name      TEXT    NOT NULL,
  address   INTEGER NOT NULL,
  size      INTEGER NOT NULL,
  perm      TEXT    NOT NULL,
  UNIQUE (image_id, ordinal)
);

CREATE TABLE functions (
  id           INTEGER PRIMARY KEY,
  image_id     INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,
  address      INTEGER NOT NULL,
  end_address  INTEGER,
  name         TEXT    NOT NULL,
  exported     INTEGER NOT NULL,
  estimated    INTEGER NOT NULL,
  block_count  INTEGER NOT NULL,
  UNIQUE (image_id, address)
);

CREATE TABLE analysis_runs (
  id            INTEGER PRIMARY KEY,
  image_id      INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,
  tool_version  TEXT    NOT NULL,
  partial       INTEGER NOT NULL,
  instructions  INTEGER NOT NULL,
  xrefs         INTEGER NOT NULL,
  strings       INTEGER NOT NULL,
  created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX sections_by_image ON sections(image_id);
CREATE INDEX functions_by_image ON functions(image_id);
CREATE INDEX analysis_runs_by_image ON analysis_runs(image_id);
)sql";

/// v2 adds user annotations. They are keyed by address inside an image so they
/// survive re-import, which replaces only derived analysis rows.
constexpr const char* kSchemaV2 = R"sql(
CREATE TABLE annotations (
  image_id   INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,
  kind       TEXT    NOT NULL CHECK (kind IN ('rename', 'comment')),
  address    INTEGER NOT NULL,
  text       TEXT    NOT NULL,
  updated_at TEXT    NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (image_id, kind, address)
);
)sql";

Diagnostic storage_error(sqlite3* db, std::string code, const std::string& context) {
  const char* message = db != nullptr ? sqlite3_errmsg(db) : "no database";
  return Diagnostic::make(Status::InternalError, std::move(code),
                          context + ": " + (message != nullptr ? message : "unknown error"));
}

/// Thin RAII wrapper. Callers check `ok()` after construction and `done()`
/// after stepping; no exception is ever thrown across the storage boundary.
class Statement {
 public:
  Statement(sqlite3* db, const char* sql) {
    ok_ = sqlite3_prepare_v2(db, sql, -1, &stmt_, nullptr) == SQLITE_OK;
  }
  ~Statement() {
    if (stmt_ != nullptr) {
      sqlite3_finalize(stmt_);
    }
  }
  Statement(const Statement&) = delete;
  Statement& operator=(const Statement&) = delete;

  [[nodiscard]] bool ok() const noexcept { return ok_; }

  void bind(int index, std::int64_t value) {
    if (ok_) {
      ok_ = sqlite3_bind_int64(stmt_, index, value) == SQLITE_OK;
    }
  }
  void bind(int index, const std::string& value) {
    if (ok_) {
      ok_ = sqlite3_bind_text(stmt_, index, value.c_str(), -1, SQLITE_TRANSIENT) == SQLITE_OK;
    }
  }
  void bind_null(int index) {
    if (ok_) {
      ok_ = sqlite3_bind_null(stmt_, index) == SQLITE_OK;
    }
  }

  /// True when a row is available. Returns false on SQLITE_DONE or error.
  bool step() {
    if (!ok_) {
      return false;
    }
    const int code = sqlite3_step(stmt_);
    if (code == SQLITE_ROW) {
      return true;
    }
    ok_ = code == SQLITE_DONE;
    return false;
  }
  /// Runs a statement that returns no rows. Returns true only when it reaches
  /// SQLITE_DONE; a SELECT would report failure here.
  bool execute_statement() {
    if (!ok_) {
      return false;
    }
    ok_ = sqlite3_step(stmt_) == SQLITE_DONE;
    return ok_;
  }
  [[nodiscard]] bool done() const noexcept { return ok_; }
  [[nodiscard]] std::int64_t integer(int column) const {
    return sqlite3_column_int64(stmt_, column);
  }
  [[nodiscard]] std::string text(int column) const {
    const unsigned char* value = sqlite3_column_text(stmt_, column);
    return value != nullptr ? reinterpret_cast<const char*>(value) : std::string();
  }

 private:
  sqlite3_stmt* stmt_ = nullptr;
  bool ok_ = false;
};

bool execute(sqlite3* db, const char* sql) {
  return sqlite3_exec(db, sql, nullptr, nullptr, nullptr) == SQLITE_OK;
}

Result<int> read_schema_version(sqlite3* db) {
  Statement statement(db, "PRAGMA user_version");
  if (!statement.ok() || !statement.step()) {
    return make_error<int>(Status::CorruptProject, "project.schema_read_failed",
                           "could not read PRAGMA user_version");
  }
  const std::int64_t version = statement.integer(0);
  if (version < 0 || version > std::numeric_limits<int>::max()) {
    return make_error<int>(Status::CorruptProject, "project.schema_version_invalid",
                           "project schema version is out of range");
  }
  return static_cast<int>(version);
}

bool fits_storage(std::uint64_t value) {
  return value <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
}

std::string permissions(const Section& section) {
  std::string out = "---";
  out[0] = section.readable ? 'r' : '-';
  out[1] = section.writable ? 'w' : '-';
  out[2] = section.executable ? 'x' : '-';
  return out;
}

}  // namespace

struct Project::Impl {
  sqlite3* db = nullptr;
  std::string path;
  int schema_version = 0;

  ~Impl() {
    if (db != nullptr) {
      // Fold the WAL back into the main database so a project can be copied
      // without carrying sidecar files.
      sqlite3_wal_checkpoint_v2(db, nullptr, SQLITE_CHECKPOINT_TRUNCATE, nullptr, nullptr);
      sqlite3_close(db);
      db = nullptr;
    }
  }
};

Project::~Project() = default;
Project::Project(Project&& other) noexcept = default;
Project& Project::operator=(Project&& other) noexcept = default;

Result<Project> Project::open(const std::string& path) {
  {
    Project project;
    project.impl_ = std::make_unique<Impl>();
    project.impl_->path = path;

    sqlite3* db = nullptr;
    const int open_result = sqlite3_open_v2(path.c_str(), &db, SQLITE_OPEN_READWRITE, nullptr);
    if (open_result != SQLITE_OK) {
      const std::string message = db != nullptr ? sqlite3_errmsg(db) : "unknown error";
      if (db != nullptr) {
        sqlite3_close(db);
      }
      return make_error<Project>(Status::CorruptProject, "project.open_failed",
                                 "could not open project '" + path + "': " + message);
    }
    project.impl_->db = db;

    if (!execute(db, "PRAGMA foreign_keys=ON") || !execute(db, "PRAGMA synchronous=FULL")) {
      // A file that is not a SQLite database must be reported as corrupt input,
      // not as an internal failure of the storage layer.
      const int code = sqlite3_extended_errcode(db) & 0xFF;
      const Status status = (code == SQLITE_NOTADB || code == SQLITE_CORRUPT)
                                ? Status::CorruptProject
                                : Status::InternalError;
      return make_error<Project>(
          status, "project.pragma_failed",
          storage_error(db, "project.pragma_failed", "could not set pragmas").message);
    }
    // WAL is best-effort: filesystems that refuse it still work in rollback
    // journal mode. The statement must be finalized before any transaction
    // begins, otherwise its read lock keeps BEGIN IMMEDIATE from running.
    {
      Statement journal(db, "PRAGMA journal_mode=WAL");
      if (journal.ok()) {
        journal.step();
      }
    }

    auto version = read_schema_version(db);
    if (!version) {
      return make_error<Project>(version.diagnostic().status, version.diagnostic().code,
                                 version.diagnostic().message);
    }
    int schema = version.value();
    if (schema > kProjectSchemaVersion) {
      return make_error<Project>(Status::Unsupported, "project.schema_too_new",
                                 "project schema " + std::to_string(schema) +
                                     " is newer than supported schema " +
                                     std::to_string(kProjectSchemaVersion));
    }
    if (schema == 0) {
      const int rc_begin = sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr);
      const int rc_schema = sqlite3_exec(db, kSchemaV1, nullptr, nullptr, nullptr);
      const int rc_schema2 = sqlite3_exec(db, kSchemaV2, nullptr, nullptr, nullptr);
      const int rc_version = sqlite3_exec(db, "PRAGMA user_version=2", nullptr, nullptr, nullptr);
      const int rc_commit = sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr);
      if (rc_begin != SQLITE_OK || rc_schema != SQLITE_OK || rc_schema2 != SQLITE_OK ||
          rc_version != SQLITE_OK || rc_commit != SQLITE_OK) {
        execute(db, "ROLLBACK");
        return make_error<Project>(Status::InternalError, "project.migration_failed",
                                   "migrate: " + std::string(sqlite3_errstr(rc_begin)) + "/" +
                                       std::string(sqlite3_errstr(rc_schema)) + "/" +
                                       std::string(sqlite3_errstr(rc_schema2)) + "/" +
                                       std::string(sqlite3_errstr(rc_version)) + "/" +
                                       std::string(sqlite3_errstr(rc_commit)) +
                                       " msg=" + sqlite3_errmsg(db));
      }
      schema = 2;
    } else if (schema == 1) {
      const int rc_begin = sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr);
      const int rc_schema = sqlite3_exec(db, kSchemaV2, nullptr, nullptr, nullptr);
      const int rc_version = sqlite3_exec(db, "PRAGMA user_version=2", nullptr, nullptr, nullptr);
      const int rc_commit = sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr);
      if (rc_begin != SQLITE_OK || rc_schema != SQLITE_OK || rc_version != SQLITE_OK ||
          rc_commit != SQLITE_OK) {
        execute(db, "ROLLBACK");
        return make_error<Project>(Status::InternalError, "project.migration_failed",
                                   "migrate v1->v2: " + std::string(sqlite3_errstr(rc_begin)) +
                                       "/" + std::string(sqlite3_errstr(rc_schema)) + "/" +
                                       std::string(sqlite3_errstr(rc_version)) + "/" +
                                       std::string(sqlite3_errstr(rc_commit)) +
                                       " msg=" + sqlite3_errmsg(db));
      }
      schema = 2;
    }
    project.impl_->schema_version = schema;
    return project;
  }
}

Result<Project> Project::create(const std::string& path) {
  {
    sqlite3* probe = nullptr;
    const int result =
        sqlite3_open_v2(path.c_str(), &probe, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
    if (result != SQLITE_OK) {
      const std::string message = probe != nullptr ? sqlite3_errmsg(probe) : "unknown error";
      if (probe != nullptr) {
        sqlite3_close(probe);
      }
      return make_error<Project>(Status::CorruptProject, "project.create_failed",
                                 "could not create project '" + path + "': " + message);
    }
    sqlite3_close(probe);
  }
  return open(path);
}

bool Project::is_open() const noexcept {
  return impl_ != nullptr && impl_->db != nullptr;
}

const std::string& Project::path() const noexcept {
  static const std::string empty;
  return impl_ != nullptr ? impl_->path : empty;
}

int Project::schema_version() const noexcept {
  return impl_ != nullptr ? impl_->schema_version : 0;
}

Result<std::int64_t> Project::import(const LoadedBinary& loaded, const AnalysisResult& analysis) {
  if (!is_open()) {
    return make_error<std::int64_t>(Status::InvalidInput, "project.not_open",
                                    "no project database is open");
  }
  sqlite3* db = impl_->db;
  const BinaryImage& image = loaded.image;
  if (image.sha256.empty()) {
    return make_error<std::int64_t>(Status::InvalidInput, "project.missing_hash",
                                    "image has no SHA-256; refusing to import");
  }
  const std::uint64_t addresses[] = {image.image_base, image.entry_point, image.file_size};
  for (const std::uint64_t value : addresses) {
    if (!fits_storage(value)) {
      return make_error<std::int64_t>(Status::InvalidInput, "project.value_out_of_range",
                                      "image metadata does not fit the storage integer range",
                                      value);
    }
  }
  for (const Function& function : analysis.functions) {
    if (!fits_storage(function.address) ||
        (function.has_extent && !fits_storage(function.end_address))) {
      return make_error<std::int64_t>(Status::InvalidInput, "project.value_out_of_range",
                                      "function address does not fit the storage integer range",
                                      function.address);
    }
  }

  if (!execute(db, "BEGIN IMMEDIATE")) {
    return make_error<std::int64_t>(
        Status::InternalError, "project.transaction_failed",
        storage_error(db, "project.transaction_failed", "begin").message);
  }
  auto fail = [&](Status status, std::string code, std::string message,
                  std::optional<std::uint64_t> offset = std::nullopt) {
    execute(db, "ROLLBACK");
    return make_error<std::int64_t>(status, std::move(code), std::move(message), offset);
  };

  std::int64_t image_id = 0;
  {
    Statement query(db, "SELECT id FROM images WHERE sha256 = ?1");
    query.bind(1, image.sha256);
    if (!query.ok() || !query.step()) {
      if (!query.done()) {
        return fail(Status::InternalError, "project.query_failed",
                    storage_error(db, "project.query_failed", "lookup image").message);
      }
    } else {
      image_id = query.integer(0);
    }
  }

  if (image_id != 0) {
    // Re-import replaces derived rows so stale analysis never survives.
    for (const char* table : {"sections", "functions", "analysis_runs"}) {
      Statement remove(db, (std::string("DELETE FROM ") + table + " WHERE image_id = ?1").c_str());
      remove.bind(1, image_id);
      if (!remove.execute_statement()) {
        return fail(Status::InternalError, "project.delete_failed",
                    storage_error(db, "project.delete_failed", table).message);
      }
    }
    Statement update(db,
                     "UPDATE images SET path=?2, format=?3, architecture=?4, bits=?5, endian=?6, "
                     "image_base=?7, entry_point=?8, file_size=?9, imported_at=datetime('now') "
                     "WHERE id=?1");
    update.bind(1, image_id);
    update.bind(2, image.path);
    update.bind(3, format_name(image.format));
    update.bind(4, architecture_name(image.architecture));
    update.bind(5, static_cast<std::int64_t>(image.bits));
    update.bind(6, endian_name(image.endian));
    update.bind(7, static_cast<std::int64_t>(image.image_base));
    update.bind(8, static_cast<std::int64_t>(image.entry_point));
    update.bind(9, static_cast<std::int64_t>(image.file_size));
    if (!update.execute_statement()) {
      return fail(Status::InternalError, "project.update_failed",
                  storage_error(db, "project.update_failed", "image").message);
    }
  } else {
    Statement insert(
        db,
        "INSERT INTO images(path, sha256, format, architecture, bits, endian, image_base, "
        "entry_point, file_size) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)");
    insert.bind(1, image.path);
    insert.bind(2, image.sha256);
    insert.bind(3, format_name(image.format));
    insert.bind(4, architecture_name(image.architecture));
    insert.bind(5, static_cast<std::int64_t>(image.bits));
    insert.bind(6, endian_name(image.endian));
    insert.bind(7, static_cast<std::int64_t>(image.image_base));
    insert.bind(8, static_cast<std::int64_t>(image.entry_point));
    insert.bind(9, static_cast<std::int64_t>(image.file_size));
    if (!insert.execute_statement()) {
      return fail(Status::InternalError, "project.insert_failed",
                  storage_error(db, "project.insert_failed", "image").message);
    }
    image_id = sqlite3_last_insert_rowid(db);
  }

  for (std::size_t ordinal = 0; ordinal < image.sections.size(); ++ordinal) {
    const Section& section = image.sections[ordinal];
    if (!fits_storage(section.address)) {
      return fail(Status::InvalidInput, "project.value_out_of_range",
                  "section address does not fit the storage integer range", section.address);
    }
    const std::uint64_t size = section.virtual_size != 0 ? section.virtual_size : section.file_size;
    if (!fits_storage(size)) {
      return fail(Status::InvalidInput, "project.value_out_of_range",
                  "section size does not fit the storage integer range", size);
    }
    Statement insert(db,
                     "INSERT INTO sections(image_id, ordinal, name, address, size, perm) "
                     "VALUES(?1, ?2, ?3, ?4, ?5, ?6)");
    insert.bind(1, image_id);
    insert.bind(2, static_cast<std::int64_t>(ordinal));
    insert.bind(3, section.name);
    insert.bind(4, static_cast<std::int64_t>(section.address));
    insert.bind(5, static_cast<std::int64_t>(size));
    insert.bind(6, permissions(section));
    if (!insert.execute_statement()) {
      return fail(Status::InternalError, "project.insert_failed",
                  storage_error(db, "project.insert_failed", "section").message);
    }
  }

  for (const Function& function : analysis.functions) {
    Statement insert(
        db,
        "INSERT INTO functions(image_id, address, end_address, name, exported, estimated, "
        "block_count) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)");
    insert.bind(1, image_id);
    insert.bind(2, static_cast<std::int64_t>(function.address));
    if (function.has_extent) {
      insert.bind(3, static_cast<std::int64_t>(function.end_address));
    } else {
      insert.bind_null(3);
    }
    insert.bind(4, function.name);
    insert.bind(5, static_cast<std::int64_t>(function.exported ? 1 : 0));
    insert.bind(6, static_cast<std::int64_t>(function.estimated ? 1 : 0));
    insert.bind(7, static_cast<std::int64_t>(function.block_count));
    if (!insert.execute_statement()) {
      return fail(Status::InternalError, "project.insert_failed",
                  storage_error(db, "project.insert_failed", "function").message);
    }
  }

  {
    Statement insert(
        db,
        "INSERT INTO analysis_runs(image_id, tool_version, partial, instructions, xrefs, strings) "
        "VALUES(?1, ?2, ?3, ?4, ?5, ?6)");
    insert.bind(1, image_id);
    insert.bind(2, std::string(version()));
    insert.bind(3, static_cast<std::int64_t>(analysis.partial ? 1 : 0));
    insert.bind(4, static_cast<std::int64_t>(analysis.instructions.size()));
    insert.bind(5, static_cast<std::int64_t>(analysis.xrefs.size()));
    insert.bind(6, static_cast<std::int64_t>(analysis.strings.size()));
    if (!insert.execute_statement()) {
      return fail(Status::InternalError, "project.insert_failed",
                  storage_error(db, "project.insert_failed", "analysis").message);
    }
  }

  if (!execute(db, "COMMIT")) {
    const std::string message = storage_error(db, "project.commit_failed", "commit").message;
    execute(db, "ROLLBACK");
    return make_error<std::int64_t>(Status::InternalError, "project.commit_failed", message);
  }
  return image_id;
}

Result<std::vector<ProjectImage>> Project::images() const {
  if (!is_open()) {
    return make_error<std::vector<ProjectImage>>(Status::InvalidInput, "project.not_open",
                                                 "no project database is open");
  }
  Statement query(impl_->db,
                  "SELECT i.id, i.path, i.sha256, i.format, i.architecture, i.bits, i.image_base, "
                  "i.entry_point, i.file_size, "
                  "(SELECT COUNT(*) FROM sections s WHERE s.image_id = i.id), "
                  "(SELECT COUNT(*) FROM functions f WHERE f.image_id = i.id), "
                  "(SELECT COUNT(*) FROM annotations a WHERE a.image_id = i.id), "
                  "COALESCE((SELECT r.partial FROM analysis_runs r WHERE r.image_id = i.id "
                  "ORDER BY r.id DESC LIMIT 1), 0) "
                  "FROM images i ORDER BY i.id");
  if (!query.ok()) {
    return make_error<std::vector<ProjectImage>>(
        Status::InternalError, "project.query_failed",
        storage_error(impl_->db, "project.query_failed", "list images").message);
  }
  std::vector<ProjectImage> out;
  while (query.step()) {
    ProjectImage image;
    image.id = query.integer(0);
    image.path = query.text(1);
    image.sha256 = query.text(2);
    image.format = query.text(3);
    image.architecture = query.text(4);
    image.bits = static_cast<unsigned>(query.integer(5));
    image.image_base = static_cast<std::uint64_t>(query.integer(6));
    image.entry_point = static_cast<std::uint64_t>(query.integer(7));
    image.file_size = static_cast<std::uint64_t>(query.integer(8));
    image.sections = static_cast<std::size_t>(query.integer(9));
    image.functions = static_cast<std::size_t>(query.integer(10));
    image.annotations = static_cast<std::size_t>(query.integer(11));
    image.analysis_partial = query.integer(12) != 0;
    out.push_back(std::move(image));
  }
  if (!query.done()) {
    return make_error<std::vector<ProjectImage>>(
        Status::InternalError, "project.query_failed",
        storage_error(impl_->db, "project.query_failed", "read images").message);
  }
  return out;
}

Result<void> Project::set_annotation(std::int64_t image_id, AnnotationKind kind,
                                     std::uint64_t address, const std::string& text) {
  if (!is_open()) {
    return make_void_error(Status::InvalidInput, "project.not_open", "no project database is open");
  }
  if (!fits_storage(address)) {
    return make_void_error(Status::InvalidInput, "project.value_out_of_range",
                           "annotation address does not fit the storage integer range", address);
  }
  constexpr std::size_t kMaxAnnotationLength = 4096;
  if (text.size() > kMaxAnnotationLength) {
    return make_void_error(Status::InvalidInput, "project.annotation_too_long",
                           "annotation text exceeds 4096 bytes");
  }
  if (text.empty()) {
    return clear_annotation(image_id, kind, address);
  }

  sqlite3* db = impl_->db;
  {
    Statement check(db, "SELECT 1 FROM images WHERE id = ?1");
    check.bind(1, image_id);
    if (!check.ok() || !check.step()) {
      if (!check.done()) {
        return make_void_error(
            Status::InternalError, "project.query_failed",
            storage_error(db, "project.query_failed", "lookup image for annotation").message);
      }
      return make_void_error(Status::InvalidInput, "project.image_not_found",
                             "no image with id " + std::to_string(image_id));
    }
  }

  Statement upsert(db,
                   "INSERT INTO annotations(image_id, kind, address, text) VALUES(?1, ?2, ?3, ?4) "
                   "ON CONFLICT(image_id, kind, address) DO UPDATE SET text = excluded.text, "
                   "updated_at = datetime('now')");
  upsert.bind(1, image_id);
  upsert.bind(2, std::string(annotation_kind_name(kind)));
  upsert.bind(3, static_cast<std::int64_t>(address));
  upsert.bind(4, text);
  if (!upsert.execute_statement()) {
    return make_void_error(
        Status::InternalError, "project.annotation_write_failed",
        storage_error(db, "project.annotation_write_failed", "write annotation").message);
  }
  return Result<void>();
}

Result<void> Project::clear_annotation(std::int64_t image_id, AnnotationKind kind,
                                       std::uint64_t address) {
  if (!is_open()) {
    return make_void_error(Status::InvalidInput, "project.not_open", "no project database is open");
  }
  if (!fits_storage(address)) {
    return make_void_error(Status::InvalidInput, "project.value_out_of_range",
                           "annotation address does not fit the storage integer range", address);
  }
  Statement remove(impl_->db,
                   "DELETE FROM annotations WHERE image_id = ?1 AND kind = ?2 AND address = ?3");
  remove.bind(1, image_id);
  remove.bind(2, std::string(annotation_kind_name(kind)));
  remove.bind(3, static_cast<std::int64_t>(address));
  if (!remove.execute_statement()) {
    return make_void_error(
        Status::InternalError, "project.annotation_delete_failed",
        storage_error(impl_->db, "project.annotation_delete_failed", "delete annotation").message);
  }
  return Result<void>();
}

Result<std::vector<Annotation>> Project::annotations(std::int64_t image_id) const {
  if (!is_open()) {
    return make_error<std::vector<Annotation>>(Status::InvalidInput, "project.not_open",
                                               "no project database is open");
  }
  Statement query(impl_->db,
                  "SELECT kind, address, text FROM annotations WHERE image_id = ?1 "
                  "ORDER BY address, kind");
  query.bind(1, image_id);
  if (!query.ok()) {
    return make_error<std::vector<Annotation>>(
        Status::InternalError, "project.query_failed",
        storage_error(impl_->db, "project.query_failed", "list annotations").message);
  }
  std::vector<Annotation> out;
  while (query.step()) {
    const std::string kind = query.text(0);
    Annotation annotation;
    if (kind == "rename") {
      annotation.kind = AnnotationKind::Rename;
    } else if (kind == "comment") {
      annotation.kind = AnnotationKind::Comment;
    } else {
      return make_error<std::vector<Annotation>>(
          Status::CorruptProject, "project.annotation_kind_invalid",
          "annotation row has an unknown kind '" + kind + "'");
    }
    annotation.address = static_cast<std::uint64_t>(query.integer(1));
    annotation.text = query.text(2);
    out.push_back(std::move(annotation));
  }
  if (!query.done()) {
    return make_error<std::vector<Annotation>>(
        Status::InternalError, "project.query_failed",
        storage_error(impl_->db, "project.query_failed", "read annotations").message);
  }
  return out;
}

Result<void> Project::replace_annotations(std::int64_t image_id,
                                          const std::vector<Annotation>& annotations) {
  if (!is_open()) {
    return make_void_error(Status::InvalidInput, "project.not_open", "no project database is open");
  }
  sqlite3* db = impl_->db;
  for (const Annotation& annotation : annotations) {
    if (!fits_storage(annotation.address)) {
      return make_void_error(Status::InvalidInput, "project.value_out_of_range",
                             "annotation address does not fit the storage integer range",
                             annotation.address);
    }
    constexpr std::size_t kMaxAnnotationLength = 4096;
    if (annotation.text.size() > kMaxAnnotationLength) {
      return make_void_error(Status::InvalidInput, "project.annotation_too_long",
                             "annotation text exceeds 4096 bytes");
    }
  }
  {
    Statement check(db, "SELECT 1 FROM images WHERE id = ?1");
    check.bind(1, image_id);
    if (!check.ok() || !check.step()) {
      if (!check.done()) {
        return make_void_error(
            Status::InternalError, "project.query_failed",
            storage_error(db, "project.query_failed", "lookup image for annotations").message);
      }
      return make_void_error(Status::InvalidInput, "project.image_not_found",
                             "no image with id " + std::to_string(image_id));
    }
  }

  if (!execute(db, "BEGIN IMMEDIATE")) {
    return make_void_error(
        Status::InternalError, "project.transaction_failed",
        storage_error(db, "project.transaction_failed", "begin annotations").message);
  }
  auto fail = [&](std::string code, const std::string& context) {
    execute(db, "ROLLBACK");
    return make_void_error(Status::InternalError, std::move(code),
                           storage_error(db, code, context).message);
  };

  {
    Statement remove(db, "DELETE FROM annotations WHERE image_id = ?1");
    remove.bind(1, image_id);
    if (!remove.execute_statement()) {
      return fail("project.annotation_delete_failed", "clear annotations");
    }
  }
  for (const Annotation& annotation : annotations) {
    Statement insert(db,
                     "INSERT INTO annotations(image_id, kind, address, text) "
                     "VALUES(?1, ?2, ?3, ?4)");
    insert.bind(1, image_id);
    insert.bind(2, std::string(annotation_kind_name(annotation.kind)));
    insert.bind(3, static_cast<std::int64_t>(annotation.address));
    insert.bind(4, annotation.text);
    if (!insert.execute_statement()) {
      return fail("project.annotation_write_failed", "insert annotation");
    }
  }
  if (!execute(db, "COMMIT")) {
    const std::string message =
        storage_error(db, "project.commit_failed", "commit annotations").message;
    execute(db, "ROLLBACK");
    return make_void_error(Status::InternalError, "project.commit_failed", message);
  }
  return Result<void>();
}

Result<bool> Project::check_integrity() const {
  if (!is_open()) {
    return make_error<bool>(Status::InvalidInput, "project.not_open",
                            "no project database is open");
  }
  {
    Statement check(impl_->db, "PRAGMA integrity_check");
    if (!check.ok() || !check.step()) {
      return make_error<bool>(Status::CorruptProject, "project.integrity_failed",
                              "integrity_check did not return a result");
    }
    if (check.text(0) != "ok") {
      return false;
    }
  }
  Statement foreign_keys(impl_->db, "PRAGMA foreign_key_check");
  if (!foreign_keys.ok()) {
    return make_error<bool>(
        Status::CorruptProject, "project.integrity_failed",
        storage_error(impl_->db, "project.integrity_failed", "foreign keys").message);
  }
  return !foreign_keys.step();
}

}  // namespace donkey
