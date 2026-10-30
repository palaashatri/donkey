#include <gtest/gtest.h>
#include <sqlite3.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <utility>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/project/project.h"

namespace {

using donkey::AnalysisResult;
using donkey::LoadedBinary;
using donkey::Project;

std::string fixture_path(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/binaries/" + name;
}

/// Unique database path that removes itself and its SQLite sidecars.
class TempPath {
 public:
  explicit TempPath(const std::string& name) {
    static std::uint64_t counter = 0;
    path_ = std::filesystem::temp_directory_path() /
            ("donkey-" + name + "-" + std::to_string(++counter) + ".db");
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

LoadedBinary load_elf() {
  auto loaded = donkey::load_binary(fixture_path("tiny-elf-x86_64"));
  EXPECT_TRUE(loaded.has_value());
  return loaded.has_value() ? std::move(loaded.value()) : LoadedBinary{};
}

TEST(Project, CreatesReopensAndPersistsImage) {
  TempPath path("persist");
  auto loaded = load_elf();
  auto analysis = donkey::analyze(loaded.image, loaded.data);
  ASSERT_TRUE(analysis.has_value());

  {
    auto created = Project::create(path.str());
    ASSERT_TRUE(created.has_value())
        << created.diagnostic().code << ": " << created.diagnostic().message;
    EXPECT_EQ(created.value().schema_version(), donkey::kProjectSchemaVersion);
    auto id = created.value().import(loaded, analysis.value());
    ASSERT_TRUE(id.has_value()) << id.diagnostic().message;
    EXPECT_GT(id.value(), 0);
    auto integrity = created.value().check_integrity();
    ASSERT_TRUE(integrity.has_value());
    EXPECT_TRUE(integrity.value());
  }

  auto reopened = Project::open(path.str());
  ASSERT_TRUE(reopened.has_value()) << reopened.diagnostic().message;
  auto images = reopened.value().images();
  ASSERT_TRUE(images.has_value()) << images.diagnostic().message;
  ASSERT_EQ(images.value().size(), 1U);

  const auto& image = images.value().front();
  EXPECT_EQ(image.sha256, loaded.image.sha256);
  EXPECT_EQ(image.format, "ELF");
  EXPECT_EQ(image.architecture, "x86_64");
  EXPECT_EQ(image.bits, 64U);
  EXPECT_EQ(image.entry_point, 0x400100U);
  EXPECT_GE(image.sections, 5U);
  EXPECT_EQ(image.functions, 2U);
  EXPECT_FALSE(image.analysis_partial);

  auto integrity = reopened.value().check_integrity();
  ASSERT_TRUE(integrity.has_value());
  EXPECT_TRUE(integrity.value());
}

TEST(Project, ReimportReplacesDerivedRows) {
  TempPath path("reimport");
  auto loaded = load_elf();
  auto analysis = donkey::analyze(loaded.image, loaded.data);
  ASSERT_TRUE(analysis.has_value());

  auto project = Project::create(path.str());
  ASSERT_TRUE(project.has_value());
  ASSERT_TRUE(project.value().import(loaded, analysis.value()).has_value());
  ASSERT_TRUE(project.value().import(loaded, analysis.value()).has_value());

  auto images = project.value().images();
  ASSERT_TRUE(images.has_value());
  ASSERT_EQ(images.value().size(), 1U);
  EXPECT_EQ(images.value().front().functions, 2U);
}

TEST(Project, FailedImportRollsBackEverything) {
  TempPath path("rollback");
  {
    auto loaded = load_elf();
    auto analysis = donkey::analyze(loaded.image, loaded.data);
    ASSERT_TRUE(analysis.has_value());

    // A section address that cannot be represented forces a failure after the
    // transaction has inserted the image row.
    loaded.image.sections.front().address = std::numeric_limits<std::uint64_t>::max();

    auto project = Project::create(path.str());
    ASSERT_TRUE(project.has_value());
    auto imported = project.value().import(loaded, analysis.value());
    ASSERT_FALSE(imported.has_value());
    EXPECT_EQ(imported.diagnostic().code, "project.value_out_of_range");

    auto images = project.value().images();
    ASSERT_TRUE(images.has_value());
    EXPECT_TRUE(images.value().empty());

    auto integrity = project.value().check_integrity();
    ASSERT_TRUE(integrity.has_value());
    EXPECT_TRUE(integrity.value());
  }
}

TEST(Project, RejectsCorruptDatabaseFile) {
  TempPath path("corrupt");
  {
    std::ofstream file(path.str(), std::ios::binary);
    file << "this is not a SQLite database";
  }
  auto project = Project::open(path.str());
  ASSERT_FALSE(project.has_value());
  EXPECT_EQ(project.diagnostic().status, donkey::Status::CorruptProject)
      << project.diagnostic().code << ": " << project.diagnostic().message;
}

TEST(Project, RejectsMissingDatabaseFile) {
  TempPath path("missing");
  auto project = Project::open(path.str());
  ASSERT_FALSE(project.has_value());
  EXPECT_EQ(project.diagnostic().code, "project.open_failed");
}

TEST(Project, RejectsNewerSchemaWithoutTouchingIt) {
  TempPath path("newer");
  {
    auto project = Project::create(path.str());
    ASSERT_TRUE(project.has_value());
  }

  sqlite3* raw = nullptr;
  ASSERT_EQ(sqlite3_open(path.str().c_str(), &raw), SQLITE_OK);
  ASSERT_EQ(sqlite3_exec(raw, "PRAGMA user_version=99", nullptr, nullptr, nullptr), SQLITE_OK);
  sqlite3_close(raw);

  auto project = Project::open(path.str());
  ASSERT_FALSE(project.has_value());
  EXPECT_EQ(project.diagnostic().code, "project.schema_too_new");
  EXPECT_EQ(project.diagnostic().status, donkey::Status::Unsupported);
}

}  // namespace
