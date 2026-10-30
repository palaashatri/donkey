#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/core/result.h"
#include "donkey/core/status.h"

namespace donkey {

struct PatchEntry {
  uint64_t id = 0;
  uint64_t file_offset = 0;
  std::optional<uint64_t> virtual_address;
  std::vector<uint8_t> original_bytes;
  std::vector<uint8_t> replacement_bytes;
  std::string comment;
  std::string author;
  uint64_t timestamp = 0;
  bool applied = false;
};

struct PatchDiff {
  uint64_t file_offset = 0;
  std::optional<uint64_t> virtual_address;
  std::vector<uint8_t> before_bytes;
  std::vector<uint8_t> after_bytes;
  std::string comment;
};

struct ExportResult {
  std::string path;
  std::string sha256;
  uint64_t bytes_written = 0;
  bool signature_invalidated = false;
  std::vector<std::string> warnings;
};

using InvalidationCallback = std::function<void(uint64_t offset, size_t size)>;

class PatchManager {
 public:
  PatchManager() = default;
  explicit PatchManager(const BinaryImage* image) : image_(image) {}

  /// Stage a new patch entry without applying it yet.
  Result<uint64_t> stage_patch(uint64_t file_offset, std::span<const uint8_t> original,
                               std::span<const uint8_t> replacement, std::string comment = "",
                               std::string author = "", std::optional<uint64_t> va = std::nullopt);

  /// Apply a staged patch to an in-memory buffer representing file bytes.
  Result<void> apply_patch(uint64_t patch_id, std::span<uint8_t> file_bytes);

  /// Revert an applied patch in an in-memory buffer representing file bytes.
  Result<void> revert_patch(uint64_t patch_id, std::span<uint8_t> file_bytes);

  /// Preview all active patches as differences.
  [[nodiscard]] std::vector<PatchDiff> preview() const;

  /// Full audit history of patches.
  [[nodiscard]] const std::vector<PatchEntry>& history() const noexcept { return history_; }

  /// Export patched binary to a destination path. Refuses to overwrite source_path
  /// unless force_overwrite is true.
  Result<ExportResult> export_patched_binary(const std::string& source_path,
                                             const std::string& destination_path,
                                             bool force_overwrite = false) const;

  /// Set callback invoked whenever byte edits invalidate analysis/decode ranges.
  void set_invalidation_callback(InvalidationCallback callback) {
    invalidation_callback_ = std::move(callback);
  }

  /// Look up patch by ID.
  [[nodiscard]] const PatchEntry* find_patch(uint64_t patch_id) const noexcept;

 private:
  const BinaryImage* image_ = nullptr;
  uint64_t next_id_ = 1;
  std::vector<PatchEntry> history_;
  InvalidationCallback invalidation_callback_;
};

}  // namespace donkey
