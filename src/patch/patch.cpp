#include "donkey/patch/patch.h"

#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>

#include "donkey/core/sha256.h"

namespace donkey {

Result<uint64_t> PatchManager::stage_patch(uint64_t file_offset, std::span<const uint8_t> original,
                                           std::span<const uint8_t> replacement,
                                           std::string comment, std::string author,
                                           std::optional<uint64_t> va) {
  if (original.empty()) {
    return Diagnostic::make(Status::InvalidInput, "patch.empty_original",
                            "Patch original bytes cannot be empty", file_offset);
  }

  if (replacement.empty()) {
    return Diagnostic::make(Status::InvalidInput, "patch.empty_replacement",
                            "Patch replacement bytes cannot be empty", file_offset);
  }

  if (original.size() != replacement.size()) {
    return Diagnostic::make(Status::InvalidInput, "patch.size_mismatch",
                            "Original bytes size (" + std::to_string(original.size()) +
                                ") must equal replacement bytes size (" +
                                std::to_string(replacement.size()) + ")",
                            file_offset);
  }

  // Safe overflow check: file_offset + replacement.size()
  if (replacement.size() > std::numeric_limits<uint64_t>::max() - file_offset) {
    return Diagnostic::make(Status::InvalidInput, "patch.offset_overflow",
                            "Patch offset and size cause integer overflow", file_offset);
  }

  // Detect overlapping patches
  const uint64_t patch_start = file_offset;
  const uint64_t patch_end = file_offset + replacement.size();
  for (const auto& existing : history_) {
    if (existing.reverted) {
      continue;
    }
    const uint64_t exist_start = existing.file_offset;
    const uint64_t exist_end = existing.file_offset + existing.replacement_bytes.size();
    if (patch_start < exist_end && exist_start < patch_end) {
      return Diagnostic::make(
          Status::InvalidInput, "patch.overlap",
          "Patch range overlaps with existing patch ID " + std::to_string(existing.id),
          file_offset);
    }
  }

  uint64_t id = next_id_++;
  auto now = std::chrono::duration_cast<std::chrono::seconds>(
                 std::chrono::system_clock::now().time_since_epoch())
                 .count();

  PatchEntry entry{
      .id = id,
      .file_offset = file_offset,
      .virtual_address = va,
      .original_bytes = {original.begin(), original.end()},
      .replacement_bytes = {replacement.begin(), replacement.end()},
      .comment = std::move(comment),
      .author = std::move(author),
      .timestamp = static_cast<uint64_t>(now),
      .applied = false,
      .reverted = false,
  };

  if (!entry.virtual_address && image_) {
    auto va_res = image_->file_offset_to_va(file_offset);
    if (va_res) {
      entry.virtual_address = va_res.value();
    }
  }

  history_.push_back(std::move(entry));
  return id;
}

const PatchEntry* PatchManager::find_patch(uint64_t patch_id) const noexcept {
  for (const auto& p : history_) {
    if (p.id == patch_id) {
      return &p;
    }
  }
  return nullptr;
}

Result<void> PatchManager::apply_patch(uint64_t patch_id, std::span<uint8_t> file_bytes) {
  auto* it = const_cast<PatchEntry*>(find_patch(patch_id));
  if (!it) {
    return Diagnostic::make(Status::InvalidInput, "patch.not_found",
                            "Patch ID " + std::to_string(patch_id) + " not found");
  }

  if (it->applied) {
    return Result<void>{};
  }

  if (it->reverted) {
    return Diagnostic::make(
        Status::InvalidInput, "patch.retired",
        "Patch ID " + std::to_string(patch_id) + " has been reverted and cannot be reapplied",
        it->file_offset);
  }

  // Safe overflow and range check
  if (it->file_offset > file_bytes.size() ||
      it->replacement_bytes.size() > file_bytes.size() - it->file_offset) {
    return Diagnostic::make(Status::InvalidInput, "patch.out_of_bounds",
                            "Patch offset is out of bounds of the file buffer", it->file_offset);
  }

  if (std::memcmp(file_bytes.data() + it->file_offset, it->original_bytes.data(),
                  it->original_bytes.size()) != 0) {
    return Diagnostic::make(Status::InvalidInput, "patch.original_bytes_mismatch",
                            "Original bytes at target offset do not match expected patch bytes",
                            it->file_offset);
  }

  std::memcpy(file_bytes.data() + it->file_offset, it->replacement_bytes.data(),
              it->replacement_bytes.size());
  it->applied = true;

  if (invalidation_callback_) {
    invalidation_callback_(it->file_offset, it->replacement_bytes.size());
  }

  return Result<void>{};
}

Result<void> PatchManager::revert_patch(uint64_t patch_id, std::span<uint8_t> file_bytes) {
  auto* it = const_cast<PatchEntry*>(find_patch(patch_id));
  if (!it) {
    return Diagnostic::make(Status::InvalidInput, "patch.not_found",
                            "Patch ID " + std::to_string(patch_id) + " not found");
  }

  if (!it->applied) {
    return Result<void>{};
  }

  // Safe overflow and range check
  if (it->file_offset > file_bytes.size() ||
      it->replacement_bytes.size() > file_bytes.size() - it->file_offset) {
    return Diagnostic::make(Status::InvalidInput, "patch.out_of_bounds",
                            "Patch offset is out of bounds of the file buffer", it->file_offset);
  }

  if (std::memcmp(file_bytes.data() + it->file_offset, it->replacement_bytes.data(),
                  it->replacement_bytes.size()) != 0) {
    return Diagnostic::make(Status::InvalidInput, "patch.replacement_bytes_mismatch",
                            "Buffer bytes at target offset do not match applied replacement bytes",
                            it->file_offset);
  }

  std::memcpy(file_bytes.data() + it->file_offset, it->original_bytes.data(),
              it->original_bytes.size());
  it->applied = false;
  it->reverted = true;

  if (invalidation_callback_) {
    invalidation_callback_(it->file_offset, it->original_bytes.size());
  }

  return Result<void>{};
}

std::vector<PatchDiff> PatchManager::preview() const {
  std::vector<PatchDiff> diffs;
  for (const auto& p : history_) {
    if (p.applied) {
      diffs.push_back(PatchDiff{
          .file_offset = p.file_offset,
          .virtual_address = p.virtual_address,
          .before_bytes = p.original_bytes,
          .after_bytes = p.replacement_bytes,
          .comment = p.comment,
      });
    }
  }
  return diffs;
}

static bool detect_macho_code_signature(std::span<const uint8_t> bytes) {
  if (bytes.size() < 32) return false;
  uint32_t magic = 0;
  std::memcpy(&magic, bytes.data(), 4);
  bool is_macho =
      (magic == 0xfeedface || magic == 0xfeedfacf || magic == 0xcefaedfe || magic == 0xcffaedfe);
  if (!is_macho) return false;

  bool is_64 = (magic == 0xfeedfacf || magic == 0xcffaedfe);
  size_t header_size = is_64 ? 32 : 28;
  if (bytes.size() < header_size) return false;

  uint32_t ncmds = 0;
  std::memcpy(&ncmds, bytes.data() + 16, 4);

  size_t offset = header_size;
  for (uint32_t i = 0; i < ncmds; ++i) {
    if (offset > bytes.size() || bytes.size() - offset < 8) break;
    uint32_t cmd = 0;
    uint32_t cmdsize = 0;
    std::memcpy(&cmd, bytes.data() + offset, 4);
    std::memcpy(&cmdsize, bytes.data() + offset + 4, 4);
    if (cmdsize < 8) break;
    if (cmd == 0x1d) {  // LC_CODE_SIGNATURE
      return true;
    }
    const size_t cmdsize_st = static_cast<size_t>(cmdsize);
    if (offset > bytes.size() || bytes.size() - offset < cmdsize_st) break;
    offset += cmdsize_st;
  }
  return false;
}

static bool detect_pe_signature(std::span<const uint8_t> bytes) {
  if (bytes.size() < 64) return false;
  if (bytes[0] != 'M' || bytes[1] != 'Z') return false;

  uint32_t pe_offset_raw = 0;
  std::memcpy(&pe_offset_raw, bytes.data() + 0x3c, 4);
  const size_t pe_offset = static_cast<size_t>(pe_offset_raw);

  // Cast to size_t and use subtraction-based bounds guards before every dereference
  if (pe_offset > bytes.size() || bytes.size() - pe_offset < 24) return false;
  if (std::memcmp(bytes.data() + pe_offset, "PE\0\0", 4) != 0) return false;

  const size_t opt_offset = pe_offset + 24;
  if (opt_offset > bytes.size() || bytes.size() - opt_offset < 2) return false;

  uint16_t magic = 0;
  std::memcpy(&magic, bytes.data() + opt_offset, 2);
  const bool pe32plus = (magic == 0x20b);

  const size_t dir_base_offset = pe32plus ? 112 : 96;
  const size_t cert_entry_offset = 4 * 8;  // Entry 4: IMAGE_DIRECTORY_ENTRY_SECURITY
  const size_t sec_dir_offset_within_opt = dir_base_offset + cert_entry_offset;

  if (opt_offset > bytes.size() || bytes.size() - opt_offset < sec_dir_offset_within_opt)
    return false;
  const size_t sec_dir_offset = opt_offset + sec_dir_offset_within_opt;
  if (sec_dir_offset > bytes.size() || bytes.size() - sec_dir_offset < 8) return false;

  uint32_t sec_size = 0;
  std::memcpy(&sec_size, bytes.data() + sec_dir_offset + 4, 4);
  return sec_size > 0;
}

Result<ExportResult> PatchManager::export_patched_binary(const std::string& source_path,
                                                         const std::string& destination_path,
                                                         bool force_overwrite) const {
  std::error_code ec;
  auto src_canon = std::filesystem::weakly_canonical(source_path, ec);
  auto dst_canon = std::filesystem::weakly_canonical(destination_path, ec);

  if (!force_overwrite && (src_canon == dst_canon || source_path == destination_path)) {
    return Diagnostic::make(Status::InvalidInput, "patch.refuse_overwrite_source",
                            "ExportPatchedBinary refuses to overwrite source binary without "
                            "force_overwrite = true");
  }

  std::ifstream in(source_path, std::ios::binary);
  if (!in.is_open()) {
    return Diagnostic::make(Status::InvalidInput, "patch.source_open_failed",
                            "Failed to open source binary: " + source_path);
  }

  std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(in)),
                              std::istreambuf_iterator<char>());
  in.close();

  // Validate and apply all patches marked applied
  for (const auto& p : history_) {
    if (!p.applied) continue;

    if (p.file_offset > buffer.size() || p.original_bytes.size() > buffer.size() - p.file_offset ||
        p.replacement_bytes.size() > buffer.size() - p.file_offset) {
      return Diagnostic::make(Status::InternalError, "patch.export_out_of_bounds",
                              "Patch is out of bounds for source binary size", p.file_offset);
    }

    if (!p.original_bytes.empty()) {
      if (std::memcmp(buffer.data() + p.file_offset, p.original_bytes.data(),
                      p.original_bytes.size()) != 0) {
        return Diagnostic::make(Status::InternalError, "patch.original_bytes_mismatch",
                                "Original bytes in source binary do not match expected patch bytes",
                                p.file_offset);
      }
    }

    std::memcpy(buffer.data() + p.file_offset, p.replacement_bytes.data(),
                p.replacement_bytes.size());
  }

  bool signature_invalidated = false;
  std::vector<std::string> warnings;

  if (detect_macho_code_signature(buffer)) {
    signature_invalidated = true;
    warnings.push_back(
        "Binary contains Mach-O LC_CODE_SIGNATURE; patching invalidates the existing signature.");
  } else if (detect_pe_signature(buffer)) {
    signature_invalidated = true;
    warnings.push_back(
        "Binary contains PE Certificate Directory; patching invalidates the existing signature.");
  }

  std::string sha256 = Sha256::hex(std::as_bytes(std::span(buffer)));

  // Write to a temporary file with the source's permissions, then rename it
  // into place so the destination is never partially written.
  std::string temp_dest = destination_path + ".tmp";
  auto discard_temp = [&]() {
    std::error_code ignored;
    std::filesystem::remove(temp_dest, ignored);
  };
  {
    std::ofstream out(temp_dest, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
      return Diagnostic::make(Status::InternalError, "patch.dest_open_failed",
                              "Failed to create temporary output file: " + temp_dest);
    }
    out.write(reinterpret_cast<const char*>(buffer.data()),
              static_cast<std::streamsize>(buffer.size()));
    out.flush();
    if (!out.good()) {
      out.close();
      discard_temp();
      return Diagnostic::make(Status::InternalError, "patch.write_failed",
                              "Failed to write patched bytes to temporary output file");
    }
  }

  auto perms = std::filesystem::status(source_path, ec).permissions();
  if (!ec) {
    std::filesystem::permissions(temp_dest, perms, ec);
  }

  std::filesystem::rename(temp_dest, destination_path, ec);
  if (ec) {
    discard_temp();
    return Diagnostic::make(Status::InternalError, "patch.rename_failed",
                            "Failed to rename temporary file to destination: " + ec.message());
  }

  return ExportResult{
      .path = destination_path,
      .sha256 = std::move(sha256),
      .bytes_written = buffer.size(),
      .signature_invalidated = signature_invalidated,
      .warnings = std::move(warnings),
  };
}

}  // namespace donkey
