#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "components.h"
#include "views.h"

namespace donkey::ui::views {
namespace {

constexpr std::uint64_t kBytesPerRow = 16;

bool printable(std::byte value) {
  const auto byte = static_cast<unsigned char>(value);
  return byte >= 0x20U && byte <= 0x7EU;
}

std::string row_address(std::uint64_t address) {
  char buffer[32];
  std::snprintf(buffer, sizeof(buffer), "0x%llx", static_cast<unsigned long long>(address));
  return buffer;
}

std::string ascii_column(const std::uint8_t* bytes, std::size_t count) {
  std::string out;
  out.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    out.push_back(printable(static_cast<std::byte>(bytes[i])) ? static_cast<char>(bytes[i]) : '.');
  }
  return out;
}

/// Reset the patch session when a different document is shown.
void sync_patch_state(const Document& document, UiState& state) {
  // Pointer identity alone is not enough: a new document can be allocated
  // where a freed one lived.
  if (state.patch_document == &document && state.patches != nullptr &&
      state.patch_document_sha == document.loaded.image.sha256 &&
      state.patched_bytes.size() == document.loaded.data.size()) {
    return;
  }
  state.patch_document = &document;
  state.patch_document_sha = document.loaded.image.sha256;
  state.patches = std::make_shared<PatchManager>(&document.loaded.image);
  state.patched_bytes.resize(document.loaded.data.size());
  std::memcpy(state.patched_bytes.data(), document.loaded.data.data(), document.loaded.data.size());
  state.hex_cursor = ~std::uint64_t{0};
  state.patch_hex[0] = '\0';
  state.patch_message.clear();
  std::snprintf(state.patch_export_path, sizeof(state.patch_export_path), "%s.patched",
                document.loaded.image.path.c_str());
}

bool parse_hex(const char* text, std::vector<std::uint8_t>& out) {
  out.clear();
  int high = -1;
  for (const char* p = text; *p != '\0'; ++p) {
    const char c = *p;
    int nibble = -1;
    if (c >= '0' && c <= '9') {
      nibble = c - '0';
    } else if (c >= 'a' && c <= 'f') {
      nibble = c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
      nibble = c - 'A' + 10;
    } else if (c == ' ' || c == ',' || c == '\t') {
      continue;
    } else {
      return false;
    }
    if (high < 0) {
      high = nibble;
    } else {
      out.push_back(static_cast<std::uint8_t>(high * 16 + nibble));
      high = -1;
    }
  }
  return high < 0 && !out.empty();
}

void fill_editor(UiState& state, std::uint64_t offset) {
  state.hex_cursor = offset;
  const std::size_t count =
      static_cast<std::size_t>(std::min<std::uint64_t>(8, state.patched_bytes.size() - offset));
  std::string text;
  for (std::size_t i = 0; i < count; ++i) {
    char byte[4];
    std::snprintf(byte, sizeof(byte), "%02x ", state.patched_bytes[offset + i]);
    text += byte;
  }
  std::snprintf(state.patch_hex, sizeof(state.patch_hex), "%s", text.c_str());
}

bool is_patched(const UiState& state, std::uint64_t offset) {
  for (const PatchEntry& entry : state.patches->history()) {
    if (entry.applied && offset >= entry.file_offset &&
        offset - entry.file_offset < entry.replacement_bytes.size()) {
      return true;
    }
  }
  return false;
}

void apply_edit(const Document& document, UiState& state) {
  std::vector<std::uint8_t> replacement;
  if (!parse_hex(state.patch_hex, replacement)) {
    state.patch_message = "Enter whole bytes in hex, for example: 90 90 c3";
    return;
  }
  const std::uint64_t offset = state.hex_cursor;
  if (offset > state.patched_bytes.size() ||
      replacement.size() > state.patched_bytes.size() - offset) {
    state.patch_message = "The edit runs past the end of the file.";
    return;
  }
  // Patches replace bytes in place; the originals are the current file bytes
  // (patches never overlap, so they are also the bytes on disk).
  std::vector<std::uint8_t> original(
      state.patched_bytes.begin() + static_cast<std::ptrdiff_t>(offset),
      state.patched_bytes.begin() + static_cast<std::ptrdiff_t>(offset + replacement.size()));
  if (original == replacement) {
    state.patch_message = "Those are already the bytes at this offset.";
    return;
  }
  std::optional<std::uint64_t> va;
  if (auto address = document.loaded.image.file_offset_to_va(offset)) {
    va = address.value();
  }
  auto staged =
      state.patches->stage_patch(offset, original, replacement, "edited in hex view", "", va);
  if (!staged) {
    state.patch_message = staged.diagnostic().message + " [" + staged.diagnostic().code + "]";
    return;
  }
  auto applied = state.patches->apply_patch(staged.value(), state.patched_bytes);
  state.patch_message = applied
                            ? std::string()
                            : applied.diagnostic().message + " [" + applied.diagnostic().code + "]";
}

void start_export(const Document& document, UiState& state) {
  if (state.patch_export != nullptr && !state.patch_export->done) {
    return;
  }
  auto job = std::make_shared<UiState::PatchExportJob>();
  state.patch_export = job;
  // The worker owns copies: the patch list and both paths.
  auto patches = std::make_shared<PatchManager>(*state.patches);
  std::thread([job, patches, source = document.loaded.image.path,
               destination = std::string(state.patch_export_path)]() {
    auto result = patches->export_patched_binary(source, destination, false);
    std::string message;
    if (result) {
      message = "Wrote " + result.value().path + " (SHA-256 " + result.value().sha256 + ")";
      for (const std::string& warning : result.value().warnings) {
        message += "\nWarning: " + warning;
      }
    } else {
      message =
          "Export failed: " + result.diagnostic().message + " [" + result.diagnostic().code + "]";
    }
    std::lock_guard<std::mutex> lock(job->mutex);
    job->message = std::move(message);
    job->done = true;
  }).detach();
}

void draw_patch_editor(const Document& document, UiState& state) {
  const bool has_cursor = state.hex_cursor < state.patched_bytes.size();
  if (!has_cursor) {
    ImGui::TextDisabled(
        "Click a byte to edit it. Edits are staged; the opened file is never "
        "modified.");
  } else {
    ImGui::Text("Offset 0x%llx", static_cast<unsigned long long>(state.hex_cursor));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(260.0f);
    const bool enter = ImGui::InputText(
        "##patch_hex", state.patch_hex, sizeof(state.patch_hex),
        ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SameLine();
    if (ImGui::Button("Patch") || enter) {
      apply_edit(document, state);
    }
  }
  if (!state.patch_message.empty()) {
    ImGui::TextColored(components::status_color("Unsupported"), "%s", state.patch_message.c_str());
  }

  const auto& history = state.patches->history();
  std::size_t applied = 0;
  for (const PatchEntry& entry : history) {
    applied += entry.applied ? 1 : 0;
  }
  if (applied == 0) {
    return;
  }
  if (ImGui::TreeNode("##patches", "%zu staged patch%s", applied, applied == 1 ? "" : "es")) {
    std::uint64_t revert = 0;
    for (const PatchEntry& entry : history) {
      if (!entry.applied) {
        continue;
      }
      ImGui::PushID(static_cast<int>(entry.id));
      std::string before;
      std::string after;
      for (std::size_t i = 0; i < entry.replacement_bytes.size() && i < 8; ++i) {
        char byte[4];
        std::snprintf(byte, sizeof(byte), "%02x", entry.original_bytes[i]);
        before += byte;
        std::snprintf(byte, sizeof(byte), "%02x", entry.replacement_bytes[i]);
        after += byte;
      }
      if (ImGui::SmallButton("Revert")) {
        revert = entry.id;
      }
      ImGui::SameLine();
      ImGui::Text("0x%llx  %s -> %s", static_cast<unsigned long long>(entry.file_offset),
                  before.c_str(), after.c_str());
      ImGui::PopID();
    }
    ImGui::TreePop();
    if (revert != 0) {
      auto reverted = state.patches->revert_patch(revert, state.patched_bytes);
      state.patch_message =
          reverted ? std::string()
                   : reverted.diagnostic().message + " [" + reverted.diagnostic().code + "]";
    }
  }
  ImGui::SetNextItemWidth(-140.0f);
  ImGui::InputText("##export_path", state.patch_export_path, sizeof(state.patch_export_path));
  ImGui::SameLine();
  const bool exporting = state.patch_export != nullptr && !state.patch_export->done;
  if (exporting) {
    ImGui::BeginDisabled();
  }
  if (ImGui::Button("Export patched")) {
    start_export(document, state);
  }
  if (exporting) {
    ImGui::EndDisabled();
  }
  if (state.patch_export != nullptr) {
    std::lock_guard<std::mutex> lock(state.patch_export->mutex);
    if (state.patch_export->done) {
      ImGui::PushTextWrapPos(0.0f);
      ImGui::TextDisabled("%s", state.patch_export->message.c_str());
      ImGui::PopTextWrapPos();
    } else {
      ImGui::TextDisabled("Exporting...");
    }
  }
}

}  // namespace

void hex(const Document& document, UiState& state) {
  const BinaryImage& image = document.loaded.image;
  sync_patch_state(document, state);

  ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.60f, 0.68f, 1.0f));
  ImGui::TextUnformatted("16 bytes per row; start follows the selection; patched bytes in orange");
  ImGui::PopStyleColor();

  // Anchor on the selection when it is backed by file data, otherwise fall
  // back to the entry point or the first mapped section.
  std::uint64_t base = state.selected_address & ~std::uint64_t{15};
  if (!image.va_to_file_offset(base)) {
    base = 0;
    if (image.has_entry_point() && image.va_to_file_offset(image.entry_point)) {
      base = image.entry_point & ~std::uint64_t{15};
    } else {
      for (const Section& section : image.sections) {
        if (section.address == 0) {
          continue;
        }
        if (image.va_to_file_offset(section.address)) {
          base = section.address & ~std::uint64_t{15};
          break;
        }
      }
    }
  }

  auto file_offset = image.va_to_file_offset(base);
  if (!file_offset) {
    ImGui::Spacing();
    ImGui::TextWrapped("Address %s is not backed by file data; select a mapped address.",
                       components::format_address(base).c_str());
    return;
  }

  const std::uint64_t offset = file_offset.value();
  if (offset >= state.patched_bytes.size()) {
    ImGui::TextWrapped("Address %s is outside the file.", components::format_address(base).c_str());
    return;
  }

  const std::uint64_t remaining = state.patched_bytes.size() - offset;
  const std::uint64_t rows = (remaining + kBytesPerRow - 1) / kBytesPerRow;
  const std::uint8_t* bytes = state.patched_bytes.data() + offset;

  const ImGuiTableFlags flags = ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_RowBg |
                                ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV;
  const float editor_height = ImGui::GetFrameHeightWithSpacing() * 5.0f;
  const float table_height = std::max(ImGui::GetContentRegionAvail().y - editor_height, 80.0f);
  if (ImGui::BeginTable("##hexdump", 3, flags, ImVec2(0.0f, table_height))) {
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch, 1.1f);
    ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthStretch, 3.2f);
    ImGui::TableSetupColumn("ASCII", ImGuiTableColumnFlags_WidthStretch, 1.0f);
    ImGui::TableHeadersRow();

    const ImVec4 patched_color(0.98f, 0.62f, 0.25f, 1.0f);
    const ImVec4 cursor_color(0.99f, 0.84f, 0.45f, 1.0f);
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(rows));
    while (clipper.Step()) {
      for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
        const std::uint64_t row_offset = static_cast<std::uint64_t>(row) * kBytesPerRow;
        const std::uint64_t count =
            remaining - row_offset < kBytesPerRow ? remaining - row_offset : kBytesPerRow;
        const std::uint64_t row_address_value = base + row_offset;

        const bool contains_selection = state.selected_address >= row_address_value &&
                                        state.selected_address < row_address_value + count;

        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);
        if (contains_selection) {
          ImGui::PushStyleColor(ImGuiCol_Text, cursor_color);
        }
        ImGui::TextUnformatted(row_address(row_address_value).c_str());
        if (contains_selection) {
          ImGui::PopStyleColor();
        }

        ImGui::TableSetColumnIndex(1);
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.0f, 0.0f));
        for (std::uint64_t i = 0; i < count; ++i) {
          const std::uint64_t byte_offset = offset + row_offset + i;
          char label[8];
          std::snprintf(label, sizeof(label), "%02x##%x", bytes[row_offset + i],
                        static_cast<unsigned>(i));
          const bool patched = is_patched(state, byte_offset);
          const bool cursor = byte_offset == state.hex_cursor;
          if (patched || cursor) {
            ImGui::PushStyleColor(ImGuiCol_Text, cursor ? cursor_color : patched_color);
          }
          ImGui::PushID(row);
          if (ImGui::Selectable(label, cursor, 0, ImGui::CalcTextSize("00 "))) {
            fill_editor(state, byte_offset);
          }
          ImGui::PopID();
          if (patched || cursor) {
            ImGui::PopStyleColor();
          }
          if (i + 1 < count) {
            ImGui::SameLine(0.0f, i == 7 ? ImGui::CalcTextSize(" ").x : 0.0f);
          }
        }
        ImGui::PopStyleVar();

        ImGui::TableSetColumnIndex(2);
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.72f, 0.78f, 0.86f, 1.0f));
        ImGui::TextUnformatted(
            ascii_column(bytes + row_offset, static_cast<std::size_t>(count)).c_str());
        ImGui::PopStyleColor();
      }
    }
    ImGui::EndTable();
  }
  ImGui::Separator();
  draw_patch_editor(document, state);
}

}  // namespace donkey::ui::views
