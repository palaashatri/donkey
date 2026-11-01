#include <cstdio>
#include <string>

#include "components.h"
#include "imgui.h"
#include "views.h"
#include "workspace.h"

namespace donkey::ui {

// A test screen built only from the shared components (M0), and the
// 1,000,000-row virtualised table the M2 scrolling test measures. Rows are
// generated on demand from the row index: nothing per row is stored, and
// ImGuiListClipper submits only the rows that intersect the view.
void draw_component_gallery(GalleryState& gallery) {
  if (!gallery.open) {
    return;
  }
  ImGui::SetNextWindowSize(ImVec2(720.0f, 520.0f), ImGuiCond_FirstUseEver);
  if (!ImGui::Begin(kGalleryWindow, &gallery.open)) {
    ImGui::End();
    gallery.rows_submitted_last_frame = 0;
    return;
  }
  components::heading("Shared components", "src/ui/components");
  if (components::toolbar_button("Reset", "Clear the search and selection")) {
    gallery.search.clear();
    gallery.selected_row = -1;
    ++gallery.button_presses;
  }
  ImGui::SameLine();
  components::badge("Complete", components::status_color("Complete"));
  ImGui::SameLine();
  components::badge("Partial", components::status_color("Partial"));
  ImGui::SameLine();
  components::badge("Unsupported", components::status_color("Unsupported"));
  components::search_field("##gallery_search", gallery.search, "Jump to row number");
  gallery.search_id = ImGui::GetItemID();

  // A row number typed into the search box scrolls there.
  if (!gallery.search.empty()) {
    char* end = nullptr;
    const long long row = std::strtoll(gallery.search.c_str(), &end, 10);
    if (end != nullptr && *end == '\0' && row >= 0 && row < gallery.row_count &&
        row != gallery.search_row) {
      gallery.search_row = row;
      gallery.scroll_to_row = row;
      gallery.selected_row = row;
    }
  }

  components::heading("Synthetic disassembly",
                      (std::to_string(gallery.row_count) + " rows").c_str());
  const ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                                ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit;
  int submitted = 0;
  if (ImGui::BeginTable("##gallery_rows", 3, flags, ImVec2(0.0f, 0.0f))) {
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Address");
    ImGui::TableSetupColumn("Bytes");
    ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableHeadersRow();
    const float row_height = ImGui::GetTextLineHeightWithSpacing();
    if (gallery.scroll_to_row >= 0) {
      ImGui::SetScrollY(static_cast<float>(gallery.scroll_to_row) * row_height);
      gallery.scroll_to_row = -1;
    }
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(gallery.row_count), row_height);
    char text[64];
    while (clipper.Step()) {
      for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
        ++submitted;
        const std::uint64_t address = 0x400000ULL + static_cast<std::uint64_t>(row) * 4ULL;
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::PushID(row);
        std::snprintf(text, sizeof(text), "%016llx", static_cast<unsigned long long>(address));
        if (components::selectable_row(text, gallery.selected_row == row,
                                       ImGuiSelectableFlags_SpanAllColumns)) {
          gallery.selected_row = row;
        }
        ImGui::PopID();
        ImGui::TableNextColumn();
        std::snprintf(text, sizeof(text), "%02x %02x %02x %02x", row & 0xff, (row >> 8) & 0xff,
                      (row >> 16) & 0xff, (row >> 24) & 0xff);
        ImGui::TextUnformatted(text);
        ImGui::TableNextColumn();
        std::snprintf(text, sizeof(text), "add x%d, x%d, #%d", row % 31, (row + 1) % 31,
                      row % 4096);
        ImGui::TextUnformatted(text);
      }
    }
    gallery.scroll_y = ImGui::GetScrollY();
    ImGui::EndTable();
  }
  gallery.rows_submitted_last_frame = submitted;
  ImGui::End();
}

}  // namespace donkey::ui
