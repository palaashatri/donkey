#include "components.h"

#include <string>

#include <cinttypes>
#include <cstdio>
#include <cstring>

namespace donkey::ui::components {
namespace {

ImVec4 with_alpha(ImVec4 color, float alpha) {
  color.w = alpha;
  return color;
}

}  // namespace

ImVec4 status_color(std::string_view status) {
  if (status == "Complete" || status == "Success") {
    return ImVec4(0.36f, 0.75f, 0.51f, 1.0f);
  }
  if (status == "Partial" || status == "Lifting" || status == "Loading") {
    return ImVec4(0.93f, 0.72f, 0.29f, 1.0f);
  }
  if (status == "Unsupported") {
    return ImVec4(0.58f, 0.58f, 0.62f, 1.0f);
  }
  return ImVec4(0.90f, 0.42f, 0.42f, 1.0f);
}

void badge(std::string_view label, const ImVec4& color) {
  ImGui::PushStyleColor(ImGuiCol_Text, color);
  ImGui::PushStyleColor(ImGuiCol_Button, with_alpha(color, 0.16f));
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, with_alpha(color, 0.16f));
  ImGui::PushStyleColor(ImGuiCol_ButtonActive, with_alpha(color, 0.16f));
  ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 3.0f);
  ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.0f, 2.0f));
  // A badge is a label: keyboard navigation and Tab must skip it.
  ImGui::PushItemFlag(ImGuiItemFlags_NoTabStop, true);
  ImGui::PushItemFlag(ImGuiItemFlags_NoNav, true);
  const std::string text(label);  // string_view is not NUL-terminated
  ImGui::Button(text.c_str(), ImVec2(0.0f, 0.0f));
  ImGui::PopItemFlag();
  ImGui::PopItemFlag();
  ImGui::PopStyleVar(2);
  ImGui::PopStyleColor(4);
}

bool toolbar_button(const char* label, const char* tooltip) {
  const bool pressed = ImGui::Button(label);
  if (tooltip != nullptr && ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNormal)) {
    ImGui::SetTooltip("%s", tooltip);
  }
  return pressed;
}

std::string format_address(std::uint64_t value) {
  char buffer[32];
  std::snprintf(buffer, sizeof(buffer), "0x%" PRIx64, value);
  return buffer;
}

std::string format_size(std::uint64_t bytes) {
  char buffer[32];
  if (bytes >= (1ULL << 20)) {
    std::snprintf(buffer, sizeof(buffer), "%.1f MiB",
                  static_cast<double>(bytes) / static_cast<double>(1ULL << 20));
  } else if (bytes >= (1ULL << 10)) {
    std::snprintf(buffer, sizeof(buffer), "%.1f KiB",
                  static_cast<double>(bytes) / static_cast<double>(1ULL << 10));
  } else {
    std::snprintf(buffer, sizeof(buffer), "%" PRIu64 " B", bytes);
  }
  return buffer;
}

void address(std::uint64_t value, bool highlighted) {
  const std::string text = format_address(value);
  if (highlighted) {
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.99f, 0.84f, 0.45f, 1.0f));
    ImGui::TextUnformatted(text.c_str());
    ImGui::PopStyleColor();
    return;
  }
  ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.62f, 0.78f, 0.98f, 1.0f));
  ImGui::TextUnformatted(text.c_str());
  ImGui::PopStyleColor();
}

bool search_field(const char* id, std::string& text, const char* hint) {
  ImGui::SetNextItemWidth(-1.0f);
  char buffer[256];
  std::snprintf(buffer, sizeof(buffer), "%s", text.c_str());
  const bool changed = ImGui::InputTextWithHint(id, hint, buffer, sizeof(buffer));
  if (changed) {
    text = buffer;
  }
  return changed;
}

void heading(const char* title, const char* detail) {
  ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.86f, 0.90f, 0.96f, 1.0f));
  ImGui::TextUnformatted(title);
  ImGui::PopStyleColor();
  if (detail != nullptr && detail[0] != '\0') {
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.60f, 0.68f, 1.0f));
    ImGui::TextUnformatted(detail);
    ImGui::PopStyleColor();
  }
  ImGui::Separator();
}

bool selectable_row(const char* label, bool selected, ImGuiSelectableFlags flags) {
  return ImGui::Selectable(label, selected, flags);
}

}  // namespace donkey::ui::components
