#include "theme.h"

#include <string>

#include "imgui.h"

namespace donkey::ui::theme {
namespace {

// Monospace faces are loaded from the host at runtime (never redistributed) so
// addresses and hex columns line up. Everything degrades to the built-in font.
bool load_monospace_font(float scale) {
  static const char* const kCandidates[] = {
      "/System/Library/Fonts/SFNSMono.ttf",
      "/System/Library/Fonts/Menlo.ttc",
      "/Library/Fonts/Menlo.ttc",
      "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
      "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
  };
  ImGuiIO& io = ImGui::GetIO();
  for (const char* path : kCandidates) {
    ImFont* font = io.Fonts->AddFontFromFileTTF(path, 15.0f);
    if (font != nullptr) {
      std::fprintf(stderr, "donkey: ui font %s\n", path);
      return true;
    }
  }
  std::fprintf(stderr, "donkey: ui font built-in fallback\n");
  io.Fonts->AddFontDefault();
  (void)scale;
  return false;
}

}  // namespace

void apply(float scale) {
  ImGuiStyle& style = ImGui::GetStyle();
  ImGui::StyleColorsDark(&style);
  load_monospace_font(scale);

  const ImVec4 accent(0.35f, 0.62f, 0.94f, 1.0f);
  const ImVec4 accent_dim(0.25f, 0.45f, 0.70f, 1.0f);
  const ImVec4 surface(0.11f, 0.12f, 0.14f, 1.0f);
  const ImVec4 surface_alt(0.14f, 0.15f, 0.18f, 1.0f);
  const ImVec4 surface_hi(0.19f, 0.21f, 0.25f, 1.0f);
  const ImVec4 text(0.88f, 0.90f, 0.94f, 1.0f);
  const ImVec4 text_dim(0.58f, 0.62f, 0.68f, 1.0f);

  style.Colors[ImGuiCol_Text] = text;
  style.Colors[ImGuiCol_TextDisabled] = text_dim;
  style.Colors[ImGuiCol_WindowBg] = surface;
  style.Colors[ImGuiCol_ChildBg] = surface;
  style.Colors[ImGuiCol_PopupBg] = surface_alt;
  style.Colors[ImGuiCol_Border] = ImVec4(0.22f, 0.24f, 0.28f, 0.70f);
  style.Colors[ImGuiCol_BorderShadow] = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
  style.Colors[ImGuiCol_FrameBg] = surface_alt;
  style.Colors[ImGuiCol_FrameBgHovered] = surface_hi;
  style.Colors[ImGuiCol_FrameBgActive] = surface_hi;
  style.Colors[ImGuiCol_TitleBg] = surface;
  style.Colors[ImGuiCol_TitleBgActive] = surface_alt;
  style.Colors[ImGuiCol_TitleBgCollapsed] = surface;
  style.Colors[ImGuiCol_MenuBarBg] = surface_alt;
  style.Colors[ImGuiCol_ScrollbarBg] = surface;
  style.Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.28f, 0.30f, 0.34f, 1.0f);
  style.Colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.34f, 0.37f, 0.42f, 1.0f);
  style.Colors[ImGuiCol_ScrollbarGrabActive] = accent_dim;
  style.Colors[ImGuiCol_CheckMark] = accent;
  style.Colors[ImGuiCol_SliderGrab] = accent_dim;
  style.Colors[ImGuiCol_SliderGrabActive] = accent;
  style.Colors[ImGuiCol_Button] = surface_hi;
  style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.26f, 0.32f, 0.42f, 1.0f);
  style.Colors[ImGuiCol_ButtonActive] = accent_dim;
  style.Colors[ImGuiCol_Header] = ImVec4(0.20f, 0.27f, 0.38f, 1.0f);
  style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.24f, 0.33f, 0.47f, 1.0f);
  style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.27f, 0.38f, 0.55f, 1.0f);
  style.Colors[ImGuiCol_Separator] = ImVec4(0.22f, 0.24f, 0.28f, 0.80f);
  style.Colors[ImGuiCol_SeparatorHovered] = accent_dim;
  style.Colors[ImGuiCol_SeparatorActive] = accent;
  style.Colors[ImGuiCol_ResizeGrip] = ImVec4(0.30f, 0.34f, 0.40f, 0.60f);
  style.Colors[ImGuiCol_ResizeGripHovered] = accent_dim;
  style.Colors[ImGuiCol_ResizeGripActive] = accent;
  style.Colors[ImGuiCol_Tab] = surface_alt;
  style.Colors[ImGuiCol_TabHovered] = ImVec4(0.26f, 0.34f, 0.46f, 1.0f);
  style.Colors[ImGuiCol_TabSelected] = ImVec4(0.20f, 0.28f, 0.40f, 1.0f);
  style.Colors[ImGuiCol_TabDimmed] = surface_alt;
  style.Colors[ImGuiCol_TabDimmedSelected] = surface_hi;
  style.Colors[ImGuiCol_TableHeaderBg] = surface_alt;
  style.Colors[ImGuiCol_TableBorderStrong] = ImVec4(0.22f, 0.24f, 0.28f, 0.90f);
  style.Colors[ImGuiCol_TableBorderLight] = ImVec4(0.18f, 0.20f, 0.23f, 0.70f);
  style.Colors[ImGuiCol_TableRowBg] = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
  style.Colors[ImGuiCol_TableRowBgAlt] = ImVec4(1.0f, 1.0f, 1.0f, 0.02f);
  style.Colors[ImGuiCol_TextSelectedBg] = ImVec4(0.35f, 0.62f, 0.94f, 0.35f);
  style.Colors[ImGuiCol_NavCursor] = accent;

  style.WindowRounding = 4.0f;
  style.ChildRounding = 3.0f;
  style.FrameRounding = 3.0f;
  style.PopupRounding = 4.0f;
  style.ScrollbarRounding = 6.0f;
  style.GrabRounding = 3.0f;
  style.TabRounding = 4.0f;
  style.WindowBorderSize = 1.0f;
  style.FrameBorderSize = 0.0f;
  style.WindowPadding = ImVec2(10.0f, 8.0f);
  style.FramePadding = ImVec2(7.0f, 4.0f);
  style.ItemSpacing = ImVec2(8.0f, 6.0f);
  style.ScrollbarSize = 12.0f;

  style.ScaleAllSizes(scale);
}

}  // namespace donkey::ui::theme
