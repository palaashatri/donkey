#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include "imgui.h"
#include "session.h"

namespace donkey::ui {

/// Selection and filter state shared by every panel. It is render-thread
/// state only; the parsed document stays immutable.
struct UiState {
  std::uint64_t selected_address = 0;
  std::string selected_section;
  std::string section_filter;
  std::string function_filter;
  std::string string_filter;
  std::string xref_filter;
  std::string disassembly_filter;
  bool show_hex_bytes = true;
  bool follow_selection = true;
};

class Workspace {
 public:
  explicit Workspace(Session& session);

  /// Draw one frame: menu bar, dockspace and all panels. Sets `quit` when the
  /// user asks to close the application.
  void draw(bool& quit);

  /// Installs the native file-picker callback. Optional; without it the menu
  /// only offers the manual path entry box.
  void set_open_file_handler(std::function<void()> handler) {
    open_file_handler_ = std::move(handler);
  }

  void focus_address(std::uint64_t address, const std::string& section);

 private:
  void draw_menu_bar(bool& quit);
  void draw_dockspace();
  void draw_panels();
  void build_default_layout(ImGuiID dockspace_id);

  Session& session_;
  const Document* last_document_ = nullptr;
  UiState state_;
  bool layout_initialized_ = false;
  bool show_overview_ = true;
  bool show_sections_ = true;
  bool show_functions_ = true;
  bool show_disassembly_ = true;
  bool show_hex_ = true;
  bool show_strings_ = true;
  bool show_xrefs_ = true;
  bool show_diagnostics_ = true;
  bool show_about_ = false;
  char path_buffer_[1024] = {};
  bool open_path_popup_ = false;
  std::function<void()> open_file_handler_;
};

}  // namespace donkey::ui
