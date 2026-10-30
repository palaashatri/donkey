#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "donkey/core/navigation.h"
#include "donkey/debug/debug.h"
#include "donkey/ir/ir.h"
#include "imgui.h"
#include "session.h"

namespace donkey::ui {

struct AsyncDecompileState {
  std::mutex mutex;
  std::uint64_t current_generation = 0;
  bool ready = false;
  std::uint64_t ready_address = 0;
  std::string ready_status;
  std::string ready_code;
  std::string ready_text;
  std::vector<PseudocodeLine> ready_lines;
};

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

  /// Current annotation snapshot for this frame, owned by the caller. Views
  /// only read it; edits go through Workspace's modal into the session.
  const Annotations* annotations = nullptr;

  // --- annotation editor ----------------------------------------------------
  // Views set a request; Workspace owns the modal and forwards the result to
  // Session::set_annotation, which mutates an immutable snapshot off-thread.
  bool annotation_modal_requested = false;
  AnnotationKind annotation_kind = AnnotationKind::Rename;
  std::uint64_t annotation_address = 0;
  char annotation_buffer[512] = {};

  /// Cached decompilation for the currently selected function. Lifting is
  /// bounded and executed asynchronously off the render thread.
  const Document* pseudocode_document = nullptr;
  std::uint64_t pseudocode_address = 0;
  std::string pseudocode_function;
  std::string pseudocode_status;
  std::string pseudocode_code;
  std::string pseudocode_text;
  std::vector<PseudocodeLine> pseudocode_lines;
  bool pseudocode_in_progress = false;
  std::shared_ptr<AsyncDecompileState> async_decompile = std::make_shared<AsyncDecompileState>();

  // --- navigation history ---------------------------------------------------
  NavigationHistory nav_history;

  void navigate_to(std::uint64_t address, const Document* doc = nullptr) {
    if (address == 0 || selected_address == address) {
      return;
    }
    nav_history.navigate_to(address);
    selected_address = address;
    if (doc != nullptr) {
      const Section* s = doc->loaded.image.section_for_va(address);
      if (s != nullptr) {
        selected_section = s->name;
      }
    }
  }

  [[nodiscard]] bool can_nav_back() const { return nav_history.can_nav_back(); }
  [[nodiscard]] bool can_nav_forward() const { return nav_history.can_nav_forward(); }

  void nav_back(const Document* doc = nullptr) {
    if (auto target = nav_history.nav_back(); target.has_value()) {
      selected_address = target.value();
      if (doc != nullptr) {
        const Section* s = doc->loaded.image.section_for_va(selected_address);
        if (s != nullptr) {
          selected_section = s->name;
        }
      }
    }
  }

  void nav_forward(const Document* doc = nullptr) {
    if (auto target = nav_history.nav_forward(); target.has_value()) {
      selected_address = target.value();
      if (doc != nullptr) {
        const Section* s = doc->loaded.image.section_for_va(selected_address);
        if (s != nullptr) {
          selected_section = s->name;
        }
      }
    }
  }

  // --- CFG graph view -------------------------------------------------------
  // Pan/zoom is render-thread state. The layout is re-derived per frame from
  // the immutable analysis; blocks are bounded by the CFG builder.
  float graph_zoom = 0.0f;  // 0 = fit on first draw
  ImVec2 graph_pan{0.0f, 0.0f};
  ImVec2 graph_canvas_size{0.0f, 0.0f};
  bool graph_user_adjusted = false;
  const Document* graph_document = nullptr;
  std::uint64_t graph_function = 0;

  // --- Debugger state -------------------------------------------------------
  std::unique_ptr<debug::DebugAdapter> debug_adapter;
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
  bool show_decompiler_ = true;
  bool show_graph_ = true;
  bool show_hex_ = true;
  bool show_strings_ = true;
  bool show_xrefs_ = true;
  bool show_bookmarks_ = true;
  bool show_debugger_ = true;
  bool show_diagnostics_ = true;
  bool show_about_ = false;
  char path_buffer_[1024] = {};
  char project_path_buffer_[1024] = {};
  char backup_path_buffer_[1024] = {};
  bool open_path_popup_ = false;
  bool open_project_popup_ = false;
  bool save_project_popup_ = false;
  bool backup_project_popup_ = false;
  bool restore_project_popup_ = false;
  std::function<void()> open_file_handler_;
};

}  // namespace donkey::ui
