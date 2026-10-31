#include "workspace.h"

#include <cstdio>
#include <cstring>

#include "components.h"
#include "imgui.h"
#include "imgui_internal.h"
#include "theme.h"
#include "views.h"

namespace donkey::ui {
namespace {

constexpr const char* kSectionsWindow = "Sections";
constexpr const char* kFunctionsWindow = "Functions";
constexpr const char* kDisassemblyWindow = "Disassembly";
constexpr const char* kDecompilerWindow = "Decompiler";
constexpr const char* kGraphWindow = "Graph";
constexpr const char* kHexWindow = "Hex";
constexpr const char* kStringsWindow = "Strings";
constexpr const char* kXrefsWindow = "Xrefs";
constexpr const char* kBookmarksWindow = "Bookmarks";
constexpr const char* kDebuggerWindow = "Debugger";
constexpr const char* kOverviewWindow = "Overview";
constexpr const char* kDiagnosticsWindow = "Diagnostics";

ImGuiWindowFlags panel_flags() {
  return ImGuiWindowFlags_NoCollapse;
}

}  // namespace

Workspace::Workspace(Session& session) : session_(session) {}

void Workspace::focus_address(std::uint64_t address, const std::string& section) {
  state_.selected_address = address;
  state_.selected_section = section;
}

void Workspace::draw(bool& quit) {
  draw_menu_bar(quit);

  if (state_.function_edit_requested) {
    state_.function_edit_requested = false;
    session_.set_function_edit(state_.function_edit_address, state_.function_edit_action);
  }
  // A boundary edit made while the worker was busy runs once it is free.
  if (!session_.busy() && session_.reanalysis_pending()) {
    session_.reanalyze();
  }

  ImGuiViewport* viewport = ImGui::GetMainViewport();
  ImGui::SetNextWindowPos(viewport->WorkPos);
  ImGui::SetNextWindowSize(viewport->WorkSize);
  ImGui::SetNextWindowViewport(viewport->ID);
  const ImGuiWindowFlags flags = ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoTitleBar |
                                 ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize |
                                 ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus |
                                 ImGuiWindowFlags_NoNavFocus;

  ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
  ImGui::Begin("##donkey_root", nullptr, flags);
  ImGui::PopStyleVar(3);

  // The dockspace ID must be resolved inside this window: DockBuilder and
  // DockSpace look it up in different ID stacks otherwise and the layout
  // silently never applies.
  const ImGuiID dockspace_id = ImGui::GetID("DonkeyDockspace");
  if (!layout_initialized_) {
    build_default_layout(dockspace_id);
    layout_initialized_ = true;
  }
  ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f), ImGuiDockNodeFlags_None);
  ImGui::End();

  draw_panels();

  if (!ImGui::GetIO().WantTextInput) {
    const bool cmd_or_ctrl = (ImGui::GetIO().KeyMods & ImGuiMod_Shortcut) != 0;
    const bool alt = ImGui::GetIO().KeyAlt;
    const bool shift = ImGui::GetIO().KeyShift;

    if (cmd_or_ctrl && ImGui::IsKeyPressed(ImGuiKey_Z)) {
      if (shift) {
        session_.redo();
      } else {
        session_.undo();
      }
    } else if (cmd_or_ctrl && ImGui::IsKeyPressed(ImGuiKey_B)) {
      if (state_.selected_address != 0) {
        session_.toggle_bookmark(state_.selected_address);
      }
    } else if (alt && ImGui::IsKeyPressed(ImGuiKey_LeftArrow)) {
      state_.nav_back(session_.document().get());
    } else if (alt && ImGui::IsKeyPressed(ImGuiKey_RightArrow)) {
      state_.nav_forward(session_.document().get());
    } else if (ImGui::IsKeyPressed(ImGuiKey_Escape) && session_.busy()) {
      session_.cancel();
    }
  }

  if (open_path_popup_) {
    ImGui::OpenPopup("Open binary");
    open_path_popup_ = false;
  }
  if (ImGui::BeginPopupModal("Open binary", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
    ImGui::TextUnformatted("Path to a binary file");
    ImGui::SetNextItemWidth(520.0f);
    if (ImGui::InputText("##path", path_buffer_, sizeof(path_buffer_),
                         ImGuiInputTextFlags_EnterReturnsTrue)) {
      session_.open(path_buffer_);
      ImGui::CloseCurrentPopup();
    }
    if (ImGui::Button("Open") && path_buffer_[0] != '\0') {
      session_.open(path_buffer_);
      ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel")) {
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }

  if (open_project_popup_) {
    ImGui::OpenPopup("Open project");
    open_project_popup_ = false;
  }
  if (ImGui::BeginPopupModal("Open project", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
    ImGui::TextUnformatted("Path to a project database");
    ImGui::SetNextItemWidth(520.0f);
    const bool open_busy = session_.busy();
    ImGui::BeginDisabled(open_busy);
    const bool open_submitted =
        ImGui::InputText("##projectpath", project_path_buffer_, sizeof(project_path_buffer_),
                         ImGuiInputTextFlags_EnterReturnsTrue);
    const bool open_clicked = ImGui::Button("Open");
    ImGui::EndDisabled();

    if (!open_busy && (open_submitted || open_clicked) && project_path_buffer_[0] != '\0') {
      session_.open_project(project_path_buffer_);
      ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel")) {
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }

  if (save_project_popup_) {
    ImGui::OpenPopup("Save project");
    save_project_popup_ = false;
  }
  if (ImGui::BeginPopupModal("Save project", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
    ImGui::TextUnformatted("Database path for this project");
    ImGui::SetNextItemWidth(520.0f);
    const bool save_busy = session_.busy();
    ImGui::BeginDisabled(save_busy);
    const bool save_submitted =
        ImGui::InputText("##saveprojectpath", project_path_buffer_, sizeof(project_path_buffer_),
                         ImGuiInputTextFlags_EnterReturnsTrue);
    const bool save_clicked = ImGui::Button("Save");
    ImGui::EndDisabled();

    if (!save_busy && (save_submitted || save_clicked) && project_path_buffer_[0] != '\0') {
      session_.save_project(project_path_buffer_);
      ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel")) {
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }

  if (backup_project_popup_) {
    ImGui::OpenPopup("Backup project");
    backup_project_popup_ = false;
  }
  if (ImGui::BeginPopupModal("Backup project", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
    ImGui::TextUnformatted("Destination path for the project backup");
    if (session_.dirty()) {
      ImGui::TextDisabled(
          "Unsaved in-memory annotation edits are not included until you Save Project.");
    }
    ImGui::SetNextItemWidth(520.0f);
    const bool backup_busy = session_.busy();
    ImGui::BeginDisabled(backup_busy);
    const bool backup_submitted =
        ImGui::InputText("##backupprojectpath", backup_path_buffer_, sizeof(backup_path_buffer_),
                         ImGuiInputTextFlags_EnterReturnsTrue);
    const bool backup_clicked = ImGui::Button("Backup");
    ImGui::EndDisabled();

    if (!backup_busy && (backup_submitted || backup_clicked) && backup_path_buffer_[0] != '\0') {
      session_.backup_project(backup_path_buffer_, true);
      ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel")) {
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }

  if (restore_project_popup_) {
    ImGui::OpenPopup("Restore project");
    restore_project_popup_ = false;
  }
  if (ImGui::BeginPopupModal("Restore project", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
    ImGui::TextUnformatted("Backup database path to restore into the current project");
    ImGui::SetNextItemWidth(520.0f);
    const bool restore_busy = session_.busy();
    ImGui::BeginDisabled(restore_busy);
    const bool restore_submitted =
        ImGui::InputText("##restoreprojectpath", backup_path_buffer_, sizeof(backup_path_buffer_),
                         ImGuiInputTextFlags_EnterReturnsTrue);
    const bool restore_clicked = ImGui::Button("Restore");
    ImGui::EndDisabled();

    if (!restore_busy && (restore_submitted || restore_clicked) && backup_path_buffer_[0] != '\0') {
      session_.restore_project(backup_path_buffer_);
      ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel")) {
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }

  if (state_.annotation_modal_requested) {
    ImGui::OpenPopup("Annotate");
    state_.annotation_modal_requested = false;
  }
  if (ImGui::BeginPopupModal("Annotate", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
    const char* kind_label = "Rename at";
    if (state_.annotation_kind == AnnotationKind::Comment) {
      kind_label = "Comment at";
    } else if (state_.annotation_kind == AnnotationKind::Bookmark) {
      kind_label = "Bookmark at";
    }
    ImGui::Text("%s %s", kind_label, components::format_address(state_.annotation_address).c_str());
    ImGui::SetNextItemWidth(520.0f);
    const bool submitted =
        ImGui::InputText("##annotation", state_.annotation_buffer, sizeof(state_.annotation_buffer),
                         ImGuiInputTextFlags_EnterReturnsTrue);
    const bool save = (submitted || ImGui::Button("Save")) && !session_.busy();
    if (save) {
      session_.set_annotation(state_.annotation_kind, state_.annotation_address,
                              state_.annotation_buffer);
      ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("Remove")) {
      session_.set_annotation(state_.annotation_kind, state_.annotation_address, "");
      ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel")) {
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }

  if (show_about_) {
    ImGui::Begin("About Donkey", &show_about_, ImGuiWindowFlags_AlwaysAutoResize);
    ImGui::TextUnformatted("Donkey — native binary reverse-engineering suite");
    ImGui::Separator();
    ImGui::TextWrapped(
        "Early implementation. The headless core parses ELF, PE and Mach-O, "
        "decodes x86, x86-64 and AArch64 with Capstone, builds a bounded CFG "
        "with estimated function extents, and lifts x86-64, x86-32 subset and "
        "AArch64 subset functions into verified IR before printing pseudocode. "
        "Projects save, reopen, back up and restore address-keyed renames and "
        "comments. The debugger and 32-bit ARM lifting are not implemented.");
    ImGui::Spacing();
    ImGui::TextDisabled("Opened files are only read; nothing is executed.");
    ImGui::End();
  }
}

void Workspace::draw_menu_bar(bool& quit) {
  if (!ImGui::BeginMainMenuBar()) {
    return;
  }
  if (ImGui::BeginMenu("File")) {
    if (ImGui::MenuItem("Open File…", "Cmd+O", false, open_file_handler_ != nullptr)) {
      open_file_handler_();
    }
    if (ImGui::MenuItem("Open path…")) {
      open_path_popup_ = true;
    }
    if (ImGui::MenuItem("Open Project…", nullptr, false, !session_.busy())) {
      open_project_popup_ = true;
    }
    ImGui::Separator();
    if (ImGui::MenuItem("Save Project", "Cmd+S", false,
                        session_.has_project() && !session_.busy())) {
      session_.save_project(session_.project_path());
    }
    if (ImGui::MenuItem("Save Project As…", nullptr, false,
                        session_.document() != nullptr && !session_.busy())) {
      const std::string existing = session_.project_path();
      std::snprintf(project_path_buffer_, sizeof(project_path_buffer_), "%s", existing.c_str());
      save_project_popup_ = true;
    }
    if (ImGui::MenuItem("Backup Project…", nullptr, false,
                        session_.has_project() && !session_.busy())) {
      if (backup_path_buffer_[0] == '\0') {
        const std::string suggested = session_.project_path() + ".bak";
        std::snprintf(backup_path_buffer_, sizeof(backup_path_buffer_), "%s", suggested.c_str());
      }
      backup_project_popup_ = true;
    }
    if (ImGui::MenuItem("Restore Project…", nullptr, false,
                        session_.has_project() && !session_.busy())) {
      if (backup_path_buffer_[0] == '\0') {
        const std::string suggested = session_.project_path() + ".bak";
        std::snprintf(backup_path_buffer_, sizeof(backup_path_buffer_), "%s", suggested.c_str());
      }
      restore_project_popup_ = true;
    }
    if (ImGui::MenuItem("Reload", nullptr, false, !session_.path().empty() && !session_.busy())) {
      session_.open(session_.path());
    }
    ImGui::Separator();
    if (ImGui::MenuItem("Quit", "Cmd+Q")) {
      quit = true;
    }
    ImGui::EndMenu();
  }
  if (ImGui::BeginMenu("Edit")) {
    if (ImGui::MenuItem("Undo", "Cmd+Z", false, session_.can_undo())) {
      session_.undo();
    }
    if (ImGui::MenuItem("Redo", "Cmd+Shift+Z", false, session_.can_redo())) {
      session_.redo();
    }
    ImGui::Separator();
    const bool bookmarked =
        state_.annotations != nullptr && state_.annotations->has_bookmark(state_.selected_address);
    if (ImGui::MenuItem(bookmarked ? "Remove Bookmark" : "Toggle Bookmark", "Cmd+B", false,
                        state_.selected_address != 0)) {
      session_.toggle_bookmark(state_.selected_address);
    }
    if (session_.busy()) {
      ImGui::Separator();
      if (ImGui::MenuItem("Cancel Task", "Esc")) {
        session_.cancel();
      }
    }
    ImGui::EndMenu();
  }
  if (ImGui::BeginMenu("Navigate")) {
    if (ImGui::MenuItem("Back", "Alt+Left", false, state_.can_nav_back())) {
      state_.nav_back(session_.document().get());
    }
    if (ImGui::MenuItem("Forward", "Alt+Right", false, state_.can_nav_forward())) {
      state_.nav_forward(session_.document().get());
    }
    ImGui::EndMenu();
  }
  if (ImGui::BeginMenu("View")) {
    ImGui::MenuItem(kOverviewWindow, nullptr, &show_overview_);
    ImGui::MenuItem(kSectionsWindow, nullptr, &show_sections_);
    ImGui::MenuItem(kFunctionsWindow, nullptr, &show_functions_);
    ImGui::MenuItem(kDisassemblyWindow, nullptr, &show_disassembly_);
    ImGui::MenuItem(kDecompilerWindow, nullptr, &show_decompiler_);
    ImGui::MenuItem(kGraphWindow, nullptr, &show_graph_);
    ImGui::MenuItem(kHexWindow, nullptr, &show_hex_);
    ImGui::MenuItem(kStringsWindow, nullptr, &show_strings_);
    ImGui::MenuItem(kXrefsWindow, nullptr, &show_xrefs_);
    ImGui::MenuItem(kBookmarksWindow, nullptr, &show_bookmarks_);
    ImGui::MenuItem(kDebuggerWindow, nullptr, &show_debugger_);
    ImGui::MenuItem(kDiagnosticsWindow, nullptr, &show_diagnostics_);
    ImGui::EndMenu();
  }
  if (ImGui::BeginMenu("Help")) {
    ImGui::MenuItem("About Donkey", nullptr, &show_about_);
    ImGui::EndMenu();
  }

  const std::string status = session_.status();
  const std::string document_name =
      session_.path().empty() ? std::string("No file") : session_.path();
  // Right-aligned document name and status. The window title already shows the
  // path, so cap the width here instead of letting it push badges off-screen.
  const float badge_width = session_.busy() ? 190.0f : 110.0f;
  const float max_name_width = ImGui::GetWindowWidth() - badge_width - 320.0f;
  ImGui::SameLine(max_name_width > 140.0f ? max_name_width : 140.0f);
  char short_name[96];
  const char* base = std::strrchr(document_name.c_str(), '/');
  std::snprintf(short_name, sizeof(short_name), "%s",
                base != nullptr ? base + 1 : document_name.c_str());
  ImGui::TextDisabled("%s", short_name);
  if (session_.has_project()) {
    const std::string project = session_.project_path();
    const char* project_base = std::strrchr(project.c_str(), '/');
    ImGui::SameLine();
    ImGui::TextDisabled("· project %s%s",
                        project_base != nullptr ? project_base + 1 : project.c_str(),
                        session_.dirty() ? " *" : "");
  }
  ImGui::SameLine();
  if (session_.busy()) {
    components::badge("Loading", components::status_color("Partial"));
    ImGui::SameLine();
  }
  const auto document = session_.document();
  if (document) {
    const char* status_text = document->analysis.partial ? "Partial" : "Complete";
    components::badge(status_text, components::status_color(status_text));
  }
  ImGui::EndMainMenuBar();
}

void Workspace::build_default_layout(ImGuiID dockspace_id) {
  ImGui::DockBuilderRemoveNode(dockspace_id);
  ImGuiID root = ImGui::DockBuilderAddNode(dockspace_id, ImGuiDockNodeFlags_DockSpace);
  ImGui::DockBuilderSetNodeSize(root, ImGui::GetMainViewport()->WorkSize);

  ImGuiID center = root;
  ImGuiID left = ImGui::DockBuilderSplitNode(center, ImGuiDir_Left, 0.24f, nullptr, &center);
  ImGuiID right = ImGui::DockBuilderSplitNode(center, ImGuiDir_Right, 0.28f, nullptr, &center);
  ImGuiID bottom = ImGui::DockBuilderSplitNode(center, ImGuiDir_Down, 0.34f, nullptr, &center);
  ImGuiID decompiler = ImGui::DockBuilderSplitNode(center, ImGuiDir_Down, 0.45f, nullptr, &center);
  ImGuiID left_bottom = ImGui::DockBuilderSplitNode(left, ImGuiDir_Down, 0.48f, nullptr, &left);
  ImGuiID right_bottom = ImGui::DockBuilderSplitNode(right, ImGuiDir_Down, 0.55f, nullptr, &right);

  ImGui::DockBuilderDockWindow(kDisassemblyWindow, center);
  ImGui::DockBuilderDockWindow(kGraphWindow, center);
  ImGui::DockBuilderDockWindow(kDecompilerWindow, decompiler);
  ImGui::DockBuilderDockWindow(kHexWindow, bottom);
  ImGui::DockBuilderDockWindow(kStringsWindow, bottom);
  ImGui::DockBuilderDockWindow(kXrefsWindow, bottom);
  ImGui::DockBuilderDockWindow(kBookmarksWindow, bottom);
  ImGui::DockBuilderDockWindow(kDebuggerWindow, bottom);
  ImGui::DockBuilderDockWindow(kSectionsWindow, left);
  ImGui::DockBuilderDockWindow(kFunctionsWindow, left_bottom);
  ImGui::DockBuilderDockWindow(kOverviewWindow, right);
  ImGui::DockBuilderDockWindow(kDiagnosticsWindow, right_bottom);
  ImGui::DockBuilderFinish(root);
}

void Workspace::draw_panels() {
  const auto document = session_.document();
  state_.pseudocode_document_owner = document;
  // Keep the annotation snapshot alive for the whole frame; views only keep
  // the raw pointer in UiState.
  const auto annotations = session_.annotations();
  state_.annotations = annotations.get();

  if (document && document.get() != last_document_) {
    last_document_ = document.get();
    const BinaryImage& image = document->loaded.image;
    std::uint64_t initial = 0;
    if (image.has_entry_point() && image.va_to_file_offset(image.entry_point)) {
      initial = image.entry_point;
    } else {
      for (const Section& section : image.sections) {
        if (section.address != 0 && section.has_file_data &&
            image.va_to_file_offset(section.address)) {
          initial = section.address;
          break;
        }
      }
    }
    state_.selected_address = initial;
    state_.selected_section.clear();
    if (const Section* section = image.section_for_va(initial); section != nullptr) {
      state_.selected_section = section->name;
    }
  }

  if (show_overview_) {
    ImGui::Begin(kOverviewWindow, &show_overview_, panel_flags());
    if (document) {
      views::overview(*document, state_);
    } else {
      ImGui::TextDisabled("No document.");
    }
    ImGui::End();
  }
  if (show_sections_) {
    ImGui::Begin(kSectionsWindow, &show_sections_, panel_flags());
    if (document) {
      views::sections(*document, state_);
    } else {
      ImGui::TextDisabled("No document.");
    }
    ImGui::End();
  }
  if (show_functions_) {
    ImGui::Begin(kFunctionsWindow, &show_functions_, panel_flags());
    if (document) {
      views::functions(*document, state_);
    } else {
      ImGui::TextDisabled("No document.");
    }
    ImGui::End();
  }
  if (show_disassembly_) {
    ImGui::Begin(kDisassemblyWindow, &show_disassembly_, panel_flags());
    if (document) {
      views::disassembly(*document, state_);
    } else {
      ImGui::TextDisabled("No document.");
    }
    ImGui::End();
  }
  if (show_decompiler_) {
    ImGui::Begin(kDecompilerWindow, &show_decompiler_, panel_flags());
    if (document) {
      views::decompiler(*document, state_);
    } else {
      ImGui::TextDisabled("No document.");
    }
    ImGui::End();
  }
  if (show_graph_) {
    ImGui::Begin(kGraphWindow, &show_graph_, panel_flags());
    if (document) {
      views::cfg_graph(*document, state_);
    } else {
      ImGui::TextDisabled("No document.");
    }
    ImGui::End();
  }
  if (show_hex_) {
    ImGui::Begin(kHexWindow, &show_hex_, panel_flags());
    if (document) {
      views::hex(*document, state_);
    } else {
      ImGui::TextDisabled("No document.");
    }
    ImGui::End();
  }
  if (show_strings_) {
    ImGui::Begin(kStringsWindow, &show_strings_, panel_flags());
    if (document) {
      views::strings(*document, state_);
    } else {
      ImGui::TextDisabled("No document.");
    }
    ImGui::End();
  }
  if (show_xrefs_) {
    ImGui::Begin(kXrefsWindow, &show_xrefs_, panel_flags());
    if (document) {
      views::xrefs(*document, state_);
    } else {
      ImGui::TextDisabled("No document.");
    }
    ImGui::End();
  }
  if (show_bookmarks_) {
    ImGui::Begin(kBookmarksWindow, &show_bookmarks_, panel_flags());
    if (document) {
      views::bookmarks(*document, state_);
    } else {
      ImGui::TextDisabled("No document.");
    }
    ImGui::End();
  }
  if (show_debugger_) {
    ImGui::Begin(kDebuggerWindow, &show_debugger_, panel_flags());
    if (document) {
      views::debugger(*document, state_);
    } else {
      ImGui::TextDisabled("No document.");
    }
    ImGui::End();
  }
  if (show_diagnostics_) {
    ImGui::Begin(kDiagnosticsWindow, &show_diagnostics_, panel_flags());
    if (document) {
      views::diagnostics(*document, state_);
    } else {
      ImGui::TextDisabled("No document.");
    }
    ImGui::End();
  }
}

}  // namespace donkey::ui
