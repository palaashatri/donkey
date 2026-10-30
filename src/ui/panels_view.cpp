#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>

#include "components.h"
#include "views.h"

namespace donkey::ui::views {
namespace {

bool matches(std::string_view haystack, const std::string& needle) {
  if (needle.empty()) {
    return true;
  }
  return haystack.find(needle) != std::string_view::npos;
}

std::string permissions(bool readable, bool writable, bool executable) {
  std::string out = "---";
  out[0] = readable ? 'r' : '-';
  out[1] = writable ? 'w' : '-';
  out[2] = executable ? 'x' : '-';
  return out;
}

}  // namespace

void overview(const Document& document, UiState& state) {
  const BinaryImage& image = document.loaded.image;
  const AnalysisResult& analysis = document.analysis;

  components::heading("File");
  ImGui::TextWrapped("%s", image.path.c_str());
  ImGui::Spacing();
  ImGui::Text("Format      %s", image.format_detail.c_str());
  ImGui::Text("Architecture %s", architecture_name(image.architecture));
  ImGui::Text("Size        %s", components::format_size(image.file_size).c_str());
  ImGui::Text("Entry       %s", image.has_entry_point()
                                    ? components::format_address(image.entry_point).c_str()
                                    : "unavailable");
  ImGui::Text("Base        %s", components::format_address(image.image_base).c_str());
  ImGui::Text("SHA-256");
  ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.62f, 0.78f, 0.98f, 1.0f));
  ImGui::TextWrapped("%s", image.sha256.c_str());
  ImGui::PopStyleColor();

  ImGui::Spacing();
  components::heading("Status");
  const char* image_status = image.partial ? "Partial" : "Complete";
  components::badge(image_status, components::status_color(image_status));
  ImGui::SameLine();
  const char* analysis_status = analysis.partial ? "Partial" : "Complete";
  components::badge(analysis_status, components::status_color(analysis_status));

  ImGui::Spacing();
  components::heading("Analysis");
  ImGui::Text("Instructions %zu", analysis.instructions.size());
  ImGui::Text("Functions    %zu seeds", analysis.functions.size());
  ImGui::Text("Xrefs        %zu", analysis.xrefs.size());
  ImGui::Text("Strings      %zu", analysis.strings.size());
  ImGui::TextDisabled("Linear/seeded analysis: no CFG or function extents yet.");

  ImGui::Spacing();
  components::heading("Selection");
  ImGui::Text("Address %s", components::format_address(state.selected_address).c_str());
  if (const Section* section = image.section_for_va(state.selected_address); section != nullptr) {
    ImGui::Text("Section %s", section->name.c_str());
  }
}

void sections(const Document& document, UiState& state) {
  const BinaryImage& image = document.loaded.image;
  components::search_field("##sectionfilter", state.section_filter, "Filter sections");

  const ImGuiTableFlags flags = ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_RowBg |
                                ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV;
  if (!ImGui::BeginTable("##sections", 4, flags)) {
    return;
  }
  ImGui::TableSetupScrollFreeze(0, 1);
  ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 2.2f);
  ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch, 1.2f);
  ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthStretch, 0.8f);
  ImGui::TableSetupColumn("Perm", ImGuiTableColumnFlags_WidthStretch, 0.6f);
  ImGui::TableHeadersRow();

  for (const Section& section : image.sections) {
    if (!matches(section.name, state.section_filter)) {
      continue;
    }
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    const bool selected = state.selected_section == section.name &&
                          state.selected_address >= section.address &&
                          state.selected_address < section.address + section.virtual_size;
    if (ImGui::Selectable(section.name.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns)) {
      state.selected_section = section.name;
      state.selected_address = section.address;
    }
    ImGui::TableSetColumnIndex(1);
    ImGui::TextUnformatted(components::format_address(section.address).c_str());
    ImGui::TableSetColumnIndex(2);
    ImGui::TextUnformatted(components::format_size(section.virtual_size).c_str());
    ImGui::TableSetColumnIndex(3);
    ImGui::TextUnformatted(
        permissions(section.readable, section.writable, section.executable).c_str());
  }
  ImGui::EndTable();
}

void functions(const Document& document, UiState& state) {
  components::search_field("##functionfilter", state.function_filter, "Filter functions");

  const ImGuiTableFlags flags = ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_RowBg |
                                ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV;
  if (!ImGui::BeginTable("##functions", 4, flags)) {
    return;
  }
  ImGui::TableSetupScrollFreeze(0, 1);
  ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch, 0.9f);
  ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 1.8f);
  ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthStretch, 0.65f);
  ImGui::TableSetupColumn("Blocks", ImGuiTableColumnFlags_WidthStretch, 0.75f);
  ImGui::TableHeadersRow();

  for (const Function& function : document.analysis.functions) {
    const std::string* renamed =
        state.annotations != nullptr ? state.annotations->rename_at(function.address) : nullptr;
    const std::string display = renamed != nullptr ? *renamed : function.name;
    if (!matches(display, state.function_filter)) {
      continue;
    }
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    if (ImGui::Selectable(components::format_address(function.address).c_str(),
                          state.selected_address == function.address,
                          ImGuiSelectableFlags_SpanAllColumns)) {
      state.selected_address = function.address;
    }
    if (ImGui::BeginPopupContextItem("##functioncontext")) {
      if (ImGui::MenuItem("Rename…")) {
        state.annotation_kind = AnnotationKind::Rename;
        state.annotation_address = function.address;
        std::snprintf(state.annotation_buffer, sizeof(state.annotation_buffer), "%s",
                      display.c_str());
        state.annotation_modal_requested = true;
      }
      const std::string* comment =
          state.annotations != nullptr ? state.annotations->comment_at(function.address) : nullptr;
      if (ImGui::MenuItem(comment != nullptr ? "Edit comment…" : "Add comment…")) {
        state.annotation_kind = AnnotationKind::Comment;
        state.annotation_address = function.address;
        std::snprintf(state.annotation_buffer, sizeof(state.annotation_buffer), "%s",
                      comment != nullptr ? comment->c_str() : "");
        state.annotation_modal_requested = true;
      }
      ImGui::EndPopup();
    }
    ImGui::TableSetColumnIndex(1);
    ImGui::TextUnformatted(display.c_str());
    if (renamed != nullptr) {
      ImGui::SameLine();
      components::badge("user", components::status_color("Success"));
    }
    if (function.exported) {
      ImGui::SameLine();
      components::badge("export", components::status_color("Success"));
    }
    if (function.estimated) {
      ImGui::SameLine();
      components::badge("~", components::status_color("Partial"));
      if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("Extent is a lower bound: indirect branch, overlap or limit");
      }
    }
    ImGui::TableSetColumnIndex(2);
    if (function.has_extent) {
      ImGui::TextUnformatted(
          components::format_size(function.end_address - function.address).c_str());
    } else {
      ImGui::TextDisabled("unknown");
    }
    ImGui::TableSetColumnIndex(3);
    ImGui::Text("%u", function.block_count);
  }
  ImGui::EndTable();
}

void strings(const Document& document, UiState& state) {
  components::search_field("##stringfilter", state.string_filter, "Filter strings");

  const ImGuiTableFlags flags = ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_RowBg |
                                ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV;
  if (!ImGui::BeginTable("##strings", 3, flags)) {
    return;
  }
  ImGui::TableSetupScrollFreeze(0, 1);
  ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch, 1.1f);
  ImGui::TableSetupColumn("Encoding", ImGuiTableColumnFlags_WidthStretch, 0.7f);
  ImGui::TableSetupColumn("Text", ImGuiTableColumnFlags_WidthStretch, 3.0f);
  ImGui::TableHeadersRow();

  for (const StringLiteral& literal : document.analysis.strings) {
    if (!matches(literal.text, state.string_filter)) {
      continue;
    }
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    if (literal.mapped) {
      if (ImGui::Selectable(components::format_address(literal.address).c_str(),
                            state.selected_address == literal.address,
                            ImGuiSelectableFlags_SpanAllColumns)) {
        state.selected_address = literal.address;
      }
    } else {
      ImGui::TextDisabled("<unmapped>");
    }
    ImGui::TableSetColumnIndex(1);
    ImGui::TextDisabled("%s", literal.encoding.c_str());
    ImGui::TableSetColumnIndex(2);
    ImGui::TextUnformatted(literal.text.c_str());
  }
  ImGui::EndTable();
}

void xrefs(const Document& document, UiState& state) {
  components::search_field("##xreffilter", state.xref_filter, "Filter by kind, source or target");

  const ImGuiTableFlags flags = ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_RowBg |
                                ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV;
  if (!ImGui::BeginTable("##xrefs", 3, flags)) {
    return;
  }
  ImGui::TableSetupScrollFreeze(0, 1);
  ImGui::TableSetupColumn("From", ImGuiTableColumnFlags_WidthStretch, 1.2f);
  ImGui::TableSetupColumn("To", ImGuiTableColumnFlags_WidthStretch, 1.2f);
  ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthStretch, 1.0f);
  ImGui::TableHeadersRow();

  for (const Xref& xref : document.analysis.xrefs) {
    const std::string from = components::format_address(xref.from);
    const std::string to = components::format_address(xref.to);
    const std::string kind = xref_kind_name(xref.kind);
    if (!matches(from + to + kind, state.xref_filter)) {
      continue;
    }
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    if (ImGui::Selectable(from.c_str(), state.selected_address == xref.from,
                          ImGuiSelectableFlags_SpanAllColumns)) {
      state.selected_address = xref.from;
    }
    ImGui::TableSetColumnIndex(1);
    ImGui::TextUnformatted(to.c_str());
    ImGui::TableSetColumnIndex(2);
    ImGui::TextDisabled("%s", kind.c_str());
  }
  ImGui::EndTable();
}

void bookmarks(const Document& document, UiState& state) {
  if (state.annotations == nullptr || state.annotations->bookmarks.empty()) {
    ImGui::TextDisabled(
        "No bookmarks set. Right-click an instruction or use Edit -> Toggle Bookmark to set one.");
    return;
  }

  const ImGuiTableFlags flags = ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_RowBg |
                                ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV;
  if (!ImGui::BeginTable("##bookmarks", 3, flags)) {
    return;
  }
  ImGui::TableSetupScrollFreeze(0, 1);
  ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch, 1.0f);
  ImGui::TableSetupColumn("Label / Note", ImGuiTableColumnFlags_WidthStretch, 2.5f);
  ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthStretch, 0.8f);
  ImGui::TableHeadersRow();

  std::vector<std::pair<std::uint64_t, std::string>> sorted_bookmarks(
      state.annotations->bookmarks.begin(), state.annotations->bookmarks.end());
  std::sort(sorted_bookmarks.begin(), sorted_bookmarks.end(),
            [](const auto& a, const auto& b) { return a.first < b.first; });

  for (const auto& [address, note] : sorted_bookmarks) {
    const std::string addr_str = components::format_address(address);
    const bool selected = state.selected_address == address;

    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    if (ImGui::Selectable(addr_str.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns)) {
      state.navigate_to(address, &document);
    }
    ImGui::TableSetColumnIndex(1);
    ImGui::TextUnformatted(note.c_str());
    ImGui::TableSetColumnIndex(2);
    ImGui::PushID(static_cast<int>(address));
    if (ImGui::SmallButton("Remove")) {
      state.annotation_kind = AnnotationKind::Bookmark;
      state.annotation_address = address;
      state.annotation_buffer[0] = '\0';
      state.annotation_modal_requested = true;
    }
    ImGui::PopID();
  }
  ImGui::EndTable();
}

void diagnostics(const Document& document, UiState& state) {
  (void)state;
  const auto& diagnostics = document.analysis.diagnostics;
  const auto& image_diagnostics = document.loaded.image.diagnostics;
  if (diagnostics.empty() && image_diagnostics.empty()) {
    ImGui::TextWrapped("No diagnostics. Nothing was silently dropped.");
    return;
  }

  const ImGuiTableFlags flags = ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_RowBg |
                                ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV;
  if (!ImGui::BeginTable("##diagnostics", 3, flags)) {
    return;
  }
  ImGui::TableSetupScrollFreeze(0, 1);
  ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthStretch, 0.7f);
  ImGui::TableSetupColumn("Code", ImGuiTableColumnFlags_WidthStretch, 1.6f);
  ImGui::TableSetupColumn("Message", ImGuiTableColumnFlags_WidthStretch, 3.0f);
  ImGui::TableHeadersRow();

  auto row = [](const Diagnostic& diagnostic) {
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::PushStyleColor(ImGuiCol_Text, components::status_color(status_name(diagnostic.status)));
    ImGui::TextUnformatted(status_name(diagnostic.status));
    ImGui::PopStyleColor();
    ImGui::TableSetColumnIndex(1);
    ImGui::TextUnformatted(diagnostic.code.c_str());
    ImGui::TableSetColumnIndex(2);
    ImGui::TextWrapped("%s", diagnostic.message.c_str());
  };

  for (const Diagnostic& diagnostic : image_diagnostics) {
    row(diagnostic);
  }
  for (const Diagnostic& diagnostic : diagnostics) {
    row(diagnostic);
  }
  ImGui::EndTable();
}

}  // namespace donkey::ui::views
