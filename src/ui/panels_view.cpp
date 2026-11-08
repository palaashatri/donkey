#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "components.h"
#include "names.h"
#include "views.h"

#include "donkey/binary/image.h"
#include "donkey/binary/rtti.h"
#include "donkey/project/project.h"

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

  ImGui::Spacing();
  components::heading("Debug information");
  ImGui::TextWrapped(
      "%s", document.debug_info_note.empty() ? "Not read" : document.debug_info_note.c_str());
  if (document.debug_info) {
    for (const std::string& producer : document.debug_info->producers) {
      ImGui::TextDisabled("%s", producer.c_str());
    }
    ImGui::TextDisabled("Imported names never replace your renames.");
  }

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

namespace {

const Function* function_containing(const Document& document, std::uint64_t address) {
  const Function* best = nullptr;
  for (const Function& function : document.analysis.functions) {
    if (function.address == address) {
      return &function;
    }
    if (function.has_extent && address >= function.address && address < function.end_address &&
        (best == nullptr || function.address > best->address)) {
      best = &function;
    }
  }
  return best;
}

std::string function_label(UiState& state, const Document& document, std::uint64_t address) {
  for (const Function& function : document.analysis.functions) {
    if (function.address == address) {
      return shown_function_name(state, function);
    }
  }
  return components::format_address(address);
}

/// After a function's Selectable: its raw symbol in a tooltip when the readable name differs.
void raw_name_tooltip(UiState& state, const Document& document, std::uint64_t address) {
  if (!ImGui::IsItemHovered()) {
    return;
  }
  for (const Function& function : document.analysis.functions) {
    if (function.address == address) {
      if (shown_function_name(state, function) != function.name) {
        ImGui::SetTooltip("%s", function.name.c_str());
      }
      return;
    }
  }
}

/// Callers and callees of the selected function, from the call graph.
void call_graph_panel(const Document& document, UiState& state) {
  const Function* function = function_containing(document, state.selected_address);
  if (function == nullptr) {
    ImGui::TextDisabled("Select a function to see its calls.");
    return;
  }
  const CallGraph& graph = document.analysis.call_graph;
  const auto callees = graph.callees_of(function->address);
  const auto callers = graph.callers_of(function->address);
  std::size_t indirect = 0;
  for (const auto& site : graph.unresolved) {
    indirect += site.caller == function->address ? 1 : 0;
  }
  const std::string shown = shown_function_name(state, *function);
  ImGui::TextDisabled("%s: calls %zu, called by %zu%s", shown.c_str(), callees.size(),
                      callers.size(),
                      indirect != 0 ? (", " + std::to_string(indirect) + " indirect").c_str() : "");
  if (ImGui::IsItemHovered() && shown != function->name) {
    ImGui::SetTooltip("%s", function->name.c_str());
  }
  if (ImGui::BeginChild("##calls", ImVec2(0.0f, 0.0f))) {
    if (ImGui::TreeNodeEx("Calls", ImGuiTreeNodeFlags_DefaultOpen)) {
      for (const CallGraphEdge& edge : callees) {
        ImGui::PushID(static_cast<int>(edge.site & 0x7fffffff));
        const std::string label = function_label(state, document, edge.callee) + "  (at " +
                                  components::format_address(edge.site) + ")";
        if (ImGui::Selectable(label.c_str())) {
          state.navigate_to(edge.callee, &document);
        }
        raw_name_tooltip(state, document, edge.callee);
        ImGui::PopID();
      }
      ImGui::TreePop();
    }
    if (ImGui::TreeNodeEx("Called by", ImGuiTreeNodeFlags_DefaultOpen)) {
      for (const CallGraphEdge& edge : callers) {
        ImGui::PushID(static_cast<int>(edge.site & 0x7fffffff));
        const std::string label = function_label(state, document, edge.caller) + "  (at " +
                                  components::format_address(edge.site) + ")";
        if (ImGui::Selectable(label.c_str())) {
          state.navigate_to(edge.site, &document);
        }
        raw_name_tooltip(state, document, edge.caller);
        ImGui::PopID();
      }
      ImGui::TreePop();
    }
  }
  ImGui::EndChild();
}

}  // namespace

std::string shown_function_name(UiState& state, const Function& function) {
  const std::string* renamed =
      state.annotations != nullptr ? state.annotations->rename_at(function.address) : nullptr;
  if (renamed != nullptr) {
    return *renamed;  // a user's name is shown as typed
  }
  return cached_readable_name(state.readable_names, function.name);
}

void functions(const Document& document, UiState& state) {
  components::search_field("##functionfilter", state.function_filter, "Filter functions");

  const ImGuiTableFlags flags = ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_RowBg |
                                ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV;
  // Leave room under the table for the selected function's calls.
  const float calls_height = ImGui::GetTextLineHeightWithSpacing() * 9.0f;
  const float table_height = std::max(ImGui::GetContentRegionAvail().y - calls_height, 80.0f);
  if (!ImGui::BeginTable("##functions", 4, flags, ImVec2(0.0f, table_height))) {
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
    const std::string display = shown_function_name(state, function);
    if (!matches(display, state.function_filter) &&
        !matches(function.name, state.function_filter)) {
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
                      (renamed != nullptr ? *renamed : function.name).c_str());
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
    const DebugFunction* debug =
        document.debug_info ? document.debug_info->function_at(function.address) : nullptr;
    if (debug == nullptr && display != function.name && ImGui::IsItemHovered()) {
      ImGui::SetTooltip("%s", function.name.c_str());
    } else if (debug != nullptr && ImGui::IsItemHovered()) {
      std::string tip = document.debug_info->prototype(*debug);
      if (!debug->file.empty()) {
        tip += "\n" + debug->file + ":" + std::to_string(debug->line);
      }
      tip += "\nfrom " + debug->provenance.label();
      ImGui::SetTooltip("%s", tip.c_str());
    }
    if (debug != nullptr && !function.from_symbol && renamed == nullptr) {
      ImGui::SameLine();
      components::badge("dwarf", components::status_color("Partial"));
    }
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
  call_graph_panel(document, state);
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

namespace {

/// The text of a string's bytes for the Data view: printable characters as they are, and the rest
/// escaped, at most 48 characters. `count` includes the terminator, which is not shown.
std::string string_preview(const Document& document, std::uint64_t address, std::uint64_t count) {
  const std::optional<FileLocation> location = file_location_of(document.loaded.image, address);
  const std::span<const std::byte> file = document.loaded.data.span();
  if (!location || location->offset >= file.size() || count == 0) {
    return "";
  }
  std::string out;
  const std::uint64_t end =
      std::min<std::uint64_t>({count - 1, location->remaining, file.size() - location->offset});
  for (std::uint64_t i = 0; i < end && out.size() < 48; ++i) {
    const unsigned char c = std::to_integer<unsigned char>(file[location->offset + i]);
    if (c >= 0x20 && c < 0x7f && c != '"' && c != '\\') {
      out += static_cast<char>(c);
    } else {
      char escaped[8];
      std::snprintf(escaped, sizeof(escaped), "\\x%02x", static_cast<unsigned>(c));
      out += escaped;
    }
  }
  return out;
}

/// What a data range's text says, in words: the array's shape, the string and its preview, or the
/// undefined bytes (element size 0).
/// The text of a UTF-16LE string for the Data view: each code unit below 0x80 that is printable is
/// shown as it is, and every other unit as \uXXXX, at most 48 characters. `bytes` includes the
/// terminator unit, which is not shown.
std::string string16_preview(const Document& document, std::uint64_t address, std::uint64_t bytes) {
  const std::optional<FileLocation> location = file_location_of(document.loaded.image, address);
  const std::span<const std::byte> file = document.loaded.data.span();
  if (!location || location->offset >= file.size() || bytes < 2) {
    return "";
  }
  const std::uint64_t limit =
      std::min<std::uint64_t>({bytes - 2, location->remaining, file.size() - location->offset});
  std::string out;
  for (std::uint64_t i = 0; i + 2 <= limit && out.size() < 48; i += 2) {
    const unsigned unit = std::to_integer<unsigned>(file[location->offset + i]) |
                          (std::to_integer<unsigned>(file[location->offset + i + 1]) << 8);
    if (unit >= 0x20 && unit < 0x7f && unit != '"' && unit != '\\') {
      out += static_cast<char>(unit);
    } else {
      char escaped[8];
      std::snprintf(escaped, sizeof(escaped), "\\u%04x", unit);
      out += escaped;
    }
  }
  return out;
}

std::string describe_data_range(const Document& document, std::uint64_t address,
                                const std::string& text) {
  std::uint64_t element_size = 0;
  std::uint64_t count = 0;
  StringEncoding encoding = StringEncoding::None;
  if (!parse_data_extent(text, element_size, count, encoding)) {
    return "invalid: " + text;
  }
  if (encoding == StringEncoding::Bytes) {
    return "string, " + std::to_string(count) + " bytes: \"" +
           string_preview(document, address, count) + "\"";
  }
  if (encoding == StringEncoding::Utf16Le) {
    const std::uint64_t bytes = count * element_size;
    return "UTF-16 string, " + std::to_string(bytes) + " bytes: \"" +
           string16_preview(document, address, bytes) + "\"";
  }
  if (element_size == 0) {
    return "undefined, " + std::to_string(count) + " bytes";
  }
  if (element_size == 1) {
    return "bytes, " + std::to_string(count);
  }
  return "array, " + std::to_string(count) + " elements of " + std::to_string(element_size) +
         " bytes";
}

}  // namespace

void data_ranges(const Document& document, UiState& state) {
  if (state.annotations == nullptr || state.annotations->data_ranges.empty()) {
    ImGui::TextDisabled(
        "No data defined. D makes a byte, A a string at the selected address, and Shift+D an "
        "array (<size>:<count>).");
    return;
  }
  const ImGuiTableFlags flags = ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_RowBg |
                                ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV;
  if (!ImGui::BeginTable("##data", 3, flags)) {
    return;
  }
  ImGui::TableSetupScrollFreeze(0, 1);
  ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch, 1.0f);
  ImGui::TableSetupColumn("Definition", ImGuiTableColumnFlags_WidthStretch, 2.5f);
  ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthStretch, 0.9f);
  ImGui::TableHeadersRow();

  std::vector<std::pair<std::uint64_t, std::string>> sorted(state.annotations->data_ranges.begin(),
                                                            state.annotations->data_ranges.end());
  std::sort(sorted.begin(), sorted.end(),
            [](const auto& a, const auto& b) { return a.first < b.first; });
  for (const auto& [address, text] : sorted) {
    const std::string addr_str = components::format_address(address);
    const bool selected = state.selected_address == address;
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    if (ImGui::Selectable(addr_str.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns)) {
      state.navigate_to(address, &document);
    }
    ImGui::TableSetColumnIndex(1);
    ImGui::TextUnformatted(describe_data_range(document, address, text).c_str());
    ImGui::TableSetColumnIndex(2);
    ImGui::PushID(static_cast<int>(address));
    if (ImGui::SmallButton("Edit")) {
      state.annotation_kind = AnnotationKind::DataRange;
      state.annotation_address = address;
      std::snprintf(state.annotation_buffer, sizeof(state.annotation_buffer), "%s", text.c_str());
      state.annotation_modal_requested = true;
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Remove")) {
      state.annotation_kind = AnnotationKind::DataRange;
      state.annotation_address = address;
      state.annotation_buffer[0] = '\0';
      state.annotation_modal_requested = true;
    }
    ImGui::PopID();
  }
  ImGui::EndTable();
}

void classes(const Document& document, UiState& state) {
  components::search_field("##classfilter", state.class_filter, "Filter classes");
  if (!document.rtti) {
    ImGui::TextWrapped("%s", document.rtti_note.empty() ? "No RTTI was read for this image."
                                                        : document.rtti_note.c_str());
    return;
  }
  const RttiInfo& info = *document.rtti;
  ImGui::TextDisabled("%s", document.rtti_note.c_str());

  const ImGuiTableFlags flags = ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_RowBg |
                                ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV;
  if (!ImGui::BeginTable("##classes", 5, flags)) {
    return;
  }
  ImGui::TableSetupScrollFreeze(0, 1);
  ImGui::TableSetupColumn("Class", ImGuiTableColumnFlags_WidthStretch, 2.4f);
  ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthStretch, 0.9f);
  ImGui::TableSetupColumn("Bases", ImGuiTableColumnFlags_WidthStretch, 2.0f);
  ImGui::TableSetupColumn("Vtable", ImGuiTableColumnFlags_WidthStretch, 1.1f);
  ImGui::TableSetupColumn("Slots", ImGuiTableColumnFlags_WidthStretch, 0.6f);
  ImGui::TableHeadersRow();

  for (const RttiClass& cls : info.classes) {
    if (!matches(cls.name, state.class_filter)) {
      continue;
    }
    const std::uint64_t address =
        cls.vtable_address != 0 ? cls.vtable_address : cls.typeinfo_address;
    std::string bases;
    for (const std::uint64_t base : cls.bases) {
      const RttiClass* found = find_rtti_class(info, base);
      if (!bases.empty()) {
        bases += ", ";
      }
      bases += found != nullptr ? found->name : components::format_address(base);
    }
    std::size_t slots = cls.groups.empty() ? 0 : cls.groups.front().slots.size();

    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    const std::string label = cls.name + "##" + std::to_string(cls.typeinfo_address);
    if (ImGui::Selectable(label.c_str(), state.selected_address == address,
                          ImGuiSelectableFlags_SpanAllColumns)) {
      state.navigate_to(address, &document);
    }
    if (ImGui::IsItemHovered() && !cls.typeinfo_symbol.empty()) {
      ImGui::SetTooltip("%s", cls.typeinfo_symbol.c_str());
    }
    ImGui::TableSetColumnIndex(1);
    ImGui::TextUnformatted(rtti_kind_name(cls.kind));
    ImGui::TableSetColumnIndex(2);
    ImGui::TextUnformatted(bases.empty() ? "-" : bases.c_str());
    ImGui::TableSetColumnIndex(3);
    if (cls.vtable_address != 0) {
      ImGui::TextUnformatted(components::format_address(cls.vtable_address).c_str());
    } else {
      ImGui::TextDisabled("-");
    }
    ImGui::TableSetColumnIndex(4);
    ImGui::Text("%zu", slots);
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
