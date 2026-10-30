#include <algorithm>
#include <cctype>
#include <cstdio>
#include <string>
#include <vector>

#include "components.h"
#include "views.h"

namespace donkey::ui::views {
namespace {

struct DisassemblyCache {
  const Document* document = nullptr;
  std::string filter;
  std::vector<std::uint32_t> indices;
};

bool contains_lower(std::string_view haystack, std::string_view needle) {
  if (needle.empty()) {
    return true;
  }
  auto lower = [](char ch) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  };
  std::size_t matched = 0;
  for (const char ch : haystack) {
    if (lower(ch) == lower(needle[matched])) {
      ++matched;
      if (matched == needle.size()) {
        return true;
      }
    }
  }
  return false;
}

void rebuild(const Document& document, UiState& state, DisassemblyCache& cache) {
  cache.document = &document;
  cache.filter = state.disassembly_filter;
  cache.indices.clear();
  const auto& instructions = document.analysis.instructions;
  cache.indices.reserve(instructions.size());
  char address[32];
  for (std::uint32_t i = 0; i < instructions.size(); ++i) {
    if (!cache.filter.empty()) {
      std::snprintf(address, sizeof(address), "%llx",
                    static_cast<unsigned long long>(instructions[i].address));
      const bool address_match = contains_lower(address, cache.filter) ||
                                 contains_lower(instructions[i].mnemonic, cache.filter) ||
                                 contains_lower(instructions[i].operands, cache.filter);
      if (!address_match) {
        continue;
      }
    }
    cache.indices.push_back(i);
  }
}

}  // namespace

void disassembly(const Document& document, UiState& state) {
  static DisassemblyCache cache;
  if (cache.document != &document || cache.filter != state.disassembly_filter) {
    rebuild(document, state, cache);
  }

  const auto& instructions = document.analysis.instructions;
  ImGui::SetNextItemWidth(-1.0f);
  char filter[128];
  std::snprintf(filter, sizeof(filter), "%s", state.disassembly_filter.c_str());
  if (ImGui::InputTextWithHint("##disasmfilter", "Filter by address or mnemonic", filter,
                               sizeof(filter))) {
    state.disassembly_filter = filter;
    rebuild(document, state, cache);
  }

  ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.60f, 0.68f, 1.0f));
  ImGui::Text("%zu of %zu instructions", cache.indices.size(), instructions.size());
  ImGui::PopStyleColor();

  const ImGuiTableFlags flags = ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_RowBg |
                                ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV;
  if (!ImGui::BeginTable("##disasm", 5, flags)) {
    return;
  }
  ImGui::TableSetupScrollFreeze(0, 1);
  ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch, 1.0f);
  ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthStretch, 1.0f);
  ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch, 2.6f);
  ImGui::TableSetupColumn("Target", ImGuiTableColumnFlags_WidthStretch, 1.1f);
  ImGui::TableSetupColumn("Comment", ImGuiTableColumnFlags_WidthStretch, 1.8f);
  ImGui::TableHeadersRow();

  ImGuiListClipper clipper;
  clipper.Begin(static_cast<int>(cache.indices.size()));
  while (clipper.Step()) {
    for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
      const Instruction& instruction = instructions[cache.indices[static_cast<std::size_t>(row)]];
      const bool selected = state.selected_address == instruction.address;

      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      const bool bookmarked =
          state.annotations != nullptr && state.annotations->has_bookmark(instruction.address);
      const std::string address =
          (bookmarked ? "[*] " : "") + components::format_address(instruction.address);
      if (ImGui::Selectable(address.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns)) {
        state.navigate_to(instruction.address, &document);
      }
      if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
        if (instruction.direct_target.has_value()) {
          state.navigate_to(instruction.direct_target.value(), &document);
        } else if (!instruction.data_references.empty()) {
          state.navigate_to(instruction.data_references.front(), &document);
        }
      }
      if (ImGui::BeginPopupContextItem("##disasmcontext")) {
        if (ImGui::MenuItem(bookmarked ? "Remove bookmark" : "Add bookmark")) {
          state.annotation_kind = AnnotationKind::Bookmark;
          state.annotation_address = instruction.address;
          std::snprintf(state.annotation_buffer, sizeof(state.annotation_buffer), "%s",
                        bookmarked ? "" : "Bookmark");
          state.annotation_modal_requested = true;
        }
        const std::string* comment = state.annotations != nullptr
                                         ? state.annotations->comment_at(instruction.address)
                                         : nullptr;
        if (ImGui::MenuItem(comment != nullptr ? "Edit comment…" : "Add comment…")) {
          state.annotation_kind = AnnotationKind::Comment;
          state.annotation_address = instruction.address;
          std::snprintf(state.annotation_buffer, sizeof(state.annotation_buffer), "%s",
                        comment != nullptr ? comment->c_str() : "");
          state.annotation_modal_requested = true;
        }
        if (instruction.direct_target.has_value()) {
          const std::uint64_t target = instruction.direct_target.value();
          const std::string* rename =
              state.annotations != nullptr ? state.annotations->rename_at(target) : nullptr;
          if (ImGui::MenuItem("Rename target…")) {
            state.annotation_kind = AnnotationKind::Rename;
            state.annotation_address = target;
            std::snprintf(state.annotation_buffer, sizeof(state.annotation_buffer), "%s",
                          rename != nullptr ? rename->c_str() : "");
            state.annotation_modal_requested = true;
          }
        }
        ImGui::EndPopup();
      }

      ImGui::TableSetColumnIndex(1);
      ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.62f, 0.68f, 0.76f, 1.0f));
      ImGui::TextUnformatted(instruction_bytes_hex(instruction).c_str());
      ImGui::PopStyleColor();

      ImGui::TableSetColumnIndex(2);
      const std::string text = instruction.mnemonic + " " + instruction.operands;
      if (instruction.classification == InstructionClass::Call) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.82f, 0.62f, 1.0f));
      } else if (instruction.classification == InstructionClass::Return) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.90f, 0.55f, 0.55f, 1.0f));
      } else if (instruction.classification == InstructionClass::Jump ||
                 instruction.classification == InstructionClass::ConditionalJump) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 0.80f, 0.50f, 1.0f));
      }
      ImGui::TextUnformatted(text.c_str());
      if (instruction.classification != InstructionClass::Other) {
        ImGui::PopStyleColor();
      }

      ImGui::TableSetColumnIndex(3);
      if (instruction.direct_target.has_value()) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.62f, 0.78f, 0.98f, 1.0f));
        ImGui::TextUnformatted(
            components::format_address(instruction.direct_target.value()).c_str());
        ImGui::PopStyleColor();
      }

      ImGui::TableSetColumnIndex(4);
      if (state.annotations != nullptr) {
        if (const std::string* comment = state.annotations->comment_at(instruction.address)) {
          ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.85f, 0.78f, 0.55f, 1.0f));
          ImGui::TextUnformatted(comment->c_str());
          ImGui::PopStyleColor();
        }
      }
    }
  }
  ImGui::EndTable();
}

}  // namespace donkey::ui::views
