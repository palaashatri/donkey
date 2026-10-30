#include <cstdint>
#include <string>

#include "components.h"
#include "donkey/ir/lift.h"
#include "imgui.h"
#include "views.h"

namespace donkey::ui::views {
namespace {

const Function* selected_function(const Document& document, std::uint64_t address) {
  const AnalysisResult& analysis = document.analysis;
  if (analysis.functions.empty()) {
    return nullptr;
  }
  for (const Function& function : analysis.functions) {
    if (function.address == address) {
      return &function;
    }
  }
  // Fall back to the function whose estimated extent contains the selection.
  for (const Function& function : analysis.functions) {
    if (function.has_extent && address >= function.address && address < function.end_address) {
      return &function;
    }
  }
  return &analysis.functions.front();
}

/// Lifts and formats one function, caching the result in the shared UI state.
/// Never runs on a background thread: the lifter is bounded and only reads
/// the immutable analysis, so it cannot stall the session's worker.
void refresh(UiState& state, const Document& document, const Function& function) {
  const std::string* renamed =
      state.annotations != nullptr ? state.annotations->rename_at(function.address) : nullptr;
  const std::string name = renamed != nullptr ? *renamed : function.name;
  if (state.pseudocode_document == &document && state.pseudocode_address == function.address &&
      state.pseudocode_function == name) {
    return;
  }
  state.pseudocode_document = &document;
  state.pseudocode_address = function.address;
  state.pseudocode_function = name;
  state.pseudocode_status.clear();
  state.pseudocode_code.clear();
  state.pseudocode_text.clear();

  // A user rename only changes the printed name, so lift a cheap copy of the
  // function record instead of mutating the shared analysis.
  Function target = function;
  if (renamed != nullptr) {
    target.name = *renamed;
  }
  auto lifted = lift_function(document.loaded.image, document.analysis, target);
  if (!lifted) {
    state.pseudocode_status = "Unsupported";
    state.pseudocode_code = lifted.diagnostic().code;
    state.pseudocode_text = lifted.diagnostic().message;
    return;
  }
  auto text = format_pseudocode(lifted.value());
  if (!text) {
    state.pseudocode_status = "InvalidIR";
    state.pseudocode_code = text.diagnostic().code;
    state.pseudocode_text = text.diagnostic().code + ": " + text.diagnostic().message;
    return;
  }
  state.pseudocode_status = lifted.value().partial ? "Partial" : "Complete";
  state.pseudocode_text = std::move(text.value());
}

}  // namespace

void decompiler(const Document& document, UiState& state) {
  const Function* function = selected_function(document, state.selected_address);
  if (function == nullptr) {
    ImGui::TextDisabled("No function seeds were discovered.");
    return;
  }
  refresh(state, document, *function);

  components::heading("Pseudocode");
  ImGui::SameLine();
  ImGui::TextDisabled("%s", components::format_address(function->address).c_str());
  ImGui::SameLine();
  components::badge(state.pseudocode_status, components::status_color(state.pseudocode_status));
  if (ImGui::IsItemHovered() && !state.pseudocode_code.empty()) {
    ImGui::SetTooltip("%s", state.pseudocode_code.c_str());
  }
  ImGui::SameLine();
  if (ImGui::SmallButton("Copy")) {
    ImGui::SetClipboardText(state.pseudocode_text.c_str());
  }
  ImGui::SameLine();
  ImGui::TextDisabled("verified IR only; no string-formatted or model-generated code");

  ImGui::Separator();
  ImGui::BeginChild("##pseudocode", ImVec2(0.0f, 0.0f), ImGuiChildFlags_None,
                    ImGuiWindowFlags_HorizontalScrollbar);
  if (state.pseudocode_status == "Unsupported" || state.pseudocode_status == "InvalidIR") {
    ImGui::PushStyleColor(ImGuiCol_Text, components::status_color("Unsupported"));
    ImGui::TextWrapped("%s", state.pseudocode_text.c_str());
    ImGui::PopStyleColor();
    if (state.pseudocode_status == "Unsupported") {
      ImGui::Spacing();
      ImGui::TextWrapped(
          "The lifter models a documented x86-64 subset. Other architectures "
          "return an explicit refusal instead of wrong pseudocode.");
    }
  } else {
    ImGui::TextUnformatted(state.pseudocode_text.c_str());
  }
  ImGui::EndChild();
}

}  // namespace donkey::ui::views
