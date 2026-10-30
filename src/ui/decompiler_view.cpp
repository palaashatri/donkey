#include <cstdint>
#include <string>
#include <thread>

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

/// Lifts and formats one function asynchronously off the render thread, caching
/// the result in the shared UI state. The render thread never executes CPU-heavy
/// lifting synchronously.
void refresh(UiState& state, const Document& document, const Function& function) {
  const std::string* renamed =
      state.annotations != nullptr ? state.annotations->rename_at(function.address) : nullptr;
  const std::string name = renamed != nullptr ? *renamed : function.name;

  // 1. If currently showing this exact function and not in progress, nothing to do.
  if (state.pseudocode_document == &document && state.pseudocode_address == function.address &&
      state.pseudocode_function == name && !state.pseudocode_in_progress) {
    return;
  }

  // 2. Check if background decompiler finished.
  if (state.async_decompile) {
    std::lock_guard<std::mutex> lock(state.async_decompile->mutex);
    if (state.async_decompile->ready && state.async_decompile->ready_address == function.address &&
        state.pseudocode_document == &document) {
      state.pseudocode_status = std::move(state.async_decompile->ready_status);
      state.pseudocode_code = std::move(state.async_decompile->ready_code);
      state.pseudocode_text = std::move(state.async_decompile->ready_text);
      state.pseudocode_lines = std::move(state.async_decompile->ready_lines);
      state.pseudocode_address = function.address;
      state.pseudocode_function = name;
      state.pseudocode_in_progress = false;
      state.async_decompile->ready = false;
      return;
    }
  }

  // 3. If already in progress for this exact function, wait for it to complete.
  if (state.pseudocode_document == &document && state.pseudocode_address == function.address &&
      state.pseudocode_function == name && state.pseudocode_in_progress) {
    return;
  }

  // 4. Otherwise, initiate asynchronous lift off the UI render thread.
  state.pseudocode_document = &document;
  state.pseudocode_address = function.address;
  state.pseudocode_function = name;
  state.pseudocode_status = "Lifting";
  state.pseudocode_code.clear();
  state.pseudocode_text = "Lifting in background...";
  state.pseudocode_lines.clear();
  state.pseudocode_in_progress = true;

  if (!state.async_decompile) {
    state.async_decompile = std::make_shared<AsyncDecompileState>();
  }

  Function target = function;
  if (renamed != nullptr) {
    target.name = *renamed;
  }

  std::shared_ptr<AsyncDecompileState> async_state = state.async_decompile;
  std::uint64_t gen = 0;
  {
    std::lock_guard<std::mutex> lock(async_state->mutex);
    gen = ++async_state->current_generation;
    async_state->ready = false;
  }

  std::thread([async_state, gen, image = document.loaded.image, analysis = document.analysis,
               target]() {
    auto lifted = lift_function(image, analysis, target);
    std::string status;
    std::string code;
    std::string full_text;
    std::vector<PseudocodeLine> lines;

    if (!lifted) {
      status = "Unsupported";
      code = lifted.diagnostic().code;
      full_text = lifted.diagnostic().message;
    } else {
      auto text = format_pseudocode_lines(lifted.value());
      if (!text) {
        status = "InvalidIR";
        code = text.diagnostic().code;
        full_text = text.diagnostic().code + ": " + text.diagnostic().message;
      } else {
        status = lifted.value().partial ? "Partial" : "Complete";
        full_text = std::move(text.value().full_text);
        lines = std::move(text.value().lines);
      }
    }

    std::lock_guard<std::mutex> lock(async_state->mutex);
    if (async_state->current_generation == gen) {
      async_state->ready_status = std::move(status);
      async_state->ready_code = std::move(code);
      async_state->ready_text = std::move(full_text);
      async_state->ready_lines = std::move(lines);
      async_state->ready_address = target.address;
      async_state->ready = true;
    }
  }).detach();
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
  if (state.pseudocode_in_progress) {
    ImGui::TextDisabled("Decompiling %s in background...", function->name.c_str());
  } else if (state.pseudocode_status == "Unsupported" || state.pseudocode_status == "InvalidIR") {
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
    for (std::size_t i = 0; i < state.pseudocode_lines.size(); ++i) {
      const auto& line = state.pseudocode_lines[i];
      const bool has_addr = line.source_address != 0;
      const bool selected = has_addr && state.selected_address == line.source_address;
      if (selected) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.9f, 0.4f, 1.0f));
      }
      char num[32];
      std::snprintf(num, sizeof(num), "%3zu ", i + 1);
      ImGui::TextDisabled("%s", num);
      ImGui::SameLine();
      if (ImGui::Selectable(line.text.c_str(), selected)) {
        if (has_addr) {
          state.navigate_to(line.source_address, &document);
        }
      }
      if (selected) {
        ImGui::PopStyleColor();
      }
    }
  }
  ImGui::EndChild();
}

}  // namespace donkey::ui::views
