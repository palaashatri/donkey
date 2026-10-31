#include <algorithm>
#include <cstdint>
#include <string>
#include <thread>

#include "components.h"
#include "donkey/ir/lift.h"
#include "imgui.h"
#include "views.h"

namespace donkey::ui {

namespace {

AsyncDecompileState::Output lift_and_format(const Document& document, const Function& target) {
  AsyncDecompileState::Output out;
  auto lifted = lift_function(document.loaded.image, document.analysis, target);
  if (!lifted) {
    out.status = "Unsupported";
    out.code = lifted.diagnostic().code;
    out.text = lifted.diagnostic().message;
    return out;
  }
  auto text = format_pseudocode_lines(lifted.value());
  if (!text) {
    out.status = "InvalidIR";
    out.code = text.diagnostic().code;
    out.text = text.diagnostic().code + ": " + text.diagnostic().message;
    return out;
  }
  out.status = lifted.value().partial ? "Partial" : "Complete";
  out.text = std::move(text.value().full_text);
  out.lines = std::move(text.value().lines);
  return out;
}

std::string cache_key(const Function& target) {
  return std::to_string(target.address) + ":" + target.name;
}

}  // namespace

void AsyncDecompileState::reset_cache_for(const Document* document) {
  // Caller holds `mutex`.
  if (cache_document != document) {
    cache_document = document;
    cache.clear();
    scheduler.cancel_all();  // nothing queued for the old document is useful
  }
}

void AsyncDecompileState::request_lift(std::uint64_t gen, std::shared_ptr<const Document> doc,
                                       Function target) {
  if (!doc) {
    return;
  }
  {
    std::lock_guard<std::mutex> lock(mutex);
    current_generation = gen;
    ready = false;
    reset_cache_for(doc.get());
    const auto hit = cache.find(cache_key(target));
    if (hit != cache.end()) {
      ready_status = hit->second.status;
      ready_code = hit->second.code;
      ready_text = hit->second.text;
      ready_lines = hit->second.lines;
      ready_address = target.address;
      ready_name = target.name;
      ready = true;
      return;
    }
  }
  scheduler.submit(
      JobPriority::Visible,
      [this, gen, doc, target](const CancellationToken& token) {
        {
          std::lock_guard<std::mutex> lock(mutex);
          if (current_generation != gen || token.is_cancelled()) {
            return;  // superseded before the CPU-heavy part
          }
        }
        Output out = lift_and_format(*doc, target);
        std::lock_guard<std::mutex> lock(mutex);
        if (cache_document == doc.get()) {
          cache[cache_key(target)] = out;
        }
        if (current_generation == gen) {
          ready_status = std::move(out.status);
          ready_code = std::move(out.code);
          ready_text = std::move(out.text);
          ready_lines = std::move(out.lines);
          ready_address = target.address;
          ready_name = target.name;
          ready = true;
        }
      },
      "visible");
}

void AsyncDecompileState::prefetch(const std::shared_ptr<const Document>& doc,
                                   std::vector<Function> targets) {
  if (!doc) {
    return;
  }
  for (Function& target : targets) {
    const std::string key = cache_key(target);
    {
      std::lock_guard<std::mutex> lock(mutex);
      reset_cache_for(doc.get());
      if (cache.count(key) != 0) {
        continue;
      }
    }
    scheduler.submit(
        JobPriority::Background,
        [this, doc, target = std::move(target), key](const CancellationToken& token) {
          if (token.is_cancelled()) {
            return;
          }
          Output out = lift_and_format(*doc, target);
          std::lock_guard<std::mutex> lock(mutex);
          if (cache_document == doc.get() && !token.is_cancelled()) {
            cache.emplace(key, std::move(out));
          }
        },
        "prefetch:" + key);
  }
}

}  // namespace donkey::ui

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
        state.async_decompile->ready_name == name && state.pseudocode_document == &document) {
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

  std::uint64_t gen = 0;
  {
    std::lock_guard<std::mutex> lock(state.async_decompile->mutex);
    gen = ++state.async_decompile->current_generation;
  }

  state.async_decompile->request_lift(gen, state.pseudocode_document_owner, std::move(target));

  // Callees are the likeliest next stop; lift a few in the background.
  constexpr std::size_t kPrefetch = 4;
  std::vector<Function> next;
  for (const CallGraphEdge& edge : document.analysis.call_graph.callees_of(function.address)) {
    if (next.size() >= kPrefetch) {
      break;
    }
    for (const Function& candidate : document.analysis.functions) {
      if (candidate.address == edge.callee &&
          std::none_of(next.begin(), next.end(),
                       [&](const Function& f) { return f.address == candidate.address; })) {
        Function callee = candidate;
        if (state.annotations != nullptr) {
          if (const std::string* rename = state.annotations->rename_at(candidate.address)) {
            callee.name = *rename;
          }
        }
        next.push_back(std::move(callee));
        break;
      }
    }
  }
  state.async_decompile->prefetch(state.pseudocode_document_owner, std::move(next));
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
