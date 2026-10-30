#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

#include "components.h"
#include "donkey/debug/debug.h"
#include "imgui.h"
#include "views.h"

namespace donkey::ui::views {

namespace {

using debug::SessionState;
using debug::StopReason;

constexpr ImGuiTableFlags kTableFlags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                                        ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit;

std::vector<std::string> split_arguments(const char* text) {
  std::vector<std::string> out;
  std::istringstream in(text);
  std::string word;
  while (in >> word) {
    out.push_back(word);
  }
  return out;
}

void ensure_adapter(UiState& state) {
  if (state.debug_adapter != nullptr) {
    return;
  }
  state.debug_adapter = debug::create_debug_adapter(state.debug_simulation);
}

bool is_live(SessionState s) {
  return s == SessionState::Stopped || s == SessionState::Running;
}

/// Refresh the per-stop snapshot and move the code views to the stop.
void refresh_snapshot(const Document& document, UiState& state, const debug::StopInfo& stop) {
  auto* adapter = state.debug_adapter.get();
  UiState::DebugSnapshot snapshot;
  snapshot.stop = stop;
  if (adapter->state() == SessionState::Stopped) {
    if (auto regs = adapter->read_registers()) {
      snapshot.registers = std::move(regs.value());
    }
    if (auto frames = adapter->call_stack()) {
      snapshot.frames = std::move(frames.value());
    }
    if (auto threads = adapter->threads()) {
      snapshot.threads = std::move(threads.value());
    }
    if (auto modules = adapter->modules()) {
      snapshot.modules = std::move(modules.value());
    }
    if (!snapshot.frames.empty()) {
      snapshot.static_pc = snapshot.frames.front().static_address;
    } else if (stop.address != 0) {
      snapshot.static_pc = adapter->address_translator().runtime_to_static(stop.address);
    }
    // Follow the target in the disassembly when the stop is inside the image.
    if (snapshot.static_pc != 0 &&
        document.loaded.image.section_for_va(snapshot.static_pc) != nullptr) {
      state.navigate_to(snapshot.static_pc, &document);
    }
  }
  state.debug_snapshot = std::move(snapshot);
}

void report(UiState& state, const Result<bool>& result, const char* action) {
  if (result) {
    state.debug_message.clear();
  } else {
    state.debug_message = std::string(action) + " failed: " + result.diagnostic().message + " [" +
                          result.diagnostic().code + "]";
  }
}

void launch(const Document& document, UiState& state) {
  ensure_adapter(state);
  auto* adapter = state.debug_adapter.get();
  debug::LaunchConfig config;
  config.binary_path = document.loaded.image.path;
  config.arguments = split_arguments(state.debug_arguments);
  config.stop_at_entry = true;
  auto launched = adapter->launch(config);
  report(state, launched, "Launch");
  if (!launched) {
    return;
  }
  state.debug_target = config.binary_path;
  const auto& translator = adapter->address_translator();
  for (std::uint64_t address : state.debug_breakpoints) {
    auto bp = adapter->set_breakpoint(translator.static_to_runtime(address));
    if (!bp) {
      state.debug_message = "Breakpoint at " + components::format_address(address) +
                            " failed: " + bp.diagnostic().message;
    }
  }
  auto stop = adapter->poll_events();
  refresh_snapshot(document, state, stop ? stop.value() : debug::StopInfo{});
}

void toggle_breakpoint(UiState& state, std::uint64_t static_address) {
  auto& list = state.debug_breakpoints;
  const auto it = std::find(list.begin(), list.end(), static_address);
  auto* adapter = state.debug_adapter.get();
  const bool live = adapter != nullptr && is_live(adapter->state());
  const std::uint64_t runtime =
      live ? adapter->address_translator().static_to_runtime(static_address) : 0;
  if (it != list.end()) {
    list.erase(it);
    if (live) {
      (void)adapter->remove_breakpoint(runtime);
    }
    return;
  }
  list.push_back(static_address);
  if (live) {
    auto bp = adapter->set_breakpoint(runtime);
    if (!bp) {
      state.debug_message = "Breakpoint failed: " + bp.diagnostic().message;
    }
  }
}

void draw_launch_modal(const Document& document, UiState& state) {
  if (state.debug_confirm_launch) {
    ImGui::OpenPopup("Run program under debugger?");
    state.debug_confirm_launch = false;
  }
  ImGui::SetNextWindowSize(ImVec2(520.0f, 0.0f), ImGuiCond_Appearing);
  if (ImGui::BeginPopupModal("Run program under debugger?", nullptr,
                             ImGuiWindowFlags_AlwaysAutoResize)) {
    ImGui::PushTextWrapPos(500.0f);
    ImGui::TextUnformatted(
        "Debugging executes the program on this computer with your permissions. Opening a file "
        "in Donkey never runs it; this does. Only continue for programs you trust or inside a "
        "disposable VM.");
    ImGui::PopTextWrapPos();
    ImGui::Spacing();
    ImGui::TextDisabled("%s", document.loaded.image.path.c_str());
    ImGui::SetNextItemWidth(380.0f);
    ImGui::InputText("Arguments", state.debug_arguments, sizeof(state.debug_arguments));
    ImGui::Spacing();
    if (ImGui::Button("Run")) {
      launch(document, state);
      ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel")) {
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }
}

void draw_controls(const Document& document, UiState& state) {
  auto* adapter = state.debug_adapter.get();
  const SessionState s = adapter->state();
  auto act = [&](const Result<bool>& result, const char* action) {
    report(state, result, action);
    auto stop = adapter->poll_events();
    refresh_snapshot(document, state, stop ? stop.value() : debug::StopInfo{});
  };

  if (!is_live(s)) {
    const bool can = adapter->capabilities().can_launch;
    if (!can) {
      ImGui::BeginDisabled();
    }
    if (ImGui::Button(state.debug_simulation ? "Launch simulation" : "Launch...")) {
      if (state.debug_simulation) {
        launch(document, state);
      } else {
        state.debug_confirm_launch = true;
      }
    }
    if (!can) {
      ImGui::EndDisabled();
    }
    return;
  }
  if (s == SessionState::Stopped) {
    if (ImGui::Button("Continue")) {
      act(adapter->resume(), "Continue");
    }
    ImGui::SameLine();
    if (ImGui::Button("Step Into")) {
      act(adapter->step_into(), "Step");
    }
    ImGui::SameLine();
    if (ImGui::Button("Step Over")) {
      act(adapter->step_over(), "Step over");
    }
    ImGui::SameLine();
    if (ImGui::Button("Step Out")) {
      act(adapter->step_out(), "Step out");
    }
  } else if (ImGui::Button("Pause")) {
    act(adapter->pause(), "Pause");
  }
  ImGui::SameLine();
  if (ImGui::Button("Terminate")) {
    act(adapter->terminate(), "Terminate");
  }
  ImGui::SameLine();
  if (ImGui::Button("Detach")) {
    act(adapter->detach(), "Detach");
  }
}

void draw_breakpoints(const Document& document, UiState& state) {
  if (ImGui::Button("Toggle breakpoint at selection") && state.selected_address != 0) {
    toggle_breakpoint(state, state.selected_address);
  }
  if (state.debug_breakpoints.empty()) {
    ImGui::TextDisabled("No breakpoints. Select an instruction and toggle one.");
    return;
  }
  const float rows =
      static_cast<float>(std::min<std::size_t>(state.debug_breakpoints.size(), 4) + 1);
  const float height = rows * ImGui::GetFrameHeight() + ImGui::GetStyle().CellPadding.y * 2.0f;
  if (ImGui::BeginTable("##breakpoints", 3, kTableFlags, ImVec2(0.0f, height))) {
    ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
    ImGui::TableSetupColumn("Symbol", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 70.0f);
    ImGui::TableHeadersRow();
    std::uint64_t remove = 0;
    for (std::uint64_t address : state.debug_breakpoints) {
      ImGui::PushID(static_cast<int>(address & 0x7fffffff));
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      if (ImGui::Selectable(components::format_address(address).c_str(), false)) {
        state.navigate_to(address, &document);
      }
      ImGui::TableSetColumnIndex(1);
      const Symbol* symbol = document.loaded.image.symbol_at(address);
      ImGui::TextDisabled("%s", symbol != nullptr ? symbol->name.c_str() : "");
      ImGui::TableSetColumnIndex(2);
      if (ImGui::SmallButton("Remove")) {
        remove = address;
      }
      ImGui::PopID();
    }
    ImGui::EndTable();
    if (remove != 0) {
      toggle_breakpoint(state, remove);
    }
  }
}

void draw_memory(UiState& state) {
  auto* adapter = state.debug_adapter.get();
  ImGui::SetNextItemWidth(180.0f);
  const bool enter = ImGui::InputTextWithHint(
      "##mem_address", "runtime address (hex)", state.debug_memory_address,
      sizeof(state.debug_memory_address), ImGuiInputTextFlags_EnterReturnsTrue);
  ImGui::SameLine();
  if ((ImGui::Button("Read 256 bytes") || enter) && adapter != nullptr) {
    state.debug_memory_base = std::strtoull(state.debug_memory_address, nullptr, 16);
    auto bytes = adapter->read_memory(state.debug_memory_base, 256);
    if (bytes) {
      state.debug_memory = std::move(bytes.value());
      state.debug_memory_error.clear();
    } else {
      state.debug_memory.clear();
      state.debug_memory_error = bytes.diagnostic().message;
    }
  }
  if (!state.debug_memory_error.empty()) {
    ImGui::TextColored(components::status_color("Unsupported"), "%s",
                       state.debug_memory_error.c_str());
  }
  for (std::size_t row = 0; row < state.debug_memory.size(); row += 16) {
    char line[128];
    int used = std::snprintf(line, sizeof(line), "%016" PRIx64 "  ", state.debug_memory_base + row);
    for (std::size_t i = row; i < row + 16 && i < state.debug_memory.size(); ++i) {
      used += std::snprintf(line + used, sizeof(line) - static_cast<std::size_t>(used), "%02x ",
                            std::to_integer<unsigned>(state.debug_memory[i]));
    }
    ImGui::TextUnformatted(line);
  }
}

}  // namespace

void debugger(const Document& document, UiState& state) {
  ensure_adapter(state);
  auto* adapter = state.debug_adapter.get();

  // A running target is polled once per frame without blocking.
  if (adapter->state() == SessionState::Running) {
    auto event = adapter->poll_events();
    if (event && event.value().reason != StopReason::None) {
      refresh_snapshot(document, state, event.value());
    }
  }

  const SessionState s = adapter->state();
  components::heading(state.debug_simulation ? "Debugger (simulation)" : "Debugger");
  ImGui::SameLine();
  components::badge(debug::session_state_name(s),
                    components::status_color(s == SessionState::Stopped   ? "Complete"
                                             : s == SessionState::Running ? "Partial"
                                                                          : "Unsupported"));

  static const bool native_available =
      debug::create_debug_adapter(false)->capabilities().can_launch;
  ImGui::PushTextWrapPos(0.0f);
  if (state.debug_simulation) {
    ImGui::TextDisabled(
        "Simulation adapter: registers, memory and the call stack are synthetic and do not "
        "come from the loaded binary.");
  } else if (!native_available) {
    ImGui::TextDisabled(
        "Native debugging is not implemented on this host (it is available on Linux x86-64/"
        "AArch64 and Windows x64). You can explore the controls with the simulation adapter.");
  }
  ImGui::PopTextWrapPos();
  if (!is_live(s)) {
    bool simulation = state.debug_simulation;
    if (ImGui::Checkbox("Use simulation adapter", &simulation)) {
      state.debug_simulation = simulation;
      state.debug_adapter.reset();
      ensure_adapter(state);
      adapter = state.debug_adapter.get();
    }
  }

  draw_controls(document, state);
  draw_launch_modal(document, state);

  const auto& stop = state.debug_snapshot.stop;
  if (stop.reason != StopReason::None) {
    ImGui::Text("%s at %s", debug::stop_reason_name(stop.reason),
                components::format_address(stop.address).c_str());
    if (state.debug_snapshot.static_pc != 0) {
      ImGui::SameLine();
      ImGui::TextDisabled("(static %s)",
                          components::format_address(state.debug_snapshot.static_pc).c_str());
    }
    if (!stop.description.empty()) {
      ImGui::SameLine();
      ImGui::TextDisabled("- %s", stop.description.c_str());
    }
  }
  if (!state.debug_message.empty()) {
    ImGui::PushTextWrapPos(0.0f);
    ImGui::TextColored(components::status_color("Unsupported"), "%s", state.debug_message.c_str());
    ImGui::PopTextWrapPos();
  }

  ImGui::Separator();
  draw_breakpoints(document, state);
  ImGui::Separator();

  if (ImGui::BeginTabBar("##debug_tabs")) {
    if (ImGui::BeginTabItem("Registers")) {
      if (state.debug_snapshot.registers.empty()) {
        ImGui::TextDisabled("Registers are available while the target is stopped.");
      } else if (ImGui::BeginTable("##registers", 2, kTableFlags, ImVec2(0.0f, 220.0f))) {
        ImGui::TableSetupColumn("Register", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        for (const auto& reg : state.debug_snapshot.registers) {
          ImGui::TableNextRow();
          ImGui::TableSetColumnIndex(0);
          ImGui::TextUnformatted(reg.name.c_str());
          ImGui::TableSetColumnIndex(1);
          ImGui::Text("0x%016" PRIx64, reg.value);
        }
        ImGui::EndTable();
      }
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Call Stack")) {
      if (state.debug_snapshot.frames.empty()) {
        ImGui::TextDisabled("The call stack is available while the target is stopped.");
      } else if (ImGui::BeginTable("##frames", 5, kTableFlags, ImVec2(0.0f, 220.0f))) {
        ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 30.0f);
        ImGui::TableSetupColumn("Function", ImGuiTableColumnFlags_WidthFixed, 180.0f);
        ImGui::TableSetupColumn("Runtime", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Static", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        for (const auto& frame : state.debug_snapshot.frames) {
          ImGui::TableNextRow();
          ImGui::TableSetColumnIndex(0);
          ImGui::Text("%u", frame.index);
          ImGui::TableSetColumnIndex(1);
          ImGui::PushID(static_cast<int>(frame.index));
          const char* name = frame.function_name.empty() ? "?" : frame.function_name.c_str();
          if (ImGui::Selectable(name, false, ImGuiSelectableFlags_SpanAllColumns) &&
              document.loaded.image.section_for_va(frame.static_address) != nullptr) {
            state.navigate_to(frame.static_address, &document);
          }
          ImGui::PopID();
          ImGui::TableSetColumnIndex(2);
          ImGui::TextUnformatted(components::format_address(frame.instruction_pointer).c_str());
          ImGui::TableSetColumnIndex(3);
          ImGui::TextUnformatted(components::format_address(frame.static_address).c_str());
          ImGui::TableSetColumnIndex(4);
          ImGui::TextDisabled("%s", frame.module_name.c_str());
        }
        ImGui::EndTable();
      }
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Threads")) {
      for (const auto& thread : state.debug_snapshot.threads) {
        ImGui::BulletText("%" PRIu64 "  %s%s", thread.id, thread.name.c_str(),
                          thread.is_current ? "  [current]" : "");
      }
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Modules")) {
      for (const auto& module : state.debug_snapshot.modules) {
        ImGui::BulletText("%s  %s  (%s)", components::format_address(module.base_address).c_str(),
                          module.name.c_str(), module.path.c_str());
      }
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Memory")) {
      draw_memory(state);
      ImGui::EndTabItem();
    }
    ImGui::EndTabBar();
  }
}

}  // namespace donkey::ui::views
