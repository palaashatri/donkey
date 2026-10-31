#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

#include "components.h"
#include "donkey/debug/controller.h"
#include "imgui.h"
#include "views.h"

namespace donkey::ui::views {

namespace {

using debug::DebugSnapshot;
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

debug::DebugController& controller(UiState& state) {
  if (state.debug_controller == nullptr) {
    state.debug_controller = std::make_unique<debug::DebugController>(state.debug_simulation);
  }
  return *state.debug_controller;
}

bool is_live(SessionState s) {
  return s == SessionState::Stopped || s == SessionState::Running;
}

void launch(const Document& document, UiState& state) {
  debug::LaunchConfig config;
  config.binary_path = document.loaded.image.path;
  config.arguments = split_arguments(state.debug_arguments);
  config.stop_at_entry = true;
  controller(state).launch(std::move(config));
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

void draw_controls(const Document& document, UiState& state, const DebugSnapshot& snap) {
  auto& ctl = controller(state);
  if (snap.busy) {
    ImGui::BeginDisabled();
  }
  if (!is_live(snap.state)) {
    const bool can = snap.capabilities.can_launch;
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
  } else {
    if (snap.state == SessionState::Stopped) {
      if (ImGui::Button("Continue")) {
        ctl.resume();
      }
      ImGui::SameLine();
      if (ImGui::Button("Step Into")) {
        ctl.step_into();
      }
      ImGui::SameLine();
      if (ImGui::Button("Step Over")) {
        ctl.step_over();
      }
      ImGui::SameLine();
      if (ImGui::Button("Step Out")) {
        ctl.step_out();
      }
    } else if (ImGui::Button("Pause")) {
      ctl.pause();
    }
    ImGui::SameLine();
    if (ImGui::Button("Terminate")) {
      ctl.terminate();
    }
    ImGui::SameLine();
    if (ImGui::Button("Detach")) {
      ctl.detach();
    }
  }
  if (snap.busy) {
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::TextDisabled("working...");
  }
}

void draw_breakpoints(const Document& document, UiState& state, const DebugSnapshot& snap) {
  if (ImGui::Button("Toggle breakpoint at selection") && state.selected_address != 0) {
    controller(state).toggle_breakpoint(state.selected_address);
  }
  if (snap.breakpoints.empty()) {
    ImGui::TextDisabled("No breakpoints. Select an instruction and toggle one.");
    return;
  }
  const float rows = static_cast<float>(std::min<std::size_t>(snap.breakpoints.size(), 4) + 1);
  const float height = rows * ImGui::GetFrameHeight() + ImGui::GetStyle().CellPadding.y * 2.0f;
  if (ImGui::BeginTable("##breakpoints", 3, kTableFlags, ImVec2(0.0f, height))) {
    ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
    ImGui::TableSetupColumn("Symbol", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 70.0f);
    ImGui::TableHeadersRow();
    for (std::uint64_t address : snap.breakpoints) {
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
        controller(state).toggle_breakpoint(address);
      }
      ImGui::PopID();
    }
    ImGui::EndTable();
  }
}

void draw_memory(UiState& state, const DebugSnapshot& snap) {
  ImGui::SetNextItemWidth(180.0f);
  const bool enter = ImGui::InputTextWithHint(
      "##mem_address", "runtime address (hex)", state.debug_memory_address,
      sizeof(state.debug_memory_address), ImGuiInputTextFlags_EnterReturnsTrue);
  ImGui::SameLine();
  if (ImGui::Button("Read 256 bytes") || enter) {
    controller(state).read_memory(std::strtoull(state.debug_memory_address, nullptr, 16), 256);
  }
  for (std::size_t row = 0; row < snap.memory.size(); row += 16) {
    char line[128];
    int used = std::snprintf(line, sizeof(line), "%016" PRIx64 "  ", snap.memory_address + row);
    for (std::size_t i = row; i < row + 16 && i < snap.memory.size(); ++i) {
      used += std::snprintf(line + used, sizeof(line) - static_cast<std::size_t>(used), "%02x ",
                            std::to_integer<unsigned>(snap.memory[i]));
    }
    ImGui::TextUnformatted(line);
  }
}

}  // namespace

void debugger(const Document& document, UiState& state) {
  // Reading the snapshot is a copy under a short lock; nothing here waits for
  // the target.
  const DebugSnapshot snap = controller(state).snapshot();

  // Follow each new stop in the code views once.
  if (snap.state == SessionState::Stopped && snap.revision != state.debug_followed_revision &&
      !snap.busy) {
    state.debug_followed_revision = snap.revision;
    if (snap.static_pc != 0 && document.loaded.image.section_for_va(snap.static_pc) != nullptr) {
      state.navigate_to(snap.static_pc, &document);
    }
  }

  components::heading(state.debug_simulation ? "Debugger (simulation)" : "Debugger");
  ImGui::SameLine();
  components::badge(
      debug::session_state_name(snap.state),
      components::status_color(snap.state == SessionState::Stopped   ? "Complete"
                               : snap.state == SessionState::Running ? "Partial"
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
  if (!is_live(snap.state) && !snap.busy) {
    bool simulation = state.debug_simulation;
    if (ImGui::Checkbox("Use simulation adapter", &simulation)) {
      state.debug_simulation = simulation;
      state.debug_controller.reset();
      return;
    }
  }

  draw_controls(document, state, snap);
  draw_launch_modal(document, state);

  if (snap.stop.reason != StopReason::None) {
    ImGui::Text("%s at %s", debug::stop_reason_name(snap.stop.reason),
                components::format_address(snap.stop.address).c_str());
    if (snap.static_pc != 0) {
      ImGui::SameLine();
      ImGui::TextDisabled("(static %s)", components::format_address(snap.static_pc).c_str());
    }
    if (!snap.stop.description.empty()) {
      ImGui::SameLine();
      ImGui::TextDisabled("- %s", snap.stop.description.c_str());
    }
  }
  if (!snap.message.empty()) {
    ImGui::PushTextWrapPos(0.0f);
    ImGui::TextColored(components::status_color("Unsupported"), "%s", snap.message.c_str());
    ImGui::PopTextWrapPos();
  }

  ImGui::Separator();
  draw_breakpoints(document, state, snap);
  ImGui::Separator();

  if (ImGui::BeginTabBar("##debug_tabs")) {
    if (ImGui::BeginTabItem("Registers")) {
      if (snap.registers.empty()) {
        ImGui::TextDisabled("Registers are available while the target is stopped.");
      } else if (ImGui::BeginTable("##registers", 2, kTableFlags, ImVec2(0.0f, 220.0f))) {
        ImGui::TableSetupColumn("Register", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        for (const auto& reg : snap.registers) {
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
      if (snap.frames.empty()) {
        ImGui::TextDisabled("The call stack is available while the target is stopped.");
      } else if (ImGui::BeginTable("##frames", 5, kTableFlags, ImVec2(0.0f, 220.0f))) {
        ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 30.0f);
        ImGui::TableSetupColumn("Function", ImGuiTableColumnFlags_WidthFixed, 180.0f);
        ImGui::TableSetupColumn("Runtime", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Static", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        for (const auto& frame : snap.frames) {
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
      for (const auto& thread : snap.threads) {
        ImGui::BulletText("%" PRIu64 "  %s%s", thread.id, thread.name.c_str(),
                          thread.is_current ? "  [current]" : "");
      }
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Modules")) {
      for (const auto& module : snap.modules) {
        ImGui::BulletText("%s  %s  (%s)", components::format_address(module.base_address).c_str(),
                          module.name.c_str(), module.path.c_str());
      }
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Memory")) {
      draw_memory(state, snap);
      ImGui::EndTabItem();
    }
    ImGui::EndTabBar();
  }
}

}  // namespace donkey::ui::views
