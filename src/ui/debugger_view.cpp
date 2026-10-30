#include <cinttypes>
#include <cstdint>
#include <string>
#include <vector>

#include "components.h"
#include "donkey/debug/debug.h"
#include "imgui.h"
#include "views.h"

namespace donkey::ui::views {

void debugger(const Document& document, UiState& state) {
  if (state.debug_adapter == nullptr) {
    state.debug_adapter = debug::create_debug_adapter(/*mock=*/true);
  }

  auto* adapter = state.debug_adapter.get();
  if (adapter == nullptr) {
    ImGui::TextDisabled("No debug adapter available.");
    return;
  }

  components::heading("Debugger (Mock Architecture Simulation)");
  ImGui::SameLine();
  const char* state_str = debug::session_state_name(adapter->state());
  components::badge(
      state_str,
      components::status_color(
          adapter->state() == debug::SessionState::Stopped
              ? "Complete"
              : (adapter->state() == debug::SessionState::Running ? "Partial" : "Unsupported")));

  ImGui::PushTextWrapPos(0.0f);
  ImGui::TextDisabled(
      "Note: The Debugger view is currently connected to a mock architecture adapter. Native "
      "OS-level process debugging (Mach VM/ptrace/Win32) is not yet implemented.");
  ImGui::PopTextWrapPos();

  ImGui::Spacing();
  if (adapter->state() == debug::SessionState::Disconnected ||
      adapter->state() == debug::SessionState::Exited) {
    if (ImGui::Button("Launch Simulation (Mock)")) {
      debug::LaunchConfig cfg;
      cfg.binary_path =
          !document.loaded.image.path.empty() ? document.loaded.image.path : "/bin/ls";
      cfg.stop_at_entry = true;
      (void)adapter->launch(cfg);
    }
    ImGui::PushTextWrapPos(0.0f);
    ImGui::TextDisabled(
        "(Synthetic simulation; registers and call stack do not reflect loaded binary execution)");
    ImGui::PopTextWrapPos();
  } else if (adapter->state() == debug::SessionState::Stopped) {
    if (ImGui::Button("Continue")) {
      (void)adapter->resume();
    }
    ImGui::SameLine();
    if (ImGui::Button("Step Into")) {
      (void)adapter->step_into();
    }
    ImGui::SameLine();
    if (ImGui::Button("Step Over")) {
      (void)adapter->step_over();
    }
    ImGui::SameLine();
    if (ImGui::Button("Terminate")) {
      (void)adapter->terminate();
    }
  } else if (adapter->state() == debug::SessionState::Running) {
    if (ImGui::Button("Pause")) {
      (void)adapter->pause();
    }
    ImGui::SameLine();
    if (ImGui::Button("Terminate")) {
      (void)adapter->terminate();
    }
  }

  ImGui::SameLine();
  if (ImGui::Button("Toggle BP at Selection")) {
    if (state.selected_address != 0) {
      (void)adapter->set_breakpoint(state.selected_address);
    }
  }

  ImGui::Separator();

  // Call stack and Registers side-by-side or tabs
  if (ImGui::BeginTabBar("##debug_tabs")) {
    if (ImGui::BeginTabItem("Call Stack")) {
      auto frames_res = adapter->call_stack();
      if (frames_res.has_value() && !frames_res.value().empty()) {
        static constexpr ImGuiTableFlags kTableFlags =
            ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_SizingFixedFit;
        if (ImGui::BeginTable("##call_stack_tbl", 5, kTableFlags, ImVec2(0.0f, 180.0f))) {
          ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 30.0f);
          ImGui::TableSetupColumn("Function", ImGuiTableColumnFlags_WidthFixed, 140.0f);
          ImGui::TableSetupColumn("Instruction Pointer", ImGuiTableColumnFlags_WidthFixed, 140.0f);
          ImGui::TableSetupColumn("Static VA", ImGuiTableColumnFlags_WidthFixed, 140.0f);
          ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthStretch);
          ImGui::TableHeadersRow();

          for (const auto& frame : frames_res.value()) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%u", frame.index);
            ImGui::TableSetColumnIndex(1);
            if (ImGui::Selectable(frame.function_name.c_str(), false,
                                  ImGuiSelectableFlags_SpanAllColumns)) {
              if (frame.static_address != 0) {
                state.navigate_to(frame.static_address, &document);
              }
            }
            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%s", components::format_address(frame.instruction_pointer).c_str());
            ImGui::TableSetColumnIndex(3);
            ImGui::Text("%s", components::format_address(frame.static_address).c_str());
            ImGui::TableSetColumnIndex(4);
            ImGui::TextDisabled("%s", frame.module_name.c_str());
          }
          ImGui::EndTable();
        }
      } else {
        ImGui::TextDisabled("Target not running or no active call frames.");
      }
      ImGui::EndTabItem();
    }

    if (ImGui::BeginTabItem("Registers")) {
      auto regs_res = adapter->read_registers();
      if (regs_res.has_value() && !regs_res.value().empty()) {
        static constexpr ImGuiTableFlags kRegFlags =
            ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_SizingFixedFit;
        if (ImGui::BeginTable("##registers_tbl", 2, kRegFlags, ImVec2(0.0f, 180.0f))) {
          ImGui::TableSetupColumn("Register", ImGuiTableColumnFlags_WidthFixed, 80.0f);
          ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
          ImGui::TableHeadersRow();

          for (const auto& reg : regs_res.value()) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%s", reg.name.c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("0x%016" PRIx64, reg.value);
          }
          ImGui::EndTable();
        }
      } else {
        ImGui::TextDisabled("Registers unavailable.");
      }
      ImGui::EndTabItem();
    }

    if (ImGui::BeginTabItem("Threads")) {
      auto threads_res = adapter->threads();
      if (threads_res.has_value()) {
        for (const auto& th : threads_res.value()) {
          ImGui::BulletText("Thread %" PRIu64 ": %s %s", th.id, th.name.c_str(),
                            th.is_current ? "[current]" : "");
        }
      }
      ImGui::EndTabItem();
    }

    ImGui::EndTabBar();
  }
}

}  // namespace donkey::ui::views
