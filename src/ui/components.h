#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "imgui.h"

namespace donkey::ui::components {

/// Colour used for a status word. Never the only signal: callers also render
/// the status text.
ImVec4 status_color(std::string_view status);

/// Small rounded label with an accent colour.
void badge(std::string_view label, const ImVec4& color);

/// Compact toolbar button with optional tooltip.
bool toolbar_button(const char* label, const char* tooltip = nullptr);

/// Monospaced-looking address text. `highlighted` paints an accent background.
void address(std::uint64_t value, bool highlighted = false);

[[nodiscard]] std::string format_address(std::uint64_t value);
[[nodiscard]] std::string format_size(std::uint64_t bytes);

/// Full-width search box with a stable hidden label.
bool search_field(const char* id, std::string& text, const char* hint);

/// Section heading with an optional right-aligned detail.
void heading(const char* title, const char* detail = nullptr);

/// Selectable table row helper. Returns true when clicked.
bool selectable_row(const char* label, bool selected, ImGuiSelectableFlags flags = 0);

}  // namespace donkey::ui::components
