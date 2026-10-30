#include <cstdio>
#include <string>

#include "components.h"
#include "views.h"

namespace donkey::ui::views {
namespace {

constexpr std::uint64_t kBytesPerRow = 16;

bool printable(std::byte value) {
  const auto byte = static_cast<unsigned char>(value);
  return byte >= 0x20U && byte <= 0x7EU;
}

std::string row_address(std::uint64_t address) {
  char buffer[32];
  std::snprintf(buffer, sizeof(buffer), "0x%llx", static_cast<unsigned long long>(address));
  return buffer;
}

std::string hex_column(const std::uint8_t* bytes, std::size_t count) {
  char buffer[3 * 16 + 2];
  std::size_t used = 0;
  for (std::size_t i = 0; i < 16; ++i) {
    if (i < count) {
      used += static_cast<std::size_t>(
          std::snprintf(buffer + used, sizeof(buffer) - used, "%02x ", bytes[i]));
    } else {
      used += static_cast<std::size_t>(std::snprintf(buffer + used, sizeof(buffer) - used, "   "));
    }
    if (i == 7) {
      buffer[used++] = ' ';
    }
  }
  return std::string(buffer, used);
}

std::string ascii_column(const std::uint8_t* bytes, std::size_t count) {
  std::string out;
  out.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    out.push_back(printable(static_cast<std::byte>(bytes[i])) ? static_cast<char>(bytes[i]) : '.');
  }
  return out;
}

}  // namespace

void hex(const Document& document, UiState& state) {
  const BinaryImage& image = document.loaded.image;

  ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.60f, 0.68f, 1.0f));
  ImGui::TextUnformatted("16 bytes per row; start follows the selection");
  ImGui::PopStyleColor();

  // Anchor on the selection when it is backed by file data, otherwise fall
  // back to the entry point or the first mapped section.
  std::uint64_t base = state.selected_address & ~std::uint64_t{15};
  if (!image.va_to_file_offset(base)) {
    base = 0;
    if (image.has_entry_point() && image.va_to_file_offset(image.entry_point)) {
      base = image.entry_point & ~std::uint64_t{15};
    } else {
      for (const Section& section : image.sections) {
        if (section.address == 0) {
          continue;
        }
        if (image.va_to_file_offset(section.address)) {
          base = section.address & ~std::uint64_t{15};
          break;
        }
      }
    }
  }

  auto file_offset = image.va_to_file_offset(base);
  if (!file_offset) {
    ImGui::Spacing();
    ImGui::TextWrapped("Address %s is not backed by file data; select a mapped address.",
                       components::format_address(base).c_str());
    return;
  }

  const std::uint64_t offset = file_offset.value();
  if (offset >= document.loaded.data.size()) {
    ImGui::TextWrapped("Address %s is outside the file.", components::format_address(base).c_str());
    return;
  }

  const std::uint64_t remaining = document.loaded.data.size() - offset;
  const std::uint64_t rows = (remaining + kBytesPerRow - 1) / kBytesPerRow;
  const auto* bytes = reinterpret_cast<const std::uint8_t*>(document.loaded.data.data() + offset);

  const ImGuiTableFlags flags = ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_RowBg |
                                ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV;
  if (!ImGui::BeginTable("##hexdump", 3, flags)) {
    return;
  }
  ImGui::TableSetupScrollFreeze(0, 1);
  ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch, 1.1f);
  ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthStretch, 3.2f);
  ImGui::TableSetupColumn("ASCII", ImGuiTableColumnFlags_WidthStretch, 1.0f);
  ImGui::TableHeadersRow();

  ImGuiListClipper clipper;
  clipper.Begin(static_cast<int>(rows));
  while (clipper.Step()) {
    for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
      const std::uint64_t row_offset = static_cast<std::uint64_t>(row) * kBytesPerRow;
      const std::uint64_t count =
          remaining - row_offset < kBytesPerRow ? remaining - row_offset : kBytesPerRow;
      const std::uint64_t row_address_value = base + row_offset;

      const bool contains_selection = state.selected_address >= row_address_value &&
                                      state.selected_address < row_address_value + count;

      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      if (contains_selection) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.99f, 0.84f, 0.45f, 1.0f));
      }
      ImGui::TextUnformatted(row_address(row_address_value).c_str());
      if (contains_selection) {
        ImGui::PopStyleColor();
      }

      ImGui::TableSetColumnIndex(1);
      ImGui::TextUnformatted(
          hex_column(bytes + row_offset, static_cast<std::size_t>(count)).c_str());

      ImGui::TableSetColumnIndex(2);
      ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.72f, 0.78f, 0.86f, 1.0f));
      ImGui::TextUnformatted(
          ascii_column(bytes + row_offset, static_cast<std::size_t>(count)).c_str());
      ImGui::PopStyleColor();
    }
  }
  ImGui::EndTable();
}

}  // namespace donkey::ui::views
