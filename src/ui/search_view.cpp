// The Search window (G17): byte, immediate and regular expression searches. The searches run on the
// scheduler, off the render thread, through the headless core (donkey/analysis/search.h); the window
// only draws the newest finished result.

#include <algorithm>
#include <cstdio>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include "components.h"
#include "donkey/analysis/search.h"
#include "imgui.h"
#include "views.h"
#include "workspace.h"

namespace donkey::ui {
namespace {

constexpr std::size_t kMaxRows = 10000;

struct SearchOutput {
  std::vector<SearchRow> rows;
  std::string status;
  std::string error;
};

std::string hex_bytes(std::span<const std::byte> bytes) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string text;
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    if (i != 0) {
      text.push_back(' ');
    }
    const auto value = std::to_integer<unsigned>(bytes[i]);
    text.push_back(kDigits[(value >> 4U) & 0xFU]);
    text.push_back(kDigits[value & 0xFU]);
  }
  return text;
}

/// The instruction at `address`: a binary search when the list is in address order, which the
/// analysis produces; otherwise a linear scan, so a hit is never missed.
const Instruction* instruction_at(const std::vector<Instruction>& instructions, bool sorted,
                                  std::uint64_t address) {
  if (sorted) {
    const auto it = std::lower_bound(
        instructions.begin(), instructions.end(), address,
        [](const Instruction& instruction, std::uint64_t value) {
          return instruction.address < value;
        });
    return it != instructions.end() && it->address == address ? &*it : nullptr;
  }
  for (const Instruction& instruction : instructions) {
    if (instruction.address == address) {
      return &instruction;
    }
  }
  return nullptr;
}

/// A number typed for the immediate search: decimal, or hexadecimal with a 0x prefix. Nothing else.
std::optional<std::uint64_t> parse_number(const std::string& text) {
  if (text.empty() || std::isdigit(static_cast<unsigned char>(text[0])) == 0) {
    return std::nullopt;
  }
  const bool hex = text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X');
  try {
    std::size_t consumed = 0;
    const unsigned long long value = std::stoull(text, &consumed, hex ? 16 : 10);
    if (consumed != text.size()) {
      return std::nullopt;
    }
    return static_cast<std::uint64_t>(value);
  } catch (const std::logic_error&) {  // invalid_argument or out_of_range
    return std::nullopt;
  }
}

SearchOutput run_search(const Document& document, SearchKind kind, const std::string& query,
                        const CancellationToken& token) {
  SearchOutput out;
  SearchOptions options;
  options.max_hits = kMaxRows;
  Result<SearchHits> result = Result<SearchHits>(SearchHits{});
  bool by_bytes = false;
  switch (kind) {
    case SearchKind::Bytes:
      by_bytes = true;
      result = search_bytes(document.loaded.image, document.loaded.data, query, options, token);
      break;
    case SearchKind::Immediate: {
      const std::optional<std::uint64_t> value = parse_number(query);
      if (!value) {
        out.error = "search.value: type a number, in decimal or with a 0x prefix";
        return out;
      }
      result = search_immediate(document.analysis.instructions, *value, options, token);
      break;
    }
    case SearchKind::Text:
      result = search_text(document.analysis.instructions, query, options, token);
      break;
  }
  if (!result) {
    out.error = result.diagnostic().code + ": " + result.diagnostic().message;
    return out;
  }
  const SearchHits& hits = result.value();
  const auto& instructions = document.analysis.instructions;
  const bool sorted = std::is_sorted(
      instructions.begin(), instructions.end(),
      [](const Instruction& a, const Instruction& b) { return a.address < b.address; });
  out.rows.reserve(hits.addresses.size());
  for (const std::uint64_t address : hits.addresses) {
    SearchRow row;
    row.address = address;
    if (by_bytes) {
      const auto offset = document.loaded.image.va_to_file_offset(address);
      if (offset && offset.value() < document.loaded.data.size()) {
        const std::size_t available = document.loaded.data.size() - offset.value();
        const std::size_t count = std::min<std::size_t>(8, available);
        row.preview = hex_bytes(document.loaded.data.span().subspan(
            static_cast<std::size_t>(offset.value()), count));
      }
    } else if (const Instruction* instruction = instruction_at(instructions, sorted, address)) {
      row.preview = instruction->mnemonic + " " + instruction->operands;
    }
    out.rows.push_back(std::move(row));
  }
  out.status = std::to_string(out.rows.size()) + (out.rows.size() == 1 ? " hit" : " hits");
  if (hits.truncated) {
    out.status += " (stopped at the limit of " + std::to_string(kMaxRows) + ")";
  }
  if (hits.cancelled) {
    out.status += ", cancelled";
  }
  return out;
}

}  // namespace

void AsyncSearchState::start(std::shared_ptr<const Document> doc, SearchKind kind,
                             std::string query) {
  if (!doc) {
    return;
  }
  std::uint64_t gen = 0;
  {
    std::lock_guard<std::mutex> lock(mutex);
    gen = ++generation;
    running = true;
    error.clear();
    rows.clear();
    status = "Searching...";
  }
  scheduler.cancel_all();  // a newer search supersedes the one still running
  scheduler.submit(JobPriority::Visible,
                   [this, gen, doc, kind, query](const CancellationToken& token) {
                     SearchOutput out = run_search(*doc, kind, query, token);
                     std::lock_guard<std::mutex> lock(mutex);
                     if (generation != gen) {
                       return;  // superseded: its result is not shown
                     }
                     running = false;
                     error = std::move(out.error);
                     status = std::move(out.status);
                     rows = std::move(out.rows);
                   },
                   "search");
}

void AsyncSearchState::wait() {
  scheduler.wait_idle();
}

}  // namespace donkey::ui

namespace donkey::ui::views {

void search(const Document& document, UiState& state) {
  AsyncSearchState& search = *state.search;
  static const char* const kKinds = "Bytes (hex, ?? any byte)\0Immediate (a number)\0Regex (instruction text)\0";
  ImGui::SetNextItemWidth(230.0f);
  ImGui::Combo("##searchkind", &search.kind_input, kKinds);
  ImGui::SameLine();
  ImGui::SetNextItemWidth(-90.0f);
  const bool enter = ImGui::InputText("##searchquery", search.query_input,
                                      sizeof(search.query_input),
                                      ImGuiInputTextFlags_EnterReturnsTrue);
  ImGui::SameLine();
  if ((ImGui::Button("Search") || enter) && state.search_document_owner) {
    search.start(state.search_document_owner, static_cast<SearchKind>(search.kind_input),
                 search.query_input);
  }

  std::lock_guard<std::mutex> lock(search.mutex);
  if (!search.error.empty()) {
    ImGui::PushStyleColor(ImGuiCol_Text, components::status_color("Unsupported"));
    ImGui::TextWrapped("%s", search.error.c_str());
    ImGui::PopStyleColor();
  }
  ImGui::TextDisabled("%s", search.status.c_str());

  const ImGuiTableFlags flags = ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_RowBg |
                                ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV;
  if (!ImGui::BeginTable("##searchhits", 2, flags)) {
    return;
  }
  ImGui::TableSetupScrollFreeze(0, 1);
  ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch, 1.0f);
  ImGui::TableSetupColumn("Match", ImGuiTableColumnFlags_WidthStretch, 3.0f);
  ImGui::TableHeadersRow();
  ImGuiListClipper clipper;
  clipper.Begin(static_cast<int>(search.rows.size()));
  while (clipper.Step()) {
    for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
      const SearchRow& hit = search.rows[static_cast<std::size_t>(row)];
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      if (ImGui::Selectable(components::format_address(hit.address).c_str(),
                            state.selected_address == hit.address,
                            ImGuiSelectableFlags_SpanAllColumns)) {
        state.navigate_to(hit.address, &document);
      }
      ImGui::TableSetColumnIndex(1);
      ImGui::TextUnformatted(hit.preview.c_str());
    }
  }
  ImGui::EndTable();
}

}  // namespace donkey::ui::views
