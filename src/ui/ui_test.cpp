#include "ui_test.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

#include "donkey/analysis/analysis.h"
#include "donkey/core/thread_priority.h"
#include "imgui.h"
#include "imgui_internal.h"
#include "session.h"
#include "workspace.h"

namespace donkey::ui {
namespace {

std::vector<std::string> split_words(const std::string& text) {
  std::vector<std::string> words;
  std::istringstream in(text);
  std::string word;
  while (in >> word) {
    words.push_back(word);
  }
  return words;
}

std::string lower(std::string text) {
  for (char& c : text) {
    if (c >= 'A' && c <= 'Z') {
      c = static_cast<char>(c - 'A' + 'a');
    }
  }
  return text;
}

double percentile(std::vector<double> values, double p) {
  if (values.empty()) {
    return 0.0;
  }
  std::sort(values.begin(), values.end());
  // Nearest-rank: the smallest value with at least p% of samples at or below.
  const double rank = std::ceil(p / 100.0 * static_cast<double>(values.size()));
  const std::size_t index =
      static_cast<std::size_t>(std::clamp(rank, 1.0, static_cast<double>(values.size()))) - 1;
  return values[index];
}

SDL_Scancode scancode_for(const std::string& key) {
  if (key.size() == 1 && key[0] >= 'a' && key[0] <= 'z') {
    return static_cast<SDL_Scancode>(SDL_SCANCODE_A + (key[0] - 'a'));
  }
  if (key.size() == 1 && key[0] >= '1' && key[0] <= '9') {
    return static_cast<SDL_Scancode>(SDL_SCANCODE_1 + (key[0] - '1'));
  }
  static const struct {
    const char* name;
    SDL_Scancode code;
  } kNamed[] = {
      {"0", SDL_SCANCODE_0},
      {"enter", SDL_SCANCODE_RETURN},
      {"return", SDL_SCANCODE_RETURN},
      {"escape", SDL_SCANCODE_ESCAPE},
      {"tab", SDL_SCANCODE_TAB},
      {"space", SDL_SCANCODE_SPACE},
      {"backspace", SDL_SCANCODE_BACKSPACE},
      {"delete", SDL_SCANCODE_DELETE},
      {"up", SDL_SCANCODE_UP},
      {"down", SDL_SCANCODE_DOWN},
      {"left", SDL_SCANCODE_LEFT},
      {"right", SDL_SCANCODE_RIGHT},
      {"home", SDL_SCANCODE_HOME},
      {"end", SDL_SCANCODE_END},
      {"pageup", SDL_SCANCODE_PAGEUP},
      {"pagedown", SDL_SCANCODE_PAGEDOWN},
      {"semicolon", SDL_SCANCODE_SEMICOLON},
      {"f6", SDL_SCANCODE_F6},
  };
  for (const auto& entry : kNamed) {
    if (key == entry.name) {
      return entry.code;
    }
  }
  return SDL_SCANCODE_UNKNOWN;
}

/// Entries ImGui keeps alive between frames. Rows of a clipped table must not
/// add to this; widgets that were interacted with may.
std::size_t imgui_storage_entries() {
  ImGuiContext& g = *GImGui;
  std::size_t total = static_cast<std::size_t>(g.WindowsById.Data.Size);
  for (ImGuiWindow* window : g.Windows) {
    total += static_cast<std::size_t>(window->StateStorage.Data.Size);
  }
  total += static_cast<std::size_t>(g.Tables.GetAliveCount());
  return total;
}

bool name_matches(const char* window_name, const std::string& wanted) {
  if (window_name == nullptr) {
    return false;
  }
  const std::string name(window_name);
  // "Functions", "Functions##x", popups "Go to" ...
  return name == wanted || name.rfind(wanted + "##", 0) == 0;
}

bool rect_intersects_a_display(SDL_Window* window) {
  int x = 0;
  int y = 0;
  int w = 0;
  int h = 0;
  SDL_GetWindowPosition(window, &x, &y);
  SDL_GetWindowSize(window, &w, &h);
  int count = 0;
  SDL_DisplayID* displays = SDL_GetDisplays(&count);
  bool visible = false;
  for (int i = 0; displays != nullptr && i < count; ++i) {
    SDL_Rect bounds{};
    if (!SDL_GetDisplayBounds(displays[i], &bounds)) {
      continue;
    }
    // Most of the title bar area must be on the display, not a sliver.
    const int overlap_w = std::min(x + w, bounds.x + bounds.w) - std::max(x, bounds.x);
    const int overlap_h = std::min(y + h, bounds.y + bounds.h) - std::max(y, bounds.y);
    if (overlap_w >= std::min(w, 200) && overlap_h >= std::min(h, 100)) {
      visible = true;
    }
  }
  SDL_free(displays);
  return visible;
}

}  // namespace

UiScriptRunner::~UiScriptRunner() {
  stop_background_load();
}

bool UiScriptRunner::load(const std::string& path, std::string& error) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    error = "cannot read UI script " + path;
    return false;
  }
  std::string line;
  int number = 0;
  while (std::getline(in, line)) {
    ++number;
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    const std::size_t start = line.find_first_not_of(" \t");
    if (start == std::string::npos || line[start] == '#') {
      continue;
    }
    line = line.substr(start);
    Command command;
    command.line = number;
    const std::size_t space = line.find(' ');
    command.name = line.substr(0, space);
    if (space != std::string::npos) {
      command.rest = line.substr(space + 1);
    }
    command.args = split_words(command.rest);
    commands_.push_back(std::move(command));
  }
  if (commands_.empty()) {
    error = "UI script " + path + " has no commands";
    return false;
  }
  return true;
}

void UiScriptRunner::fail(const Command& command, const std::string& message) {
  const std::string text =
      "line " + std::to_string(command.line) + " (" + command.name + "): " + message;
  std::fprintf(stderr, "donkey ui-test: FAIL %s\n", text.c_str());
  failures_.push_back(text);
}

void UiScriptRunner::note_input() {
  pending_inputs_.push_back(std::chrono::steady_clock::now());
}

void UiScriptRunner::push_key(const std::string& spec, UiTestHost& host, const Command& command) {
  SDL_Keymod mod = SDL_KMOD_NONE;
  std::string key;
  std::size_t begin = 0;
  const std::string lowered = lower(spec);
  while (begin <= lowered.size()) {
    std::size_t plus = lowered.find('+', begin);
    if (plus == begin) {  // "+" itself is not a supported key name
      plus = std::string::npos;
    }
    const std::string part =
        lowered.substr(begin, plus == std::string::npos ? std::string::npos : plus - begin);
    if (plus == std::string::npos) {
      key = part;
      break;
    }
    if (part == "ctrl") {
      mod = static_cast<SDL_Keymod>(mod | SDL_KMOD_LCTRL);
    } else if (part == "shift") {
      mod = static_cast<SDL_Keymod>(mod | SDL_KMOD_LSHIFT);
    } else if (part == "alt") {
      mod = static_cast<SDL_Keymod>(mod | SDL_KMOD_LALT);
    } else if (part == "gui" || part == "cmd") {
      mod = static_cast<SDL_Keymod>(mod | SDL_KMOD_LGUI);
    } else {
      fail(command, "unknown modifier '" + part + "'");
      return;
    }
    begin = plus + 1;
  }
  const SDL_Scancode scancode = scancode_for(key);
  if (scancode == SDL_SCANCODE_UNKNOWN) {
    fail(command, "unknown key '" + key + "'");
    return;
  }
  const SDL_WindowID id = SDL_GetWindowID(host.window);
  auto send = [&](SDL_EventType type, SDL_Scancode code, SDL_Keymod state) {
    SDL_Event event{};
    event.type = type;
    event.key.windowID = id;
    event.key.scancode = code;
    // Like a real key event: the unshifted keycode, modifiers in `mod`.
    event.key.key = SDL_GetKeyFromScancode(code, SDL_KMOD_NONE, true);
    event.key.mod = state;
    event.key.down = type == SDL_EVENT_KEY_DOWN;
    SDL_PushEvent(&event);
  };
  struct Modifier {
    SDL_Keymod flag;
    SDL_Scancode code;
  };
  const Modifier modifiers[] = {{SDL_KMOD_LCTRL, SDL_SCANCODE_LCTRL},
                                {SDL_KMOD_LSHIFT, SDL_SCANCODE_LSHIFT},
                                {SDL_KMOD_LALT, SDL_SCANCODE_LALT},
                                {SDL_KMOD_LGUI, SDL_SCANCODE_LGUI}};
  for (const Modifier& m : modifiers) {
    if ((mod & m.flag) != 0) {
      send(SDL_EVENT_KEY_DOWN, m.code, mod);
    }
  }
  send(SDL_EVENT_KEY_DOWN, scancode, mod);
  send(SDL_EVENT_KEY_UP, scancode, mod);
  for (const Modifier& m : modifiers) {
    if ((mod & m.flag) != 0) {
      send(SDL_EVENT_KEY_UP, m.code, SDL_KMOD_NONE);
    }
  }
  note_input();
}

void UiScriptRunner::push_text(const std::string& text, UiTestHost& host, bool composing) {
  event_text_.push_back(text);
  SDL_Event event{};
  if (composing) {
    event.type = SDL_EVENT_TEXT_EDITING;
    event.edit.windowID = SDL_GetWindowID(host.window);
    event.edit.text = event_text_.back().c_str();
    event.edit.start = 0;
    event.edit.length = static_cast<Sint32>(text.size());
  } else {
    event.type = SDL_EVENT_TEXT_INPUT;
    event.text.windowID = SDL_GetWindowID(host.window);
    event.text.text = event_text_.back().c_str();
  }
  SDL_PushEvent(&event);
  note_input();
}

void UiScriptRunner::push_window_event(SDL_EventType type, UiTestHost& host) {
  SDL_Event event{};
  event.type = type;
  event.window.windowID = SDL_GetWindowID(host.window);
  SDL_PushEvent(&event);
}

void UiScriptRunner::stop_background_load() {
  if (load_stop_) {
    load_stop_->store(true);
  }
  for (std::thread& thread : load_threads_) {
    if (thread.joinable()) {
      thread.join();
    }
  }
  load_threads_.clear();
}

bool UiScriptRunner::execute(const Command& c, UiTestHost& host) {
  Workspace& workspace = *host.workspace;
  Session& session = *host.session;
  const auto arg = [&](std::size_t i) -> std::string {
    return i < c.args.size() ? c.args[i] : std::string();
  };
  const auto number = [&](std::size_t i, double fallback) {
    return i < c.args.size() ? std::atof(c.args[i].c_str()) : fallback;
  };
  constexpr int kSettleFrames = 3;

  if (c.name == "frames") {
    wait_frames_ = std::max(1, static_cast<int>(number(0, 1)));
    return false;
  }
  if (c.name == "wait_idle") {
    waiting_idle_ = true;
    waiting_command_ = &c;
    wait_deadline_ = std::chrono::steady_clock::now() +
                     std::chrono::milliseconds(static_cast<int>(number(0, 30000)));
    return false;
  }
  if (c.name == "key") {
    push_key(arg(0), host, c);
    wait_frames_ = kSettleFrames;
    return false;
  }
  if (c.name == "text" || c.name == "ime_compose") {
    push_text(c.rest, host, c.name == "ime_compose");
    wait_frames_ = kSettleFrames;
    return false;
  }
  if (c.name == "focus_lost" || c.name == "focus_gained") {
    push_window_event(
        c.name == "focus_lost" ? SDL_EVENT_WINDOW_FOCUS_LOST : SDL_EVENT_WINDOW_FOCUS_GAINED, host);
    wait_frames_ = kSettleFrames;
    return false;
  }
  if (c.name == "scale") {
    const float scale = static_cast<float>(number(0, 1.0));
    if (host.set_scale_override) {
      host.set_scale_override(scale);
    }
    push_window_event(SDL_EVENT_WINDOW_DISPLAY_SCALE_CHANGED, host);
    wait_frames_ = kSettleFrames;
    return false;
  }
  if (c.name == "move_window") {
    SDL_SetWindowPosition(host.window, static_cast<int>(number(0, 0)),
                          static_cast<int>(number(1, 0)));
    SDL_SyncWindow(host.window);
    wait_frames_ = kSettleFrames;
    return false;
  }
  if (c.name == "display_removed") {
    SDL_Event event{};
    event.type = SDL_EVENT_DISPLAY_REMOVED;
    event.display.displayID = 0x7fff;  // a display that no longer exists
    SDL_PushEvent(&event);
    wait_frames_ = kSettleFrames;
    return false;
  }
  if (c.name == "device_lost") {
    SDL_Event event{};
    event.type = SDL_EVENT_RENDER_DEVICE_LOST;
    SDL_PushEvent(&event);
    wait_frames_ = kSettleFrames;
    return false;
  }
  if (c.name == "undock") {
    ImGuiWindow* window = ImGui::FindWindowByName(c.rest.c_str());
    if (window == nullptr) {
      fail(c, "no window named '" + c.rest + "'");
      return true;
    }
    ImGui::DockContextQueueUndockWindow(GImGui, window);
    wait_frames_ = kSettleFrames;
    return false;
  }
  if (c.name == "gallery_open") {
    workspace.gallery().open = true;
    wait_frames_ = kSettleFrames;
    return false;
  }
  if (c.name == "focus_window") {
    ImGui::SetWindowFocus(c.rest.c_str());
    wait_frames_ = kSettleFrames;
    return false;
  }
  if (c.name == "measure") {
    measuring_label_ = arg(0);
    measuring_frames_ = std::max(1, static_cast<int>(number(1, 60)));
    return false;
  }
  if (c.name == "sweep") {
    measuring_label_ = arg(0);
    sweep_frames_ = std::max(1, static_cast<int>(number(1, 120)));
    measuring_frames_ = sweep_frames_;
    sweep_index_ = 0;
    sweep_max_rows_ = 0;
    return false;
  }
  if (c.name == "background_load") {
    const auto document = session.document();
    if (!document) {
      fail(c, "background_load needs an open document");
      return true;
    }
    stop_background_load();
    load_stop_ = std::make_shared<std::atomic<bool>>(false);
    load_runs_ = std::make_shared<std::atomic<std::uint64_t>>(0);
    const int threads = std::max(1, static_cast<int>(number(0, 8)));
    for (int i = 0; i < threads; ++i) {
      load_threads_.emplace_back([document, stop = load_stop_, runs = load_runs_]() {
        // The same priority Donkey's own analysis workers use.
        make_current_thread_background();
        while (!stop->load()) {
          AnalysisOptions options;
          auto result = analyze(document->loaded.image, document->loaded.data, options);
          (void)result;
          runs->fetch_add(1);
        }
      });
    }
    log_.push_back("background analysis load: " + std::to_string(threads) + " threads");
    return true;
  }
  if (c.name == "stop_background_load") {
    const std::uint64_t runs = load_runs_ ? load_runs_->load() : 0;
    stop_background_load();
    log_.push_back("background analyses completed: " + std::to_string(runs));
    if (runs == 0) {
      fail(c, "the background load never completed an analysis");
    }
    return true;
  }
  if (c.name == "storage_baseline") {
    storage_baseline_ = imgui_storage_entries();
    return true;
  }
  if (c.name == "dump_nav") {
    // Script-writing aid: what has keyboard focus right now.
    ImGuiContext& g = *GImGui;
    std::fprintf(stderr,
                 "donkey ui-test: line %d nav window '%s' nav id %08x active id %08x "
                 "want text %d gallery search id %08x\n",
                 c.line, g.NavWindow != nullptr ? g.NavWindow->Name : "<none>", g.NavId, g.ActiveId,
                 ImGui::GetIO().WantTextInput ? 1 : 0, workspace.gallery().search_id);
    return true;
  }
  if (c.name == "quit") {
    done_ = true;
    return false;
  }

  // ---- assertions (never yield) ----
  if (c.name == "assert_selected") {
    const std::uint64_t want = workspace.resolve_location(c.rest);
    const std::uint64_t got = workspace.state().selected_address;
    if (want == 0 || got != want) {
      char buffer[96];
      std::snprintf(buffer, sizeof(buffer), "selected 0x%llx, wanted 0x%llx",
                    static_cast<unsigned long long>(got), static_cast<unsigned long long>(want));
      fail(c, buffer);
    }
    return true;
  }
  if (c.name == "assert_annotation") {
    // assert_annotation rename|comment <address-or-name> <text...>|-
    const std::string kind = arg(0);
    const std::uint64_t address = workspace.resolve_location(arg(1));
    const std::size_t text_at = c.rest.find(arg(1)) + arg(1).size() + 1;
    const std::string want = text_at <= c.rest.size() ? c.rest.substr(text_at) : std::string();
    const auto annotations = session.annotations();
    const std::string* got = nullptr;
    if (annotations && kind == "rename") {
      got = annotations->rename_at(address);
    } else if (annotations && kind == "comment") {
      got = annotations->comment_at(address);
    }
    if (want == "-" ? got != nullptr : (got == nullptr || *got != want)) {
      fail(c, "annotation is '" + (got != nullptr ? *got : std::string("<none>")) + "', wanted '" +
                  want + "'");
    }
    return true;
  }
  if (c.name == "assert_focus") {
    ImGuiWindow* nav = GImGui->NavWindow;
    if (!name_matches(nav != nullptr ? nav->Name : nullptr, c.rest)) {
      fail(c, std::string("focused window is '") + (nav != nullptr ? nav->Name : "<none>") + "'");
    }
    return true;
  }
  if (c.name == "assert_text_input") {
    const bool want = number(0, 1) != 0.0;
    const bool imgui = ImGui::GetIO().WantTextInput;
    // SDL only starts text input (and so the IME) for the window that has
    // keyboard focus; report both so a headless display without focus is
    // visible in the log rather than silently passing.
    const bool focused = SDL_GetKeyboardFocus() == host.window;
    const bool sdl = SDL_TextInputActive(host.window);
    if (imgui != want || (focused && sdl != want)) {
      fail(c, std::string("WantTextInput=") + (imgui ? "1" : "0") + " SDL_TextInputActive=" +
                  (sdl ? "1" : "0") + " keyboard focus=" + (focused ? "1" : "0"));
    }
    if (!focused) {
      log_.push_back("line " + std::to_string(c.line) +
                     ": window has no keyboard focus; SDL text input state not checked");
    }
    return true;
  }
  if (c.name == "assert_ime_rect") {
    const ImGuiPlatformImeData& ime = GImGui->PlatformImeData;
    ImGuiWindow* nav = GImGui->NavWindow;
    if (!ime.WantVisible || nav == nullptr || !nav->Rect().Contains(ime.InputPos)) {
      fail(c, "IME candidate position is not inside the focused text field's window");
    }
    return true;
  }
  if (c.name == "assert_scale") {
    const float want = static_cast<float>(number(0, 1.0));
    const ImGuiStyle& style = ImGui::GetStyle();
    if (std::fabs(style.FontScaleDpi - want) > 0.01f ||
        std::fabs(style.ScrollbarSize - 12.0f * want) > 0.5f) {
      char buffer[96];
      std::snprintf(buffer, sizeof(buffer), "FontScaleDpi %.2f ScrollbarSize %.1f",
                    static_cast<double>(style.FontScaleDpi),
                    static_cast<double>(style.ScrollbarSize));
      fail(c, buffer);
    }
    return true;
  }
  if (c.name == "assert_window_on_display") {
    if (!rect_intersects_a_display(host.window)) {
      int x = 0;
      int y = 0;
      SDL_GetWindowPosition(host.window, &x, &y);
      fail(c,
           "window at " + std::to_string(x) + "," + std::to_string(y) + " is not on any display");
    }
    return true;
  }
  if (c.name == "require_window_off_display") {
    // Some window managers (macOS) keep windows on screen whatever the app
    // asks; then the display-removal recovery below cannot be exercised and
    // the rest of the script up to `end_require` is skipped, with a note.
    if (rect_intersects_a_display(host.window)) {
      log_.push_back("line " + std::to_string(c.line) +
                     ": the window manager kept the window on screen; display-removal "
                     "recovery NOT exercised on this host");
      std::fprintf(stderr, "donkey ui-test: NOTE display-removal recovery not exercised\n");
      while (next_ < commands_.size() && commands_[next_].name != "end_require") {
        ++next_;
      }
    }
    return true;
  }
  if (c.name == "end_require") {
    return true;
  }
  if (c.name == "assert_graphics_resets") {
    if (host.graphics_resets < static_cast<int>(number(0, 1))) {
      fail(c, "graphics were recreated " + std::to_string(host.graphics_resets) + " times");
    }
    return true;
  }
  if (c.name == "assert_floating" || c.name == "assert_docked") {
    ImGuiWindow* window = ImGui::FindWindowByName(c.rest.c_str());
    if (window == nullptr) {
      fail(c, "no window named '" + c.rest + "'");
      return true;
    }
    const bool docked = window->DockIsActive;
    if (docked != (c.name == "assert_docked")) {
      fail(c, std::string("window is ") + (docked ? "docked" : "floating"));
    }
    return true;
  }
  if (c.name == "assert_gallery_rows_max") {
    const int rows = workspace.gallery().rows_submitted_last_frame;
    const int limit = std::max(sweep_max_rows_, rows);
    if (rows <= 0 || limit > static_cast<int>(number(0, 200))) {
      fail(c, "rows submitted per frame: " + std::to_string(limit));
    }
    return true;
  }
  if (c.name == "assert_gallery_selected") {
    if (workspace.gallery().selected_row != static_cast<long long>(number(0, -1))) {
      fail(c, "selected row " + std::to_string(workspace.gallery().selected_row));
    }
    return true;
  }
  if (c.name == "assert_gallery_scrolled_past") {
    const float row_height = ImGui::GetTextLineHeightWithSpacing();
    if (workspace.gallery().scroll_y < static_cast<float>(number(0, 0)) * row_height) {
      fail(c, "gallery scroll position " + std::to_string(workspace.gallery().scroll_y));
    }
    return true;
  }
  if (c.name == "assert_storage_growth_max") {
    const std::size_t now = imgui_storage_entries();
    const std::size_t growth = now > storage_baseline_ ? now - storage_baseline_ : 0;
    if (growth > static_cast<std::size_t>(number(0, 0))) {
      fail(c, "ImGui persistent storage grew by " + std::to_string(growth) + " entries");
    }
    return true;
  }
  if (c.name == "assert_p95" || c.name == "assert_p99") {
    const auto it = samples_.find(arg(0));
    if (it == samples_.end() || it->second.empty()) {
      fail(c, "no samples recorded for '" + arg(0) + "'");
      return true;
    }
    const double p = c.name == "assert_p95" ? 95.0 : 99.0;
    const double value = percentile(it->second, p);
    if (value > number(1, 0)) {
      char buffer[96];
      std::snprintf(buffer, sizeof(buffer), "p%.0f %.2f ms exceeds %.2f ms", p, value,
                    number(1, 0));
      fail(c, buffer);
    }
    return true;
  }
  if (c.name == "assert_no_error") {
    if (auto error = session.take_error(); error.has_value()) {
      fail(c, "session error: " + *error);
    }
    return true;
  }
  fail(c, "unknown command");
  return true;
}

void UiScriptRunner::before_frame(UiTestHost& host) {
  if (done_) {
    return;
  }
  if (measuring_frames_ > 0) {
    if (sweep_frames_ > 0) {
      // Jump across the whole 1M-row table in large, irregular strides.
      GalleryState& gallery = host.workspace->gallery();
      const long long rows = gallery.row_count;
      gallery.scroll_to_row = static_cast<long long>(
          (static_cast<unsigned long long>(sweep_index_) * 7919ULL * 127ULL) %
          static_cast<unsigned long long>(rows));
      if (sweep_index_ == sweep_frames_ - 1) {
        gallery.scroll_to_row = rows - 1;  // and the very end
      }
      ++sweep_index_;
    }
    return;
  }
  if (wait_frames_ > 0) {
    return;
  }
  if (waiting_idle_) {
    if (host.session->busy()) {
      if (std::chrono::steady_clock::now() > wait_deadline_) {
        fail(*waiting_command_, "session still busy at the deadline");
        waiting_idle_ = false;
      }
      return;
    }
    waiting_idle_ = false;
  }
  while (next_ < commands_.size() && !done_) {
    const Command& command = commands_[next_++];
    if (!execute(command, host)) {
      return;
    }
  }
  if (next_ >= commands_.size()) {
    done_ = true;
  }
}

void UiScriptRunner::after_frame(UiTestHost& host, double cpu_ms,
                                 std::chrono::steady_clock::time_point submitted) {
  ++frames_;
  samples_["frame"].push_back(cpu_ms);
  const auto now = std::chrono::steady_clock::now();
  if (frames_ > 1) {
    // Includes present / vsync / display-server time: environment-dependent.
    samples_["frame_interval"].push_back(
        std::chrono::duration<double, std::milli>(now - last_frame_end_).count());
  }
  last_frame_end_ = now;
  for (const auto& pushed : pending_inputs_) {
    const double latency = std::chrono::duration<double, std::milli>(submitted - pushed).count();
    samples_["input"].push_back(latency);
    if (load_stop_ && !load_stop_->load()) {
      samples_["input_under_load"].push_back(latency);
    }
  }
  pending_inputs_.clear();
  if (measuring_frames_ > 0) {
    samples_[measuring_label_].push_back(cpu_ms);
    if (sweep_frames_ > 0) {
      sweep_max_rows_ =
          std::max(sweep_max_rows_, host.workspace->gallery().rows_submitted_last_frame);
    }
    if (--measuring_frames_ == 0) {
      sweep_frames_ = 0;
    }
  }
  if (wait_frames_ > 0) {
    --wait_frames_;
  }
}

bool UiScriptRunner::write_report(const std::string& path, const UiTestHost& host) const {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  out << "{\n  \"schema\": \"donkey.ui_report.v1\",\n";
  out << "  \"renderer\": \"" << host.renderer_name << "\",\n";
  out << "  \"frames\": " << frames_ << ",\n";
  out << "  \"graphics_resets\": " << host.graphics_resets << ",\n";
  out << "  \"note\": \"frame = ms from NewFrame to draw submission; input = ms from "
         "SDL_PushEvent to submission of the frame that consumed it; frame_interval = ms "
         "between frames including present, vsync and the display server "
         "(environment-dependent)\",\n";
  out << "  \"measurements\": {";
  bool first = true;
  char buffer[256];
  for (const auto& [label, values] : samples_) {
    if (values.empty()) {
      continue;
    }
    std::snprintf(buffer, sizeof(buffer),
                  "%s\n    \"%s\": {\"count\": %zu, \"p50\": %.3f, \"p95\": %.3f, \"p99\": %.3f, "
                  "\"max\": %.3f}",
                  first ? "" : ",", label.c_str(), values.size(), percentile(values, 50),
                  percentile(values, 95), percentile(values, 99),
                  *std::max_element(values.begin(), values.end()));
    out << buffer;
    first = false;
  }
  out << "\n  },\n  \"log\": [";
  for (std::size_t i = 0; i < log_.size(); ++i) {
    out << (i == 0 ? "\n" : ",\n") << "    \"" << log_[i] << "\"";
  }
  out << "\n  ],\n  \"failures\": [";
  for (std::size_t i = 0; i < failures_.size(); ++i) {
    std::string escaped;
    for (char ch : failures_[i]) {
      if (ch == '"' || ch == '\\') {
        escaped.push_back('\\');
      }
      escaped.push_back(ch);
    }
    out << (i == 0 ? "\n" : ",\n") << "    \"" << escaped << "\"";
  }
  out << "\n  ]\n}\n";
  return static_cast<bool>(out);
}

}  // namespace donkey::ui
