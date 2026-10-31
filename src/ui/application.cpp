#include "donkey/ui/application.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>
#include <system_error>
#include <utility>

#include <SDL3/SDL.h>

#include "imgui.h"
#include "imgui_impl_sdl3.h"
#include "imgui_impl_sdlgpu3.h"
#include "imgui_impl_sdlrenderer3.h"
#include "session.h"
#include "theme.h"
#include "ui_test.h"
#include "workspace.h"

namespace donkey::ui {
namespace {

constexpr const char* kWindowTitle = "Donkey";

struct AppState {
  Session session;
  Workspace workspace{session};
  std::string error;
  SDL_Window* window = nullptr;
};

void SDLCALL on_file_selected(void* userdata, const char* const* filelist, int /*filter*/) {
  if (userdata == nullptr || filelist == nullptr || filelist[0] == nullptr) {
    return;
  }
  auto* state = static_cast<AppState*>(userdata);
  state->session.open(filelist[0]);
}

void open_file_dialog(AppState& state) {
  static const SDL_DialogFileFilter filters[] = {
      {"Executables and binaries", "elf;exe;dll;so;dylib;bin;o"},
      {"All files", "*"},
  };
  SDL_ShowOpenFileDialog(on_file_selected, &state, state.window, filters,
                         static_cast<int>(sizeof(filters) / sizeof(filters[0])), nullptr, false);
}

void update_window_title(AppState& state) {
  const auto document = state.session.document();
  if (!document) {
    SDL_SetWindowTitle(state.window, kWindowTitle);
    return;
  }
  const BinaryImage& image = document->loaded.image;
  const std::string title = std::string(kWindowTitle) + " — " + image.path + " [" +
                            architecture_name(image.architecture) + "]";
  SDL_SetWindowTitle(state.window, title.c_str());
}

/// The GUI draws through SDL_GPU (Vulkan, D3D12 or Metal) when the host has a
/// usable device, otherwise through SDL_Renderer, whose drivers include
/// OpenGL, Direct3D 11 and a pure software rasteriser. That keeps the app
/// usable in VMs, remote desktops and CI machines without a modern GPU.
struct Graphics {
  SDL_GPUDevice* device = nullptr;
  SDL_Renderer* renderer = nullptr;
  std::string name;
};

void fatal(SDL_Window* window, const char* what, const char* detail) {
  std::fprintf(stderr, "donkey: %s: %s\n", what, detail);
  const std::string message = std::string(what) + ":\n" + detail;
  SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Donkey", message.c_str(), window);
}

bool create_graphics(SDL_Window* window, const std::string& choice, Graphics& out) {
  if (choice != "software") {
#if defined(NDEBUG)
    constexpr bool kDebugLayers = false;
#else
    constexpr bool kDebugLayers = true;
#endif
    SDL_GPUDevice* device =
        SDL_CreateGPUDevice(SDL_GPU_SHADERFORMAT_SPIRV | SDL_GPU_SHADERFORMAT_DXIL |
                                SDL_GPU_SHADERFORMAT_MSL | SDL_GPU_SHADERFORMAT_METALLIB,
                            kDebugLayers, nullptr);
    if (device != nullptr && SDL_ClaimWindowForGPUDevice(device, window)) {
      out.device = device;
      out.name = std::string("SDL_GPU/") + SDL_GetGPUDeviceDriver(device);
      return true;
    }
    std::fprintf(stderr, "donkey: SDL_GPU unavailable (%s)\n", SDL_GetError());
    if (device != nullptr) {
      SDL_DestroyGPUDevice(device);
    }
    if (choice == "gpu") {
      return false;
    }
  }
  SDL_Renderer* renderer =
      SDL_CreateRenderer(window, choice == "software" ? SDL_SOFTWARE_RENDERER : nullptr);
  if (renderer == nullptr) {
    return false;
  }
  out.renderer = renderer;
  out.name = std::string("SDL_Renderer/") + SDL_GetRendererName(renderer);
  return true;
}

bool render_gpu(SDL_GPUDevice* device, SDL_Window* window, ImDrawData* draw_data, bool is_minimized,
                const ImVec4& clear_color, std::chrono::steady_clock::time_point frame_start,
                double& cpu_ms) {
  SDL_GPUCommandBuffer* command_buffer = SDL_AcquireGPUCommandBuffer(device);
  if (command_buffer == nullptr) {
    std::fprintf(stderr, "donkey: SDL_AcquireGPUCommandBuffer failed: %s\n", SDL_GetError());
    return false;
  }
  // The frame's CPU cost ends here: acquiring the swapchain waits for vsync
  // (or the compositor), which is not work Donkey does.
  cpu_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - frame_start)
               .count();
  SDL_GPUTexture* swapchain_texture = nullptr;
  SDL_WaitAndAcquireGPUSwapchainTexture(command_buffer, window, &swapchain_texture, nullptr,
                                        nullptr);
  if (swapchain_texture != nullptr && !is_minimized) {
    ImGui_ImplSDLGPU3_PrepareDrawData(draw_data, command_buffer);
    SDL_GPUColorTargetInfo target_info = {};
    target_info.texture = swapchain_texture;
    target_info.clear_color =
        SDL_FColor{clear_color.x, clear_color.y, clear_color.z, clear_color.w};
    target_info.load_op = SDL_GPU_LOADOP_CLEAR;
    target_info.store_op = SDL_GPU_STOREOP_STORE;
    target_info.mip_level = 0;
    target_info.layer_or_depth_plane = 0;
    target_info.cycle = false;
    SDL_GPURenderPass* render_pass =
        SDL_BeginGPURenderPass(command_buffer, &target_info, 1, nullptr);
    ImGui_ImplSDLGPU3_RenderDrawData(draw_data, command_buffer, render_pass);
    SDL_EndGPURenderPass(render_pass);
  }
  SDL_SubmitGPUCommandBuffer(command_buffer);
  return true;
}

/// Tear down and recreate the renderer and both ImGui backends (device loss).
/// Fonts and textures are re-uploaded by the backends on the next frame.
void shutdown_backends(Graphics& graphics) {
  if (graphics.device != nullptr) {
    SDL_WaitForGPUIdle(graphics.device);
    ImGui_ImplSDLGPU3_Shutdown();
  } else if (graphics.renderer != nullptr) {
    ImGui_ImplSDLRenderer3_Shutdown();
  }
  ImGui_ImplSDL3_Shutdown();
}

void destroy_graphics(SDL_Window* window, Graphics& graphics) {
  if (graphics.device != nullptr) {
    SDL_ReleaseWindowFromGPUDevice(graphics.device, window);
    SDL_DestroyGPUDevice(graphics.device);
  } else if (graphics.renderer != nullptr) {
    SDL_DestroyRenderer(graphics.renderer);
  }
  graphics = Graphics{};
}

void init_backends(SDL_Window* window, Graphics& graphics, bool vsync) {
  if (graphics.device != nullptr) {
    SDL_SetGPUSwapchainParameters(
        graphics.device, window, SDL_GPU_SWAPCHAINCOMPOSITION_SDR,
        vsync || !SDL_WindowSupportsGPUPresentMode(graphics.device, window,
                                                   SDL_GPU_PRESENTMODE_IMMEDIATE)
            ? SDL_GPU_PRESENTMODE_VSYNC
            : SDL_GPU_PRESENTMODE_IMMEDIATE);
    ImGui_ImplSDL3_InitForSDLGPU(window);
    ImGui_ImplSDLGPU3_InitInfo init_info = {};
    init_info.Device = graphics.device;
    init_info.ColorTargetFormat = SDL_GetGPUSwapchainTextureFormat(graphics.device, window);
    init_info.MSAASamples = SDL_GPU_SAMPLECOUNT_1;
    init_info.SwapchainComposition = SDL_GPU_SWAPCHAINCOMPOSITION_SDR;
    init_info.PresentMode = vsync ? SDL_GPU_PRESENTMODE_VSYNC : SDL_GPU_PRESENTMODE_IMMEDIATE;
    ImGui_ImplSDLGPU3_Init(&init_info);
  } else {
    SDL_SetRenderVSync(graphics.renderer, vsync ? 1 : 0);
    ImGui_ImplSDL3_InitForSDLRenderer(window, graphics.renderer);
    ImGui_ImplSDLRenderer3_Init(graphics.renderer);
  }
}

/// Move the window back onto a connected display when the one it was on
/// went away (or it ended up off every display).
void keep_window_on_a_display(SDL_Window* window) {
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
    if (SDL_GetDisplayBounds(displays[i], &bounds)) {
      const int overlap_w = std::min(x + w, bounds.x + bounds.w) - std::max(x, bounds.x);
      const int overlap_h = std::min(y + h, bounds.y + bounds.h) - std::max(y, bounds.y);
      visible = visible || (overlap_w >= std::min(w, 200) && overlap_h >= std::min(h, 100));
    }
  }
  SDL_free(displays);
  if (visible) {
    return;
  }
  SDL_Rect usable{};
  if (SDL_GetDisplayUsableBounds(SDL_GetPrimaryDisplay(), &usable) && usable.w > 0) {
    if ((SDL_GetWindowFlags(window) & SDL_WINDOW_MAXIMIZED) == 0) {
      SDL_SetWindowSize(window, std::min(w, usable.w), std::min(h, usable.h));
    }
    SDL_SetWindowPosition(window, usable.x + std::max(0, (usable.w - std::min(w, usable.w)) / 2),
                          usable.y + std::max(0, (usable.h - std::min(h, usable.h)) / 2));
  } else {
    SDL_SetWindowPosition(window, SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED);
  }
  SDL_SyncWindow(window);
  std::fprintf(stderr, "donkey: window moved back onto the primary display\n");
}

std::string layout_file(const AppOptions& options) {
  std::string dir = options.config_dir;
  if (dir.empty()) {
    char* pref = SDL_GetPrefPath("Donkey", "Donkey");
    if (pref == nullptr) {
      return {};
    }
    dir = pref;
    SDL_free(pref);
  }
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  return (std::filesystem::path(dir) / "layout.ini").string();
}

}  // namespace

int run(const AppOptions& options) {
  UiScriptRunner script;
  const bool scripted = !options.ui_script.empty();
  if (scripted) {
    std::string error;
    if (!script.load(options.ui_script, error)) {
      std::fprintf(stderr, "donkey: %s\n", error.c_str());
      return 2;
    }
  }

  if (!SDL_Init(SDL_INIT_VIDEO)) {
    fatal(nullptr, "SDL_Init failed", SDL_GetError());
    return 1;
  }

  const float main_scale = SDL_GetDisplayContentScale(SDL_GetPrimaryDisplay());
  // SDL window sizes are in points, not pixels: SDL applies the display scale
  // itself. Multiplying by main_scale here would create a window wider than
  // the desktop and push the docked panels off-screen.
  SDL_Rect usable{};
  if (!SDL_GetDisplayUsableBounds(SDL_GetPrimaryDisplay(), &usable)) {
    usable = SDL_Rect{0, 0, 1440, 900};
  }
  int window_width = std::min(1440, usable.w - 80);
  int window_height = std::min(900, usable.h - 80);
  if (window_width < 900) {
    window_width = usable.w > 0 ? usable.w : 1440;
  }
  if (window_height < 600) {
    window_height = usable.h > 0 ? usable.h : 900;
  }

  SDL_WindowFlags window_flags =
      SDL_WINDOW_RESIZABLE | SDL_WINDOW_HIDDEN | SDL_WINDOW_HIGH_PIXEL_DENSITY;
  SDL_Window* window = SDL_CreateWindow(kWindowTitle, window_width, window_height, window_flags);
  if (window == nullptr) {
    std::fprintf(stderr, "donkey: SDL_CreateWindow failed: %s\n", SDL_GetError());
    SDL_Quit();
    return 1;
  }
  SDL_SetWindowPosition(window, SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED);

  Graphics graphics;
  if (!create_graphics(window, options.renderer, graphics)) {
    fatal(window, "Donkey could not initialise graphics", SDL_GetError());
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 1;
  }
  std::fprintf(stderr, "donkey: renderer %s\n", graphics.name.c_str());

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO& io = ImGui::GetIO();
  io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
  io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
  // The dock layout persists in the user's preference directory. Without a
  // saved file the workspace builds its default layout.
  const std::string layout_path = layout_file(options);
  std::error_code layout_ec;
  const bool layout_saved =
      !layout_path.empty() && std::filesystem::is_regular_file(layout_path, layout_ec);
  io.IniFilename = layout_path.empty() ? nullptr : layout_path.c_str();

  float current_scale = main_scale > 0.0f ? main_scale : 1.0f;
  float scale_override = 0.0f;
  theme::apply(current_scale);

  // Scripted runs measure frame cost, so they do not wait for vsync.
  const bool vsync = !scripted;
  init_backends(window, graphics, vsync);

  SDL_ShowWindow(window);
  if (scripted) {
    SDL_RaiseWindow(window);
    SDL_SyncWindow(window);
  }

  AppState state;
  state.window = window;
  state.workspace.set_open_file_handler([&state]() { open_file_dialog(state); });
  state.workspace.set_layout_restored(layout_saved);
  if (!options.initial_project.empty()) {
    state.session.open_project(options.initial_project);
  } else if (!options.initial_path.empty()) {
    state.session.open(options.initial_path);
  }

  UiTestHost host;
  host.window = window;
  host.session = &state.session;
  host.workspace = &state.workspace;
  host.renderer_name = graphics.name;
  host.set_scale_override = [&scale_override](float scale) { scale_override = scale; };

  auto recreate_graphics = [&]() {
    shutdown_backends(graphics);
    destroy_graphics(window, graphics);
    if (!create_graphics(window, options.renderer, graphics)) {
      return false;
    }
    init_backends(window, graphics, vsync);
    ++host.graphics_resets;
    host.renderer_name = graphics.name;
    std::fprintf(stderr, "donkey: graphics recreated (%s)\n", graphics.name.c_str());
    return true;
  };

  const ImVec4 clear_color(0.07f, 0.07f, 0.09f, 1.0f);
  bool quit = false;
  int frames = 0;
  int consecutive_render_failures = 0;
  int exit_code = 0;

  while (!quit) {
    if (scripted) {
      script.before_frame(host);
      if (script.done()) {
        break;
      }
    }
    bool device_lost = false;
    SDL_Event event;
    while (SDL_PollEvent(&event)) {
      ImGui_ImplSDL3_ProcessEvent(&event);
      switch (event.type) {
        case SDL_EVENT_QUIT:
          quit = true;
          break;
        case SDL_EVENT_WINDOW_CLOSE_REQUESTED:
          if (event.window.windowID == SDL_GetWindowID(window)) {
            quit = true;
          }
          break;
        case SDL_EVENT_DROP_FILE:
          if (event.drop.data != nullptr) {
            state.session.open(event.drop.data);
          }
          break;
        case SDL_EVENT_WINDOW_DISPLAY_SCALE_CHANGED:
        case SDL_EVENT_WINDOW_DISPLAY_CHANGED: {
          // Moving between monitors with different DPI rebuilds the style
          // and font scale for the new display.
          const float scale =
              scale_override > 0.0f ? scale_override : SDL_GetWindowDisplayScale(window);
          if (scale > 0.0f && scale != current_scale) {
            current_scale = scale;
            theme::apply(current_scale);
          }
          break;
        }
        case SDL_EVENT_DISPLAY_REMOVED:
        case SDL_EVENT_DISPLAY_MOVED:
        case SDL_EVENT_DISPLAY_CURRENT_MODE_CHANGED:
          keep_window_on_a_display(window);
          break;
        case SDL_EVENT_RENDER_DEVICE_LOST:
        case SDL_EVENT_RENDER_DEVICE_RESET:
          device_lost = true;
          break;
        default:
          break;
      }
    }
    if (device_lost && !recreate_graphics()) {
      fatal(window, "Donkey lost its graphics device and could not recreate it", SDL_GetError());
      exit_code = 1;
      break;
    }

    if (auto error = state.session.take_error(); error.has_value()) {
      state.error = std::move(error.value());
    }

    if ((SDL_GetWindowFlags(window) & SDL_WINDOW_MINIMIZED) != 0) {
      SDL_Delay(10);
      continue;
    }

    const auto frame_start = std::chrono::steady_clock::now();
    if (graphics.device != nullptr) {
      ImGui_ImplSDLGPU3_NewFrame();
    } else {
      ImGui_ImplSDLRenderer3_NewFrame();
    }
    ImGui_ImplSDL3_NewFrame();
    ImGui::NewFrame();

    state.workspace.draw(quit);
    update_window_title(state);

    if (!state.error.empty()) {
      ImGui::OpenPopup("Could not open file");
    }
    if (ImGui::BeginPopupModal("Could not open file", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
      ImGui::TextWrapped("%s", state.error.c_str());
      if (ImGui::Button("Close")) {
        state.error.clear();
        ImGui::CloseCurrentPopup();
      }
      ImGui::EndPopup();
    }

    ImGui::Render();
    ImDrawData* draw_data = ImGui::GetDrawData();
    const bool is_minimized = draw_data->DisplaySize.x <= 0.0f || draw_data->DisplaySize.y <= 0.0f;

    double cpu_ms = 0.0;
    if (graphics.device != nullptr) {
      const bool rendered = render_gpu(graphics.device, window, draw_data, is_minimized,
                                       clear_color, frame_start, cpu_ms);
      if (!rendered) {
        // A failed command buffer usually means the device was lost (driver
        // reset, GPU removed). Recreate it a few times before giving up.
        if (++consecutive_render_failures > 3 || !recreate_graphics()) {
          fatal(window, "Donkey lost its graphics device and could not recreate it",
                SDL_GetError());
          exit_code = 1;
          break;
        }
        continue;
      }
    } else {
      SDL_SetRenderScale(graphics.renderer, io.DisplayFramebufferScale.x,
                         io.DisplayFramebufferScale.y);
      SDL_SetRenderDrawColorFloat(graphics.renderer, clear_color.x, clear_color.y, clear_color.z,
                                  clear_color.w);
      SDL_RenderClear(graphics.renderer);
      ImGui_ImplSDLRenderer3_RenderDrawData(draw_data, graphics.renderer);
      cpu_ms =
          std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - frame_start)
              .count();
      SDL_RenderPresent(graphics.renderer);
    }
    consecutive_render_failures = 0;
    if (scripted) {
      script.after_frame(
          host, cpu_ms,
          frame_start + std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                            std::chrono::duration<double, std::milli>(cpu_ms)));
    }

    ++frames;
    if (options.exit_after_frames > 0 && frames >= options.exit_after_frames) {
      quit = true;
    }
  }

  if (scripted) {
    if (!options.ui_report.empty() && !script.write_report(options.ui_report, host)) {
      std::fprintf(stderr, "donkey: cannot write UI report %s\n", options.ui_report.c_str());
      exit_code = 1;
    }
    if (script.exit_code() != 0) {
      exit_code = script.exit_code();
    } else {
      std::fprintf(stderr, "donkey ui-test: PASS %s\n", options.ui_script.c_str());
    }
  }

  shutdown_backends(graphics);
  // Saves the dock layout (io.IniFilename) before the context goes away.
  ImGui::DestroyContext();
  destroy_graphics(window, graphics);
  SDL_DestroyWindow(window);
  SDL_Quit();
  return exit_code;
}

}  // namespace donkey::ui
