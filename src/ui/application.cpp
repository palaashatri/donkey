#include "donkey/ui/application.h"

#include <cstdio>
#include <string>
#include <utility>

#include <SDL3/SDL.h>

#include "imgui.h"
#include "imgui_impl_sdl3.h"
#include "imgui_impl_sdlgpu3.h"
#include "imgui_impl_sdlrenderer3.h"
#include "session.h"
#include "theme.h"
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
      SDL_SetGPUSwapchainParameters(device, window, SDL_GPU_SWAPCHAINCOMPOSITION_SDR,
                                    SDL_GPU_PRESENTMODE_VSYNC);
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
  SDL_SetRenderVSync(renderer, 1);
  out.renderer = renderer;
  out.name = std::string("SDL_Renderer/") + SDL_GetRendererName(renderer);
  return true;
}

bool render_gpu(SDL_GPUDevice* device, SDL_Window* window, ImDrawData* draw_data, bool is_minimized,
                const ImVec4& clear_color) {
  SDL_GPUCommandBuffer* command_buffer = SDL_AcquireGPUCommandBuffer(device);
  if (command_buffer == nullptr) {
    std::fprintf(stderr, "donkey: SDL_AcquireGPUCommandBuffer failed: %s\n", SDL_GetError());
    return false;
  }
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

}  // namespace

int run(const AppOptions& options) {
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
  io.IniFilename = nullptr;  // Layout is built in code, not from imgui.ini.

  theme::apply(main_scale);
  ImGui::GetStyle().FontScaleDpi = main_scale;

  if (graphics.device != nullptr) {
    ImGui_ImplSDL3_InitForSDLGPU(window);
    ImGui_ImplSDLGPU3_InitInfo init_info = {};
    init_info.Device = graphics.device;
    init_info.ColorTargetFormat = SDL_GetGPUSwapchainTextureFormat(graphics.device, window);
    init_info.MSAASamples = SDL_GPU_SAMPLECOUNT_1;
    init_info.SwapchainComposition = SDL_GPU_SWAPCHAINCOMPOSITION_SDR;
    init_info.PresentMode = SDL_GPU_PRESENTMODE_VSYNC;
    ImGui_ImplSDLGPU3_Init(&init_info);
  } else {
    ImGui_ImplSDL3_InitForSDLRenderer(window, graphics.renderer);
    ImGui_ImplSDLRenderer3_Init(graphics.renderer);
  }

  SDL_ShowWindow(window);

  AppState state;
  state.window = window;
  state.workspace.set_open_file_handler([&state]() { open_file_dialog(state); });
  if (!options.initial_project.empty()) {
    state.session.open_project(options.initial_project);
  } else if (!options.initial_path.empty()) {
    state.session.open(options.initial_path);
  }

  const ImVec4 clear_color(0.07f, 0.07f, 0.09f, 1.0f);
  bool quit = false;
  int frames = 0;

  while (!quit) {
    SDL_Event event;
    while (SDL_PollEvent(&event)) {
      ImGui_ImplSDL3_ProcessEvent(&event);
      if (event.type == SDL_EVENT_QUIT) {
        quit = true;
      }
      if (event.type == SDL_EVENT_WINDOW_CLOSE_REQUESTED &&
          event.window.windowID == SDL_GetWindowID(window)) {
        quit = true;
      }
      if (event.type == SDL_EVENT_DROP_FILE && event.drop.data != nullptr) {
        state.session.open(event.drop.data);
      }
    }

    if (auto error = state.session.take_error(); error.has_value()) {
      state.error = std::move(error.value());
    }

    if ((SDL_GetWindowFlags(window) & SDL_WINDOW_MINIMIZED) != 0) {
      SDL_Delay(10);
      continue;
    }

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

    if (graphics.device != nullptr) {
      if (!render_gpu(graphics.device, window, draw_data, is_minimized, clear_color)) {
        break;
      }
    } else {
      SDL_SetRenderScale(graphics.renderer, io.DisplayFramebufferScale.x,
                         io.DisplayFramebufferScale.y);
      SDL_SetRenderDrawColorFloat(graphics.renderer, clear_color.x, clear_color.y, clear_color.z,
                                  clear_color.w);
      SDL_RenderClear(graphics.renderer);
      ImGui_ImplSDLRenderer3_RenderDrawData(draw_data, graphics.renderer);
      SDL_RenderPresent(graphics.renderer);
    }

    ++frames;
    if (options.exit_after_frames > 0 && frames >= options.exit_after_frames) {
      quit = true;
    }
  }

  if (graphics.device != nullptr) {
    SDL_WaitForGPUIdle(graphics.device);
    ImGui_ImplSDLGPU3_Shutdown();
  } else {
    ImGui_ImplSDLRenderer3_Shutdown();
  }
  ImGui_ImplSDL3_Shutdown();
  ImGui::DestroyContext();
  if (graphics.device != nullptr) {
    SDL_ReleaseWindowFromGPUDevice(graphics.device, window);
    SDL_DestroyGPUDevice(graphics.device);
  } else {
    SDL_DestroyRenderer(graphics.renderer);
  }
  SDL_DestroyWindow(window);
  SDL_Quit();
  return 0;
}

}  // namespace donkey::ui
