#include "donkey/ui/application.h"

#include <cstdio>
#include <string>
#include <utility>

#include <SDL3/SDL.h>

#include "imgui.h"
#include "imgui_impl_sdl3.h"
#include "imgui_impl_sdlgpu3.h"
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

}  // namespace

int run(const AppOptions& options) {
  if (!SDL_Init(SDL_INIT_VIDEO)) {
    std::fprintf(stderr, "donkey: SDL_Init failed: %s\n", SDL_GetError());
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

  SDL_GPUDevice* device =
      SDL_CreateGPUDevice(SDL_GPU_SHADERFORMAT_SPIRV | SDL_GPU_SHADERFORMAT_DXIL |
                              SDL_GPU_SHADERFORMAT_MSL | SDL_GPU_SHADERFORMAT_METALLIB,
                          true, nullptr);
  if (device == nullptr) {
    std::fprintf(stderr, "donkey: SDL_CreateGPUDevice failed: %s\n", SDL_GetError());
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 1;
  }
  if (!SDL_ClaimWindowForGPUDevice(device, window)) {
    std::fprintf(stderr, "donkey: SDL_ClaimWindowForGPUDevice failed: %s\n", SDL_GetError());
    SDL_DestroyGPUDevice(device);
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 1;
  }
  SDL_SetGPUSwapchainParameters(device, window, SDL_GPU_SWAPCHAINCOMPOSITION_SDR,
                                SDL_GPU_PRESENTMODE_VSYNC);

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO& io = ImGui::GetIO();
  io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
  io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
  io.IniFilename = nullptr;  // Layout is built in code, not from imgui.ini.

  theme::apply(main_scale);
  ImGui::GetStyle().FontScaleDpi = main_scale;

  ImGui_ImplSDL3_InitForSDLGPU(window);
  ImGui_ImplSDLGPU3_InitInfo init_info = {};
  init_info.Device = device;
  init_info.ColorTargetFormat = SDL_GetGPUSwapchainTextureFormat(device, window);
  init_info.MSAASamples = SDL_GPU_SAMPLECOUNT_1;
  init_info.SwapchainComposition = SDL_GPU_SWAPCHAINCOMPOSITION_SDR;
  init_info.PresentMode = SDL_GPU_PRESENTMODE_VSYNC;
  ImGui_ImplSDLGPU3_Init(&init_info);

  SDL_ShowWindow(window);

  AppState state;
  state.window = window;
  state.workspace.set_open_file_handler([&state]() { open_file_dialog(state); });
  if (!options.initial_path.empty()) {
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

    ImGui_ImplSDLGPU3_NewFrame();
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

    SDL_GPUCommandBuffer* command_buffer = SDL_AcquireGPUCommandBuffer(device);
    if (command_buffer == nullptr) {
      std::fprintf(stderr, "donkey: SDL_AcquireGPUCommandBuffer failed: %s\n", SDL_GetError());
      break;
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

    ++frames;
    if (options.exit_after_frames > 0 && frames >= options.exit_after_frames) {
      quit = true;
    }
  }

  SDL_WaitForGPUIdle(device);
  ImGui_ImplSDLGPU3_Shutdown();
  ImGui_ImplSDL3_Shutdown();
  ImGui::DestroyContext();
  SDL_ReleaseWindowFromGPUDevice(device, window);
  SDL_DestroyGPUDevice(device);
  SDL_DestroyWindow(window);
  SDL_Quit();
  return 0;
}

}  // namespace donkey::ui
