#include "donkey/debug/debug.h"

#include <chrono>
#include <filesystem>
#include <map>
#include <memory>
#include <system_error>
#include <thread>

#include "debug_internal.h"
#include "native_common.h"

namespace donkey::debug {

/// Static images of loaded modules, read on first use. Files above
/// kMaxModuleFile are not read (a debugger must not stall on a huge
/// library); their addresses resolve to the module without a function name.
class ModuleImageCache {
 public:
  static constexpr std::uint64_t kMaxModuleFile = 512ULL * 1024ULL * 1024ULL;

  const native::StaticImage* image_for(const std::string& path) {
    auto it = images_.find(path);
    if (it != images_.end()) {
      return it->second.get();
    }
    std::unique_ptr<native::StaticImage> image;
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    if (!ec && size <= kMaxModuleFile) {
      image = std::make_unique<native::StaticImage>();
      image->load(path, 0x1000);
      if (!image->image) {
        image.reset();
      }
    }
    return images_.emplace(path, std::move(image)).first->second.get();
  }

 private:
  std::map<std::string, std::unique_ptr<native::StaticImage>> images_;
};

namespace {

/// Bias between a module's runtime and static addresses. PE modules are
/// mapped with their headers at the load address, which corresponds to the
/// file's ImageBase; ELF and Mach-O map the lowest page-aligned segment there.
std::uint64_t static_origin(const native::StaticImage& image) {
  return image.image->format == BinaryFormat::Pe ? image.image->image_base : image.lowest;
}

/// Mapped size of a module; when the OS did not report one (Windows can
/// fail to at DLL-load time), the extent of its file image.
std::uint64_t extent_of(const DebugModule& module, ModuleImageCache& cache) {
  if (module.size != 0) {
    return module.size;
  }
  const native::StaticImage* image = cache.image_for(module.path);
  if (image == nullptr || image->highest <= static_origin(*image)) {
    return 0;
  }
  return image->highest - static_origin(*image);
}

bool module_matches(const DebugModule& module, const std::string& wanted) {
  return module.path == wanted || module.name == wanted ||
         std::filesystem::path(module.path).filename().string() == wanted;
}

}  // namespace

DebugAdapter::DebugAdapter() : module_images_(std::make_unique<ModuleImageCache>()) {}
DebugAdapter::~DebugAdapter() = default;

Result<ResolvedAddress> DebugAdapter::resolve_address(std::uint64_t runtime_va) {
  auto modules_now = modules();
  if (!modules_now) {
    return Result<ResolvedAddress>(modules_now.diagnostic());
  }
  for (const DebugModule& module : modules_now.value()) {
    if (runtime_va < module.base_address ||
        runtime_va - module.base_address >= extent_of(module, *module_images_)) {
      continue;
    }
    ResolvedAddress resolved;
    resolved.module_name = module.name;
    resolved.module_path = module.path;
    resolved.module_base = module.base_address;
    const native::StaticImage* image = module_images_->image_for(module.path);
    if (image == nullptr) {
      return make_error<ResolvedAddress>(Status::Unsupported, "debug.module_image_unavailable",
                                         "cannot read the file of module " + module.path);
    }
    resolved.static_address = static_origin(*image) + (runtime_va - module.base_address);
    resolved.function_name = image->function_at(resolved.static_address);
    return resolved;
  }
  return make_error<ResolvedAddress>(Status::InvalidInput, "debug.address_not_in_module",
                                     "no loaded module contains this address");
}

Result<std::uint64_t> DebugAdapter::runtime_address(const std::string& module_name,
                                                    std::uint64_t static_va) {
  auto modules_now = modules();
  if (!modules_now) {
    return Result<std::uint64_t>(modules_now.diagnostic());
  }
  for (const DebugModule& module : modules_now.value()) {
    if (!module_matches(module, module_name)) {
      continue;
    }
    const native::StaticImage* image = module_images_->image_for(module.path);
    if (image == nullptr) {
      return make_error<std::uint64_t>(Status::Unsupported, "debug.module_image_unavailable",
                                       "cannot read the file of module " + module.path);
    }
    const std::uint64_t origin = static_origin(*image);
    if (static_va < origin || static_va - origin >= extent_of(module, *module_images_)) {
      return make_error<std::uint64_t>(Status::InvalidInput, "debug.address_not_in_module",
                                       "the address is outside module " + module.name);
    }
    return module.base_address + (static_va - origin);
  }
  return make_error<std::uint64_t>(Status::InvalidInput, "debug.module_not_loaded",
                                   "module " + module_name + " is not loaded");
}

const char* session_state_name(SessionState state) noexcept {
  switch (state) {
    case SessionState::Disconnected:
      return "Disconnected";
    case SessionState::Launching:
      return "Launching";
    case SessionState::Attaching:
      return "Attaching";
    case SessionState::Running:
      return "Running";
    case SessionState::Stopped:
      return "Stopped";
    case SessionState::Terminating:
      return "Terminating";
    case SessionState::Detached:
      return "Detached";
    case SessionState::Exited:
      return "Exited";
    case SessionState::Error:
      return "Error";
  }
  return "Unknown";
}

const char* stop_reason_name(StopReason reason) noexcept {
  switch (reason) {
    case StopReason::None:
      return "None";
    case StopReason::Entrypoint:
      return "Entrypoint";
    case StopReason::Breakpoint:
      return "Breakpoint";
    case StopReason::SingleStep:
      return "SingleStep";
    case StopReason::Signal:
      return "Signal";
    case StopReason::Exception:
      return "Exception";
    case StopReason::UserPause:
      return "UserPause";
    case StopReason::Exited:
      return "Exited";
  }
  return "None";
}

Result<StopInfo> DebugAdapter::wait_for_event(int timeout_ms) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  while (true) {
    auto event = poll_events();
    if (!event || event.value().reason != StopReason::None || state() != SessionState::Running ||
        std::chrono::steady_clock::now() >= deadline) {
      return event;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
}

std::unique_ptr<DebugAdapter> create_debug_adapter(bool mock, std::uint64_t simulated_aslr_base) {
  if (mock) {
    return std::make_unique<MockDebugAdapter>(simulated_aslr_base);
  }
  return std::make_unique<LocalDebugAdapter>();
}

}  // namespace donkey::debug
