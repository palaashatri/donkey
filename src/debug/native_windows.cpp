// Native Windows debugger: Win32 debug API execution control for x64.
//
// Model: the debugger owns the debug event loop. While the target is stopped
// the triggering debug event is held (not continued), which freezes every
// thread of the process. Software breakpoints are int3; single-step uses the
// trap flag; pause uses DebugBreakProcess. Stack walks use DbgHelp's unwinder
// because x64 Windows code does not keep an RBP frame chain.

#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// clang-format off
#include <dbghelp.h>
#include <psapi.h>
// clang-format on

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <map>
#include <string>

#include "debug_internal.h"
#include "donkey/decode/decode.h"
#include "native_common.h"

namespace donkey::debug {

namespace {

using native::SoftwareBreakpoint;

constexpr std::array<std::byte, 1> kTrap{std::byte{0xcc}};
constexpr DWORD kTrapFlag = 0x100;
constexpr int kStepTimeoutMs = 2000;
constexpr int kEntryTimeoutMs = 10000;
constexpr std::size_t kMaxFrames = 64;
constexpr std::size_t kMaxRead = 16 * 1024 * 1024;

std::wstring widen(const std::string& text) {
  if (text.empty()) {
    return {};
  }
  const int size = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
  std::wstring out(static_cast<std::size_t>(size > 0 ? size - 1 : 0), L'\0');
  if (size > 1) {
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, out.data(), size);
  }
  return out;
}

std::string narrow(const std::wstring& text) {
  if (text.empty()) {
    return {};
  }
  const int size = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, nullptr, 0, nullptr, nullptr);
  std::string out(static_cast<std::size_t>(size > 0 ? size - 1 : 0), '\0');
  if (size > 1) {
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, out.data(), size, nullptr, nullptr);
  }
  return out;
}

/// Quote one argument the way CommandLineToArgvW / the CRT parse it.
std::wstring quote_argument(const std::wstring& arg) {
  if (!arg.empty() && arg.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
    return arg;
  }
  std::wstring out = L"\"";
  std::size_t backslashes = 0;
  for (wchar_t c : arg) {
    if (c == L'\\') {
      ++backslashes;
    } else if (c == L'"') {
      out.append(backslashes * 2 + 1, L'\\');
      out.push_back(c);
      backslashes = 0;
    } else {
      out.append(backslashes, L'\\');
      out.push_back(c);
      backslashes = 0;
    }
  }
  out.append(backslashes * 2, L'\\');
  out.push_back(L'"');
  return out;
}

std::string path_of_file_handle(HANDLE file) {
  if (file == nullptr || file == INVALID_HANDLE_VALUE) {
    return {};
  }
  wchar_t buffer[MAX_PATH * 2] = {};
  const DWORD length = GetFinalPathNameByHandleW(file, buffer, MAX_PATH * 2, FILE_NAME_NORMALIZED);
  if (length == 0 || length >= MAX_PATH * 2) {
    return {};
  }
  std::wstring path(buffer, length);
  if (path.rfind(L"\\\\?\\", 0) == 0) {
    path = path.substr(4);
  }
  return narrow(path);
}

Result<bool> win_error(const std::string& code, const std::string& what) {
  const DWORD error = GetLastError();
  const Status status =
      error == ERROR_ACCESS_DENIED ? Status::PermissionDenied : Status::InternalError;
  return make_error<bool>(status, code, what + " (Windows error " + std::to_string(error) + ")");
}

struct RegisterSlot {
  const char* name;
  DWORD64 CONTEXT::* field;
};

constexpr RegisterSlot kRegisterSlots[] = {
    {"rax", &CONTEXT::Rax}, {"rbx", &CONTEXT::Rbx}, {"rcx", &CONTEXT::Rcx}, {"rdx", &CONTEXT::Rdx},
    {"rsi", &CONTEXT::Rsi}, {"rdi", &CONTEXT::Rdi}, {"rbp", &CONTEXT::Rbp}, {"rsp", &CONTEXT::Rsp},
    {"r8", &CONTEXT::R8},   {"r9", &CONTEXT::R9},   {"r10", &CONTEXT::R10}, {"r11", &CONTEXT::R11},
    {"r12", &CONTEXT::R12}, {"r13", &CONTEXT::R13}, {"r14", &CONTEXT::R14}, {"r15", &CONTEXT::R15},
    {"rip", &CONTEXT::Rip},
};

}  // namespace

struct LocalDebugAdapter::Impl {
  SessionState state = SessionState::Disconnected;
  AddressTranslator translator;
  DWORD pid = 0;
  HANDLE process = nullptr;
  std::map<DWORD, HANDLE> thread_handles;
  DWORD current_thread = 0;
  bool launched = false;
  bool loader_breakpoint_seen = false;
  bool attaching = false;
  bool pause_requested = false;
  bool stepping = false;
  bool symbols_ready = false;
  /// The debug event the target is frozen on, if any.
  bool holding_event = false;
  DWORD held_thread = 0;
  DWORD continue_status = DBG_CONTINUE;
  std::string executable;
  std::uint64_t runtime_image_base = 0;
  native::StaticImage image;
  std::vector<SoftwareBreakpoint> breakpoints;
  std::vector<DebugModule> module_list;
  std::uint64_t next_breakpoint_id = 1;
  StopInfo stop;

  ~Impl() { teardown(); }

  // ---- low level ---------------------------------------------------------

  HANDLE thread() const {
    const auto it = thread_handles.find(current_thread);
    return it == thread_handles.end() ? nullptr : it->second;
  }

  bool get_context(CONTEXT& context) const {
    std::memset(&context, 0, sizeof(context));
    context.ContextFlags = CONTEXT_FULL;
    return thread() != nullptr && GetThreadContext(thread(), &context) != 0;
  }
  bool set_context(CONTEXT& context) const {
    return thread() != nullptr && SetThreadContext(thread(), &context) != 0;
  }
  std::optional<std::uint64_t> pc() const {
    CONTEXT context;
    if (!get_context(context)) {
      return std::nullopt;
    }
    return context.Rip;
  }

  bool raw_read(std::uint64_t address, void* out, std::size_t size) const {
    SIZE_T done = 0;
    return process != nullptr &&
           ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address), out, size, &done) &&
           done == size;
  }
  bool raw_write(std::uint64_t address, const void* data, std::size_t size) const {
    SIZE_T done = 0;
    const bool ok =
        process != nullptr &&
        WriteProcessMemory(process, reinterpret_cast<LPVOID>(address), data, size, &done) &&
        done == size;
    if (ok) {
      FlushInstructionCache(process, reinterpret_cast<LPCVOID>(address), size);
    }
    return ok;
  }

  bool insert(SoftwareBreakpoint& bp) {
    if (bp.inserted) {
      return true;
    }
    bp.original.assign(kTrap.size(), std::byte{0});
    if (!raw_read(bp.info.address, bp.original.data(), bp.original.size()) ||
        !raw_write(bp.info.address, kTrap.data(), kTrap.size())) {
      return false;
    }
    bp.inserted = true;
    return true;
  }
  bool uninsert(SoftwareBreakpoint& bp) {
    if (!bp.inserted) {
      return true;
    }
    if (!raw_write(bp.info.address, bp.original.data(), bp.original.size())) {
      return false;
    }
    bp.inserted = false;
    return true;
  }
  SoftwareBreakpoint* breakpoint_at(std::uint64_t address) {
    for (auto& bp : breakpoints) {
      if (bp.info.address == address && bp.inserted) {
        return &bp;
      }
    }
    return nullptr;
  }

  void drop_internal_breakpoints() {
    std::vector<std::uint64_t> freed;
    for (auto it = breakpoints.begin(); it != breakpoints.end();) {
      if (it->internal) {
        uninsert(*it);
        freed.push_back(it->info.address);
        it = breakpoints.erase(it);
      } else {
        ++it;
      }
    }
    for (auto& bp : breakpoints) {
      if (std::find(freed.begin(), freed.end(), bp.info.address) != freed.end()) {
        bp.inserted = false;
      }
      if (bp.info.enabled) {
        insert(bp);
      }
    }
  }

  void forget_process() {
    if (symbols_ready && process != nullptr) {
      SymCleanup(process);
    }
    symbols_ready = false;
    for (auto& [id, handle] : thread_handles) {
      (void)id;
      (void)handle;  // owned by the debug subsystem; closed when debugging ends
    }
    thread_handles.clear();
    module_list.clear();
    process = nullptr;
    pid = 0;
    launched = false;
    holding_event = false;
    loader_breakpoint_seen = false;
    breakpoints.erase(std::remove_if(breakpoints.begin(), breakpoints.end(),
                                     [](const SoftwareBreakpoint& bp) { return bp.internal; }),
                      breakpoints.end());
    for (auto& bp : breakpoints) {
      bp.inserted = false;
    }
  }

  void release_event() {
    if (holding_event) {
      ContinueDebugEvent(pid, held_thread, continue_status);
      holding_event = false;
      continue_status = DBG_CONTINUE;
    }
  }

  void teardown() {
    if (pid == 0) {
      return;
    }
    if (launched) {
      TerminateProcess(process, 1);
      release_event();
      while (pid != 0) {
        if (!wait(kEntryTimeoutMs)) {
          break;
        }
        if (state != SessionState::Exited && holding_event) {
          release_event();
        }
      }
      if (pid != 0) {
        DebugActiveProcessStop(pid);
        forget_process();
      }
    } else {
      (void)detach_now();
    }
  }

  void update_translator() {
    translator = AddressTranslator{};
    if (!image.image || runtime_image_base == 0) {
      return;
    }
    translator.runtime_base = runtime_image_base;
    translator.static_base = image.image->image_base != 0 ? image.image->image_base : image.lowest;
    translator.size =
        image.highest > translator.static_base ? image.highest - translator.static_base : 0x1000;
  }

  // ---- events ------------------------------------------------------------

  /// Process debug events until one stops the target (it is then held), the
  /// process exits, or the timeout elapses. Returns false on timeout.
  bool wait(int timeout_ms) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (pid != 0) {
      const auto now = std::chrono::steady_clock::now();
      DWORD slice = 0;
      if (timeout_ms < 0) {
        slice = INFINITE;
      } else if (now < deadline) {
        slice = static_cast<DWORD>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
      }
      DEBUG_EVENT event{};
      if (!WaitForDebugEvent(&event, slice)) {
        return false;
      }
      if (handle_event(event)) {
        return true;
      }
      ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
      if (timeout_ms >= 0 && std::chrono::steady_clock::now() >= deadline) {
        return false;
      }
    }
    return true;
  }

  /// Returns true when the event stops the target; the caller then holds it.
  bool handle_event(const DEBUG_EVENT& event) {
    switch (event.dwDebugEventCode) {
      case CREATE_PROCESS_DEBUG_EVENT: {
        const auto& info = event.u.CreateProcessInfo;
        process = info.hProcess;
        thread_handles[event.dwThreadId] = info.hThread;
        current_thread = event.dwThreadId;
        runtime_image_base = reinterpret_cast<std::uint64_t>(info.lpBaseOfImage);
        const std::string path = path_of_file_handle(info.hFile);
        if (executable.empty()) {
          executable = path;
        }
        DebugModule module;
        module.path = path.empty() ? executable : path;
        module.name = std::filesystem::path(module.path).filename().string();
        module.base_address = runtime_image_base;
        if (!image.image) {
          image.load(executable, 0x1000);
        }
        module.size = image.highest > image.lowest ? image.highest - image.lowest : 0;
        module_list.push_back(module);
        update_translator();
        // DbgHelp needs every module registered explicitly: at this point the
        // process has no other modules for SymInitialize to discover.
        symbols_ready = SymInitialize(process, nullptr, FALSE) != 0;
        if (symbols_ready) {
          SymLoadModuleEx(process, info.hFile, module.path.c_str(), nullptr, runtime_image_base,
                          static_cast<DWORD>(module.size), nullptr, 0);
        }
        if (info.hFile != nullptr) {
          CloseHandle(info.hFile);
        }
        return false;
      }
      case CREATE_THREAD_DEBUG_EVENT:
        thread_handles[event.dwThreadId] = event.u.CreateThread.hThread;
        return false;
      case EXIT_THREAD_DEBUG_EVENT:
        thread_handles.erase(event.dwThreadId);
        return false;
      case LOAD_DLL_DEBUG_EVENT: {
        const auto& info = event.u.LoadDll;
        DebugModule module;
        module.path = path_of_file_handle(info.hFile);
        module.name = std::filesystem::path(module.path).filename().string();
        module.base_address = reinterpret_cast<std::uint64_t>(info.lpBaseOfDll);
        MODULEINFO mi{};
        if (process != nullptr &&
            GetModuleInformation(process, reinterpret_cast<HMODULE>(info.lpBaseOfDll), &mi,
                                 sizeof(mi))) {
          module.size = mi.SizeOfImage;
        }
        if (symbols_ready) {
          SymLoadModuleEx(process, info.hFile, module.path.c_str(), nullptr, module.base_address,
                          static_cast<DWORD>(module.size), nullptr, 0);
        }
        if (info.hFile != nullptr) {
          CloseHandle(info.hFile);
        }
        module_list.push_back(module);
        return false;
      }
      case UNLOAD_DLL_DEBUG_EVENT: {
        const auto base = reinterpret_cast<std::uint64_t>(event.u.UnloadDll.lpBaseOfDll);
        if (symbols_ready) {
          SymUnloadModule64(process, base);
        }
        module_list.erase(
            std::remove_if(module_list.begin(), module_list.end(),
                           [&](const DebugModule& m) { return m.base_address == base; }),
            module_list.end());
        return false;
      }
      case OUTPUT_DEBUG_STRING_EVENT:
      case RIP_EVENT:
        return false;
      case EXIT_PROCESS_DEBUG_EVENT: {
        const int code = static_cast<int>(event.u.ExitProcess.dwExitCode);
        stop = StopInfo{StopReason::Exited, event.dwThreadId, 0,
                        "process exited with code " + std::to_string(code), code};
        state = SessionState::Exited;
        ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
        forget_process();
        return true;
      }
      case EXCEPTION_DEBUG_EVENT:
        return handle_exception(event);
      default:
        return false;
    }
  }

  bool hold(const DEBUG_EVENT& event, StopInfo info, DWORD status) {
    holding_event = true;
    held_thread = event.dwThreadId;
    continue_status = status;
    current_thread = event.dwThreadId;
    state = SessionState::Stopped;
    stop = std::move(info);
    return true;
  }

  bool handle_exception(const DEBUG_EVENT& event) {
    const auto& record = event.u.Exception.ExceptionRecord;
    const auto address = reinterpret_cast<std::uint64_t>(record.ExceptionAddress);
    const DWORD code = record.ExceptionCode;
    const DWORD tid = event.dwThreadId;
    const bool was_stepping = stepping && tid == current_thread;

    if (code == EXCEPTION_BREAKPOINT || code == 0x4000001f /* STATUS_WX86_BREAKPOINT */) {
      if (!loader_breakpoint_seen) {
        // The loader's initial breakpoint (or the attach break-in thread).
        // Hold it: launch() inserts the entry breakpoint while frozen here.
        loader_breakpoint_seen = true;
        if (attaching) {
          attaching = false;
          return hold(event, StopInfo{StopReason::UserPause, tid, address, "attached", 0},
                      DBG_CONTINUE);
        }
        return hold(event,
                    StopInfo{StopReason::Entrypoint, tid, address, "initial loader breakpoint", 0},
                    DBG_CONTINUE);
      }
      if (SoftwareBreakpoint* bp = breakpoint_at(address)) {
        current_thread = tid;
        CONTEXT context;
        if (get_context(context)) {
          context.Rip = address;
          set_context(context);
        }
        bool user_hit = false;
        for (auto& candidate : breakpoints) {
          if (candidate.info.address == address && !candidate.internal) {
            ++candidate.info.hit_count;
            user_hit = true;
          }
        }
        StopReason reason = StopReason::Breakpoint;
        std::string description = "breakpoint hit";
        if (!user_hit) {
          reason = bp->tag == "entry" ? StopReason::Entrypoint : StopReason::SingleStep;
          description = bp->tag == "entry" ? "stopped at program entry" : "step completed";
        }
        drop_internal_breakpoints();
        return hold(event, StopInfo{reason, tid, address, description, 0}, DBG_CONTINUE);
      }
      if (pause_requested) {
        pause_requested = false;
        // DebugBreakProcess runs the int3 on a new thread; report the
        // previously current thread as the one of interest.
        const DWORD interesting = thread_handles.count(current_thread) ? current_thread : tid;
        hold(event, StopInfo{StopReason::UserPause, interesting, address, "paused", 0},
             DBG_CONTINUE);
        current_thread = interesting;
        return true;
      }
      return hold(event, StopInfo{StopReason::Exception, tid, address, "breakpoint exception", 0},
                  DBG_CONTINUE);
    }
    if ((code == EXCEPTION_SINGLE_STEP || code == 0x4000001e /* STATUS_WX86_SINGLE_STEP */) &&
        was_stepping) {
      stepping = false;
      return hold(event, StopInfo{StopReason::SingleStep, tid, address, "single step", 0},
                  DBG_CONTINUE);
    }
    // A real exception in the target. Report it; on resume the target's own
    // handlers see it first (not handled by the debugger).
    char text[64];
    std::snprintf(text, sizeof(text), "exception 0x%08lx%s", static_cast<unsigned long>(code),
                  event.u.Exception.dwFirstChance ? " (first chance)" : "");
    return hold(event, StopInfo{StopReason::Exception, tid, address, text, static_cast<int>(code)},
                DBG_EXCEPTION_NOT_HANDLED);
  }

  // ---- execution control -------------------------------------------------

  bool single_step(int timeout_ms) {
    CONTEXT context;
    if (!get_context(context)) {
      return false;
    }
    SoftwareBreakpoint* bp = breakpoint_at(context.Rip);
    if (bp != nullptr) {
      uninsert(*bp);
    }
    context.EFlags |= kTrapFlag;
    if (!set_context(context)) {
      return false;
    }
    stepping = true;
    state = SessionState::Running;
    release_event();
    const bool finished = wait(timeout_ms);
    if (pid != 0 && state == SessionState::Stopped) {
      for (auto& candidate : breakpoints) {
        if (candidate.info.enabled && !candidate.inserted) {
          insert(candidate);
        }
      }
    }
    return finished;
  }

  Result<bool> continue_running() {
    auto here = pc();
    if (here && breakpoint_at(*here) != nullptr) {
      single_step(kStepTimeoutMs);
      if (pid == 0 || state != SessionState::Stopped) {
        return true;
      }
      if (stop.reason == StopReason::Breakpoint || stop.reason == StopReason::Exception) {
        return true;
      }
    }
    state = SessionState::Running;
    stop = StopInfo{};
    release_event();
    return true;
  }

  Result<bool> run_to(std::uint64_t address, const char* tag, int timeout_ms) {
    SoftwareBreakpoint temp;
    temp.info.address = address;
    temp.internal = true;
    temp.tag = tag;
    if (SoftwareBreakpoint* existing = breakpoint_at(address)) {
      temp.original = existing->original;
      temp.inserted = true;
      breakpoints.push_back(temp);
    } else {
      breakpoints.push_back(temp);
      if (!insert(breakpoints.back())) {
        breakpoints.pop_back();
        return win_error("debug.breakpoint_failed", "could not place a temporary breakpoint");
      }
    }
    auto resumed = continue_running();
    if (!resumed) {
      drop_internal_breakpoints();
      return resumed;
    }
    if (state == SessionState::Running) {
      wait(timeout_ms);
    }
    return true;
  }

  Result<bool> detach_now() {
    if (pid == 0) {
      return true;
    }
    if (state == SessionState::Running) {
      pause_requested = true;
      DebugBreakProcess(process);
      wait(kStepTimeoutMs);
      if (pid == 0) {
        return true;
      }
    }
    for (auto& bp : breakpoints) {
      uninsert(bp);
    }
    DebugSetProcessKillOnExit(FALSE);
    release_event();
    const DWORD target = pid;
    if (!DebugActiveProcessStop(target)) {
      return win_error("debug.detach_failed", "could not detach from the target");
    }
    forget_process();
    return true;
  }

  Result<bool> require_stopped(const char* action) const {
    if (pid == 0 || state != SessionState::Stopped) {
      return native::invalid_state(std::string("cannot ") + action +
                                   " unless the target is stopped");
    }
    return true;
  }
};

LocalDebugAdapter::LocalDebugAdapter() : impl_(std::make_unique<Impl>()) {}
LocalDebugAdapter::~LocalDebugAdapter() = default;

SessionState LocalDebugAdapter::state() const noexcept {
  return impl_->state;
}

const AddressTranslator& LocalDebugAdapter::address_translator() const noexcept {
  return impl_->translator;
}

DebugCapabilities LocalDebugAdapter::capabilities() const noexcept {
  DebugCapabilities caps;
  caps.can_launch = true;
  caps.can_attach = true;
  caps.can_step = true;
  caps.can_read_memory = true;
  caps.can_write_memory = true;
  caps.can_software_breakpoints = true;
  caps.can_hardware_breakpoints = false;
  return caps;
}

Result<bool> LocalDebugAdapter::launch(const LaunchConfig& config) {
  Impl& d = *impl_;
  d.teardown();
  d.stop = StopInfo{};
  if (config.binary_path.empty()) {
    d.state = SessionState::Error;
    return make_error<bool>(Status::InvalidInput, "debug.invalid_path",
                            "binary path cannot be empty");
  }
  std::error_code ec;
  if (!std::filesystem::is_regular_file(config.binary_path, ec)) {
    d.state = SessionState::Error;
    return make_error<bool>(Status::InvalidInput, "debug.file_not_executable",
                            "binary file not found: " + config.binary_path);
  }
  d.image.load(config.binary_path, 0x1000);
  if (d.image.image && d.image.image->architecture != Architecture::X86_64) {
    d.state = SessionState::Error;
    return make_error<bool>(Status::Unsupported, "debug.architecture_mismatch",
                            "only x64 programs can be debugged on this host");
  }

  std::wstring command = quote_argument(widen(config.binary_path));
  for (const auto& arg : config.arguments) {
    command += L" " + quote_argument(widen(arg));
  }
  std::wstring environment;
  if (!config.environment.empty()) {
    LPWCH current = GetEnvironmentStringsW();
    for (LPWCH p = current; p != nullptr && *p != L'\0'; p += wcslen(p) + 1) {
      environment.append(p);
      environment.push_back(L'\0');
    }
    if (current != nullptr) {
      FreeEnvironmentStringsW(current);
    }
    for (const auto& [key, value] : config.environment) {
      environment += widen(key) + L"=" + widen(value);
      environment.push_back(L'\0');
    }
    environment.push_back(L'\0');
  }
  const std::wstring application = widen(config.binary_path);
  const std::wstring cwd = widen(config.working_directory);

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION info{};
  d.state = SessionState::Launching;
  d.executable = config.binary_path;
  d.loader_breakpoint_seen = false;
  d.attaching = false;
  if (!CreateProcessW(application.c_str(), command.data(), nullptr, nullptr, FALSE,
                      DEBUG_ONLY_THIS_PROCESS | CREATE_UNICODE_ENVIRONMENT,
                      environment.empty() ? nullptr : environment.data(),
                      cwd.empty() ? nullptr : cwd.c_str(), &startup, &info)) {
    d.state = SessionState::Error;
    return win_error("debug.launch_failed", "could not start the target");
  }
  // The debug subsystem hands out its own handles in the creation event.
  CloseHandle(info.hProcess);
  CloseHandle(info.hThread);
  d.pid = info.dwProcessId;
  d.launched = true;

  // Run to the loader's initial breakpoint; the image is known by then.
  d.state = SessionState::Running;
  if (!d.wait(kEntryTimeoutMs)) {
    d.teardown();
    d.state = SessionState::Error;
    return make_error<bool>(Status::InternalError, "debug.launch_failed",
                            "the target did not finish loading");
  }
  if (d.pid == 0) {
    d.state = SessionState::Exited;
    return make_error<bool>(Status::InternalError, "debug.exited_before_entry",
                            "the target exited during start-up: " + d.stop.description);
  }

  const std::uint64_t entry = d.image.image && d.image.image->has_entry_point()
                                  ? d.translator.static_to_runtime(d.image.image->entry_point)
                                  : 0;
  if (!config.stop_at_entry) {
    return d.continue_running();
  }
  if (entry == 0) {
    return true;  // stay at the loader breakpoint; the program entry is unknown
  }
  // Insert the entry breakpoint while the process is still in the loader.
  SoftwareBreakpoint temp;
  temp.info.address = entry;
  temp.internal = true;
  temp.tag = "entry";
  d.breakpoints.push_back(temp);
  if (!d.insert(d.breakpoints.back())) {
    d.breakpoints.pop_back();
    return win_error("debug.breakpoint_failed", "could not place the entry breakpoint");
  }
  d.state = SessionState::Running;
  d.stop = StopInfo{};
  d.release_event();
  d.wait(kEntryTimeoutMs);
  if (d.state == SessionState::Running) {
    return make_error<bool>(Status::InternalError, "debug.entry_timeout",
                            "the target did not reach its entry point; it is still running");
  }
  if (d.state == SessionState::Exited) {
    return make_error<bool>(
        Status::InternalError, "debug.exited_before_entry",
        "the target exited before reaching its entry point: " + d.stop.description);
  }
  return true;
}

Result<bool> LocalDebugAdapter::attach(std::uint32_t pid) {
  Impl& d = *impl_;
  d.teardown();
  d.stop = StopInfo{};
  if (pid == 0 || pid == GetCurrentProcessId()) {
    d.state = SessionState::Error;
    return make_error<bool>(Status::InvalidInput, "debug.invalid_pid",
                            "cannot attach to that process");
  }
  d.state = SessionState::Attaching;
  d.executable.clear();
  d.loader_breakpoint_seen = false;
  d.attaching = true;
  if (!DebugActiveProcess(pid)) {
    d.state = SessionState::Error;
    if (GetLastError() == ERROR_ACCESS_DENIED) {
      return make_error<bool>(Status::PermissionDenied, "debug.permission_denied",
                              "attach was refused; the target may run at a higher integrity "
                              "level or be protected");
    }
    return win_error("debug.attach_failed", "could not attach");
  }
  d.pid = pid;
  d.launched = false;
  if (!d.wait(kEntryTimeoutMs) || d.pid == 0) {
    d.state = SessionState::Error;
    return make_error<bool>(Status::InternalError, "debug.attach_failed",
                            "the target did not stop after attach");
  }
  return true;
}

Result<bool> LocalDebugAdapter::detach() {
  Impl& d = *impl_;
  auto detached = d.detach_now();
  if (!detached) {
    return detached;
  }
  d.state = SessionState::Detached;
  d.stop = StopInfo{};
  return true;
}

Result<bool> LocalDebugAdapter::terminate() {
  Impl& d = *impl_;
  if (d.pid != 0) {
    d.state = SessionState::Terminating;
    TerminateProcess(d.process, 1);
    d.release_event();
    while (d.pid != 0 && d.wait(kEntryTimeoutMs)) {
      if (d.pid != 0) {
        d.release_event();
      }
    }
  }
  d.state = SessionState::Exited;
  return true;
}

Result<bool> LocalDebugAdapter::resume() {
  Impl& d = *impl_;
  if (auto ok = d.require_stopped("resume"); !ok) {
    return ok;
  }
  return d.continue_running();
}

Result<bool> LocalDebugAdapter::pause() {
  Impl& d = *impl_;
  if (d.pid == 0 || d.state != SessionState::Running) {
    return native::invalid_state("cannot pause unless the target is running");
  }
  d.pause_requested = true;
  if (!DebugBreakProcess(d.process)) {
    d.pause_requested = false;
    return win_error("debug.pause_failed", "could not break into the target");
  }
  d.wait(kStepTimeoutMs);
  return true;
}

Result<bool> LocalDebugAdapter::step_into() {
  Impl& d = *impl_;
  if (auto ok = d.require_stopped("step"); !ok) {
    return ok;
  }
  if (!d.single_step(kStepTimeoutMs) && d.pid != 0 && d.state != SessionState::Running) {
    return win_error("debug.step_failed", "could not single-step the target");
  }
  return true;
}

Result<bool> LocalDebugAdapter::step_over() {
  Impl& d = *impl_;
  if (auto ok = d.require_stopped("step"); !ok) {
    return ok;
  }
  const auto here = d.pc();
  if (!here) {
    return win_error("debug.step_failed", "could not read the program counter");
  }
  std::vector<std::byte> bytes(16);
  if (!d.raw_read(*here, bytes.data(), bytes.size())) {
    return step_into();
  }
  native::hide_breakpoints(d.breakpoints, *here, bytes);
  auto decoder = Decoder::create(Architecture::X86_64, Endian::Little);
  if (!decoder) {
    return step_into();
  }
  auto instruction = decoder.value().decode_one(bytes, *here);
  if (!instruction || instruction.value().classification != InstructionClass::Call) {
    return step_into();
  }
  return d.run_to(*here + instruction.value().length, "step", kStepTimeoutMs);
}

Result<bool> LocalDebugAdapter::step_out() {
  Impl& d = *impl_;
  if (auto ok = d.require_stopped("step out"); !ok) {
    return ok;
  }
  auto stack = call_stack();
  if (!stack || stack.value().size() < 2 || stack.value()[1].instruction_pointer == 0) {
    return make_error<bool>(Status::Unsupported, "debug.unsupported",
                            "could not unwind to the caller at this location");
  }
  return d.run_to(stack.value()[1].instruction_pointer, "step", kStepTimeoutMs);
}

Result<Breakpoint> LocalDebugAdapter::set_breakpoint(std::uint64_t address) {
  Impl& d = *impl_;
  for (const auto& bp : d.breakpoints) {
    if (!bp.internal && bp.info.address == address) {
      return bp.info;
    }
  }
  if (d.pid == 0) {
    return make_error<Breakpoint>(Status::InvalidInput, "debug.invalid_state",
                                  "no target is running; launch or attach first");
  }
  SoftwareBreakpoint bp;
  bp.info.id = d.next_breakpoint_id++;
  bp.info.address = address;
  bp.info.enabled = true;
  if (SoftwareBreakpoint* existing = d.breakpoint_at(address)) {
    bp.original = existing->original;
    bp.inserted = true;
  } else if (!d.insert(bp)) {
    return make_error<Breakpoint>(Status::InvalidInput, "debug.breakpoint_failed",
                                  "could not write a breakpoint at that address (unmapped?)");
  }
  d.breakpoints.push_back(bp);
  return bp.info;
}

Result<bool> LocalDebugAdapter::remove_breakpoint(std::uint64_t id_or_address) {
  Impl& d = *impl_;
  for (auto it = d.breakpoints.begin(); it != d.breakpoints.end(); ++it) {
    if (it->internal || (it->info.id != id_or_address && it->info.address != id_or_address)) {
      continue;
    }
    bool shared = false;
    for (const auto& other : d.breakpoints) {
      if (&other != &*it && other.info.address == it->info.address && other.inserted) {
        shared = true;
      }
    }
    if (!shared && d.pid != 0 && !d.uninsert(*it)) {
      return win_error("debug.breakpoint_failed", "could not restore the original bytes");
    }
    d.breakpoints.erase(it);
    return true;
  }
  return make_error<bool>(Status::InvalidInput, "debug.breakpoint_not_found",
                          "breakpoint does not exist");
}

Result<std::vector<std::byte>> LocalDebugAdapter::read_memory(std::uint64_t address,
                                                              std::size_t size) {
  Impl& d = *impl_;
  if (d.pid == 0 || d.state != SessionState::Stopped) {
    return make_error<std::vector<std::byte>>(Status::InvalidInput, "debug.invalid_state",
                                              "memory can only be read while stopped");
  }
  if (size > kMaxRead) {
    return make_error<std::vector<std::byte>>(Status::ResourceLimit, "debug.read_too_large",
                                              "memory reads are limited to 16 MiB");
  }
  std::vector<std::byte> bytes(size);
  if (size != 0 && !d.raw_read(address, bytes.data(), size)) {
    return make_error<std::vector<std::byte>>(Status::InvalidInput, "debug.memory_unreadable",
                                              "the address range is not readable in the target");
  }
  native::hide_breakpoints(d.breakpoints, address, bytes);
  return bytes;
}

Result<std::size_t> LocalDebugAdapter::write_memory(std::uint64_t address,
                                                    std::span<const std::byte> data) {
  Impl& d = *impl_;
  if (d.pid == 0 || d.state != SessionState::Stopped) {
    return make_error<std::size_t>(Status::InvalidInput, "debug.invalid_state",
                                   "memory can only be written while stopped");
  }
  if (!d.raw_write(address, data.data(), data.size())) {
    return make_error<std::size_t>(Status::InvalidInput, "debug.memory_unwritable",
                                   "the address range is not writable in the target");
  }
  const std::vector<std::byte> written(data.begin(), data.end());
  for (std::size_t index : native::absorb_write(d.breakpoints, address, written)) {
    d.raw_write(d.breakpoints[index].info.address, kTrap.data(), kTrap.size());
  }
  return data.size();
}

Result<std::vector<RegisterValue>> LocalDebugAdapter::read_registers() {
  Impl& d = *impl_;
  if (d.pid == 0 || d.state != SessionState::Stopped) {
    return make_error<std::vector<RegisterValue>>(Status::InvalidInput, "debug.invalid_state",
                                                  "registers can only be read while stopped");
  }
  CONTEXT context;
  if (!d.get_context(context)) {
    return make_error<std::vector<RegisterValue>>(Status::InternalError, "debug.registers_failed",
                                                  "GetThreadContext failed");
  }
  std::vector<RegisterValue> out;
  for (const RegisterSlot& slot : kRegisterSlots) {
    out.push_back(RegisterValue{slot.name, context.*slot.field, 8});
  }
  out.push_back(RegisterValue{"rflags", context.EFlags, 4});
  out.push_back(RegisterValue{"cs", context.SegCs, 2});
  out.push_back(RegisterValue{"ss", context.SegSs, 2});
  return out;
}

Result<bool> LocalDebugAdapter::write_register(const std::string& name, std::uint64_t value) {
  Impl& d = *impl_;
  if (auto ok = d.require_stopped("write registers"); !ok) {
    return ok;
  }
  CONTEXT context;
  if (!d.get_context(context)) {
    return win_error("debug.registers_failed", "could not read registers");
  }
  bool found = false;
  for (const RegisterSlot& slot : kRegisterSlots) {
    if (name == slot.name) {
      context.*slot.field = value;
      found = true;
    }
  }
  if (name == "rflags") {
    context.EFlags = static_cast<DWORD>(value);
    found = true;
  }
  if (!found) {
    return make_error<bool>(Status::InvalidInput, "debug.unknown_register",
                            "unknown register '" + name + "'");
  }
  if (!d.set_context(context)) {
    return win_error("debug.registers_failed", "could not write registers");
  }
  return true;
}

Result<std::vector<StackFrame>> LocalDebugAdapter::call_stack() {
  Impl& d = *impl_;
  if (d.pid == 0 || d.state != SessionState::Stopped) {
    return make_error<std::vector<StackFrame>>(Status::InvalidInput, "debug.invalid_state",
                                               "the call stack can only be read while stopped");
  }
  CONTEXT context;
  if (!d.get_context(context)) {
    return make_error<std::vector<StackFrame>>(Status::InternalError, "debug.registers_failed",
                                               "GetThreadContext failed");
  }
  auto module_of = [&](std::uint64_t address) {
    for (const auto& m : d.module_list) {
      if (address >= m.base_address &&
          address < m.base_address + std::max<std::uint64_t>(m.size, 1)) {
        return m.name;
      }
    }
    return std::string();
  };
  auto name_of = [&](std::uint64_t address, std::uint64_t static_address) {
    if (static_address != address || d.translator.runtime_base == d.translator.static_base) {
      std::string name = d.image.function_at(static_address);
      if (!name.empty()) {
        return name;
      }
    }
    if (d.symbols_ready) {
      alignas(SYMBOL_INFO) char buffer[sizeof(SYMBOL_INFO) + 256] = {};
      auto* symbol = reinterpret_cast<SYMBOL_INFO*>(buffer);
      symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
      symbol->MaxNameLen = 255;
      DWORD64 displacement = 0;
      if (SymFromAddr(d.process, address, &displacement, symbol)) {
        return std::string(symbol->Name);
      }
    }
    // A DLL DbgHelp has no symbols for: use the DLL file's own symbols.
    if (auto resolved = resolve_address(address)) {
      return resolved.value().function_name;
    }
    return std::string();
  };

  std::vector<StackFrame> frames;
  STACKFRAME64 frame{};
  frame.AddrPC.Offset = context.Rip;
  frame.AddrPC.Mode = AddrModeFlat;
  frame.AddrStack.Offset = context.Rsp;
  frame.AddrStack.Mode = AddrModeFlat;
  frame.AddrFrame.Offset = context.Rbp;
  frame.AddrFrame.Mode = AddrModeFlat;
  CONTEXT walk = context;
  while (frames.size() < kMaxFrames) {
    if (!d.symbols_ready ||
        !StackWalk64(IMAGE_FILE_MACHINE_AMD64, d.process, d.thread(), &frame, &walk, nullptr,
                     SymFunctionTableAccess64, SymGetModuleBase64, nullptr)) {
      break;
    }
    if (frame.AddrPC.Offset == 0) {
      break;
    }
    StackFrame out;
    out.index = static_cast<std::uint32_t>(frames.size());
    out.instruction_pointer = frame.AddrPC.Offset;
    out.stack_pointer = frame.AddrStack.Offset;
    out.frame_pointer = frame.AddrFrame.Offset;
    out.module_name = module_of(out.instruction_pointer);
    out.static_address = d.translator.runtime_to_static(out.instruction_pointer);
    out.function_name = name_of(out.instruction_pointer, out.static_address);
    frames.push_back(out);
  }
  if (frames.empty()) {
    StackFrame out;
    out.instruction_pointer = context.Rip;
    out.stack_pointer = context.Rsp;
    out.frame_pointer = context.Rbp;
    out.module_name = module_of(context.Rip);
    out.static_address = d.translator.runtime_to_static(context.Rip);
    out.function_name = name_of(context.Rip, out.static_address);
    frames.push_back(out);
  }
  return frames;
}

Result<std::vector<DebugThread>> LocalDebugAdapter::threads() {
  Impl& d = *impl_;
  std::vector<DebugThread> list;
  for (const auto& [id, handle] : d.thread_handles) {
    (void)handle;
    DebugThread thread;
    thread.id = id;
    thread.name = "thread " + std::to_string(id);
    thread.is_current = id == d.current_thread;
    thread.stop_reason = thread.is_current ? d.stop.reason : StopReason::None;
    list.push_back(thread);
  }
  return list;
}

Result<std::vector<DebugModule>> LocalDebugAdapter::modules() {
  Impl& d = *impl_;
  auto list = d.module_list;
  std::sort(list.begin(), list.end(), [](const DebugModule& a, const DebugModule& b) {
    return a.base_address < b.base_address;
  });
  return list;
}

Result<StopInfo> LocalDebugAdapter::poll_events() {
  Impl& d = *impl_;
  if (d.pid != 0 && d.state == SessionState::Running) {
    if (!d.wait(0)) {
      return StopInfo{};
    }
  }
  return d.stop;
}

Result<StopInfo> LocalDebugAdapter::wait_for_event(int timeout_ms) {
  Impl& d = *impl_;
  if (d.pid != 0 && d.state == SessionState::Running) {
    if (!d.wait(timeout_ms)) {
      return StopInfo{};
    }
  }
  return d.stop;
}

}  // namespace donkey::debug

#endif
