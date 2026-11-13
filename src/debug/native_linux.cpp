// Native Linux debugger: ptrace execution control for x86-64 and AArch64.
//
// Model: one traced thread (the thread that exec'd or was attached). Other
// threads of the target are listed but not individually controlled; they
// keep running while the traced thread is stopped. Software breakpoints are
// int3 (x86-64) or BRK #0 (AArch64); memory goes through /proc/<pid>/mem.

#if defined(__linux__) && (defined(__x86_64__) || defined(__aarch64__))

#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <thread>

#include "debug_internal.h"
#include "donkey/decode/decode.h"
#include "native_common.h"

namespace donkey::debug {

namespace {

using native::SoftwareBreakpoint;

#if defined(__x86_64__)
using NativeRegs = user_regs_struct;
constexpr std::array<std::byte, 1> kTrap{std::byte{0xcc}};
constexpr Architecture kHostArch = Architecture::X86_64;
#else
using NativeRegs = user_regs_struct;  // glibc <sys/user.h>: regs[31], sp, pc, pstate
// BRK #0, little endian.
constexpr std::array<std::byte, 4> kTrap{std::byte{0x00}, std::byte{0x00}, std::byte{0x20},
                                         std::byte{0xd4}};
constexpr Architecture kHostArch = Architecture::AArch64;
#endif

constexpr int kStepTimeoutMs = 2000;
constexpr int kEntryTimeoutMs = 10000;
constexpr std::size_t kMaxFrames = 64;
constexpr std::size_t kMaxRead = 16 * 1024 * 1024;

// The kernel register structs use `unsigned long long`, which is distinct
// from std::uint64_t (`unsigned long`) on LP64 Linux.
using RegWord = unsigned long long;
static_assert(sizeof(RegWord) == 8);

struct RegisterSlot {
  const char* name;
  RegWord NativeRegs::* field;
};

#if defined(__x86_64__)
constexpr RegisterSlot kRegisterSlots[] = {
    {"rax", &NativeRegs::rax},         {"rbx", &NativeRegs::rbx},
    {"rcx", &NativeRegs::rcx},         {"rdx", &NativeRegs::rdx},
    {"rsi", &NativeRegs::rsi},         {"rdi", &NativeRegs::rdi},
    {"rbp", &NativeRegs::rbp},         {"rsp", &NativeRegs::rsp},
    {"r8", &NativeRegs::r8},           {"r9", &NativeRegs::r9},
    {"r10", &NativeRegs::r10},         {"r11", &NativeRegs::r11},
    {"r12", &NativeRegs::r12},         {"r13", &NativeRegs::r13},
    {"r14", &NativeRegs::r14},         {"r15", &NativeRegs::r15},
    {"rip", &NativeRegs::rip},         {"rflags", &NativeRegs::eflags},
    {"cs", &NativeRegs::cs},           {"ss", &NativeRegs::ss},
    {"ds", &NativeRegs::ds},           {"es", &NativeRegs::es},
    {"fs", &NativeRegs::fs},           {"gs", &NativeRegs::gs},
    {"fs_base", &NativeRegs::fs_base}, {"gs_base", &NativeRegs::gs_base},
};
RegWord& reg_pc(NativeRegs& r) {
  return r.rip;
}
std::uint64_t reg_sp(const NativeRegs& r) {
  return r.rsp;
}
std::uint64_t reg_fp(const NativeRegs& r) {
  return r.rbp;
}
#else
RegWord& reg_pc(NativeRegs& r) {
  return r.pc;
}
std::uint64_t reg_sp(const NativeRegs& r) {
  return r.sp;
}
std::uint64_t reg_fp(const NativeRegs& r) {
  return r.regs[29];
}
#endif

Result<bool> unsupported(const std::string& what) {
  return make_error<bool>(Status::Unsupported, "debug.unsupported", what);
}

Result<bool> errno_error(const std::string& code, const std::string& what) {
  const int saved = errno;
  const Status status =
      (saved == EPERM || saved == EACCES) ? Status::PermissionDenied : Status::InternalError;
  return make_error<bool>(status, code, what + ": " + std::strerror(saved));
}

struct Mapping {
  std::uint64_t start = 0;
  std::uint64_t end = 0;
  std::uint64_t offset = 0;
  bool executable = false;
  std::string path;
};

std::vector<Mapping> read_maps(pid_t pid) {
  std::vector<Mapping> maps;
  std::ifstream in("/proc/" + std::to_string(pid) + "/maps");
  std::string line;
  while (std::getline(in, line)) {
    std::istringstream fields(line);
    std::string range, perms, offset, device, inode, path;
    fields >> range >> perms >> offset >> device >> inode;
    std::getline(fields, path);
    const auto first = path.find_first_not_of(' ');
    path = first == std::string::npos ? std::string() : path.substr(first);
    const auto dash = range.find('-');
    if (dash == std::string::npos) {
      continue;
    }
    Mapping m;
    m.start = std::strtoull(range.substr(0, dash).c_str(), nullptr, 16);
    m.end = std::strtoull(range.substr(dash + 1).c_str(), nullptr, 16);
    m.offset = std::strtoull(offset.c_str(), nullptr, 16);
    m.executable = perms.size() > 2 && perms[2] == 'x';
    m.path = path;
    maps.push_back(std::move(m));
  }
  return maps;
}

std::string canonical_or_self(const std::string& path) {
  std::error_code ec;
  auto canonical = std::filesystem::canonical(path, ec);
  return ec ? path : canonical.string();
}

/// The value of a register of this host, by the name read_registers gives it. Empty when the host
/// has no register of that name.
std::optional<std::uint64_t> register_value(const NativeRegs& regs, const std::string& name) {
#if defined(__x86_64__)
  for (const RegisterSlot& slot : kRegisterSlots) {
    if (name == slot.name) {
      return static_cast<std::uint64_t>(regs.*slot.field);
    }
  }
#else
  if (name == "sp") {
    return static_cast<std::uint64_t>(regs.sp);
  }
  if (name == "pc") {
    return static_cast<std::uint64_t>(regs.pc);
  }
  if (name == "pstate") {
    return static_cast<std::uint64_t>(regs.pstate);
  }
  if (name.size() >= 2 && name[0] == 'x') {
    const int index = std::atoi(name.c_str() + 1);
    if (index >= 0 && index < 31 && name == "x" + std::to_string(index)) {
      return static_cast<std::uint64_t>(regs.regs[index]);
    }
  }
#endif
  return std::nullopt;
}

bool is_host_register(const std::string& name) {
  return register_value(NativeRegs{}, name).has_value();
}

}  // namespace

struct LocalDebugAdapter::Impl {
  SessionState state = SessionState::Disconnected;
  AddressTranslator translator;
  pid_t pid = -1;
  int mem_fd = -1;
  bool launched = false;  ///< we own the process: kill it on teardown
  std::string executable;
  native::StaticImage image;
  std::vector<SoftwareBreakpoint> breakpoints;
  std::uint64_t next_breakpoint_id = 1;
  /// What the event loop does after a status it handled without reporting a stop (G14-T5).
  enum class After : std::uint8_t { Report, PassOver, Resume };
  After after = After::Report;
  std::uint64_t pass_address = 0;  ///< the breakpoint a PassOver steps off
  bool silent_step = false;        ///< the step in progress passes over a breakpoint silently
  StopInfo stop;
  // Threads. The session is all-stop: when one thread stops, every other
  // traced thread is stopped before the stop is reported, and a resume
  // continues them all. New threads are traced through PTRACE_O_TRACECLONE.
  pid_t current = -1;                ///< the thread the session reports and steps
  std::set<pid_t> tids;              ///< every traced thread, leader included
  std::set<pid_t> stopped;           ///< traced threads in a ptrace stop
  std::map<pid_t, int> pending;      ///< signal to deliver to a thread on resume
  std::set<pid_t> sigstop_expected;  ///< threads with a SIGSTOP of ours still to swallow
  bool pause_requested = false;
  bool stepping = false;
  std::uint64_t page_size = static_cast<std::uint64_t>(::sysconf(_SC_PAGESIZE));

  // Hardware watchpoints (x86-64). DR0-DR3 hold four addresses, and DR7 enables each slot and
  // sets its size and access type. Slot i is watches[i]. A traced thread has its own debug
  // registers, and a new thread starts without them, so each thread is armed whenever it stops
  // and whenever the set of watches changes.
  static constexpr std::size_t kWatchSlots = 4;
  std::vector<Watchpoint> watches;
  std::uint64_t next_watch_id = 1;
  /// What a trap with a watch bit set means: the first hit whose condition holds stops the target
  /// (`stop`), and a trap whose hits all have false conditions is passed over (`passed`).
  struct WatchOutcome {
    std::optional<StopInfo> stop;
    bool passed = false;
  };

#if defined(__x86_64__)
  static std::uintptr_t debugreg_offset(int index) {
    return offsetof(struct user, u_debugreg) +
           sizeof(unsigned long) * static_cast<std::size_t>(index);
  }

  static bool poke_debugreg(pid_t thread, int index, unsigned long value) {
    return ::ptrace(PTRACE_POKEUSER, thread, reinterpret_cast<void*>(debugreg_offset(index)),
                    reinterpret_cast<void*>(value)) == 0;
  }

  static bool peek_debugreg(pid_t thread, int index, unsigned long& value) {
    errno = 0;
    const long word =
        ::ptrace(PTRACE_PEEKUSER, thread, reinterpret_cast<void*>(debugreg_offset(index)), nullptr);
    if (word == -1 && errno != 0) {
      return false;
    }
    value = static_cast<unsigned long>(word);
    return true;
  }

  /// Programs DR0-DR3 and DR7 of one stopped thread from `watches`, and clears DR6.
  bool arm_thread(pid_t thread) const {
    unsigned long dr7 = 0;
    for (std::size_t slot = 0; slot < watches.size() && slot < kWatchSlots; ++slot) {
      const Watchpoint& watch = watches[slot];
      const int index = static_cast<int>(slot);
      if (!poke_debugreg(thread, index, static_cast<unsigned long>(watch.address))) {
        return false;
      }
      // DR7: the local enable L<n> is bit 2n; the access R/W<n> is bits 16+4n (01 for writes,
      // 11 for reads or writes); the size LEN<n> is bits 18+4n (00, 01, 11 and 10 for 1, 2, 4
      // and 8 bytes).
      const unsigned long access = watch.kind == WatchKind::Write ? 0x1UL : 0x3UL;
      unsigned long size = 0x3UL;
      if (watch.length == 1) {
        size = 0x0UL;
      } else if (watch.length == 2) {
        size = 0x1UL;
      } else if (watch.length == 8) {
        size = 0x2UL;
      }
      dr7 |= (1UL << (2 * index)) | (access << (16 + 4 * index)) | (size << (18 + 4 * index));
    }
    return poke_debugreg(thread, 7, dr7) && poke_debugreg(thread, 6, 0);
  }

  /// Whether a watch's condition holds at this access. An unconditional watch always does. A
  /// condition that cannot be evaluated also does, and `error` says why, so that the stop is never
  /// silent. The condition is read from its text, which was checked when the watch was set.
  bool watch_holds(const Watchpoint& watch, const NativeRegs& regs, bool have_regs,
                   std::string& error) const {
    if (watch.condition.empty()) {
      return true;
    }
    auto parsed = debug::parse_break_condition(watch.condition);
    if (!parsed) {
      error = "its condition could not be read: " + parsed.diagnostic().message;
      return true;
    }
    if (!have_regs) {
      error = "its condition could not be evaluated: the registers could not be read";
      return true;
    }
    const std::optional<std::uint64_t> operand = condition_operand(parsed.value(), regs);
    if (!operand) {
      if (parsed.value().memory) {
        char address_text[32];
        std::snprintf(address_text, sizeof(address_text), "0x%llx",
                      static_cast<unsigned long long>(parsed.value().address));
        error = std::string("its condition could not be evaluated: the word at ") + address_text +
                " could not be read";
      } else {
        error = "its condition could not be evaluated: no register named `" +
                parsed.value().register_name + "`";
      }
      return true;
    }
    return condition_holds(parsed.value(), *operand);
  }

  /// Sorts a trap on `thread` with watch bits set in DR6, and clears DR6. The first hit whose
  /// condition holds is counted and reported. When there are hits and none of their conditions
  /// holds, the trap is passed over: no hit is counted and nothing is reported.
  WatchOutcome watch_outcome(pid_t thread, std::uint64_t pc, const NativeRegs& regs,
                             bool have_regs) {
    WatchOutcome outcome;
    if (watches.empty()) {
      return outcome;
    }
    unsigned long status = 0;
    if (!peek_debugreg(thread, 6, status) || (status & 0xfUL) == 0) {
      return outcome;
    }
    poke_debugreg(thread, 6, 0);
    for (std::size_t slot = 0; slot < watches.size() && slot < kWatchSlots; ++slot) {
      if ((status & (1UL << slot)) == 0) {
        continue;
      }
      Watchpoint& watch = watches[slot];
      std::string error;
      if (!watch_holds(watch, regs, have_regs, error)) {
        continue;
      }
      ++watch.hit_count;
      char address_text[32];
      std::snprintf(address_text, sizeof(address_text), "0x%llx",
                    static_cast<unsigned long long>(watch.address));
      std::string description =
          "watchpoint " + std::to_string(watch.id) +
          " hit: " + (watch.kind == WatchKind::Write ? "write" : "read or write") + " of " +
          std::to_string(watch.length) + " bytes at " + address_text;
      if (!error.empty()) {
        description += " (" + error + ")";
      }
      outcome.stop = StopInfo{StopReason::Watchpoint, static_cast<std::uint64_t>(thread), pc,
                              std::move(description), 0};
      return outcome;
    }
    outcome.passed = true;
    return outcome;
  }
#else
  bool arm_thread(pid_t) const { return true; }
  WatchOutcome watch_outcome(pid_t, std::uint64_t, const NativeRegs&, bool) { return {}; }
#endif

  /// Arms every stopped thread. Called only while the target is stopped.
  bool arm_all() const {
    bool ok = true;
    for (pid_t thread : tids) {
      if (stopped.count(thread) != 0) {
        ok = arm_thread(thread) && ok;
      }
    }
    return ok;
  }

  /// A thread that reports a stop gets the current watches, so one that was created while the
  /// target ran is covered from its first instruction.
  void arm_stopped_thread(pid_t thread) const {
    if (!watches.empty()) {
      arm_thread(thread);
    }
  }

  ~Impl() { teardown(); }

  // ---- low level ---------------------------------------------------------

  [[nodiscard]] pid_t cur() const { return current > 0 ? current : pid; }

  static bool get_regs_of(pid_t thread, NativeRegs& regs) {
    iovec io{&regs, sizeof(regs)};
    return ::ptrace(PTRACE_GETREGSET, thread, reinterpret_cast<void*>(NT_PRSTATUS), &io) == 0;
  }
  static bool set_regs_of(pid_t thread, NativeRegs& regs) {
    iovec io{&regs, sizeof(regs)};
    return ::ptrace(PTRACE_SETREGSET, thread, reinterpret_cast<void*>(NT_PRSTATUS), &io) == 0;
  }
  bool get_regs(NativeRegs& regs) const { return get_regs_of(cur(), regs); }
  bool set_regs(NativeRegs& regs) const { return set_regs_of(cur(), regs); }

  // ---- threads -----------------------------------------------------------

  int take_pending(pid_t thread) {
    const auto it = pending.find(thread);
    if (it == pending.end()) {
      return 0;
    }
    const int sig = it->second;
    pending.erase(it);
    return sig;
  }

  bool resume_thread(pid_t thread) {
    const int sig = take_pending(thread);
    if (::ptrace(PTRACE_CONT, thread, nullptr,
                 reinterpret_cast<void*>(static_cast<std::intptr_t>(sig))) != 0) {
      return false;
    }
    stopped.erase(thread);
    return true;
  }

  void forget_thread(pid_t thread) {
    tids.erase(thread);
    stopped.erase(thread);
    pending.erase(thread);
    sigstop_expected.erase(thread);
    if (current == thread) {
      current = pid;
    }
  }

  static bool is_event(int status, int event) { return (status >> 16) == event; }

  /// A traced thread called clone(): trace the new thread. It starts with a
  /// SIGSTOP, which is swallowed when it arrives.
  void note_clone(pid_t parent) {
    unsigned long message = 0;
    if (::ptrace(PTRACE_GETEVENTMSG, parent, nullptr, &message) == 0 && message != 0) {
      const auto thread = static_cast<pid_t>(message);
      tids.insert(thread);
      sigstop_expected.insert(thread);
    }
  }

  /// A thread trapped on one of our breakpoints while the others were being
  /// stopped: move it back onto the trap so it reports the hit when resumed.
  /// (AArch64's BRK leaves the PC on the trap already.)
  void rewind_trap(pid_t thread) {
    if (kTrap.size() != 1) {
      return;
    }
    NativeRegs regs{};
    if (!get_regs_of(thread, regs)) {
      return;
    }
    const std::uint64_t trap = reg_pc(regs) - 1;
    if (SoftwareBreakpoint* bp = breakpoint_at(trap); bp != nullptr && bp->inserted) {
      reg_pc(regs) = trap;
      set_regs_of(thread, regs);
    }
  }

  /// Record what a thread reported while it was being stopped, other than
  /// the SIGSTOP we sent (which then stays pending and is swallowed later).
  void absorb_side_stop(pid_t thread, int status) {
    const int sig = WSTOPSIG(status);
    if (sig == SIGTRAP && is_event(status, PTRACE_EVENT_CLONE)) {
      note_clone(thread);
    } else if (sig == SIGSTOP && sigstop_expected.count(thread) != 0) {
      sigstop_expected.erase(thread);
      arm_stopped_thread(thread);
    } else if (sig == SIGTRAP) {
      rewind_trap(thread);
    } else {
      pending[thread] = sig;
    }
  }

  /// All-stop: stop every traced thread other than `current`. Bounded.
  void stop_others() {
    for (pid_t thread : std::vector<pid_t>(tids.begin(), tids.end())) {
      if (thread != current && stopped.count(thread) == 0 && sigstop_expected.count(thread) == 0 &&
          ::syscall(SYS_tgkill, pid, thread, SIGSTOP) == 0) {
        sigstop_expected.insert(thread);
      }
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (std::chrono::steady_clock::now() < deadline) {
      bool all_stopped = true;
      for (pid_t thread : std::vector<pid_t>(tids.begin(), tids.end())) {
        if (thread == current || stopped.count(thread) != 0) {
          continue;
        }
        all_stopped = false;
        int status = 0;
        const pid_t result = ::waitpid(thread, &status, WNOHANG | __WALL);
        if (result == 0) {
          continue;
        }
        if (result < 0 || WIFEXITED(status) || WIFSIGNALED(status)) {
          if (thread != pid) {
            forget_thread(thread);
          }
          continue;
        }
        if (WIFSTOPPED(status)) {
          stopped.insert(thread);
          absorb_side_stop(thread, status);
        }
      }
      if (all_stopped) {
        return;
      }
      std::this_thread::sleep_for(std::chrono::microseconds(200));
    }
  }

  /// Let threads that still have one of our SIGSTOPs pending take it now, so
  /// it cannot stop the process after a detach. Bounded.
  void drain_expected_sigstops() {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!sigstop_expected.empty() && std::chrono::steady_clock::now() < deadline) {
      for (pid_t thread : std::vector<pid_t>(sigstop_expected.begin(), sigstop_expected.end())) {
        if (stopped.count(thread) != 0) {
          if (::ptrace(PTRACE_CONT, thread, nullptr, nullptr) != 0) {
            forget_thread(thread);
            continue;
          }
          stopped.erase(thread);
        }
        int status = 0;
        const pid_t result = ::waitpid(thread, &status, WNOHANG | __WALL);
        if (result == 0) {
          continue;
        }
        if (result < 0 || WIFEXITED(status) || WIFSIGNALED(status)) {
          forget_thread(thread);
          continue;
        }
        if (WIFSTOPPED(status)) {
          stopped.insert(thread);
          absorb_side_stop(thread, status);
        }
      }
      std::this_thread::sleep_for(std::chrono::microseconds(200));
    }
  }

  /// Attach every thread of the process that is not traced yet. Returns how
  /// many were attached; each stops with a SIGSTOP that is swallowed.
  int attach_untraced_threads() {
    int attached = 0;
    std::error_code ec;
    for (const auto& entry :
         std::filesystem::directory_iterator("/proc/" + std::to_string(pid) + "/task", ec)) {
      const auto thread =
          static_cast<pid_t>(std::strtol(entry.path().filename().c_str(), nullptr, 10));
      if (thread <= 0 || tids.count(thread) != 0) {
        continue;
      }
      if (::ptrace(PTRACE_ATTACH, thread, nullptr, nullptr) == 0) {
        tids.insert(thread);
        sigstop_expected.insert(thread);
        ++attached;
      }
    }
    return attached;
  }

  void set_thread_options(long options) const {
    for (pid_t thread : tids) {
      ::ptrace(PTRACE_SETOPTIONS, thread, nullptr, reinterpret_cast<void*>(options));
    }
  }
  std::optional<std::uint64_t> pc() const {
    NativeRegs regs{};
    if (!get_regs(regs)) {
      return std::nullopt;
    }
    return reg_pc(regs);
  }

  bool raw_read(std::uint64_t address, void* out, std::size_t size) const {
    if (mem_fd < 0 || address > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max())) {
      return false;
    }
    auto* bytes = static_cast<char*>(out);
    std::size_t done = 0;
    while (done < size) {
      const ssize_t n =
          ::pread(mem_fd, bytes + done, size - done, static_cast<off_t>(address + done));
      if (n <= 0) {
        if (n < 0 && errno == EINTR) {
          continue;
        }
        return false;
      }
      done += static_cast<std::size_t>(n);
    }
    return true;
  }
  bool raw_write(std::uint64_t address, const void* data, std::size_t size) const {
    if (mem_fd < 0 || address > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max())) {
      return false;
    }
    const auto* bytes = static_cast<const char*>(data);
    std::size_t done = 0;
    while (done < size) {
      const ssize_t n =
          ::pwrite(mem_fd, bytes + done, size - done, static_cast<off_t>(address + done));
      if (n <= 0) {
        if (n < 0 && errno == EINTR) {
          continue;
        }
        return false;
      }
      done += static_cast<std::size_t>(n);
    }
    return true;
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

  /// Remove temporary breakpoints. A user breakpoint at the same address
  /// shared the patched bytes, so it is re-armed afterwards.
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

  void open_memory() {
    close_memory();
    mem_fd = ::open(("/proc/" + std::to_string(pid) + "/mem").c_str(), O_RDWR | O_CLOEXEC);
  }
  void close_memory() {
    if (mem_fd >= 0) {
      ::close(mem_fd);
      mem_fd = -1;
    }
  }

  void forget_process() {
    close_memory();
    pid = -1;
    current = -1;
    tids.clear();
    stopped.clear();
    pending.clear();
    sigstop_expected.clear();
    launched = false;
    breakpoints.erase(std::remove_if(breakpoints.begin(), breakpoints.end(),
                                     [](const SoftwareBreakpoint& bp) { return bp.internal; }),
                      breakpoints.end());
    for (auto& bp : breakpoints) {
      bp.inserted = false;
    }
  }

  void teardown() {
    watches.clear();
    if (pid <= 0) {
      return;
    }
    if (launched) {
      ::kill(pid, SIGKILL);
      int status = 0;
      // Reap the other threads first: the leader is reported last.
      for (pid_t thread : std::vector<pid_t>(tids.begin(), tids.end())) {
        if (thread != pid) {
          while (::waitpid(thread, &status, __WALL) < 0 && errno == EINTR) {
          }
        }
      }
      while (::waitpid(pid, &status, __WALL) < 0 && errno == EINTR) {
      }
    } else {
      (void)detach_now();
    }
    forget_process();
  }

  // ---- translator --------------------------------------------------------

  /// Runtime base = start of the executable's mapping of file offset 0;
  /// static base = page-aligned lowest segment address of the file.
  void update_translator() {
    translator = AddressTranslator{};
    if (!image.image) {
      return;
    }
    const std::string exe = canonical_or_self(executable);
    std::optional<std::uint64_t> runtime_base;
    std::uint64_t runtime_end = 0;
    for (const Mapping& m : read_maps(pid)) {
      if (m.path != exe) {
        continue;
      }
      if (m.offset == 0 && (!runtime_base || m.start < *runtime_base)) {
        runtime_base = m.start;
      }
      runtime_end = std::max(runtime_end, m.end);
    }
    if (!runtime_base) {
      return;
    }
    translator.runtime_base = *runtime_base;
    translator.static_base = image.lowest;
    translator.size =
        std::max<std::uint64_t>(image.highest - image.lowest, runtime_end - *runtime_base);
  }

  // ---- waiting -----------------------------------------------------------

  /// Wait up to `timeout_ms` (negative: forever) for the traced thread to
  /// change state and translate that into `stop`. Returns false on timeout.
  bool wait(int timeout_ms) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (true) {
      for (pid_t thread : std::vector<pid_t>(tids.begin(), tids.end())) {
        if (pid <= 0) {
          return true;
        }
        // Stopped threads are polled too: they report nothing more until
        // resumed, except dying (SIGKILL from terminate()).
        int status = 0;
        const pid_t result = ::waitpid(thread, &status, WNOHANG | __WALL);
        if (result == thread) {
          if (process_event(thread, status)) {
            return true;
          }
          continue;
        }
        if (result < 0 && errno != EINTR) {
          if (thread != pid) {
            forget_thread(thread);
            continue;
          }
          stop = StopInfo{StopReason::Exited, static_cast<std::uint64_t>(pid), 0,
                          std::string("lost the target: ") + std::strerror(errno), 0};
          state = SessionState::Exited;
          forget_process();
          return true;
        }
      }
      if (pid <= 0 || tids.empty()) {
        return true;
      }
      if (timeout_ms >= 0 && std::chrono::steady_clock::now() >= deadline) {
        return false;
      }
      std::this_thread::sleep_for(std::chrono::microseconds(500));
    }
  }

  /// One wait status from `thread`. Returns true when the session stopped or
  /// ended (and `stop` says why); false for events handled internally.
  bool process_event(pid_t thread, int status) {
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      if (thread == pid) {
        current = pid;
        handle_status(status);
        return true;
      }
      forget_thread(thread);
      return false;
    }
    if (!WIFSTOPPED(status)) {
      return false;
    }
    stopped.insert(thread);
    const int sig = WSTOPSIG(status);
    if (sig == SIGTRAP && is_event(status, PTRACE_EVENT_CLONE)) {
      note_clone(thread);
      if (stepping && thread == current) {
        if (::ptrace(PTRACE_SINGLESTEP, thread, nullptr, nullptr) == 0) {
          stopped.erase(thread);
        }
      } else if (state == SessionState::Running) {
        resume_thread(thread);
      }
      return false;
    }
    if (sig == SIGSTOP && sigstop_expected.count(thread) != 0) {
      sigstop_expected.erase(thread);
      arm_stopped_thread(thread);
      if (state == SessionState::Running && !stepping) {
        resume_thread(thread);
      }
      return false;
    }
    if (sig == SIGTRAP && is_event(status, PTRACE_EVENT_EXEC)) {
      // After exec only the thread group leader is left.
      for (pid_t other : std::vector<pid_t>(tids.begin(), tids.end())) {
        if (other != pid) {
          forget_thread(other);
        }
      }
      thread = pid;
      stopped.insert(pid);
    }
    if (stepping && thread != current) {
      // Only the stepping thread runs during a step; keep this for later.
      absorb_side_stop(thread, status);
      return false;
    }
    current = thread;
    handle_status(status);
    switch (after) {
      case After::PassOver:
        after = After::Report;
        stop_others();
        // The step's trap comes next, and nothing is reported until then.
        return !begin_pass_over(pass_address);
      case After::Resume:
        after = After::Report;
        return !resume_after_silent_step();
      case After::Report:
        break;
    }
    if (pid > 0 && state == SessionState::Stopped) {
      stop_others();
    }
    return true;
  }

  void handle_status(int status) {
    const auto tid = static_cast<std::uint64_t>(cur());
    if (WIFEXITED(status)) {
      stop = StopInfo{StopReason::Exited, tid, 0,
                      "process exited with code " + std::to_string(WEXITSTATUS(status)),
                      WEXITSTATUS(status)};
      state = SessionState::Exited;
      forget_process();
      return;
    }
    if (WIFSIGNALED(status)) {
      stop = StopInfo{StopReason::Exited, tid, 0,
                      std::string("process killed by signal ") + strsignal(WTERMSIG(status)),
                      128 + WTERMSIG(status)};
      state = SessionState::Exited;
      forget_process();
      return;
    }
    if (!WIFSTOPPED(status)) {
      return;
    }
    state = SessionState::Stopped;
    const int sig = WSTOPSIG(status);
    const bool was_stepping = stepping;
    stepping = false;
    // A step past a breakpoint whose condition is false ends here, whatever stopped it: the
    // breakpoints go back in before anything is reported.
    const bool was_silent = silent_step;
    silent_step = false;
    if (was_silent) {
      reinsert_enabled();
    }
    NativeRegs regs{};
    const bool have_regs = get_regs(regs);
    std::uint64_t at = have_regs ? reg_pc(regs) : 0;

    if (sig == SIGTRAP) {
      const WatchOutcome watch = watch_outcome(static_cast<pid_t>(tid), at, regs, have_regs);
      if (watch.stop) {
        drop_internal_breakpoints();
        stop = *watch.stop;
        return;
      }
      if (watch.passed && !was_stepping) {
        // Every hit's condition is false. A watch trap follows the store, so nothing needs to be
        // stepped off: the target runs on. A user single step that also hit a watch falls through
        // and is reported as the step it is.
        after = After::Resume;
        return;
      }
      if (was_silent) {
        after = After::Resume;  // the step is done: the target runs on
        return;
      }
      // A software breakpoint traps after the int3 on x86 and at the BRK on
      // AArch64.
      const std::uint64_t trap_address = kTrap.size() == 1 ? at - 1 : at;
      SoftwareBreakpoint* bp = breakpoint_at(trap_address);
      if (bp != nullptr && !was_stepping) {
        if (have_regs && trap_address != at) {
          reg_pc(regs) = trap_address;
          set_regs(regs);
        }
        at = trap_address;
        // An internal breakpoint (a step-over or run-to target) here is reported as itself.
        const SoftwareBreakpoint* internal_here = nullptr;
        for (const auto& candidate : breakpoints) {
          if (candidate.info.address == at && candidate.internal) {
            internal_here = &candidate;
            break;
          }
        }
        const bool internal_only = internal_here != nullptr;
        const std::string reason_text =
            internal_here != nullptr ? internal_here->tag : std::string();
        // A trap whose user breakpoints all have false conditions is passed over: no hit is
        // counted and nothing is reported. The event loop steps the thread off the breakpoint.
        const TrapVerdict verdict = trap_verdict(at, regs, have_regs);
        if (verdict.pass) {
          after = After::PassOver;
          pass_address = at;
          return;
        }
        // Count the hit on every user breakpoint here whose condition holds.
        bool user_hit = false;
        for (auto& candidate : breakpoints) {
          if (candidate.info.address == at && !candidate.internal) {
            std::string ignored;
            if (breakpoint_holds(candidate, regs, have_regs, ignored)) {
              ++candidate.info.hit_count;
              user_hit = true;
            }
          }
        }
        StopReason reason = StopReason::Breakpoint;
        std::string description = "breakpoint hit";
        if (!verdict.error.empty()) {
          description += " (" + verdict.error + ")";
        }
        if (!user_hit && internal_only) {
          reason = reason_text == "entry" ? StopReason::Entrypoint : StopReason::SingleStep;
          description = reason_text == "entry" ? "stopped at program entry" : "step completed";
        }
        drop_internal_breakpoints();
        stop = StopInfo{reason, tid, at, description, 0};
        return;
      }
      if (was_stepping) {
        stop = StopInfo{StopReason::SingleStep, tid, at, "single step", 0};
        return;
      }
      stop = StopInfo{StopReason::Signal, tid, at, "SIGTRAP", 0};
      return;
    }
    if (sig == SIGSTOP && pause_requested) {
      pause_requested = false;
      stop = StopInfo{StopReason::UserPause, tid, at, "paused", 0};
      return;
    }
    // Any other signal belongs to the target; deliver it when resumed.
    pending[cur()] = sig;
    stop = StopInfo{StopReason::Signal, tid, at, std::string("signal ") + strsignal(sig), sig};
  }

  // ---- execution control -------------------------------------------------

  /// Reinserts every enabled breakpoint that is not in memory.
  void reinsert_enabled() {
    for (auto& candidate : breakpoints) {
      if (candidate.info.enabled && !candidate.inserted) {
        insert(candidate);
      }
    }
  }

  /// The value a condition compares now: a register, or the 8-byte word at its address. Empty when
  /// it cannot be read.
  std::optional<std::uint64_t> condition_operand(const BreakCondition& condition,
                                                 const NativeRegs& regs) const {
    if (!condition.memory) {
      return register_value(regs, condition.register_name);
    }
    std::uint64_t word = 0;
    if (!raw_read(condition.address, &word, sizeof(word))) {
      return std::nullopt;
    }
    return word;
  }

  /// Whether a user breakpoint stops the target at this hit. An unconditional one always does. A
  /// condition that cannot be evaluated also does, and `error` says why, so that the stop is never
  /// silent.
  bool breakpoint_holds(const SoftwareBreakpoint& candidate, const NativeRegs& regs, bool have_regs,
                        std::string& error) const {
    if (!candidate.condition) {
      return true;
    }
    if (!have_regs) {
      error = "its condition could not be evaluated: the registers could not be read";
      return true;
    }
    const std::optional<std::uint64_t> operand = condition_operand(*candidate.condition, regs);
    if (!operand) {
      if (candidate.condition->memory) {
        char address_text[32];
        std::snprintf(address_text, sizeof(address_text), "0x%llx",
                      static_cast<unsigned long long>(candidate.condition->address));
        error = std::string("its condition could not be evaluated: the word at ") + address_text +
                " could not be read";
      } else {
        error = "its condition could not be evaluated: no register named `" +
                candidate.condition->register_name + "`";
      }
      return true;
    }
    return condition_holds(*candidate.condition, *operand);
  }

  struct TrapVerdict {
    bool pass = false;  ///< no user breakpoint here stops the target: the trap is passed over
    std::string error;  ///< why a breakpoint here stops although its condition could not be read
  };

  /// How a trap at `address` is treated. It is passed over only when it has user breakpoints, none
  /// of them internal, and every one of their conditions is false.
  TrapVerdict trap_verdict(std::uint64_t address, const NativeRegs& regs, bool have_regs) const {
    TrapVerdict verdict;
    bool any_user = false;
    bool any_holds = false;
    for (const SoftwareBreakpoint& candidate : breakpoints) {
      if (candidate.info.address != address) {
        continue;
      }
      if (candidate.internal) {
        return verdict;  // an internal breakpoint here is always reported
      }
      any_user = true;
      std::string error;
      if (breakpoint_holds(candidate, regs, have_regs, error)) {
        any_holds = true;
      }
      if (!error.empty()) {
        verdict.error = error;
      }
    }
    verdict.pass = any_user && !any_holds;
    return verdict;
  }

  /// Starts the single step that moves the trapping thread off a breakpoint whose condition is
  /// false. Every other thread is stopped by now. The step's trap comes back through handle_status,
  /// which reinserts the breakpoints and resumes the target. Returns false when the step could not
  /// start, and `stop` then says so.
  bool begin_pass_over(std::uint64_t address) {
    if (SoftwareBreakpoint* bp = breakpoint_at(address)) {
      uninsert(*bp);
    }
    const pid_t thread = cur();
    const int sig = take_pending(thread);
    stepping = true;
    silent_step = true;
    if (::ptrace(PTRACE_SINGLESTEP, thread, nullptr,
                 reinterpret_cast<void*>(static_cast<std::intptr_t>(sig))) != 0) {
      stepping = false;
      silent_step = false;
      reinsert_enabled();
      stop =
          StopInfo{StopReason::Breakpoint, static_cast<std::uint64_t>(thread), address,
                   "a breakpoint's condition is false, but the target could not step past it", 0};
      return false;
    }
    stopped.erase(thread);
    state = SessionState::Running;
    return true;
  }

  /// The silent step is done: every breakpoint goes back in, and every thread runs on. Returns
  /// false, with `stop` set, when the current thread cannot be resumed.
  bool resume_after_silent_step() {
    reinsert_enabled();
    const pid_t thread = cur();
    if (!resume_thread(thread)) {
      stop = StopInfo{StopReason::Breakpoint, static_cast<std::uint64_t>(thread), 0,
                      "could not resume the target after a breakpoint whose condition is false", 0};
      state = SessionState::Stopped;
      return false;
    }
    for (pid_t other : std::vector<pid_t>(stopped.begin(), stopped.end())) {
      resume_thread(other);  // a thread that just exited cannot be resumed
    }
    state = SessionState::Running;
    stop = StopInfo{};
    return true;
  }

  /// Execute exactly one instruction from the current PC, stepping over a
  /// breakpoint that sits there. Leaves `stop` describing the result.
  bool single_step(int timeout_ms) {
    auto here = pc();
    if (!here) {
      return false;
    }
    SoftwareBreakpoint* bp = breakpoint_at(*here);
    if (bp != nullptr) {
      uninsert(*bp);
    }
    stepping = true;
    const pid_t thread = cur();
    const int sig = take_pending(thread);
    if (::ptrace(PTRACE_SINGLESTEP, thread, nullptr,
                 reinterpret_cast<void*>(static_cast<std::intptr_t>(sig))) != 0) {
      stepping = false;
      return false;
    }
    stopped.erase(thread);
    state = SessionState::Running;
    const bool finished = wait(timeout_ms);
    if (pid > 0 && state == SessionState::Stopped) {
      reinsert_enabled();
    }
    return finished;
  }

  Result<bool> continue_running() {
    auto here = pc();
    if (here && breakpoint_at(*here) != nullptr) {
      // Step off the breakpoint first so it stays armed for the next pass.
      single_step(kStepTimeoutMs);
      if (pid <= 0 || state != SessionState::Stopped) {
        return true;  // exited or still running the stepped instruction
      }
      if (stop.reason == StopReason::Breakpoint || stop.reason == StopReason::Signal) {
        return true;  // something more interesting happened during the step
      }
    }
    // Resume the current thread first, then every other stopped thread.
    if (!resume_thread(cur())) {
      return errno_error("debug.resume_failed", "could not resume the target");
    }
    for (pid_t thread : std::vector<pid_t>(stopped.begin(), stopped.end())) {
      resume_thread(thread);  // a thread that just exited cannot be resumed
    }
    state = SessionState::Running;
    stop = StopInfo{};
    return true;
  }

  Result<bool> run_to(std::uint64_t address, const char* tag, int timeout_ms) {
    SoftwareBreakpoint temp;
    temp.info.address = address;
    temp.internal = true;
    temp.tag = tag;
    if (SoftwareBreakpoint* existing = breakpoint_at(address)) {
      // Share the user's trap; its saved bytes are the real originals.
      temp.original = existing->original;
      temp.inserted = true;
      breakpoints.push_back(temp);
    } else {
      breakpoints.push_back(temp);
      if (!insert(breakpoints.back())) {
        breakpoints.pop_back();
        return errno_error("debug.breakpoint_failed", "could not place a temporary breakpoint");
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
    if (pid <= 0) {
      return true;
    }
    if (state == SessionState::Running) {
      pause_requested = true;
      ::syscall(SYS_tgkill, pid, cur(), SIGSTOP);
      if (!wait(kStepTimeoutMs) || pid <= 0) {
        return pid <= 0 ? Result<bool>(true)
                        : make_error<bool>(Status::InternalError, "debug.detach_failed",
                                           "target did not stop for detach");
      }
    }
    drain_expected_sigstops();
    for (auto& bp : breakpoints) {
      uninsert(bp);
    }
    for (pid_t thread : std::vector<pid_t>(tids.begin(), tids.end())) {
      if (thread == pid) {
        continue;
      }
      ::ptrace(PTRACE_DETACH, thread, nullptr,
               reinterpret_cast<void*>(static_cast<std::intptr_t>(take_pending(thread))));
    }
    if (::ptrace(PTRACE_DETACH, pid, nullptr,
                 reinterpret_cast<void*>(static_cast<std::intptr_t>(take_pending(pid)))) != 0) {
      return errno_error("debug.detach_failed", "could not detach from the target");
    }
    forget_process();
    return true;
  }

  /// A plausible return address points into executable code of the target.
  bool is_code_address(std::uint64_t address) const {
    for (const Mapping& m : read_maps(pid)) {
      if (address >= m.start && address < m.end) {
        return m.executable;
      }
    }
    return false;
  }

  /// If the PC is inside its function's prologue, before the frame pointer
  /// has been set up, find the return address from the stack pointer by
  /// replaying the prologue instructions already executed. Returns nullopt
  /// when the frame pointer is already established (or nothing is known).
  std::optional<std::uint64_t> prologue_return_address(NativeRegs& regs) const {
    const std::uint64_t here = reg_pc(regs);
    const std::uint64_t static_pc = translator.runtime_to_static(here);
    if (static_pc == here && translator.runtime_base != translator.static_base) {
      return std::nullopt;
    }
    const auto start_static = image.function_start(static_pc);
    if (!start_static || static_pc - *start_static > 64) {
      return std::nullopt;
    }
    const std::uint64_t start = translator.static_to_runtime(*start_static);
    std::vector<std::byte> code(static_cast<std::size_t>(here - start));
    if (!code.empty() && !raw_read(start, code.data(), code.size())) {
      return std::nullopt;
    }
    native::hide_breakpoints(breakpoints, start, code);
    auto decoder = Decoder::create(kHostArch, Endian::Little);
    if (!decoder) {
      return std::nullopt;
    }
#if defined(__x86_64__)
    std::uint64_t sp_delta = 0;  // bytes pushed since entry
#else
    bool saved_link = false;  // x30 stored at [sp + 8] by the pre-indexed stp
#endif
    std::size_t offset = 0;
    while (offset < code.size()) {
      auto insn = decoder.value().decode_one(std::span<const std::byte>(code).subspan(offset),
                                             start + offset);
      if (!insn || insn.value().length == 0) {
        return std::nullopt;
      }
      const auto& i = insn.value();
      const auto& ops = i.structured_operands;
#if defined(__x86_64__)
      if (i.mnemonic == "push") {
        sp_delta += 8;
      } else if (i.mnemonic == "sub" && ops.size() == 2 && ops[0].reg == "rsp" &&
                 ops[1].kind == OperandKind::Immediate) {
        sp_delta += static_cast<std::uint64_t>(ops[1].immediate);
      } else if (i.mnemonic == "mov" && ops.size() == 2 && ops[0].reg == "rbp" &&
                 ops[1].reg == "rsp") {
        return std::nullopt;  // frame established: [rbp + 8] is right
      }
#else
      if (i.mnemonic == "stp" && ops.size() >= 3 && ops[0].reg == "x29" && ops[1].reg == "x30" &&
          ops[2].kind == OperandKind::Memory && ops[2].memory.base == "sp") {
        saved_link = true;
      } else if (i.mnemonic == "mov" && i.operands.find("x29, sp") != std::string::npos) {
        return std::nullopt;
      }
#endif
      offset += i.length;
    }
    std::uint64_t value = 0;
#if defined(__x86_64__)
    if (!raw_read(reg_sp(regs) + sp_delta, &value, sizeof(value))) {
      return std::nullopt;
    }
#else
    if (saved_link) {
      if (!raw_read(reg_sp(regs) + 8, &value, sizeof(value))) {
        return std::nullopt;
      }
    } else {
      value = regs.regs[30];
    }
#endif
    // Process entry points (_start) have no caller: what sits at [sp] is argc.
    return is_code_address(value) ? std::optional<std::uint64_t>(value) : std::nullopt;
  }

  /// Where the current function returns to: from the prologue replay when
  /// the frame is not set up yet, else [fp + 8] (both ABIs). Code without
  /// frame pointers has no reliable answer.
  std::optional<std::uint64_t> return_address(NativeRegs& regs) const {
    if (auto early = prologue_return_address(regs)) {
      return early;
    }
    std::uint64_t value = 0;
    const std::uint64_t fp = reg_fp(regs);
    if (fp == 0 || !raw_read(fp + 8, &value, sizeof(value)) || !is_code_address(value)) {
      return std::nullopt;
    }
    return value;
  }

  Result<bool> require_stopped(const char* action) const {
    if (pid <= 0 || state != SessionState::Stopped) {
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
#if defined(__x86_64__)
  caps.can_hardware_watchpoints = true;
#endif
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
  if (::access(config.binary_path.c_str(), X_OK) != 0) {
    d.state = SessionState::Error;
    return make_error<bool>(Status::InvalidInput, "debug.file_not_executable",
                            "binary file not found or not executable: " + config.binary_path);
  }
  d.image.load(config.binary_path, d.page_size);
  if (d.image.image && d.image.image->architecture != kHostArch) {
    d.state = SessionState::Error;
    return make_error<bool>(Status::Unsupported, "debug.architecture_mismatch",
                            "the binary's architecture does not match this host");
  }

  // Everything the child needs is prepared before fork(): after it only
  // async-signal-safe calls are allowed.
  std::vector<std::string> env_storage;
  for (const auto& [key, value] : config.environment) {
    env_storage.push_back(key + "=" + value);
  }
  std::vector<char*> argv;
  argv.push_back(const_cast<char*>(config.binary_path.c_str()));
  for (const auto& arg : config.arguments) {
    argv.push_back(const_cast<char*>(arg.c_str()));
  }
  argv.push_back(nullptr);
  std::vector<char*> envp;
  for (char** e = environ; e != nullptr && *e != nullptr; ++e) {
    envp.push_back(*e);
  }
  for (auto& entry : env_storage) {
    envp.push_back(entry.data());
  }
  envp.push_back(nullptr);
  const char* cwd = config.working_directory.empty() ? nullptr : config.working_directory.c_str();

  d.state = SessionState::Launching;
  const pid_t child = ::fork();
  if (child < 0) {
    d.state = SessionState::Error;
    return errno_error("debug.fork_failed", "could not fork");
  }
  if (child == 0) {
    if (::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) {
      ::_exit(126);
    }
    if (cwd != nullptr && ::chdir(cwd) != 0) {
      ::_exit(126);
    }
    ::execve(argv[0], argv.data(), envp.data());
    ::_exit(127);
  }

  d.pid = child;
  d.launched = true;
  d.executable = config.binary_path;
  int status = 0;
  while (::waitpid(child, &status, __WALL) < 0 && errno == EINTR) {
  }
  if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
    d.forget_process();
    d.state = SessionState::Error;
    return make_error<bool>(Status::InternalError, "debug.launch_failed",
                            "the target did not reach exec (exit status " +
                                std::to_string(WIFEXITED(status) ? WEXITSTATUS(status) : -1) + ")");
  }
  d.current = child;
  d.tids = {child};
  d.stopped = {child};
  // Kill the debuggee if the debugger dies, keep exec stops distinct, and
  // trace every thread the program creates (inherited by new threads).
  ::ptrace(PTRACE_SETOPTIONS, child, nullptr,
           reinterpret_cast<void*>(PTRACE_O_EXITKILL | PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE));
  d.open_memory();
  d.state = SessionState::Stopped;
  d.update_translator();

  const std::uint64_t entry = d.image.image && d.image.image->has_entry_point()
                                  ? d.translator.static_to_runtime(d.image.image->entry_point)
                                  : 0;
  if (entry == 0) {
    // Without a known entry, stop where exec left us (the dynamic loader).
    d.stop = StopInfo{StopReason::Entrypoint, static_cast<std::uint64_t>(child), d.pc().value_or(0),
                      "stopped after exec (program entry unknown)", 0};
    if (!config.stop_at_entry) {
      return d.continue_running();
    }
    return true;
  }
  if (!config.stop_at_entry) {
    return d.continue_running();
  }
  auto ran = d.run_to(entry, "entry", kEntryTimeoutMs);
  if (!ran) {
    return ran;
  }
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
  if (pid == 0) {
    d.state = SessionState::Error;
    return make_error<bool>(Status::InvalidInput, "debug.invalid_pid", "cannot attach to pid 0");
  }
  if (static_cast<pid_t>(pid) == ::getpid()) {
    d.state = SessionState::Error;
    return make_error<bool>(Status::InvalidInput, "debug.invalid_pid",
                            "cannot attach to the debugger itself");
  }
  d.state = SessionState::Attaching;
  if (::ptrace(PTRACE_ATTACH, static_cast<pid_t>(pid), nullptr, nullptr) != 0) {
    const int saved = errno;
    d.state = SessionState::Error;
    if (saved == EPERM || saved == EACCES) {
      return make_error<bool>(
          Status::PermissionDenied, "debug.permission_denied",
          "ptrace attach was refused; attaching to a process you did not start needs "
          "CAP_SYS_PTRACE or /proc/sys/kernel/yama/ptrace_scope set to 0");
    }
    errno = saved;
    return errno_error("debug.attach_failed", "could not attach");
  }
  d.pid = static_cast<pid_t>(pid);
  d.current = d.pid;
  d.tids = {d.pid};
  d.launched = false;
  d.pause_requested = true;  // PTRACE_ATTACH stops the target with SIGSTOP
  d.attach_untraced_threads();
  if (!d.wait(kEntryTimeoutMs) || d.pid <= 0) {
    d.state = SessionState::Error;
    return make_error<bool>(Status::InternalError, "debug.attach_failed",
                            "the target did not stop after attach");
  }
  // Trace threads created from now on; then attach any created before the
  // options took effect, until there are none left.
  constexpr long kAttachOptions = PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE;
  d.set_thread_options(kAttachOptions);
  for (int round = 0; round < 8 && d.attach_untraced_threads() > 0; ++round) {
    d.stop_others();
    d.set_thread_options(kAttachOptions);
  }
  std::error_code ec;
  d.executable = std::filesystem::read_symlink("/proc/" + std::to_string(pid) + "/exe", ec);
  d.open_memory();
  d.image.load(d.executable, d.page_size);
  d.update_translator();
  return true;
}

Result<bool> LocalDebugAdapter::detach() {
  Impl& d = *impl_;
  if (d.pid <= 0) {
    d.state = SessionState::Detached;
    return true;
  }
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
  if (d.pid > 0) {
    d.state = SessionState::Terminating;
    ::kill(d.pid, SIGKILL);
    // SIGKILL ends a traced process even while stopped; reap it.
    while (d.pid > 0) {
      d.wait(-1);
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
  if (d.pid <= 0 || d.state != SessionState::Running) {
    return native::invalid_state("cannot pause unless the target is running");
  }
  d.pause_requested = true;
  if (::syscall(SYS_tgkill, d.pid, d.cur(), SIGSTOP) != 0) {
    d.pause_requested = false;
    return errno_error("debug.pause_failed", "could not stop the target");
  }
  d.wait(kStepTimeoutMs);
  return true;
}

Result<bool> LocalDebugAdapter::step_into() {
  Impl& d = *impl_;
  if (auto ok = d.require_stopped("step"); !ok) {
    return ok;
  }
  if (!d.single_step(kStepTimeoutMs) && d.pid > 0 && d.state != SessionState::Running) {
    return errno_error("debug.step_failed", "could not single-step the target");
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
    return errno_error("debug.step_failed", "could not read the program counter");
  }
  std::array<std::byte, 16> bytes{};
  if (!d.raw_read(*here, bytes.data(), bytes.size())) {
    return step_into();
  }
  std::vector<std::byte> visible(bytes.begin(), bytes.end());
  native::hide_breakpoints(d.breakpoints, *here, visible);
  auto decoder = Decoder::create(kHostArch, Endian::Little);
  if (!decoder) {
    return step_into();
  }
  auto instruction = decoder.value().decode_one(visible, *here);
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
  NativeRegs regs{};
  if (!d.get_regs(regs)) {
    return errno_error("debug.step_failed", "could not read registers");
  }
  auto return_address = d.return_address(regs);
  if (!return_address) {
    return unsupported("step out needs a frame pointer chain; none was found at this location");
  }
  return d.run_to(*return_address, "step", kStepTimeoutMs);
}

Result<Breakpoint> LocalDebugAdapter::set_breakpoint(std::uint64_t address) {
  Impl& d = *impl_;
  for (const auto& bp : d.breakpoints) {
    if (!bp.internal && bp.info.address == address) {
      return bp.info;
    }
  }
  if (d.pid <= 0) {
    return make_error<Breakpoint>(Status::InvalidInput, "debug.invalid_state",
                                  "no target is running; launch or attach first");
  }
  SoftwareBreakpoint bp;
  bp.info.id = d.next_breakpoint_id++;
  bp.info.address = address;
  bp.info.enabled = true;
  // An internal breakpoint may already have patched this address.
  SoftwareBreakpoint* existing = d.breakpoint_at(address);
  if (existing != nullptr) {
    bp.original = existing->original;
    bp.inserted = true;
  } else if (!d.insert(bp)) {
    return make_error<Breakpoint>(Status::InvalidInput, "debug.breakpoint_failed",
                                  "could not write a breakpoint at that address (unmapped?)");
  }
  d.breakpoints.push_back(bp);
  return bp.info;
}

Result<Breakpoint> LocalDebugAdapter::set_conditional_breakpoint(std::uint64_t address,
                                                                 const std::string& condition) {
  Impl& d = *impl_;
  auto parsed = debug::parse_break_condition(condition);
  if (!parsed) {
    return Result<Breakpoint>(parsed.diagnostic());
  }
  if (!parsed.value().memory && !is_host_register(parsed.value().register_name)) {
    return make_error<Breakpoint>(
        Status::InvalidInput, "debug.condition_register",
        "this host has no register named `" + parsed.value().register_name + "`");
  }
  // set_breakpoint returns an existing breakpoint at the address. Attaching a condition to it would
  // change a breakpoint the user set without a condition, so that case is refused.
  for (const auto& bp : d.breakpoints) {
    if (!bp.internal && bp.info.address == address) {
      return make_error<Breakpoint>(Status::InvalidInput, "debug.breakpoint_exists",
                                    "a breakpoint is already set at that address; remove it "
                                    "before setting a conditional one");
    }
  }
  auto created = set_breakpoint(address);
  if (!created) {
    return created;
  }
  for (auto& bp : d.breakpoints) {
    if (!bp.internal && bp.info.id == created.value().id) {
      bp.condition = parsed.value();
      bp.info.condition = condition;
      return bp.info;
    }
  }
  return make_error<Breakpoint>(Status::InternalError, "debug.breakpoint_lost",
                                "the new breakpoint was not recorded");
}

Result<bool> LocalDebugAdapter::remove_breakpoint(std::uint64_t id_or_address) {
  Impl& d = *impl_;
  for (auto it = d.breakpoints.begin(); it != d.breakpoints.end(); ++it) {
    if (it->internal || (it->info.id != id_or_address && it->info.address != id_or_address)) {
      continue;
    }
    const std::uint64_t address = it->info.address;
    bool shared = false;
    for (const auto& other : d.breakpoints) {
      if (&other != &*it && other.info.address == address && other.inserted) {
        shared = true;
      }
    }
    if (!shared && d.pid > 0 && !d.uninsert(*it)) {
      return errno_error("debug.breakpoint_failed", "could not restore the original bytes");
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
  if (d.pid <= 0 || d.state != SessionState::Stopped) {
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
  if (d.pid <= 0 || d.state != SessionState::Stopped) {
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
  if (d.pid <= 0 || d.state != SessionState::Stopped) {
    return make_error<std::vector<RegisterValue>>(Status::InvalidInput, "debug.invalid_state",
                                                  "registers can only be read while stopped");
  }
  NativeRegs regs{};
  if (!d.get_regs(regs)) {
    return make_error<std::vector<RegisterValue>>(Status::InternalError, "debug.registers_failed",
                                                  std::strerror(errno));
  }
  std::vector<RegisterValue> out;
#if defined(__x86_64__)
  for (const RegisterSlot& slot : kRegisterSlots) {
    out.push_back(RegisterValue{slot.name, regs.*slot.field, 8});
  }
#else
  for (int i = 0; i < 31; ++i) {
    out.push_back(RegisterValue{"x" + std::to_string(i), regs.regs[i], 8});
  }
  out.push_back(RegisterValue{"sp", regs.sp, 8});
  out.push_back(RegisterValue{"pc", regs.pc, 8});
  out.push_back(RegisterValue{"pstate", regs.pstate, 8});
#endif
  return out;
}

Result<bool> LocalDebugAdapter::write_register(const std::string& name, std::uint64_t value) {
  Impl& d = *impl_;
  if (auto ok = d.require_stopped("write registers"); !ok) {
    return ok;
  }
  NativeRegs regs{};
  if (!d.get_regs(regs)) {
    return errno_error("debug.registers_failed", "could not read registers");
  }
  bool found = false;
#if defined(__x86_64__)
  for (const RegisterSlot& slot : kRegisterSlots) {
    if (name == slot.name) {
      regs.*slot.field = value;
      found = true;
    }
  }
#else
  if (name == "sp") {
    regs.sp = value;
    found = true;
  } else if (name == "pc") {
    regs.pc = value;
    found = true;
  } else if (name == "pstate") {
    regs.pstate = value;
    found = true;
  } else if (name.size() >= 2 && name[0] == 'x') {
    const int index = std::atoi(name.c_str() + 1);
    if (index >= 0 && index < 31 && name == "x" + std::to_string(index)) {
      regs.regs[index] = value;
      found = true;
    }
  }
#endif
  if (!found) {
    return make_error<bool>(Status::InvalidInput, "debug.unknown_register",
                            "unknown register '" + name + "'");
  }
  if (!d.set_regs(regs)) {
    return errno_error("debug.registers_failed", "could not write registers");
  }
  return true;
}

Result<std::vector<StackFrame>> LocalDebugAdapter::call_stack() {
  Impl& d = *impl_;
  if (d.pid <= 0 || d.state != SessionState::Stopped) {
    return make_error<std::vector<StackFrame>>(Status::InvalidInput, "debug.invalid_state",
                                               "the call stack can only be read while stopped");
  }
  NativeRegs regs{};
  if (!d.get_regs(regs)) {
    return make_error<std::vector<StackFrame>>(Status::InternalError, "debug.registers_failed",
                                               std::strerror(errno));
  }
  const auto maps = read_maps(d.pid);
  auto module_of = [&](std::uint64_t address) {
    for (const Mapping& m : maps) {
      if (address >= m.start && address < m.end) {
        return std::filesystem::path(m.path).filename().string();
      }
    }
    return std::string();
  };
  auto make_frame = [&](std::uint32_t index, std::uint64_t ip, std::uint64_t sp, std::uint64_t fp) {
    StackFrame frame;
    frame.index = index;
    frame.instruction_pointer = ip;
    frame.stack_pointer = sp;
    frame.frame_pointer = fp;
    frame.module_name = module_of(ip);
    frame.static_address = d.translator.runtime_to_static(ip);
    if (frame.static_address != ip || d.translator.runtime_base == d.translator.static_base) {
      frame.function_name = d.image.function_at(frame.static_address);
    } else if (auto resolved = resolve_address(ip)) {
      // A shared library (also one loaded with dlopen after launch): name the
      // frame from that library's own symbols.
      frame.static_address = resolved.value().static_address;
      frame.function_name = resolved.value().function_name;
    }
    return frame;
  };

  std::vector<StackFrame> frames;
  std::uint64_t fp = reg_fp(regs);
  frames.push_back(make_frame(0, reg_pc(regs), reg_sp(regs), fp));
  if (auto caller = d.prologue_return_address(regs)) {
    // No frame of its own yet: the caller's return address comes first and
    // the frame pointer still describes the caller.
    frames.push_back(make_frame(1, *caller, reg_sp(regs), fp));
  }
  // Frame-pointer walk: [fp] = caller's fp, [fp + 8] = return address. Stops
  // at a null or non-increasing fp, an unreadable frame or kMaxFrames.
  while (fp != 0 && frames.size() < kMaxFrames) {
    std::uint64_t pair[2] = {0, 0};
    if (!d.raw_read(fp, pair, sizeof(pair)) || !d.is_code_address(pair[1])) {
      break;
    }
    frames.push_back(
        make_frame(static_cast<std::uint32_t>(frames.size()), pair[1], fp + 16, pair[0]));
    if (pair[0] <= fp) {
      break;
    }
    fp = pair[0];
  }
  return frames;
}

Result<std::vector<DebugThread>> LocalDebugAdapter::threads() {
  Impl& d = *impl_;
  std::vector<DebugThread> list;
  if (d.pid <= 0) {
    return list;
  }
  std::error_code ec;
  for (const auto& entry :
       std::filesystem::directory_iterator("/proc/" + std::to_string(d.pid) + "/task", ec)) {
    const std::string name = entry.path().filename().string();
    DebugThread thread;
    thread.id = std::strtoull(name.c_str(), nullptr, 10);
    std::ifstream comm(entry.path() / "comm");
    std::getline(comm, thread.name);
    thread.is_current = thread.id == static_cast<std::uint64_t>(d.cur());
    thread.stop_reason = thread.is_current ? d.stop.reason : StopReason::None;
    list.push_back(thread);
  }
  std::sort(list.begin(), list.end(),
            [](const DebugThread& a, const DebugThread& b) { return a.id < b.id; });
  return list;
}

Result<std::vector<DebugModule>> LocalDebugAdapter::modules() {
  Impl& d = *impl_;
  std::vector<DebugModule> list;
  if (d.pid <= 0) {
    return list;
  }
  std::map<std::string, DebugModule> by_path;
  for (const Mapping& m : read_maps(d.pid)) {
    if (m.path.empty() || m.path.front() != '/') {
      continue;
    }
    auto [it, inserted] = by_path.try_emplace(m.path);
    DebugModule& module = it->second;
    if (inserted) {
      module.path = m.path;
      module.name = std::filesystem::path(m.path).filename().string();
      module.base_address = m.start;
      module.size = m.end - m.start;
    } else {
      const std::uint64_t end = std::max(module.base_address + module.size, m.end);
      module.base_address = std::min(module.base_address, m.start);
      module.size = end - module.base_address;
    }
  }
  for (auto& [path, module] : by_path) {
    list.push_back(module);
  }
  std::sort(list.begin(), list.end(), [](const DebugModule& a, const DebugModule& b) {
    return a.base_address < b.base_address;
  });
  return list;
}

Result<StopInfo> LocalDebugAdapter::poll_events() {
  Impl& d = *impl_;
  if (d.pid > 0 && d.state == SessionState::Running) {
    if (!d.wait(0)) {
      return StopInfo{};
    }
  }
  return d.stop;
}

#if defined(__x86_64__)
Result<Watchpoint> LocalDebugAdapter::set_watchpoint(std::uint64_t address, std::uint8_t length,
                                                     WatchKind kind) {
  Impl& d = *impl_;
  if (d.pid <= 0 || d.state != SessionState::Stopped) {
    return make_error<Watchpoint>(
        Status::InvalidInput, "debug.not_stopped",
        "a hardware watchpoint can be set only while the target is stopped");
  }
  if (kind != WatchKind::Write && kind != WatchKind::ReadWrite) {
    return make_error<Watchpoint>(Status::InvalidInput, "debug.watch_kind",
                                  "unknown watchpoint kind");
  }
  if (length != 1 && length != 2 && length != 4 && length != 8) {
    return make_error<Watchpoint>(Status::InvalidInput, "debug.watch_length",
                                  "a watchpoint covers 1, 2, 4 or 8 bytes");
  }
  if (address % length != 0) {
    return make_error<Watchpoint>(Status::InvalidInput, "debug.watch_alignment",
                                  "a watchpoint address must be a multiple of its length");
  }
  if (d.watches.size() >= Impl::kWatchSlots) {
    return make_error<Watchpoint>(Status::ResourceLimit, "debug.watch_slots",
                                  "all four hardware watchpoints are in use");
  }
  Watchpoint watch;
  watch.id = d.next_watch_id++;
  watch.address = address;
  watch.length = length;
  watch.kind = kind;
  d.watches.push_back(watch);
  if (!d.arm_all()) {
    d.watches.pop_back();
    d.arm_all();
    return make_error<Watchpoint>(Status::InvalidInput, "debug.watch_failed",
                                  "the kernel refused the debug registers for that address");
  }
  return watch;
}

Result<Watchpoint> LocalDebugAdapter::set_conditional_watchpoint(std::uint64_t address,
                                                                 std::uint8_t length,
                                                                 WatchKind kind,
                                                                 const std::string& condition) {
  Impl& d = *impl_;
  auto parsed = debug::parse_break_condition(condition);
  if (!parsed) {
    return Result<Watchpoint>(parsed.diagnostic());
  }
  if (!parsed.value().memory && !is_host_register(parsed.value().register_name)) {
    return make_error<Watchpoint>(
        Status::InvalidInput, "debug.condition_register",
        "this host has no register named `" + parsed.value().register_name + "`");
  }
  // set_watchpoint checks the request and takes a debug register. Only then is the condition
  // recorded, so a refused request leaves no slot in use.
  auto created = set_watchpoint(address, length, kind);
  if (!created) {
    return created;
  }
  for (Watchpoint& watch : d.watches) {
    if (watch.id == created.value().id) {
      watch.condition = condition;
      return watch;
    }
  }
  return make_error<Watchpoint>(Status::InternalError, "debug.watch_lost",
                                "the new watchpoint was not recorded");
}

Result<bool> LocalDebugAdapter::remove_watchpoint(std::uint64_t id) {
  Impl& d = *impl_;
  const auto found = std::find_if(d.watches.begin(), d.watches.end(),
                                  [id](const Watchpoint& watch) { return watch.id == id; });
  if (found == d.watches.end()) {
    return make_error<bool>(Status::InvalidInput, "debug.no_watchpoint",
                            "no hardware watchpoint has that id");
  }
  if (d.state != SessionState::Stopped) {
    return make_error<bool>(
        Status::InvalidInput, "debug.not_stopped",
        "a hardware watchpoint can be removed only while the target is stopped");
  }
  d.watches.erase(found);
  if (!d.arm_all()) {
    return make_error<bool>(Status::InvalidInput, "debug.watch_failed",
                            "the kernel refused the debug registers");
  }
  return true;
}
#endif

Result<StopInfo> LocalDebugAdapter::wait_for_event(int timeout_ms) {
  Impl& d = *impl_;
  if (d.pid > 0 && d.state == SessionState::Running) {
    if (!d.wait(timeout_ms)) {
      return StopInfo{};
    }
  }
  return d.stop;
}

}  // namespace donkey::debug

#endif
