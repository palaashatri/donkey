#include "donkey/plugin/plugin.h"

#if defined(_WIN32)

namespace donkey {

Result<PluginExecutionResult> PluginHost::execute_isolated(const std::string&, const std::string&,
                                                           uint64_t, uint32_t, size_t) {
  return Diagnostic::make(Status::Unsupported, "plugin.isolation_unavailable",
                          "Process-isolated plugin execution is not supported on Windows host");
}

Result<PluginManifest> PluginHost::inspect_manifest_isolated(const std::string&, uint32_t, size_t) {
  return Diagnostic::make(Status::Unsupported, "plugin.isolation_unavailable",
                          "Process-isolated plugin inspection is not supported on Windows host");
}

}  // namespace donkey

#else

#include <dlfcn.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <string>
#include <vector>

namespace donkey {
namespace {

constexpr size_t kMaxPluginOutputBytes = 1024 * 1024;  // 1 MiB hard ceiling

void write_string(int fd, const std::string& s) {
  uint32_t len = static_cast<uint32_t>(s.size());
  (void)write(fd, &len, sizeof(len));
  if (len > 0) {
    (void)write(fd, s.data(), len);
  }
}

bool read_exact(int fd, void* dest, size_t size,
                const std::chrono::steady_clock::time_point& deadline) {
  size_t offset = 0;
  char* ptr = static_cast<char*>(dest);
  while (offset < size) {
    auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      return false;
    }
    int remaining_ms = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
    if (remaining_ms <= 0) return false;

    struct pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLIN | POLLHUP;

    int poll_rc = poll(&pfd, 1, remaining_ms);
    if (poll_rc <= 0) {
      if (poll_rc < 0 && errno == EINTR) continue;
      return false;
    }

    ssize_t bytes_read = read(fd, ptr + offset, size - offset);
    if (bytes_read > 0) {
      offset += static_cast<size_t>(bytes_read);
    } else if (bytes_read == 0) {
      return false;  // Unexpected EOF
    } else {
      if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
      return false;
    }
  }
  return true;
}

bool read_string(int fd, std::string& out, const std::chrono::steady_clock::time_point& deadline) {
  uint32_t len = 0;
  if (!read_exact(fd, &len, sizeof(len), deadline)) {
    return false;
  }
  if (len > kMaxPluginOutputBytes) {
    return false;
  }
  out.resize(len);
  if (len == 0) return true;
  return read_exact(fd, out.data(), len, deadline);
}

}  // namespace

Result<PluginManifest> PluginHost::inspect_manifest_isolated(const std::string& library_path,
                                                             uint32_t timeout_seconds,
                                                             size_t max_memory_bytes) {
  int pipe_fds[2];
  if (pipe(pipe_fds) != 0) {
    return Diagnostic::make(Status::InternalError, "plugin.pipe_failed",
                            "Failed to allocate pipe for isolated manifest inspection");
  }

  pid_t pid = fork();
  if (pid < 0) {
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    return Diagnostic::make(Status::InternalError, "plugin.fork_failed",
                            "Failed to fork isolated worker for manifest inspection");
  }

  if (pid == 0) {
    // Isolated child worker process
    close(pipe_fds[0]);

    if (timeout_seconds > 0) {
      struct rlimit rl_cpu{};
      rl_cpu.rlim_cur = timeout_seconds;
      rl_cpu.rlim_max = timeout_seconds + 1;
      setrlimit(RLIMIT_CPU, &rl_cpu);
    }

#ifdef RLIMIT_AS
    if (max_memory_bytes > 0) {
      struct rlimit rl_as{};
      rl_as.rlim_cur = max_memory_bytes;
      rl_as.rlim_max = max_memory_bytes;
      setrlimit(RLIMIT_AS, &rl_as);
    }
#endif

    auto manifest_res = inspect_manifest(library_path);
    if (!manifest_res) {
      uint8_t status_byte = 1;  // Error
      (void)write(pipe_fds[1], &status_byte, 1);
      int st = static_cast<int>(manifest_res.diagnostic().status);
      (void)write(pipe_fds[1], &st, sizeof(st));
      write_string(pipe_fds[1], manifest_res.diagnostic().code);
      write_string(pipe_fds[1], manifest_res.diagnostic().message);
      close(pipe_fds[1]);
      _exit(1);
    }

    uint8_t status_byte = 0;  // Success
    (void)write(pipe_fds[1], &status_byte, 1);
    const auto& m = manifest_res.value();
    write_string(pipe_fds[1], m.id);
    write_string(pipe_fds[1], m.name);
    write_string(pipe_fds[1], m.version);
    write_string(pipe_fds[1], m.author);
    write_string(pipe_fds[1], m.description);
    (void)write(pipe_fds[1], &m.abi_version_major, sizeof(m.abi_version_major));
    (void)write(pipe_fds[1], &m.abi_version_minor, sizeof(m.abi_version_minor));
    (void)write(pipe_fds[1], &m.requested_capabilities, sizeof(m.requested_capabilities));
    close(pipe_fds[1]);
    _exit(0);
  }

  // Parent supervisor process
  close(pipe_fds[1]);

  int flags = fcntl(pipe_fds[0], F_GETFL, 0);
  if (flags >= 0) {
    fcntl(pipe_fds[0], F_SETFL, flags | O_NONBLOCK);
  }

  const auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds(timeout_seconds > 0 ? timeout_seconds : 3);

  uint8_t status_byte = 0xFF;
  bool read_ok = read_exact(pipe_fds[0], &status_byte, 1, deadline);

  if (!read_ok) {
    kill(pid, SIGKILL);
    int status = 0;
    waitpid(pid, &status, 0);
    close(pipe_fds[0]);
    if (WIFSIGNALED(status)) {
      return Diagnostic::make(Status::InternalError, "plugin.crashed",
                              "Plugin worker crashed during manifest inspection");
    }
    return Diagnostic::make(Status::ResourceLimit, "plugin.timeout",
                            "Plugin manifest inspection exceeded timeout");
  }

  if (status_byte == 1) {
    // Child reported an inspection error
    int st_val = 0;
    std::string err_code, err_msg;
    read_exact(pipe_fds[0], &st_val, sizeof(st_val), deadline);
    read_string(pipe_fds[0], err_code, deadline);
    read_string(pipe_fds[0], err_msg, deadline);
    close(pipe_fds[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    return Diagnostic::make(static_cast<Status>(st_val), err_code, err_msg);
  }

  // Child reported success
  PluginManifest m;
  read_string(pipe_fds[0], m.id, deadline);
  read_string(pipe_fds[0], m.name, deadline);
  read_string(pipe_fds[0], m.version, deadline);
  read_string(pipe_fds[0], m.author, deadline);
  read_string(pipe_fds[0], m.description, deadline);
  read_exact(pipe_fds[0], &m.abi_version_major, sizeof(m.abi_version_major), deadline);
  read_exact(pipe_fds[0], &m.abi_version_minor, sizeof(m.abi_version_minor), deadline);
  read_exact(pipe_fds[0], &m.requested_capabilities, sizeof(m.requested_capabilities), deadline);

  close(pipe_fds[0]);
  int status = 0;
  waitpid(pid, &status, 0);

  return m;
}

Result<PluginExecutionResult> PluginHost::execute_isolated(const std::string& library_path,
                                                           const std::string& input_json,
                                                           uint64_t granted_capabilities,
                                                           uint32_t timeout_seconds,
                                                           size_t max_memory_bytes) {
  int pipe_fds[2];
  if (pipe(pipe_fds) != 0) {
    return Diagnostic::make(Status::InternalError, "plugin.pipe_failed",
                            "Failed to allocate pipe for isolated worker");
  }

  // Security boundary: fork worker before loading library
  pid_t pid = fork();
  if (pid < 0) {
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    return Diagnostic::make(Status::InternalError, "plugin.fork_failed",
                            "Failed to fork isolated plugin worker");
  }

  if (pid == 0) {
    // Child process: untrusted execution domain
    close(pipe_fds[0]);

    if (timeout_seconds > 0) {
      struct rlimit rl_cpu{};
      rl_cpu.rlim_cur = timeout_seconds;
      rl_cpu.rlim_max = timeout_seconds + 1;
      setrlimit(RLIMIT_CPU, &rl_cpu);
    }

#ifdef RLIMIT_AS
    if (max_memory_bytes > 0) {
      struct rlimit rl_as{};
      rl_as.rlim_cur = max_memory_bytes;
      rl_as.rlim_max = max_memory_bytes;
      setrlimit(RLIMIT_AS, &rl_as);
    }
#endif

    void* handle = dlopen(library_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
      close(pipe_fds[1]);
      _exit(1);
    }

    void* sym = dlsym(handle, DONKEY_PLUGIN_ENTRY_SYMBOL);
    if (!sym) {
      dlclose(handle);
      close(pipe_fds[1]);
      _exit(2);
    }

    auto entry_fn = reinterpret_cast<DonkeyPluginEntryFn>(sym);
    const DonkeyPluginDescriptor* desc = entry_fn();
    if (!desc || desc->struct_size != sizeof(DonkeyPluginDescriptor) ||
        desc->abi_version_major != DONKEY_PLUGIN_ABI_VERSION_MAJOR) {
      dlclose(handle);
      close(pipe_fds[1]);
      _exit(3);
    }

    if ((desc->requested_capabilities & ~granted_capabilities) != 0) {
      dlclose(handle);
      close(pipe_fds[1]);
      _exit(5);
    }

    if (desc->init) {
      int init_rc = desc->init();
      if (init_rc != 0) {
        dlclose(handle);
        close(pipe_fds[1]);
        _exit(4);
      }
    }

    std::vector<char> out_buf(65536, 0);
    int exec_rc = 0;
    if (desc->execute) {
      exec_rc = desc->execute(input_json.c_str(), out_buf.data(), out_buf.size());
    }

    if (desc->shutdown) {
      desc->shutdown();
    }

    dlclose(handle);

    // Finding 5: Bounded length check on output buffer without trusting null termination
    const void* null_pos = std::memchr(out_buf.data(), '\0', out_buf.size());
    uint32_t out_len =
        null_pos ? static_cast<uint32_t>(static_cast<const char*>(null_pos) - out_buf.data())
                 : static_cast<uint32_t>(out_buf.size());

    // Write execution code (int) and length-prefixed output string
    (void)write(pipe_fds[1], &exec_rc, sizeof(exec_rc));
    (void)write(pipe_fds[1], &out_len, sizeof(out_len));
    if (out_len > 0) {
      (void)write(pipe_fds[1], out_buf.data(), out_len);
    }

    close(pipe_fds[1]);
    _exit(0);
  }

  // Parent supervisor process
  close(pipe_fds[1]);

  // Finding 3: Non-blocking IPC with single monotonic deadline
  int flags = fcntl(pipe_fds[0], F_GETFL, 0);
  if (flags >= 0) {
    fcntl(pipe_fds[0], F_SETFL, flags | O_NONBLOCK);
  }

  const auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds(timeout_seconds > 0 ? timeout_seconds : 5);

  std::vector<char> response_acc;
  bool timed_out = false;
  bool output_limit_exceeded = false;

  while (true) {
    auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      timed_out = true;
      break;
    }
    int remaining_ms = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
    if (remaining_ms <= 0) {
      timed_out = true;
      break;
    }

    struct pollfd pfd{};
    pfd.fd = pipe_fds[0];
    pfd.events = POLLIN | POLLHUP;

    int poll_rc = poll(&pfd, 1, remaining_ms);
    if (poll_rc == 0) {
      timed_out = true;
      break;
    }
    if (poll_rc < 0) {
      if (errno == EINTR) continue;
      break;
    }

    char chunk[4096];
    ssize_t bytes_read = read(pipe_fds[0], chunk, sizeof(chunk));
    if (bytes_read > 0) {
      if (response_acc.size() + static_cast<size_t>(bytes_read) > kMaxPluginOutputBytes) {
        output_limit_exceeded = true;
        break;
      }
      response_acc.insert(response_acc.end(), chunk, chunk + bytes_read);
    } else if (bytes_read == 0) {
      // EOF - child worker closed pipe
      break;
    } else {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      }
      break;
    }
  }

  if (timed_out || output_limit_exceeded) {
    kill(pid, SIGKILL);
    int status = 0;
    waitpid(pid, &status, 0);
    close(pipe_fds[0]);

    PluginExecutionResult res;
    res.success = false;
    if (output_limit_exceeded) {
      res.error_code = "plugin.output_limit_exceeded";
      res.error_message = "Plugin worker exceeded maximum output size limit (1 MiB)";
    } else {
      res.timed_out = true;
      res.error_code = "plugin.timeout";
      res.error_message = "Plugin worker exceeded execution timeout (" +
                          std::to_string(timeout_seconds) + " seconds)";
    }
    return res;
  }

  close(pipe_fds[0]);

  int wstatus = 0;
  waitpid(pid, &wstatus, 0);

  PluginExecutionResult res;

  if (WIFSIGNALED(wstatus)) {
    int sig = WTERMSIG(wstatus);
    res.crashed = true;
    res.termination_signal = sig;
    res.success = false;
    if (sig == SIGXCPU) {
      res.timed_out = true;
      res.error_code = "plugin.timeout";
      res.error_message = "Plugin worker exceeded CPU time limit";
    } else {
      res.error_code = "plugin.crashed";
      res.error_message = "Plugin worker terminated due to signal " + std::to_string(sig);
    }
    return res;
  }

  if (WIFEXITED(wstatus)) {
    int exit_code = WEXITSTATUS(wstatus);
    if (exit_code == 3) {
      return Diagnostic::make(Status::InvalidInput, "plugin.abi_version_mismatch",
                              "Plugin ABI version mismatch or invalid descriptor");
    }
    if (exit_code == 5) {
      return Diagnostic::make(Status::PermissionDenied, "plugin.capability_denied",
                              "Plugin requested capabilities that have not been granted by user");
    }
    if (exit_code == 1) {
      return Diagnostic::make(Status::InvalidInput, "plugin.load_failed",
                              "Failed to dlopen plugin in isolated worker");
    }
    if (exit_code == 2) {
      return Diagnostic::make(Status::InvalidInput, "plugin.missing_entry",
                              "Plugin does not export donkey_plugin_entry symbol");
    }
    if (exit_code == 4) {
      return Diagnostic::make(Status::InvalidInput, "plugin.init_failed",
                              "Plugin initialization function returned non-zero code");
    }

    if (exit_code != 0 || response_acc.size() < sizeof(int)) {
      res.success = false;
      res.exit_code = exit_code;
      res.error_code = "plugin.worker_failed";
      res.error_message = "Plugin worker exited with non-zero code " + std::to_string(exit_code);
      return res;
    }

    int exec_rc = 0;
    std::memcpy(&exec_rc, response_acc.data(), sizeof(exec_rc));

    res.exit_code = exec_rc;
    if (exec_rc == 0) {
      res.success = true;
      if (response_acc.size() >= sizeof(int) + sizeof(uint32_t)) {
        uint32_t out_len = 0;
        std::memcpy(&out_len, response_acc.data() + sizeof(int), sizeof(out_len));
        size_t available = response_acc.size() - sizeof(int) - sizeof(uint32_t);
        size_t actual_len = std::min(static_cast<size_t>(out_len), available);
        res.output_json =
            std::string(response_acc.data() + sizeof(int) + sizeof(uint32_t), actual_len);
      } else {
        res.output_json =
            std::string(response_acc.data() + sizeof(int), response_acc.size() - sizeof(int));
      }
    } else {
      res.success = false;
      res.error_code = "plugin.execution_failed";
      res.error_message = "Plugin execute() returned code " + std::to_string(exec_rc);
    }
    return res;
  }

  res.success = false;
  res.error_code = "plugin.abnormal_exit";
  res.error_message = "Plugin worker exited abnormally";
  return res;
}

}  // namespace donkey

#endif
