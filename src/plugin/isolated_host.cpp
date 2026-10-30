#include <dlfcn.h>
#include <poll.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include <vector>

#include "donkey/plugin/plugin.h"

namespace donkey {

Result<PluginExecutionResult> PluginHost::execute_isolated(const std::string& library_path,
                                                           const std::string& input_json,
                                                           uint64_t granted_capabilities,
                                                           uint32_t timeout_seconds,
                                                           size_t max_memory_bytes) {
  // First, verify manifest and ABI version upfront
  auto manifest_res = inspect_manifest(library_path);
  if (!manifest_res) {
    return manifest_res.diagnostic();
  }

  const auto& manifest = manifest_res.value();
  if ((manifest.requested_capabilities & ~granted_capabilities) != 0) {
    return Diagnostic::make(Status::PermissionDenied, "plugin.capability_denied",
                            "Plugin requested capabilities that have not been granted by user");
  }

  int pipe_fds[2];
  if (pipe(pipe_fds) != 0) {
    return Diagnostic::make(Status::InternalError, "plugin.pipe_failed",
                            "Failed to allocate pipe for isolated worker");
  }

  pid_t pid = fork();
  if (pid < 0) {
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    return Diagnostic::make(Status::InternalError, "plugin.fork_failed",
                            "Failed to fork isolated plugin worker");
  }

  if (pid == 0) {
    // Child process: execute untrusted plugin
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

    // Write execution code (int) and output string
    ssize_t w1 = write(pipe_fds[1], &exec_rc, sizeof(exec_rc));
    (void)w1;
    size_t out_len = std::strlen(out_buf.data());
    ssize_t w2 = write(pipe_fds[1], out_buf.data(), out_len);
    (void)w2;

    close(pipe_fds[1]);
    _exit(0);
  }

  // Parent supervisor process
  close(pipe_fds[1]);

  int timeout_ms = timeout_seconds > 0 ? static_cast<int>(timeout_seconds * 1000) : 5000;
  struct pollfd pfd{};
  pfd.fd = pipe_fds[0];
  pfd.events = POLLIN | POLLHUP;

  bool timed_out = false;
  int poll_rc = poll(&pfd, 1, timeout_ms);
  if (poll_rc == 0) {
    timed_out = true;
  }

  PluginExecutionResult res;

  if (timed_out) {
    kill(pid, SIGKILL);
    int status = 0;
    waitpid(pid, &status, 0);
    close(pipe_fds[0]);

    res.success = false;
    res.timed_out = true;
    res.error_code = "plugin.timeout";
    res.error_message = "Plugin worker exceeded execution timeout (" +
                        std::to_string(timeout_seconds) + " seconds)";
    return res;
  }

  // Read response from child
  int exec_rc = 0;
  ssize_t r1 = read(pipe_fds[0], &exec_rc, sizeof(exec_rc));

  std::vector<char> output_acc;
  char chunk[4096];
  while (true) {
    ssize_t bytes_read = read(pipe_fds[0], chunk, sizeof(chunk));
    if (bytes_read <= 0) break;
    output_acc.insert(output_acc.end(), chunk, chunk + bytes_read);
  }
  close(pipe_fds[0]);

  int wstatus = 0;
  waitpid(pid, &wstatus, 0);

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
    if (exit_code != 0 || r1 != sizeof(exec_rc)) {
      res.success = false;
      res.exit_code = exit_code;
      res.error_code = "plugin.worker_failed";
      res.error_message = "Plugin worker exited with non-zero code " + std::to_string(exit_code);
      return res;
    }

    res.exit_code = exec_rc;
    if (exec_rc == 0) {
      res.success = true;
      res.output_json = std::string(output_acc.data(), output_acc.size());
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
