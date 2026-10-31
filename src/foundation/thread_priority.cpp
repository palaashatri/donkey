#include "donkey/core/thread_priority.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#elif defined(__APPLE__)
#include <pthread.h>
#include <sys/qos.h>
#elif defined(__linux__)
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace donkey {

bool make_current_thread_background() noexcept {
#if defined(_WIN32)
  return SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL) != 0;
#elif defined(__APPLE__)
  return pthread_set_qos_class_self_np(QOS_CLASS_UTILITY, 0) == 0;
#elif defined(__linux__)
  // On Linux the nice value is per thread when addressed by thread id.
  const auto tid = static_cast<id_t>(syscall(SYS_gettid));
  return setpriority(PRIO_PROCESS, tid, 10) == 0;
#else
  // FreeBSD: nice is per process and the idle class starves outright, so
  // there is no safe per-thread equivalent; threads keep normal priority.
  return false;
#endif
}

}  // namespace donkey
