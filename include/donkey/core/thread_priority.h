#pragma once

namespace donkey {

/// Lower the calling thread's scheduling priority so background analysis
/// never competes with the UI thread (or the display server) on a busy
/// machine: nice +10 on Linux, the utility QoS class on macOS and
/// THREAD_PRIORITY_BELOW_NORMAL on Windows. Elsewhere (FreeBSD) there is no
/// safe per-thread equivalent and it returns false. Best effort: on failure
/// the thread keeps running at its old priority.
bool make_current_thread_background() noexcept;

}  // namespace donkey
