#pragma once

// Readable symbol names for the desktop UI (G10-T4). A C++ symbol is shown in its demangled form,
// and the raw name is kept for the tooltip. The demangling is done by the headless core
// (donkey/binary/demangle.h); this file only decides what to show and caches the answer, so the
// render thread does a map lookup per row, not a demangle per frame.

#include <string>
#include <string_view>
#include <unordered_map>

namespace donkey::ui {

/// The name to show for a raw symbol: the demangled form when the name is an Itanium (`_Z`) or MSVC
/// (`?`) name that the demangler reads, and the raw name otherwise. A name the demangler refuses is
/// shown raw, never guessed.
[[nodiscard]] std::string readable_name(std::string_view raw);

/// `readable_name` through a cache keyed by the raw name. The cache is owned by the UI state, so it
/// lives as long as the session and is never demangled twice.
[[nodiscard]] const std::string& cached_readable_name(
    std::unordered_map<std::string, std::string>& cache, const std::string& raw);

}  // namespace donkey::ui
