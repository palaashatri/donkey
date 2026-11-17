#pragma once

// No-return calls (G24-T3). A call to `abort`, `exit` or another function on a fixed list does not
// come back, so the code after it is not this path's code and the function does not return there.
// The list is matched exactly on an import's name, and only when the import is bound to a runtime
// library (owner decision 4, 2026-11-17): by the ELF symbol version when the import has one,
// otherwise by DT_NEEDED when every needed library is a runtime library; on PE by the DLL that the
// import names. Every mark records the evidence (its provenance). The mark is a static assumption:
// a library preloaded at run time (`LD_PRELOAD`) could define the same name and return.

#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <string_view>

#include "donkey/binary/image.h"

namespace donkey {

/// True for a name on the fixed list of functions that never return (C, POSIX, glibc, the C++
/// runtime and the Windows API). `error` is not on it: it returns when its status is zero.
[[nodiscard]] bool is_known_no_return_name(std::string_view name) noexcept;

/// True for a library the list's names may be bound to: the C library, the C++ runtime, libgcc
/// and the Windows kernel and C runtime DLLs. ELF names are matched exactly (`libc.so.6`) or by
/// family (`libc.musl-x86_64.so.1`); PE names without regard to case.
[[nodiscard]] bool is_runtime_library(std::string_view name) noexcept;

/// The no-return imports of an image, keyed by the address a call reaches them through: each
/// stub address of `stubs` (address -> import, as plt_stub_imports and the PE import thunks give)
/// and each slot address of `slots` (GOT or IAT slot -> import). The value is the provenance,
/// `known-name:abort version:GLIBC_2.2.5 file:libc.so.6`, `known-name:abort needed:libc.so.6`, or
/// `known-name:ExitProcess dll:KERNEL32.dll`. An import is left out when its provider is not shown
/// to be a runtime library, or when the version table cannot be read.
[[nodiscard]] std::map<std::uint64_t, std::string> bind_no_return_imports(
    const BinaryImage& image, std::span<const std::byte> data,
    const std::map<std::uint64_t, std::string>& stubs,
    const std::map<std::uint64_t, std::string>& slots);

}  // namespace donkey
