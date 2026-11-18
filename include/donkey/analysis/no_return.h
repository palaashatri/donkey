#pragma once

// No-return calls (G24-T3). A call to `abort`, `exit` or another function on a fixed list does not
// come back, so the code after it is not this path's code and the function does not return there.
// The list is matched exactly on an import's name, and only when the import is shown to bind to a
// runtime library: on ELF by walking the libraries the dynamic loader would load, in its order,
// and taking the first definition each reference (with its symbol version, or without one)
// accepts (ElfLoadScope); on PE by the DLL that the import names. A library the walk cannot find
// or read before the binding leaves the import unmarked. Every mark records the evidence (its
// provenance). What the file and the system cannot show is not modelled: a library preloaded by
// the environment (`LD_PRELOAD`) could define the same name and return.

#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "donkey/binary/elf_load_scope.h"
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
/// `known-name:abort version:GLIBC_2.2.5 bound:libc.so.6 path:/lib/x86_64-linux-gnu/libc.so.6`
/// (one `version`/`unversioned` part per way the image imports the name), or
/// `known-name:ExitProcess dll:KERNEL32.dll`. An import is left out when its provider is not shown
/// to be a runtime library, or when the version table cannot be read; each name left out because
/// a library could not be found or read is added to `unverified` with the reason.
[[nodiscard]] std::map<std::uint64_t, std::string> bind_no_return_imports(
    const BinaryImage& image, std::span<const std::byte> data,
    const std::map<std::uint64_t, std::string>& stubs,
    const std::map<std::uint64_t, std::string>& slots, const ElfLibrarySearch& search = {},
    std::vector<std::string>* unverified = nullptr);

/// An import shown to bind to the C library (G21-T7): its name and the evidence, in the form of
/// bind_no_return_imports' provenance with `c-library:` in place of `known-name:`.
struct BoundImport {
  std::string name;
  std::string provenance;
};

/// Both bindings an analysis needs from one walk of the load scope, keyed like
/// bind_no_return_imports: the no-return marks, and every import whose every reference binds to the
/// C library (on ELF, a library of the C library's names; on PE, a Microsoft C runtime DLL).
struct RuntimeImportBindings {
  std::map<std::uint64_t, std::string> no_return;
  std::map<std::uint64_t, BoundImport> c_library;
};

[[nodiscard]] RuntimeImportBindings bind_runtime_imports(
    const BinaryImage& image, std::span<const std::byte> data,
    const std::map<std::uint64_t, std::string>& stubs,
    const std::map<std::uint64_t, std::string>& slots, const ElfLibrarySearch& search = {},
    std::vector<std::string>* unverified = nullptr);

}  // namespace donkey
