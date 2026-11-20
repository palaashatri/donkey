#include "donkey/analysis/no_return.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <map>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "donkey/binary/elf_load_scope.h"
#include "donkey/binary/elf_versions.h"
#include "donkey/binary/link.h"

namespace donkey {
namespace {

/// Which runtime may provide a name: the C library, the C++ runtime, the unwinder, or Windows.
enum class Provider { C, Cxx, Unwind, Windows, WindowsCrt };

struct KnownName {
  std::string_view name;
  Provider provider;
};

// The fixed list (ledger G24-T3, owner decision 4 of 2026-11-17). Each name never returns to its
// caller on any input. `error`, `error_at_line` (return when the status is 0), `raise`, `kill`
// and `RaiseException` (continuable) are deliberately absent.
constexpr std::array<KnownName, 33> kKnownNames{{
    {"abort", Provider::C},
    {"exit", Provider::C},
    {"_exit", Provider::C},
    {"_Exit", Provider::C},
    {"quick_exit", Provider::C},
    {"__stack_chk_fail", Provider::C},
    {"__fortify_fail", Provider::C},
    {"__chk_fail", Provider::C},
    {"__assert_fail", Provider::C},
    {"__assert_perror_fail", Provider::C},
    {"__assert", Provider::C},  // FreeBSD and musl's assert
    {"err", Provider::C},
    {"errx", Provider::C},
    {"verr", Provider::C},
    {"verrx", Provider::C},
    {"longjmp", Provider::C},
    {"_longjmp", Provider::C},
    {"siglongjmp", Provider::C},
    {"__longjmp_chk", Provider::C},
    {"pthread_exit", Provider::C},
    {"__libc_fatal", Provider::C},
    {"__cxa_throw", Provider::Cxx},
    {"__cxa_rethrow", Provider::Cxx},
    {"__cxa_bad_cast", Provider::Cxx},
    {"__cxa_bad_typeid", Provider::Cxx},
    {"_ZSt9terminatev", Provider::Cxx},  // std::terminate()
    {"_Unwind_Resume", Provider::Unwind},
    {"ExitProcess", Provider::Windows},
    {"ExitThread", Provider::Windows},
    {"FatalExit", Provider::Windows},
    {"FatalAppExitA", Provider::Windows},
    {"FatalAppExitW", Provider::Windows},
    {"_invalid_parameter_noinfo_noreturn", Provider::WindowsCrt},
}};

/// The CRT names that also never return when a Windows C runtime provides them.
bool is_windows_crt_name(std::string_view name) {
  static constexpr std::array<std::string_view, 8> kCrt{"abort",
                                                        "exit",
                                                        "_exit",
                                                        "_Exit",
                                                        "quick_exit",
                                                        "longjmp",
                                                        "_CxxThrowException",
                                                        "_invalid_parameter_noinfo_noreturn"};
  return std::find(kCrt.begin(), kCrt.end(), name) != kCrt.end();
}

const KnownName* known(std::string_view name) {
  for (const KnownName& entry : kKnownNames) {
    if (entry.name == name) {
      return &entry;
    }
  }
  return nullptr;
}

std::string lower(std::string_view text) {
  std::string out(text);
  std::transform(out.begin(), out.end(), out.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return out;
}

bool starts_with(std::string_view text, std::string_view prefix) {
  return text.substr(0, prefix.size()) == prefix;
}

bool ends_with(std::string_view text, std::string_view suffix) {
  return text.size() >= suffix.size() && text.substr(text.size() - suffix.size()) == suffix;
}

/// The ELF libraries that may provide a name of `provider`.
bool elf_library_provides(std::string_view file, Provider provider) {
  switch (provider) {
    case Provider::C:
      // `libc.so` is musl's own name for itself (a glibc program never needs it: glibc's libc.so
      // is a linker script).
      return file == "libc.so.6" || file == "libc.so.7" || file == "libpthread.so.0" ||
             file == "libc.so" || (starts_with(file, "libc.musl-") && ends_with(file, ".so.1")) ||
             (starts_with(file, "ld-musl-") && ends_with(file, ".so.1"));
    case Provider::Cxx:
      return file == "libstdc++.so.6" || file == "libc++.so.1" || file == "libc++abi.so.1" ||
             file == "libcxxrt.so.1";
    case Provider::Unwind:
      return file == "libgcc_s.so.1" || file == "libunwind.so.1" || file == "libunwind.so.8";
    case Provider::Windows:
    case Provider::WindowsCrt:
      return false;
  }
  return false;
}

/// The PE DLLs that may provide `name`.
bool dll_provides(std::string_view dll, std::string_view name) {
  const std::string l = lower(dll);
  const KnownName* entry = known(name);
  if (entry != nullptr && entry->provider == Provider::Windows) {
    return l == "kernel32.dll" || l == "kernelbase.dll";
  }
  if (!is_windows_crt_name(name)) {
    return false;
  }
  return l == "msvcrt.dll" || l == "ucrtbase.dll" || l == "ucrtbased.dll" ||
         starts_with(l, "api-ms-win-crt-") || (starts_with(l, "msvcr") && ends_with(l, ".dll")) ||
         (starts_with(l, "vcruntime") && ends_with(l, ".dll"));
}

}  // namespace

bool is_known_no_return_name(std::string_view name) noexcept {
  return known(name) != nullptr || is_windows_crt_name(name);
}

bool is_runtime_library(std::string_view name) noexcept {
  for (const Provider provider : {Provider::C, Provider::Cxx, Provider::Unwind}) {
    if (elf_library_provides(name, provider)) {
      return true;
    }
  }
  return dll_provides(name, "ExitProcess") || dll_provides(name, "abort");
}

namespace {

/// Whether a PE DLL is a Microsoft C runtime: every C library function it exports behaves as ISO C
/// says.
bool is_c_runtime_dll(std::string_view dll) {
  const std::string l = lower(dll);
  return l == "msvcrt.dll" || l == "ucrtbase.dll" || l == "ucrtbased.dll" ||
         starts_with(l, "api-ms-win-crt-") || (starts_with(l, "msvcr") && ends_with(l, ".dll"));
}

}  // namespace

RuntimeImportBindings bind_runtime_imports(const BinaryImage& image,
                                           std::span<const std::byte> data,
                                           const std::map<std::uint64_t, std::string>& stubs,
                                           const std::map<std::uint64_t, std::string>& slots,
                                           const ElfLibrarySearch& search,
                                           std::vector<std::string>* unverified) {
  RuntimeImportBindings out;
  // For each import name: the provenance of its no-return mark and of its C library binding, or
  // nothing.
  struct Bound {
    std::string no_return;
    std::string c_library;
  };
  std::map<std::string, Bound> bound;
  for (const auto& [address, name] : stubs) {
    bound.emplace(name, Bound{});
  }
  for (const auto& [address, name] : slots) {
    bound.emplace(name, Bound{});
  }
  if (bound.empty()) {
    return out;
  }
  if (image.format == BinaryFormat::Elf) {
    // An ELF import is bound where the dynamic loader binds it: the first library of the load
    // scope that defines the name in a form the reference accepts. Every reference of the name
    // (each version it is imported with) must bind to a library of the right kind; a library the
    // walk cannot find or read before the binding leaves the name unbound.
    auto references = read_import_references(image, data);
    if (!references) {
      if (unverified != nullptr) {
        unverified->push_back("the symbol version table: " + references.diagnostic().message);
      }
      return out;  // an unreadable version table: nothing is bound
    }
    // Each (version, hidden) form a name is imported with: every one must bind.
    std::map<std::string, std::set<std::pair<std::string, bool>>> versions_of;
    std::set<std::string> unresolved;
    for (const ElfImportReference& reference : references.value()) {
      if (!bound.contains(reference.name)) {
        continue;
      }
      if (reference.unresolved) {
        unresolved.insert(reference.name);
      }
      versions_of[reference.name].emplace(reference.version, reference.hidden);
    }
    const ElfLoadScope scope = ElfLoadScope::build(image, data, search);
    for (auto& [name, provenance] : bound) {
      const KnownName* entry = known(name);
      const auto versions = versions_of.find(name);
      if (versions == versions_of.end()) {
        continue;
      }
      if (unresolved.contains(name)) {
        if (unverified != nullptr && entry != nullptr) {
          unverified->push_back(name + ": its symbol version could not be read");
        }
        continue;
      }
      std::string evidence;
      bool no_return = entry != nullptr;  // still proven for the fixed list's kind of library
      bool c_library = true;              // still proven to be the C library's
      for (const auto& [version, hidden] : versions->second) {
        const ElfBinding binding = scope.lookup(name, version, hidden);
        if (binding.outcome == ElfBinding::Outcome::Unknown) {
          if (unverified != nullptr && entry != nullptr) {
            unverified->push_back(name + ": " + binding.reason);
          }
          no_return = c_library = false;
          break;
        }
        if (binding.outcome != ElfBinding::Outcome::Bound ||
            binding.library == scope.image_index()) {
          no_return = c_library = false;
          break;
        }
        // The library's own SONAME is only what it says about itself: the name the executable's
        // DT_NEEDED (or ld.so.preload) loaded it by must be a runtime library's name as well, so a
        // library that calls itself libc.so.6 under another name is not taken for the C library.
        const ElfScopeLibrary& library = scope.libraries()[binding.library];
        const std::string loaded_as = library.name.substr(library.name.find_last_of('/') + 1);
        const auto provides = [&](Provider provider) {
          return elf_library_provides(loaded_as, provider) &&
                 (library.soname.empty() || elf_library_provides(library.soname, provider));
        };
        no_return = no_return && provides(entry->provider);
        c_library = c_library && provides(Provider::C);
        if (!no_return && !c_library) {
          break;
        }
        const std::string& library_name = library.soname.empty() ? loaded_as : library.soname;
        evidence += (version.empty() ? std::string(" unversioned") : " version:" + version) +
                    " bound:" + library_name + " path:" + library.path;
      }
      if (evidence.empty()) {
        continue;
      }
      if (no_return) {
        provenance.no_return = "known-name:" + name + evidence;
      }
      if (c_library) {
        provenance.c_library = "c-library:" + name + evidence;
      }
    }
  } else if (image.format == BinaryFormat::Pe) {
    // Each PE import names its DLL. A name imported from two DLLs is ambiguous.
    std::map<std::string, std::set<std::string>> dlls;
    for (const Symbol& symbol : image.symbols) {
      if (symbol.imported) {
        dlls[symbol.name].insert(symbol.module);
      }
    }
    for (auto& [name, provenance] : bound) {
      const auto found = dlls.find(name);
      if (found == dlls.end() || found->second.size() != 1) {
        continue;
      }
      const std::string& dll = *found->second.begin();
      if (is_known_no_return_name(name) && dll_provides(dll, name)) {
        provenance.no_return = "known-name:" + name + " dll:" + dll;
      }
      if (is_c_runtime_dll(dll)) {
        provenance.c_library = "c-library:" + name + " dll:" + dll;
      }
    }
  }
  const auto mark = [&](std::uint64_t address, const std::string& name) {
    const auto it = bound.find(name);
    if (it == bound.end()) {
      return;
    }
    if (!it->second.no_return.empty()) {
      out.no_return.emplace(address, it->second.no_return);
    }
    if (!it->second.c_library.empty()) {
      out.c_library.emplace(address, BoundImport{name, it->second.c_library});
    }
  };
  for (const auto& [address, name] : stubs) {
    mark(address, name);
  }
  for (const auto& [address, name] : slots) {
    mark(address, name);
  }
  return out;
}

std::map<std::uint64_t, std::string> bind_no_return_imports(
    const BinaryImage& image, std::span<const std::byte> data,
    const std::map<std::uint64_t, std::string>& stubs,
    const std::map<std::uint64_t, std::string>& slots, const ElfLibrarySearch& search,
    std::vector<std::string>* unverified) {
  return bind_runtime_imports(image, data, stubs, slots, search, unverified).no_return;
}

}  // namespace donkey
