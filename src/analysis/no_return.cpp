#include "donkey/analysis/no_return.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <map>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

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
  static constexpr std::array<std::string_view, 8> kCrt{
      "abort", "exit", "_exit", "_Exit", "quick_exit", "longjmp", "_CxxThrowException",
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
      return file == "libc.so.6" || file == "libc.so.7" || file == "libpthread.so.0" ||
             (starts_with(file, "libc.musl-") && ends_with(file, ".so.1")) ||
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

std::map<std::uint64_t, std::string> bind_no_return_imports(
    const BinaryImage& image, std::span<const std::byte> data,
    const std::map<std::uint64_t, std::string>& stubs,
    const std::map<std::uint64_t, std::string>& slots) {
  std::map<std::uint64_t, std::string> marks;
  // The provenance of each import name that is bound to a runtime library, or nothing.
  std::map<std::string, std::string> bound;
  auto consider = [&](const std::string& name) {
    if (bound.contains(name) || !is_known_no_return_name(name)) {
      return;
    }
    bound.emplace(name, std::string());
  };
  for (const auto& [address, name] : stubs) {
    consider(name);
  }
  for (const auto& [address, name] : slots) {
    consider(name);
  }
  if (bound.empty()) {
    return marks;
  }
  if (image.format == BinaryFormat::Elf) {
    const KnownName* entry = nullptr;
    auto versions = read_import_versions(image, data);
    const ElfLibraryNames libraries = read_library_names(image, data);
    // An unversioned import is bound by DT_NEEDED only when every needed library is a runtime
    // library of the name's kind: another needed library could export the same name.
    for (auto& [name, provenance] : bound) {
      entry = known(name);
      if (entry == nullptr) {
        continue;
      }
      if (!versions) {
        continue;  // an unreadable version table: no mark from it, and no fallback either
      }
      if (const auto version = versions.value().find(name); version != versions.value().end()) {
        if (elf_library_provides(version->second.file, entry->provider)) {
          provenance = "known-name:" + name + " version:" + version->second.version +
                       " file:" + version->second.file;
        }
        continue;
      }
      if (libraries.needed.empty()) {
        continue;
      }
      const bool all_runtime =
          std::all_of(libraries.needed.begin(), libraries.needed.end(),
                      [](const std::string& file) { return is_runtime_library(file); });
      const bool one_provides = std::any_of(
          libraries.needed.begin(), libraries.needed.end(),
          [entry](const std::string& file) { return elf_library_provides(file, entry->provider); });
      if (all_runtime && one_provides) {
        std::string needed;
        for (const std::string& file : libraries.needed) {
          needed += (needed.empty() ? "" : ",") + file;
        }
        provenance = "known-name:" + name + " needed:" + needed;
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
      if (dll_provides(dll, name)) {
        provenance = "known-name:" + name + " dll:" + dll;
      }
    }
  }
  for (const auto& [address, name] : stubs) {
    if (const auto it = bound.find(name); it != bound.end() && !it->second.empty()) {
      marks.emplace(address, it->second);
    }
  }
  for (const auto& [address, name] : slots) {
    if (const auto it = bound.find(name); it != bound.end() && !it->second.empty()) {
      marks.emplace(address, it->second);
    }
  }
  return marks;
}

}  // namespace donkey
