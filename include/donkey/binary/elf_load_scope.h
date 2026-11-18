#pragma once

// The libraries an ELF executable loads, in the order the dynamic loader searches them, and which
// of them a symbol reference binds to (G24-T3). This is what proves where an import comes from:
// the loader binds a reference to the first library in its global scope that defines the name in a
// form the reference accepts, so a version need alone does not prove the provider (an unversioned
// definition in an earlier library also satisfies a versioned reference). Libraries are found the
// way glibc's ld.so finds them, under an optional sysroot, and are only read, never run.
//
// Not modelled: LD_PRELOAD, LD_LIBRARY_PATH and other run-time environment (a project states the
// static assumption), dlopen, and libraries that a path in DT_NEEDED names relative to the current
// directory.

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "donkey/binary/image.h"

namespace donkey {

/// Where the libraries of an image are looked for.
struct ElfLibrarySearch {
  /// A directory that stands for `/`: every absolute search directory, /etc/ld.so.conf and
  /// /etc/ld.so.preload are read under it. Empty: the host's own root.
  std::string sysroot;
  /// Directories of this machine (not under the sysroot) searched after DT_RPATH and before
  /// DT_RUNPATH, the place LD_LIBRARY_PATH takes.
  std::vector<std::string> paths;
  /// Read /etc/ld.so.preload, /etc/ld.so.conf and the default directories.
  bool system_directories = true;
};

inline constexpr std::size_t kMaxScopeLibraries = 256;
inline constexpr std::uint64_t kMaxScopeLibraryBytes = std::uint64_t{1} << 30;

/// One library of the scope.
struct ElfScopeLibrary {
  std::string name;  ///< as DT_NEEDED (or ld.so.preload) names it
  std::string path;  ///< the file found; empty when none was found
  std::string soname;
  bool preloaded = false;
};

/// Where a reference binds.
struct ElfBinding {
  enum class Outcome : std::uint8_t {
    Bound,       ///< `library` is the first library of the scope whose definition it accepts
    NotDefined,  ///< every library of the scope was read, and none defines it acceptably
    Unknown,     ///< a library before any acceptable definition could not be found or read
  };
  Outcome outcome = Outcome::Unknown;
  std::size_t library = 0;  ///< index into ElfLoadScope::libraries() when Bound
  std::string reason;       ///< why, when Unknown
};

class ElfLoadScope {
 public:
  /// The scope of the 64-bit ELF `image` (read from `path` for $ORIGIN): ld.so.preload, then
  /// DT_NEEDED breadth first, each library looked for in the loader's order: DT_RPATH (when the
  /// requesting object has no DT_RUNPATH, and the executable's), `search.paths`, DT_RUNPATH,
  /// the directories of /etc/ld.so.conf, then the default directories for the image's machine.
  /// A file of another class or machine is skipped, as the loader skips it. At most
  /// kMaxScopeLibraries libraries are read.
  static ElfLoadScope build(const BinaryImage& image, std::span<const std::byte> data,
                            const ElfLibrarySearch& search);

  /// A scope of images already in memory, in this order (the first is the executable), with no
  /// search: what tests and the fuzz target (`fuzz_load_scope`) look references up in.
  struct Input {
    std::string name;
    const BinaryImage* image = nullptr;  ///< null: a library that was not found
    std::span<const std::byte> data;
  };
  static ElfLoadScope from_images(std::span<const Input> inputs);

  ElfLoadScope();
  ~ElfLoadScope();
  ElfLoadScope(ElfLoadScope&&) noexcept;
  ElfLoadScope& operator=(ElfLoadScope&&) noexcept;

  [[nodiscard]] const std::vector<ElfScopeLibrary>& libraries() const;

  /// Where a reference to `name` binds: with a version (`version` non-empty) by glibc's rule for a
  /// versioned reference (a library without symbol versions, a definition of the same version, or
  /// a non-hidden unversioned one), without one by its rule for an unversioned reference (a
  /// definition of index 0 to 2, or the only non-hidden versioned one).
  [[nodiscard]] ElfBinding lookup(const std::string& name, const std::string& version) const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace donkey
