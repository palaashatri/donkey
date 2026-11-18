#pragma once

// The libraries an ELF executable loads, in the order the dynamic loader searches them, and which
// of them a symbol reference binds to (G24-T3). This is what proves where an import comes from:
// the loader binds a reference to the first library in its global scope that defines the name in a
// form the reference accepts, so a version need alone does not prove the provider (an unversioned
// definition in an earlier library also satisfies a versioned reference).
//
// Libraries are found by glibc's search (`_dl_map_object`), under an optional sysroot, and are only
// read, never run: DT_RPATH of the requesting object and of each object that loaded it (when the
// requester has no DT_RUNPATH), the configured `paths`, DT_RUNPATH, /etc/ld.so.cache, then the
// default directories. Whenever the model cannot know which file the loader takes, the answer is
// Unknown, never a guess: a search directory relative to the loader's working directory (an empty
// or relative DT_RPATH or DT_RUNPATH entry), `$LIB` and `$PLATFORM`, a copy in a `glibc-hwcaps` or
// legacy hardware-capability subdirectory, a cache entry for particular hardware, a name found in
// two different default directories, a file this reader refuses that the loader may accept, and a
// dynamic table that cannot be read in full.
//
// Not modelled: the run-time environment. LD_PRELOAD and LD_LIBRARY_PATH are not read; a caller
// that runs the program with them gives the same directories as `paths` (LD_LIBRARY_PATH's place in
// the search) and its preloads in the sysroot's /etc/ld.so.preload. dlopen is not modelled.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/core/result.h"

namespace donkey {

/// Where the libraries of an image are looked for.
struct ElfLibrarySearch {
  /// A directory that stands for the target's `/`: every absolute search directory and DT_NEEDED
  /// path, /etc/ld.so.cache and /etc/ld.so.preload are read under it, and symbolic links inside it
  /// are followed inside it. Empty: the host's own root.
  std::string sysroot;
  /// Directories of this machine (not under the sysroot) searched after DT_RPATH and before
  /// DT_RUNPATH, the place LD_LIBRARY_PATH takes.
  std::vector<std::string> paths;
  /// Read /etc/ld.so.preload, /etc/ld.so.cache and the default directories.
  bool system_directories = true;
  /// Libraries waiting to be looked for at once (kMaxScopeQueue). Past it, no later library is
  /// queued and the rest of the scope is not known.
  std::size_t queue_limit = 4096;
};

inline constexpr std::size_t kMaxScopeLibraries = 256;
/// Libraries waiting to be looked for at once; past it the rest of the scope is not known.
inline constexpr std::size_t kMaxScopeQueue = 4096;  // ElfLibrarySearch::queue_limit's default
inline constexpr std::uint64_t kMaxScopeLibraryBytes = std::uint64_t{1} << 30;
inline constexpr std::uint64_t kMaxLoaderCacheBytes = std::uint64_t{64} << 20;

/// One library of the scope.
struct ElfScopeLibrary {
  std::string name;  ///< as DT_NEEDED (or ld.so.preload) names it
  /// The file found, with `/` separators on every host (under the sysroot as the search spelled it,
  /// before symbolic links); empty when none was found.
  std::string path;
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

/// One entry of glibc's /etc/ld.so.cache (format `glibc-ld.so.cache1.1`, alone or after the old
/// `ld.so-1.7.0` table).
struct ElfLoaderCacheEntry {
  std::string name;  ///< the soname the entry is looked up by
  std::string path;  ///< the file, as a path of the target
  std::int32_t flags = 0;
  std::uint64_t hwcap = 0;  ///< non-zero: an entry for particular hardware
};

/// Reads an ld.so.cache image. Refuses (with a diagnostic) a file of another format or version,
/// a big-endian cache, and any entry or name outside the file.
[[nodiscard]] Result<std::vector<ElfLoaderCacheEntry>> read_loader_cache(
    std::span<const std::byte> bytes);

class ElfLoadScope {
 public:
  /// The scope of the 64-bit ELF `image` (read from `image.path`, for `$ORIGIN`): ld.so.preload,
  /// then DT_NEEDED breadth first, each library once (by name, soname or file), each looked for as
  /// the file header describes. At most kMaxScopeLibraries libraries are read.
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

  /// Where a reference to `name` binds, by glibc's `check_match`. With a version (`version`
  /// non-empty): a library without symbol versions, a definition of the same version, or (unless
  /// the reference's version need is `hidden`) a non-hidden definition whose index has no version
  /// of its own. Without one: a definition of index 0 to 2, or the only non-hidden versioned one.
  [[nodiscard]] ElfBinding lookup(const std::string& name, const std::string& version,
                                  bool hidden = false) const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace donkey
