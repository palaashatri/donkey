#pragma once

// ELF core files (G15-T3): the threads and the file mappings a core records, read from its
// PT_NOTE segments. The memory of a core is its PT_LOAD segments, which the image already
// maps, so reading memory needs no separate path. Nothing here runs the core.

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/core/result.h"

namespace donkey {

struct CoreThread {
  std::uint32_t pid = 0;    ///< the thread id (LWP) from NT_PRSTATUS
  std::int32_t signal = 0;  ///< the signal that stopped the thread (si_signo)
  /// Registers in the order of the kernel's user_regs_struct (x86-64): name and value.
  std::vector<std::pair<std::string, std::uint64_t>> registers;
  std::uint64_t pc = 0;  ///< rip for x86-64; empty registers leave it 0
  std::uint64_t sp = 0;  ///< rsp for x86-64
};

/// A file mapping recorded by NT_FILE: the address range, the offset into the file and the
/// file's path.
struct CoreMapping {
  std::uint64_t start = 0;
  std::uint64_t end = 0;
  std::uint64_t file_offset = 0;
  std::string path;
};

struct CoreInfo {
  std::string process_name;  ///< pr_fname from NT_PRPSINFO (up to 15 characters)
  std::vector<CoreThread> threads;
  std::vector<CoreMapping> mappings;
  std::vector<Diagnostic> diagnostics;
  bool partial = false;
};

struct CoreOptions {
  std::size_t max_threads = 4'096;
  std::size_t max_mappings = 100'000;
  std::size_t max_notes = 100'000;
};

/// Reads the threads and mappings of an ELF core. The image must be a 64-bit, little-endian
/// ELF of type ET_CORE; anything else returns `core.not_a_core` (InvalidInput). Register names
/// and offsets are decoded for x86-64 only; a core of another machine keeps its threads and
/// mappings but has no register names, and is reported partial. Malformed notes stop the scan
/// with a diagnostic; threads and mappings read before that are kept.
[[nodiscard]] Result<CoreInfo> read_elf_core(const BinaryImage& image,
                                             std::span<const std::byte> data,
                                             const CoreOptions& options = {});

}  // namespace donkey
