#pragma once

// Windows minidumps (G15-T3): the threads, modules, memory ranges and exception a dump records,
// read from the stream directory by the layout Microsoft documents for MINIDUMP_HEADER and its
// streams. Nothing here runs the dump. The memory of a dump is read through read_minidump_memory,
// because a dump is not mapped the way an executable is.

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "donkey/core/result.h"

namespace donkey {

struct MinidumpLimits {
  std::size_t max_streams = 4'096;
  std::size_t max_threads = 4'096;
  std::size_t max_modules = 100'000;
  std::size_t max_memory_ranges = 1'000'000;
  std::size_t max_name_length = 4'096;  ///< characters of a module name
};

struct MinidumpThread {
  std::uint32_t id = 0;
  std::uint64_t stack_start = 0;  ///< the stack's address range (its size is in `stack_size`)
  std::uint64_t stack_size = 0;
  /// Registers from the thread's context, in the order the context stores them. Empty when the
  /// context is missing or is for an architecture this reader does not decode.
  std::vector<std::pair<std::string, std::uint64_t>> registers;
  std::uint64_t pc = 0;  ///< the instruction pointer, when the registers are known
  std::uint64_t sp = 0;  ///< the stack pointer, when the registers are known
};

struct MinidumpModule {
  std::string name;
  std::uint64_t base = 0;
  std::uint32_t size = 0;
  std::uint32_t timestamp = 0;
  std::uint32_t checksum = 0;
};

/// A range of the dump's memory: its address, its length, and where its bytes are in the dump.
struct MinidumpMemory {
  std::uint64_t address = 0;
  std::uint64_t size = 0;
  std::uint64_t file_offset = 0;
};

struct MinidumpException {
  std::uint32_t thread_id = 0;
  std::uint32_t code = 0;
  std::uint64_t address = 0;
};

struct MinidumpInfo {
  std::uint16_t processor_architecture = 0xffff;  ///< MINIDUMP's PROCESSOR_ARCHITECTURE value
  std::uint32_t major_version = 0;
  std::uint32_t minor_version = 0;
  std::uint32_t build_number = 0;
  std::vector<MinidumpThread> threads;
  std::vector<MinidumpModule> modules;
  std::vector<MinidumpMemory> memory;
  bool has_exception = false;
  MinidumpException exception;
  std::vector<Diagnostic> diagnostics;
  bool partial = false;
  /// The architecture as text ("x86-64", "x86", "arm64", ...), or "unknown".
  [[nodiscard]] std::string architecture_name() const;
};

/// True when `file` begins with the MINIDUMP signature "MDMP".
[[nodiscard]] bool is_minidump(std::span<const std::byte> file) noexcept;

/// Reads the streams a dump names. A bad signature or an unreadable directory is an error
/// (`minidump.not_a_minidump` or `minidump.bad_directory`). A stream or record that runs past the
/// file, or a count over a limit, is a diagnostic and the read keeps what came before it. A
/// thread context for an architecture this reader does not decode leaves the registers empty and
/// the result partial.
[[nodiscard]] Result<MinidumpInfo> read_minidump(std::span<const std::byte> file,
                                                 const MinidumpLimits& limits = {});

/// Copies `size` bytes of the dump's memory at `address`. The bytes must lie within one range the
/// dump records; a range the dump does not hold is `minidump.memory_absent`, and a range that
/// runs past the file is `minidump.memory_truncated`.
[[nodiscard]] Result<std::vector<std::byte>> read_minidump_memory(std::span<const std::byte> file,
                                                                  const MinidumpInfo& info,
                                                                  std::uint64_t address,
                                                                  std::uint64_t size);

}  // namespace donkey
