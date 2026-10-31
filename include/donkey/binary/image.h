#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "donkey/binary/byte_buffer.h"
#include "donkey/binary/byte_reader.h"
#include "donkey/core/cancellation.h"
#include "donkey/core/ids.h"
#include "donkey/core/result.h"
#include "donkey/core/status.h"

namespace donkey {

enum class BinaryFormat : std::uint8_t { Unknown = 0, Raw, Elf, Pe, MachO };
enum class Architecture : std::uint8_t { Unknown = 0, X86, X86_64, Arm, AArch64, RiscV64 };

enum class SymbolKind : std::uint8_t {
  Unknown = 0,
  Function,
  Object,
  Section,
  File,
  Import,
  Export,
};

enum class SymbolBinding : std::uint8_t { Unknown = 0, Local, Global, Weak };

const char* format_name(BinaryFormat format) noexcept;
const char* architecture_name(Architecture architecture) noexcept;
std::optional<Architecture> parse_architecture(std::string_view name) noexcept;
const char* symbol_kind_name(SymbolKind kind) noexcept;
const char* symbol_binding_name(SymbolBinding binding) noexcept;

struct Segment {
  std::uint32_t index = 0;
  std::string name;
  std::uint64_t file_offset = 0;
  std::uint64_t file_size = 0;
  std::uint64_t virtual_address = 0;
  std::uint64_t virtual_size = 0;
  bool readable = false;
  bool writable = false;
  bool executable = false;
};

struct Section {
  SectionId id;
  std::string name;
  std::string type;
  std::uint64_t file_offset = 0;
  std::uint64_t file_size = 0;
  std::uint64_t address = 0;
  std::uint64_t virtual_size = 0;
  std::uint64_t alignment = 0;
  bool readable = false;
  bool writable = false;
  bool executable = false;
  bool has_file_data = true;
  /// ELF SHF_COMPRESSED: the bytes are a compression header plus zlib/zstd
  /// data, not the section contents.
  bool compressed = false;
};

struct Symbol {
  SymbolId id;
  std::string name;
  std::string module;
  std::uint64_t address = 0;
  std::uint64_t size = 0;
  SymbolKind kind = SymbolKind::Unknown;
  SymbolBinding binding = SymbolBinding::Unknown;
  bool imported = false;
  bool exported = false;
};

/// A parsed immutable view of one binary file. Offsets in this type follow the
/// AddressSpace rules: file offsets point into the container file, virtual
/// addresses are preferred addresses before runtime relocation.
struct BinaryImage {
  std::string path;
  BinaryFormat format = BinaryFormat::Unknown;
  Architecture architecture = Architecture::Unknown;
  Endian endian = Endian::Little;
  unsigned bits = 0;
  std::uint64_t image_base = 0;
  std::uint64_t entry_point = 0;
  std::uint64_t file_size = 0;
  std::string sha256;
  std::string format_detail;

  std::vector<Segment> segments;
  std::vector<Section> sections;
  std::vector<Symbol> symbols;
  std::vector<Architecture> fat_architectures;

  /// True when the loader understood the structure but some metadata (for
  /// example a missing entry point) is unavailable. Never set for fatal errors.
  bool partial = false;
  std::vector<Diagnostic> diagnostics;

  [[nodiscard]] bool has_entry_point() const noexcept { return entry_point != 0; }
  [[nodiscard]] bool is_64_bit() const noexcept { return bits == 64; }

  [[nodiscard]] Result<std::uint64_t> va_to_file_offset(std::uint64_t va) const;
  [[nodiscard]] Result<std::uint64_t> file_offset_to_va(std::uint64_t file_offset) const;
  [[nodiscard]] const Section* section_for_va(std::uint64_t va) const noexcept;
  [[nodiscard]] const Segment* segment_for_va(std::uint64_t va) const noexcept;
  [[nodiscard]] const Symbol* symbol_at(std::uint64_t va) const noexcept;

  void add_diagnostic(Status status, std::string code, std::string message,
                      std::optional<std::uint64_t> offset = std::nullopt);
};

struct LoadOptions {
  /// Guard against accidental multi-gigabyte allocations on hostile input.
  std::uint64_t max_file_bytes = 1ULL << 31;
  /// Preferred architecture for fat Mach-O slice selection or raw binary import.
  Architecture preferred_architecture = Architecture::Unknown;
  /// Treat the file as raw bytes with explicit mapping metadata instead of
  /// auto-detecting container headers.
  bool force_raw = false;
  unsigned raw_bits = 0;
  Endian raw_endian = Endian::Little;
  std::uint64_t raw_base_address = 0;
  std::uint64_t raw_entry_point = 0;
  bool has_raw_entry_point = false;
  /// Treat the file as untrusted and parse within an isolated OS process boundary.
  bool isolate = false;
  /// Token used to observe cancellation during file loading.
  CancellationToken cancellation_token;
  /// Files at least this large are memory-mapped read-only instead of copied
  /// (see ByteBuffer). 0 maps every non-empty file.
  std::uint64_t map_threshold_bytes = 64ULL << 20;
  /// Optional progress report while reading and hashing: (bytes done, total).
  /// Called on the loading thread.
  std::function<void(std::uint64_t, std::uint64_t)> progress;
};

/// A parsed image together with the bytes it was parsed from. Callers that
/// decode or display hex keep one copy; the image never owns mutable state.
struct LoadedBinary {
  BinaryImage image;
  ByteBuffer data;
};

/// Read and parse a file from disk. Opening a binary never executes it.
[[nodiscard]] Result<LoadedBinary> load_binary(const std::string& path,
                                               const LoadOptions& options = {});

/// Parse-only convenience wrapper for callers that do not need the bytes.
[[nodiscard]] Result<BinaryImage> load_binary_file(const std::string& path,
                                                   const LoadOptions& options = {});

/// Parse an in-memory image. Used by tests, fuzzing and embedded callers.
[[nodiscard]] Result<BinaryImage> parse_binary(std::span<const std::byte> data,
                                               std::string path = {},
                                               const LoadOptions& options = {});

}  // namespace donkey
