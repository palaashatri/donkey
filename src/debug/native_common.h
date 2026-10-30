#pragma once

// Helpers shared by the native debugger backends. Nothing here touches the
// OS; the platform files own all process control.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/debug/debug.h"

namespace donkey::debug::native {

/// One software breakpoint as the debugger sees it: the user-visible record,
/// the original bytes it replaced and whether those bytes are currently
/// patched in the target.
struct SoftwareBreakpoint {
  Breakpoint info;
  std::vector<std::byte> original;
  bool inserted = false;
  bool internal = false;  ///< temporary (entry, step-over, step-out); never listed
  std::string tag;        ///< why an internal breakpoint exists ("entry", "step")
};

inline Result<bool> invalid_state(const std::string& message) {
  return make_error<bool>(Status::InvalidInput, "debug.invalid_state", message);
}

/// Static image of the debuggee: what the analysis sees, used to translate
/// runtime addresses and to name stack frames.
struct StaticImage {
  std::optional<BinaryImage> image;
  std::uint64_t lowest = 0;   ///< page-aligned lowest mapped static VA
  std::uint64_t highest = 0;  ///< highest mapped static VA (exclusive)

  void load(const std::string& path, std::uint64_t page_size) {
    image.reset();
    lowest = highest = 0;
    auto loaded = load_binary_file(path);
    if (!loaded) {
      return;
    }
    image = std::move(loaded.value());
    bool first = true;
    for (const Segment& segment : image->segments) {
      if (segment.virtual_size == 0) {
        continue;
      }
      const std::uint64_t start = segment.virtual_address & ~(page_size - 1);
      const std::uint64_t end = segment.virtual_address + segment.virtual_size;
      if (first || start < lowest) {
        lowest = start;
      }
      if (first || end > highest) {
        highest = end;
      }
      first = false;
    }
    if (first && image->image_base != 0) {
      lowest = image->image_base;
      highest = image->image_base + page_size;
    }
  }

  /// A symbol that names code: a function, or an export / untyped symbol
  /// that lies in an executable segment (PE exports carry no type or size).
  [[nodiscard]] bool is_code_symbol(const Symbol& symbol) const {
    if (symbol.imported || symbol.address == 0 || symbol.name.empty()) {
      return false;
    }
    if (symbol.kind == SymbolKind::Function) {
      return true;
    }
    if (symbol.kind != SymbolKind::Export && symbol.kind != SymbolKind::Unknown) {
      return false;
    }
    const Segment* segment = image->segment_for_va(symbol.address);
    return segment != nullptr && segment->executable;
  }

  /// True when `static_address` is the first instruction of a known function
  /// (before its prologue has set up a frame).
  [[nodiscard]] bool is_function_start(std::uint64_t static_address) const {
    if (!image) {
      return false;
    }
    for (const Symbol& symbol : image->symbols) {
      if (symbol.address == static_address && is_code_symbol(symbol)) {
        return true;
      }
    }
    return false;
  }

  /// Start of the function containing `static_address`, if a symbol says so.
  [[nodiscard]] std::optional<std::uint64_t> function_start(std::uint64_t static_address) const {
    if (!image) {
      return std::nullopt;
    }
    const Symbol* best = nullptr;
    for (const Symbol& symbol : image->symbols) {
      if (symbol.address > static_address || !is_code_symbol(symbol)) {
        continue;
      }
      if (symbol.size != 0 && static_address >= symbol.address + symbol.size) {
        continue;
      }
      if (best == nullptr || symbol.address > best->address) {
        best = &symbol;
      }
    }
    if (best == nullptr) {
      return std::nullopt;
    }
    return best->address;
  }

  /// Name of the symbol containing `static_address`, or empty.
  [[nodiscard]] std::string function_at(std::uint64_t static_address) const {
    if (!image) {
      return {};
    }
    const Symbol* best = nullptr;
    for (const Symbol& symbol : image->symbols) {
      if (symbol.address > static_address || !is_code_symbol(symbol)) {
        continue;
      }
      if (symbol.size != 0 && static_address >= symbol.address + symbol.size) {
        continue;
      }
      if (best == nullptr || symbol.address > best->address) {
        best = &symbol;
      }
    }
    return best != nullptr ? best->name : std::string();
  }
};

/// Overlay the original bytes of inserted breakpoints onto a memory read so
/// callers never see the debugger's own trap instructions.
inline void hide_breakpoints(const std::vector<SoftwareBreakpoint>& breakpoints,
                             std::uint64_t address, std::vector<std::byte>& bytes) {
  for (const SoftwareBreakpoint& bp : breakpoints) {
    if (!bp.inserted) {
      continue;
    }
    for (std::size_t i = 0; i < bp.original.size(); ++i) {
      const std::uint64_t at = bp.info.address + i;
      if (at >= address && at - address < bytes.size()) {
        bytes[static_cast<std::size_t>(at - address)] = bp.original[i];
      }
    }
  }
}

/// After a user write, keep inserted breakpoints armed: the written bytes
/// become the new "original" bytes and the trap is re-applied by the caller.
/// Returns the indices of breakpoints overlapped by the write.
inline std::vector<std::size_t> absorb_write(std::vector<SoftwareBreakpoint>& breakpoints,
                                             std::uint64_t address,
                                             const std::vector<std::byte>& bytes) {
  std::vector<std::size_t> touched;
  for (std::size_t index = 0; index < breakpoints.size(); ++index) {
    SoftwareBreakpoint& bp = breakpoints[index];
    if (!bp.inserted) {
      continue;
    }
    bool hit = false;
    for (std::size_t i = 0; i < bp.original.size(); ++i) {
      const std::uint64_t at = bp.info.address + i;
      if (at >= address && at - address < bytes.size()) {
        bp.original[i] = bytes[static_cast<std::size_t>(at - address)];
        hit = true;
      }
    }
    if (hit) {
      touched.push_back(index);
    }
  }
  return touched;
}

}  // namespace donkey::debug::native
