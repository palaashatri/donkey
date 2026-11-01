#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/core/result.h"
#include "donkey/ir/ir.h"

namespace donkey {

/// Byte-addressed memory for the IR interpreter: read-only image sections
/// plus writable regions the caller adds (stack, argument buffers). Any
/// access outside a region is an error, never an invented value.
class IrEvalMemory {
 public:
  IrEvalMemory() = default;
  /// Map the image's sections read-only (file bytes; zero for no-file data).
  IrEvalMemory(const BinaryImage& image, std::span<const std::byte> file);

  /// Add a writable region at `base` holding `bytes`. Returns false if it
  /// overlaps an existing region.
  bool add_region(std::uint64_t base, std::vector<std::uint8_t> bytes, bool writable = true);
  [[nodiscard]] bool read(std::uint64_t address, std::size_t size, std::uint64_t& value) const;
  [[nodiscard]] bool write(std::uint64_t address, std::size_t size, std::uint64_t value);
  /// Bytes of the region that starts at `base` (for checking stores).
  [[nodiscard]] const std::vector<std::uint8_t>* region(std::uint64_t base) const;

 private:
  struct Region {
    std::uint64_t base = 0;
    std::vector<std::uint8_t> bytes;
    bool writable = false;
  };
  const Region* find(std::uint64_t address, std::size_t size) const;
  std::vector<Region> regions_;
};

enum class IrCallingConvention : std::uint8_t {
  SysV64,   ///< rdi, rsi, rdx, rcx, r8, r9, then the stack
  Win64,    ///< rcx, rdx, r8, r9, 32-byte shadow space, then the stack
  Aapcs64,  ///< x0-x7, then the stack
  Cdecl32,  ///< every argument on the stack
};

struct IrEvalOptions {
  Architecture architecture = Architecture::X86_64;
  IrCallingConvention convention = IrCallingConvention::SysV64;
  std::size_t max_steps = 1'000'000;
  std::uint64_t stack_top = 0x7fff'f000'0000ULL;
  std::size_t stack_size = 64 * 1024;
};

struct IrEvalResult {
  std::uint64_t return_value = 0;
  std::size_t steps = 0;
};

/// Run a lifted function on concrete integer arguments under the
/// architecture's register-aliasing rules (x86-64 32-bit writes zero-extend,
/// 8/16-bit writes merge; AArch64 w-register writes zero-extend; xzr/wzr read
/// zero). This is a test oracle for the lifter, not an emulator: calls,
/// unsupported statements and step-limit overruns stop with an error
/// (`ir.eval_call`, `ir.eval_unsupported`, `ir.eval_step_limit`), and a
/// memory access outside the mapped regions is `ir.eval_memory`.
[[nodiscard]] Result<IrEvalResult> evaluate_ir(const IrFunction& function,
                                               std::span<const std::uint64_t> arguments,
                                               IrEvalMemory& memory,
                                               const IrEvalOptions& options = {});

}  // namespace donkey
