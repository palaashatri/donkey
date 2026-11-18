#pragma once

// Executable models of C library functions (G21-T7). A call to an import shown to bind to the C
// library (AnalysisResult::c_library_imports) carries the function's C prototype: its arguments
// in the calling convention's registers and its result in the return register. The evaluator then
// runs the model in place of the library code, so a caller of the function can be executed and
// compared with its compiled code like any other function.
//
// A model is exact: for every input it gives the result ISO C defines, reads and writes exactly
// the bytes the function's definition reads and writes, and fails (ir.eval_model) on an input
// whose behaviour is undefined (an overlapping memcpy), or differs between C libraries (a search
// for a character outside ASCII), rather than guess. Functions whose result
// ISO C leaves partly to the implementation (memcmp, strcmp and strncmp give only a sign) have no
// model. Every model is checked against the host's C library on random inputs
// (LibcModels.AgreeWithTheHostCLibrary).

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "donkey/core/result.h"
#include "donkey/ir/eval.h"

namespace donkey {

/// The C type of one argument, which fixes the register width it is read with.
enum class LibcArgument : std::uint8_t {
  Pointer,  ///< a pointer: 64 bits
  Size,     ///< size_t: 64 bits
  Int,      ///< int: 32 bits. memset stores its low byte; memchr, strchr and strrchr search for
            ///< it only when it is ASCII (0 to 127), the only values every C library agrees on
};

struct LibcModel {
  std::string_view name;
  std::span<const LibcArgument> arguments;
};

/// The model of the C function `name`, or null when it has none.
[[nodiscard]] const LibcModel* find_libc_model(std::string_view name) noexcept;

/// Every model, in name order.
[[nodiscard]] std::span<const LibcModel> libc_models() noexcept;

/// Runs `model` on `arguments` (one value per argument, already cut to its width) against
/// `memory`. Each byte read or written counts one step against `max_steps`. Fails with
/// ir.eval_memory when a byte is outside the mapped memory, ir.eval_model when the input is one
/// whose behaviour ISO C leaves undefined, and ir.eval_step_limit past the budget.
[[nodiscard]] Result<std::uint64_t> run_libc_model(const LibcModel& model,
                                                   std::span<const std::uint64_t> arguments,
                                                   IrEvalMemory& memory, std::size_t& steps,
                                                   std::size_t max_steps);

}  // namespace donkey
