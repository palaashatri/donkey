#pragma once

#include <cstdint>

#include "donkey/analysis/analysis.h"
#include "donkey/binary/image.h"
#include "donkey/core/result.h"
#include "donkey/ir/ir.h"

namespace donkey {

struct LiftOptions {
  std::size_t max_statements = 200'000;
  std::size_t max_blocks = 20'000;
};

/// Lift one function's basic blocks into IR. The lifters model a documented
/// x86-64 and AArch64 subset; every other instruction or architecture becomes
/// an Unsupported statement/error and marks the function partial. They never
/// execute code and never invent behaviour they did not decode.
[[nodiscard]] Result<IrFunction> lift_function(const BinaryImage& image,
                                               const AnalysisResult& analysis,
                                               const Function& function,
                                               const LiftOptions& options = {});

}  // namespace donkey
