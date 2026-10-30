#pragma once

#include "donkey/ir/lift.h"

namespace donkey::internal {

/// Lift one AArch64 function. Declared here so the architecture dispatcher in
/// lift.cpp stays a single entry point and the verifier/printer contract is
/// shared by every lifter.
[[nodiscard]] Result<IrFunction> lift_aarch64(const BinaryImage& image,
                                              const AnalysisResult& analysis,
                                              const Function& function, const LiftOptions& options);

}  // namespace donkey::internal
