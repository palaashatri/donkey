#pragma once

#include "donkey/binary/image.h"
#include "donkey/ir/ir.h"

namespace donkey {

/// Fill in `function.parameters` and `function.return_width` from how the ABI
/// argument and return registers are used, and append a note explaining that
/// the signature is an inference rather than debug-info truth.
///
/// A register is treated as an incoming argument when it is read before being
/// written anywhere in the function. Registers the lifter does not model for
/// the architecture are ignored. This is deliberately conservative: a false
/// parameter would be worse than a missing one, so configurable/tail-called
/// values simply do not appear.
void infer_signature(IrFunction& function, Architecture architecture);

}  // namespace donkey
