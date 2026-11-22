#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <string_view>

#include "donkey/ir/libc_models.h"
#include "donkey/ir/lift.h"

namespace donkey::internal {

/// Lift one AArch64 function. Declared here so the architecture dispatcher in
/// lift.cpp stays a single entry point and the verifier/printer contract is
/// shared by every lifter.
[[nodiscard]] Result<IrFunction> lift_aarch64(const BinaryImage& image,
                                              const AnalysisResult& analysis,
                                              const Function& function, const LiftOptions& options);

/// Rewrites every register operand to its family (eax, ax, al and rax become rax) and
/// makes the width rules explicit: a 4-byte write zero-extends, and a 1- or 2-byte
/// write, or a high-byte write, is an explicit merge. x86-64 and AArch64 only.
void canonicalise_registers(IrFunction& function, Architecture architecture);

/// Checks that no caller-saved register is read after a call without the call defining it (G21-T1),
/// and marks the function partial when one is (see lift.cpp). The lifter runs it after the passes
/// on x86-64 and AArch64 functions, with the caller-saved set of the architecture; the corpus test
/// runs it on its replayed passes, so both see the same IR.
void check_call_clobbers(IrFunction& function, Architecture architecture = Architecture::X86_64);

/// The registers a call may change under System V x86-64 (rax, rcx, rdx, rsi, rdi, r8-r11 and
/// xmm0-xmm15, which hold every Win64 caller-saved register too) and under AAPCS64 (x0-x18, x30,
/// v0-v7 and v16-v31; v8-v15 keep their low 64 bits), as register families.
std::set<std::string> sysv_caller_saved_families();
std::set<std::string> aapcs64_caller_saved_families();

/// What `check_frame` asks of a function's returns. `Own`: on AArch64, that `ret` jumps back to the
/// caller (x30 holds its entry value). `Callee`: also what a caller relies on when a call to the
/// function resolves: the stack pointer and every callee-saved register hold their entry values,
/// and on x86-64 no store writes the return address.
enum class FrameContract : std::uint8_t { Own, Callee };

/// The frame check (G21, see frame_check.cpp): a forward dataflow over `function` (lifted without
/// passes, registers canonicalised) that follows entry values through registers and stack slots.
/// Returns the reason when some return does not meet `contract`, or nullopt when every one does.
/// x86-64 and AArch64 only.
[[nodiscard]] std::optional<std::string> check_frame(const IrFunction& function,
                                                     Architecture architecture,
                                                     FrameContract contract);

/// The model of the C library function a call or tail call target runs (G21-T7), or null: the
/// target is the stub of an import the analysis binds to the C library (`AnalysisResult::
/// c_library_imports`), or on x86-64 its GOT or IAT slot (`call *slot`), and the function has a
/// model. x86-64 and AArch64 only.
const LibcModel* modelled_libc_call(const BinaryImage& image, const AnalysisResult& analysis,
                                    const IrOperand& target);

/// Gives a call statement the C prototype of `model`: each argument in its register of the image's
/// calling convention (System V rdi, rsi, rdx; Win64 rcx, rdx, r8; AAPCS64 x0, x1, x2; an int in
/// the register's low 32 bits), the result in all of rax or x0, and `call_model`.
void apply_libc_model(const BinaryImage& image, IrStatement& statement, const LibcModel& model);

/// A no-return function of a runtime library with a fixed C prototype (G21-T5).
struct NoReturnPrototype {
  std::string_view name;
  std::array<LibcArgument, 4> arguments;
  std::uint8_t count = 0;
};

/// The prototype of the no-return import a call or tail call target is the stub or (x86-64) slot
/// of, or null: the import must be bound to its runtime library (AnalysisResult::no_return with
/// `known-name:` evidence, G24-T3) and have a fixed prototype. x86-64 and AArch64 only.
const NoReturnPrototype* no_return_prototype(const BinaryImage& image,
                                             const AnalysisResult& analysis,
                                             const IrOperand& target);

/// Gives a call the arguments of `prototype` in the image's calling convention, no result, and
/// kNoReturnPrototypeSource as its signature source. The call ends its path: the block must end at
/// it (end_block_at_no_return_call), which the verifier checks.
void apply_no_return_prototype(const BinaryImage& image, IrStatement& statement,
                               const NoReturnPrototype& prototype);

/// G21-T2 for the AArch64 lifter: when `instruction` is a direct call (or tail call) to a function
/// of the image whose call summary resolves, gives `statement` the callee's arguments, its result
/// in all of the result register, `signature_inferred` and the callee's write set, and returns
/// true. Otherwise leaves `statement` as it is and returns false.
bool resolve_known_call(const BinaryImage& image, const AnalysisResult& analysis,
                        const LiftOptions& options, const Instruction& instruction,
                        IrStatement& statement);

/// Keeps the blocks reachable from the function's entry, puts a trampoline in front of an entry
/// that is not block 0, and notes the blocks left out. Returns false when nothing changed. See
/// lift.cpp for the rules. `function_id` is the CFG function the blocks came from.
[[nodiscard]] Result<bool> keep_reachable_blocks(IrFunction& function,
                                                 const AnalysisResult& analysis,
                                                 FunctionId function_id,
                                                 std::uint8_t pointer_width);

/// G24-T3: when `block` ends in a call to an address the analysis marks as not returning (a
/// direct target, or the GOT or IAT slot an indirect call reads), marks the call `no_return` and
/// ends the block with an unreachable Return, and returns true. The lifters call it where a block
/// would otherwise fall through or get a synthetic return.
bool end_block_at_no_return_call(const AnalysisResult& analysis, IrBlock& block,
                                 std::uint8_t pointer_width);

}  // namespace donkey::internal
