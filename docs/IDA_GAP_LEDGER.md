# IDA Pro gap ledger and plan

What Donkey lacks before it can be compared with IDA Pro, and a plan to close
each gap in tasks small enough for one pull request each. It is written for
coding agents, including ones that need explicit direction: every task says
which files to touch, which tests prove it, which commands to run, and when
it is done.

- **Baseline (2026-10-31):** M0-M11 are met for the claimed features, and 23 of
  the 26 acceptance projects pass. The release-candidate scope is in
  `docs/DESIGN.md` §17.2, and measured results are in `docs/SUPPORT_MATRIX.md`.
- **Not a claim:** this file plans work. Nothing here is implemented until its
  row says DONE with evidence. Do not cite this file as a capability anywhere.

Read sections 1-3 before taking any task.

---

## 1. Rules (non-negotiable)

These come from `AGENTS.md` and `docs/DESIGN.md`. Breaking one makes the PR
wrong even if CI is green.

1. **Never fake a result.**
   - Never print pseudocode by string formatting or from a language model.
     The decompiler prints only IR that passed `verify_ir`.
   - Never return a hard-coded value to make a test pass.
   - Never mark something Complete that you did not verify. If you are
     unsure, mark it Partial and say why in a note.
2. **Never weaken a test to get green.**
   - Do not delete, skip, disable or loosen an assertion, a
     `PASS_REGULAR_EXPRESSION` or a threshold.
   - Do not add `GTEST_SKIP` for a platform where the feature is claimed.
   - If a test fails, the code is wrong until you prove the test is wrong.
     If the test is wrong, explain why in the PR description.
3. **Untrusted input.**
   - Every reader of file bytes (PDB, signature files, demangler input,
     RPC messages) is bounds-checked with `donkey/core/checked.h` and returns
     `Result<T>` with a stable diagnostic code.
   - No recursion without a depth limit, and no allocation sized from file
     data without a cap.
   - Add a fuzz target for every new parser (see `fuzz/fuzz_binary.cpp`).
4. **Licences.**
   - Allowed: MIT, BSD, Apache-2.0, zlib, Boost, public domain. No GPL, LGPL
     or AGPL code or libraries. For example, Keystone (GPL-2) and libiberty's
     demangler (LGPL) are forbidden.
   - Do not copy code, signature files, type libraries or SDK headers from
     IDA, Hex-Rays, Binary Ninja or any closed tool.
   - You may read public format specifications and documentation. Implement
     from the specification in your own words.
   - Record every new dependency in `THIRD_PARTY_NOTICES` and the SBOM
     template `packaging/sbom/donkey.spdx.json.in`. The `sbom.valid` test
     checks the SBOM.
5. **Architecture.**
   - The headless core (`src/`, `include/donkey/`) never includes SDL or
     ImGui. The `deps.core_has_no_ui_links` test enforces this.
   - UI code never parses binaries or writes SQL.
   - No file I/O or analysis on the render thread.
   - Source lists are explicit in `CMakeLists.txt`; `GLOB_RECURSE` is not
     allowed.
6. **Project database.**
   - A schema change bumps `PRAGMA user_version` in `src/project/project.cpp`
     and adds a migration from every older version.
   - Add a test that opens a project saved by the previous version.
7. **Honesty in docs.**
   - The PR that changes what Donkey can do also updates:
     - `docs/SUPPORT_MATRIX.md`
     - the truth table in `docs/DESIGN.md` §17.2
     - this ledger's row
   - State what is not done in the same sentence as what is done.
8. **One task per PR.**
   - Branch name: `agent/<area>/<task-id>-<topic>`, e.g.
     `agent/ir/G01-T1-float-ops`.
   - Never push to `main`.
   - Do not combine tasks. A small, finished, tested PR is worth more than a
     large, half-working one.

## 2. How to take a task

1. Pick the first task in section 5 whose status is TODO and whose
   dependencies are all DONE. Prefer tasks marked **[oracle]**: the
   differential corpus checks them automatically, so mistakes are caught.
2. Read every file the task lists before editing. Read the tests next to them.
3. Write the tests first, from the task's "Tests" list. Run them and see them
   fail.
4. Implement. Keep the change inside the files listed unless you must touch
   another. If you do, say why in the PR.
5. Run the full verification in section 3. All of it.
6. Update the docs listed in rule 7, and set the task's status to DONE with
   the test names.
7. Open the PR with the template in section 6.

Stop and report instead of guessing when:

- a test cannot pass without breaking a rule
- you would need a dependency that is not on the allowed list
- the task needs a decision marked **[owner decision]**
- CI fails on a platform you cannot reproduce, after two attempts. Put the
  log excerpt in the PR.

## 3. Verification commands

Run these on Linux before every PR. Each must end with 0 failures.

```bash
cmake --preset headless-linux
cmake --build --preset headless-linux --parallel
ctest --preset headless-linux --output-on-failure --parallel 8
```

```bash
# Clang as well, because macOS and Windows on Arm use it:
cmake -S . -B build/clang-headless -G Ninja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DDONKEY_BUILD_UI=OFF -DDONKEY_WARNINGS_AS_ERRORS=ON
cmake --build build/clang-headless --parallel
ctest --test-dir build/clang-headless --output-on-failure --parallel 8
```

```bash
# Desktop and UI scripts (needs Xvfb):
cmake --preset dev-linux -DDONKEY_UI_SMOKE_TEST=ON
cmake --build --preset dev-linux --parallel
XDG_RUNTIME_DIR=/tmp/xdg xvfb-run -a -s "-screen 0 1600x1000x24" ctest --preset dev-linux --output-on-failure --parallel 4
```

```bash
# Formatting, exactly as CI checks it:
python3 -m pip install clang-format
find include src apps tests -type f \( -name '*.h' -o -name '*.cpp' \) -print0 | xargs -0 clang-format --dry-run --Werror
```

```bash
# Decompiler corpus counts (after the headless tests):
cmake -DREPORT=build/headless-linux/tests/decompiler-corpus-report.json -P cmake/checks/corpus_summary.cmake
```

For any change to the AArch64 lifter or decoder, also run the aarch64 build
under qemu. The steps are in section 7.

---

## 4. The ledger

Status values:

- **TODO**
- **IN PROGRESS (branch)**
- **DONE (evidence: test names, CI run)**
- **BLOCKED (reason)**

P0 is the most important, P3 the least.

| ID | Gap | IDA Pro | Donkey today | P | Status |
|---|---|---|---|---|---|
| G01 | Floating point (x86 SSE scalar, AArch64 FP) | Decompiles float/double code | Unsupported: any FP instruction makes the function Partial | P0 | TODO |
| G02 | x86 integer gaps | Full integer semantics | `adc`/`sbb` done in G02-T1, double-width `mul`/`div` in G02-T2, `bt`/`bts`/`btr`/`btc`, `popcnt`, `tzcnt`, `lzcnt`, `bswap`, `movbe` (register forms) and `bsf`/`bsr` (Partial for a zero source) in G02-T3, and flags into a single-predecessor fall-through block in G02-T4. Still Partial or Unsupported by design: `bsf`/`bsr` with a zero source, memory forms of `bt` family, flags into a block with several predecessors | P0 | IN PROGRESS (G02-T1, T2, T3, T4 DONE; the rest is by design, see the row text) |
| G03 | AArch64 integer gaps | Full | No `ccmp`/`ccmn`, `udiv`/`sdiv`, `umulh`/`smulh`, `clz`/`rbit`/`rev`, jump tables | P0 | TODO |
| G04 | Decompiler readability | Clean C with merged variables, `for` loops, simplified conditions | Register-level output (`w8 = ...`), no copy propagation, no `for` loops, register aliases not merged | P0 | IN PROGRESS (G04-T0 DONE; T1-T4 TODO) |
| G05 | Type system and user types | Type libraries, struct/enum editing, propagation | DWARF types read-only; struct layouts inferred behind pointer arguments only; no editing | P0 | TODO |
| G06 | PDB (Windows debug info) | Full | Not read | P1 | TODO |
| G07 | Separate debug files (.dSYM, debuglink, build-id, compressed DWARF) | Full | Not read; compressed sections reported Unsupported | P1 | TODO |
| G08 | SIMD (SSE/AVX, NEON) | Decompiles to intrinsics | Unsupported: vectorised loops are Partial | P1 | TODO |
| G09 | Library function identification | FLIRT signatures, Lumina | None | P1 | TODO |
| G10 | C++ (demangling, RTTI, vtables) | Full | No demangler; no RTTI/vtable recovery | P1 | TODO |
| G11 | Scripting and automation | IDAPython, IDC, plugin SDK | C ABI plugins, `donkey-cli --json`; no scripting API | P1 | TODO |
| G12 | Interactive edits | Make code/data, define arrays and strings, rename and type locals | Rename, comment, bookmark, function boundaries | P1 | TODO |
| G13 | Processor coverage | Dozens of ISAs | x86, x86-64 and AArch64 only; no 32-bit ARM, RISC-V, MIPS or PPC decoder | P2 | TODO |
| G14 | Debugger coverage | All major OSes, remote debugging, hardware watchpoints | Linux x86-64/AArch64 and Windows x64 local only | P2 | TODO |
| G15 | Loaders and multi-image | Objects, archives, dumps, firmware; cross-image references | ELF/PE/Mach-O/raw images, one at a time | P2 | TODO |
| G16 | Scale on real large binaries | Decades of tuning | Synthetic 1 GiB test; no real-world benchmark | P2 | TODO |
| G17 | UI breadth | Many views, search kinds, command palette | Core views; text search in lists | P3 | TODO |
| G18 | Signed releases | Signed installers | Ad-hoc signed `.app`, unsigned `.exe` | P1 | BLOCKED [owner decision]: needs the owner's Apple Developer ID and Windows code-signing certificate |
| G19 | Accessibility | Platform accessibility APIs | None: Dear ImGui exposes no accessibility tree | P3 | BLOCKED (research needed; see G19) |

---

## 5. Plans

Each task has the same parts:

- **Goal**
- **Files**
- **Steps**
- **Tests**, with exact names to add
- **Done when**
- **Pitfalls**

"[oracle]" marks a task the differential decompiler corpus verifies:
`tests/corpus/*.c` is compiled at -O0/-O2/-O3, and every Complete result is
interpreted and compared with the real compiled code. Read
`tests/unit/decompiler_corpus_test.cpp` before any lifter task.

### G01 Floating point

The IR has no floating-point values today, so this gap starts in the IR and
interpreter.

**G01-T1 IR floating-point operations** (depends: none)

- **Goal:** add IEEE-754 float (4-byte) and double (8-byte) operations to the
  IR, with exact semantics in the interpreter.
- **Files:**
  - `include/donkey/ir/ir.h`
  - `src/ir/ir.cpp` (names, verifier, printer)
  - `src/ir/eval.cpp`
  - `tests/unit/ir_test.cpp`
- **Steps:**
  1. Add these `IrOp` values: `FAdd`, `FSub`, `FMul`, `FDiv`, `FSqrt`, `FNeg`,
     `FAbs`, `FCompare`, `IntToFloat`, `UIntToFloat`, `FloatToInt` (truncate
     toward zero), `FloatExtend` (4→8), `FloatTruncate` (8→4).
  2. Add `bool is_float` to the IR operand or statement so the printer and
     verifier can tell bit patterns from numbers. Width 4 means float and
     width 8 means double.
  3. In `eval.cpp`, convert with `std::bit_cast<float>` /
     `std::bit_cast<double>` on the stored bits. Use round-to-nearest only.
     Any other rounding mode → `ir.eval_unsupported`.
  4. For `FloatToInt`, use x86 `cvttsd2si` semantics: NaN or out-of-range
     gives 0x8000...0, the "integer indefinite" value. AArch64 `fcvtzs`
     saturates instead. Make the behaviour a per-architecture option on the
     statement. Do not guess.
  5. `FCompare` sets flags as x86 `ucomisd` does (ZF, PF, CF; unordered sets
     all three) and as AArch64 `fcmp` does (NZCV: unordered = 0011). Store
     which one on the statement.
  6. Printer: types `float`/`double`. Print literals as exact hexadecimal
     floats (`0x1.8p+1`), never rounded decimals.
  7. Verifier: float ops take float operands of matching width; mixing
     integer and float operands without a conversion is an error.
- **Tests:**
  - `Ir.FloatArithmeticMatchesIeee`: 10 cases with exact bit results,
    including -0.0, denormals, inf and NaN payload passing.
  - `Ir.FloatToIntIndefiniteOnX86AndSaturatesOnAArch64`
  - `Ir.FCompareUnorderedSetsFlags`
  - `Ir.VerifierRejectsMixedIntFloatOperands`
- **Done when:** the tests pass and every existing test passes.
  `fuzz_ir` builds, and runs for 60 s without a crash if you have the fuzz
  preset.
- **Pitfalls:**
  - Never use `float` arithmetic on the host for double operations.
  - Never compare NaN with `==`.
  - Do not enable `-ffast-math` anywhere.

**G01-T2 x86 SSE scalar lifting** [oracle] (depends: G01-T1)

- **Files:**
  - `src/ir/lift.cpp`
  - `src/ir/abi.cpp`
  - `tests/corpus/corpus_fp.c` (new)
  - `tests/CMakeLists.txt`
  - `tests/unit/decompiler_corpus_test.cpp`
- **Steps:**
  1. Lift these instructions:
     - moves and conversions: `movss`, `movsd` (register and memory forms),
       `movaps`/`movapd` (register to register only), `cvtsi2ss`/`cvtsi2sd`,
       `cvttss2si`/`cvttsd2si`, `cvtss2sd`/`cvtsd2ss`
     - arithmetic: `addss`, `addsd`, `subss`, `subsd`, `mulss`, `mulsd`,
       `divss`, `divsd`, `sqrtss`, `sqrtsd`
     - comparisons: `ucomiss`, `ucomisd`, `comiss`, `comisd` (they set flags;
       wire them into the existing flags tracking)
     - zeroing idioms: `xorps x, x` and `pxor x, x` set the register to zero
  2. Model an XMM register as its low lane only. Any instruction that reads
     or writes the upper lanes is Unsupported (Partial), so a function with
     one is Partial too.
  3. In the ABI, float and double arguments go in xmm0-7 on System V and
     xmm0-3 on Win64, where they share positions with integer arguments. The
     return value is in xmm0. Add `IrCallingConvention` support in
     `eval.cpp`: an argument vector of type-tagged values.
  4. Add `tests/corpus/corpus_fp.c` with at least 20 functions: arithmetic,
     comparisons and branches on doubles, int↔double conversion, float↔double,
     loops summing a double array (scalar at -O0; may vectorise at -O3, which
     is fine: Partial), and `sqrt` via `__builtin_sqrt`. No libm calls.
  5. In the corpus test, add a second native signature for FP functions
     (`double (*)(double, double, double, double)`) and compare bit patterns.
     NaN results compare equal when both are NaN.
- **Tests:**
  - `DecompilerCorpus.FloatResultsAgreeWithTheCompiledCode`, in the same
    style as the integer test: any Complete result that disagrees fails.
- **Done when:** at least 18/20 are Complete and verified at -O0 on GCC x86-64
  and on Clang, and none is wrong. Put the counts in `docs/SUPPORT_MATRIX.md`.
- **Pitfalls:**
  - `movsd` with two XMM operands merges the upper lanes. Model it as
    "low lane = source low lane".
  - `cvtsi2sd` with a 32-bit source sign-extends.
  - Flags after `ucomisd`: ZF=PF=CF=1 when unordered, which is why compilers
    emit `jp` checks. Map `jp`/`jnp`.

**G01-T3 AArch64 FP lifting** [oracle] (depends: G01-T1)

- **Files:**
  - `src/ir/lift_aarch64.cpp`
  - `src/ir/abi.cpp`
  - the same corpus files as G01-T2
- **Steps:**
  1. Lift these instructions:
     - moves: `fmov` (register/register, general↔FP, immediate)
     - arithmetic: `fadd`, `fsub`, `fmul`, `fdiv`, `fsqrt`, `fneg`, `fabs`,
       `fmadd`/`fmsub` (fused! It needs an `FFma` IR op with exact
       single-rounding semantics: `std::fma`)
     - conversions: `scvtf`, `ucvtf`, `fcvtzs`, `fcvtzu`, `fcvt`
       (single↔double)
     - comparisons: `fcmp`/`fcmpe` set NZCV and count as modelled flag
       writers in the block flag tracking (see `sets_flags` and
       `flags_exact` in `lift_aarch64.cpp`)
     - conditional select: `fcsel`
  2. `s0`-`s31` are the 4-byte views and `d0`-`d31` the 8-byte views of
     `v0`-`v31`. Writing `s`/`d` zeroes the rest of the register.
  3. AAPCS64: FP arguments in v0-v7, return value in v0.
- **Tests:**
  - FP corpus on aarch64: in CI on `ubuntu-24.04-arm` and `macos-15`, and
    locally under qemu (section 7).
- **Done when:** at least 18/20 are Complete and verified at -O0 on GCC
  aarch64 and Apple Clang, with none wrong.
- **Pitfalls:**
  - `fmadd` rounds once; `a*b+c` in two IR ops rounds twice and is WRONG.
  - Apple's ABI passes variadic FP arguments differently. The corpus has no
    variadic functions; keep it that way.

### G02 x86 integer gaps [oracle]

**G02-T1 adc/sbb and the carry flag** (depends: none)

- **Files:**
  - `src/ir/lift.cpp`
  - `src/ir/eval.cpp`
  - `include/donkey/ir/ir.h`
  - `tests/corpus/corpus.c`
- **Steps:**
  1. Add IR ops `AddCarry` and `SubBorrow`: `dest = a + b + CF`, with flags
     computed exactly.
  2. In the lifter, `adc`/`sbb` are exact only when the carry comes from a
     modelled flag writer in the same block. Use the existing `FlagsState`
     tracking. Otherwise they are Partial.
  3. Add corpus functions: `unsigned __int128` add/subtract returning the
     high half, and the `x + y < x` overflow-check idiom.
- **Tests:** the corpus covers these. Also add
  `Ir.AddCarryMatchesHardwareFlags`, with expected values computed by hand
  from the Intel SDM definitions.
- **Done when:** the `adc` Partial on Clang -O2 (`docs/SUPPORT_MATRIX.md`)
  becomes Complete and verified.
- **Status:** DONE. Evidence: `Ir.X86AddWithCarryMatchesHardwareFlags`,
  `Ir.X86SubWithBorrowMatchesHardwareFlags`,
  `Ir.X86AddOfARegisterToItselfCarriesFromTheOriginalValue`,
  `Ir.X86SubOfARegisterFromItselfKeepsTheOriginalForSignedBranches`,
  `Ir.X86AddFollowedByACarryBranchIsExact`, `Ir.AddCarryMatchesHardwareFlags`,
  `Ir.SubBorrowMatchesHardwareFlags`,
  `Ir.VerifierRejectsCarryWithoutAFlagWriterInItsBlock`, and the corpus
  functions `c_add128_hi`, `c_sub128_hi`, `c_add_wraps` in
  `DecompilerCorpus.CompleteResultsAgreeWithTheCompiledCode`. On Clang 18.1
  x86-64 those three are Complete and verified at O0, O2 and O3, so the
  `adc` Partial on Clang -O2 is gone. Also fixed in this task: `sub x, x`
  followed by a signed branch compared against the overwritten register; an
  `add`/`sub` whose memory source is addressed by its own destination
  (`add rdi, [rdi]; setb`), which now copies the source before the write
  (`Ir.X86AddFromAMemoryOperandAddressedByItsDestinationCarriesFromTheLoadedValue`);
  a register `xchg` between a flag writer and its consumer, which now passes the
  flags through (`Ir.X86CarryReachesAnAdcAcrossARegisterExchange`); an
  unsupported memory `xchg`, which now drops the flag state
  (`Ir.X86CarryIsNotReadAcrossAnUnsupportedExchange`); and the verifier
  rejects a second carry op that would read a carry out the IR does not
  represent (`Ir.VerifierRejectsACarryChainWhoseFirstCarryOutIsNotModelled`),
  a block operand (`Ir.VerifierRejectsACarryWithABlockOperand`), and a
  constant wider than the destination (`Ir.VerifierRejectsACarryConstantWiderThanItsDestination`).
- **Deviations from the steps above:** the carry is read from the flag state
  of the last `Compare`/`Test` in the block, as `CondAssign` already does,
  rather than from a separate operand. The carry out of `adc`/`sbb` is not
  modelled, so `adc; adc` chains are Partial. `xchg reg, reg` and a memory
  source for `adc`/`sbb` are lifted. AArch64 `adc`/`sbc`/`cmn` are not lifted;
  that is G03-T4.

**G02-T2 Double-width multiply and divide** (depends: none)

- **Steps:**
  1. Lift `mul`/`imul` with one operand (rdx:rax = rax * src), and `div`/`idiv`
     (rax = rdx:rax / src, rdx = remainder).
  2. Add IR ops `MulHighUnsigned`, `MulHighSigned`, `DivUnsigned`,
     `DivSigned`, `RemUnsigned`, `RemSigned`.
  3. Divide by zero, or a quotient overflow, is a hardware fault. The
     interpreter returns an `ir.eval_fault` error, and the corpus vectors must
     avoid it. Never return 0.
  4. Add corpus functions: `x / y`, `x % y` (signed and unsigned, 32 and 64
     bit) with y guarded non-zero, the `uint64 * uint64 → high` idiom, and
     division by a constant (compilers emit multiply-high).
- **Done when:** the new functions are Complete and verified on GCC and Clang
  at O0/O2/O3.
- **Status:** DONE (stacked on G02-T1; see the PR for its base). Evidence:
  `Ir.X86MulAndImulReturnTheHighHalfOfTheProduct`,
  `Ir.X86DivAndIdivReturnTheQuotientAndTheRemainder`,
  `Ir.X86DivideFaultsWhereTheHardwareDivideErrors`,
  `Ir.X86ThirtyTwoBitDivideUsesEdxAndEax`,
  `Ir.VerifierRejectsDivideWithoutItsDivisor`,
  `Ir.VerifierRejectsADivisorTemporaryThatIsNeverDefined`,
  `Ir.X86DivisorInAnArgumentRegisterIsAnInputOfTheSignature`, and the corpus functions
  `c_mulhi_u64`, `c_mulhi_s64`, `c_udiv32`, `c_urem32`, `c_sdiv32`,
  `c_srem32`, `c_udiv64`, `c_urem64`, `c_sdiv64`, `c_srem64`, `c_div10` in
  `DecompilerCorpus.CompleteResultsAgreeWithTheCompiledCode`.
- **Deviations from the steps above:** division needs three operands, so
  `IrStatement` gained a third operand `c` (the divisor). The dividend is the
  pair `a` (high) and `b` (low). The 8- and 16-bit forms are Unsupported. The
  flags after `mul`/`div` are not modelled. The signed corpus functions guard
  `INT_MIN / -1` and division by zero, because the native code traps there;
  the interpreter reports `ir.eval_fault` for both instead of returning 0.

**G02-T3 Bit operations**

- **Steps:**
  1. Lift `bt`/`bts`/`btr`/`btc` (register forms only; memory forms are
     Unsupported), `bsf`/`bsr` (destination undefined when the source is 0:
     the result is Partial unless a zero check dominates; simpler: mark the
     destination undefined and let the oracle catch use), `tzcnt`/`lzcnt`/
     `popcnt`, `bswap`, `movbe`.
  2. Add IR ops `CountTrailingZeros`, `CountLeadingZeros`, `PopCount`,
     `ByteSwap`.
- **Done when:** `c_popcount` is Complete and verified on -O3 builds with
  `-mpopcnt`. Add a corpus variant built with `-march=x86-64-v2`.
- **Status:** DONE on GCC 13.3 and Clang 18.1 (x86-64, native). Done: `popcnt`, `tzcnt`, `lzcnt`, `bswap` (32 and
  64 bit) and `bt` with a register or immediate index (the IR ops
  `CountTrailingZeros`, `CountLeadingZeros`, `PopCount` and `ByteSwap`).
  Evidence: `Ir.X86PopcntTzcntLzcntAndBswapMatchTheInstructions`,
  `Ir.X86BitTestCarriesTheSelectedBit`, and the corpus functions
  `c_popcount64`, `c_ctz64_guarded`, `c_clz64_guarded`, `c_bswap32`,
  `c_bswap64`, `c_bit_test`. Also fixed: a function containing a direct call
  was reported Complete. It is now Partial, which changed the expected status
  of `_start` in two CLI tests (`cli.decompile_elf_json`,
  `cli.decompile_elf_i386`) from Complete to Partial. Since then: `bts`, `btr`
  and `btc` with a register destination (`Ir.X86BitTestAndSetResetAndComplementWriteTheBit`,
  `Ir.X86BitTestAndSetCarriesTheBitBeforeTheWrite`); `movbe` with a register
  and a memory operand (`Ir.X86MovbeLoadsAndStoresTheBytesReversed`); and the
  `-march=x86-64-v2` corpus variant, where `c_popcount` is Complete and verified
  at O3 with `popcnt`. `bsf` and `bsr` are lifted with a register or memory
  source (`Ir.X86BitScanForwardAndReverseAreExactForANonzeroSource`): exact for
  a nonzero source, and the function is Partial because the zero-source result
  is undefined. ZF is not modelled. The guarded use `c_clz64_guarded` is Partial
  and agrees with the compiled code, and it can only become Complete once flags
  and path facts cross blocks (G02-T4). `c_ctz64_guarded` is Complete because
  GCC encodes it as `rep bsf`, which is `tzcnt`. Not done in this task: the
  `bsf`/`bsr` zero-source case itself, which the ledger's plan allows to stay
  Partial.
  Memory forms of `bt`, `bts`, `btr` and `btc` are Unsupported by design (the bit
  can lie outside the operand).

**G02-T4 Flags across blocks**

- **Goal:** a conditional branch whose flags come from the single predecessor
  block's last flag writer is exact.
- **Steps:**
  1. In the x86 lifter, after lifting all blocks, find blocks whose first
     flag reader appears before any flag writer.
  2. If the block has exactly one predecessor, that predecessor ends in a
     modelled flag writer with no writer after it, and the edge is a
     fall-through or unconditional jump, re-emit the predecessor's
     Compare/Test at the start of the block from the same operands, but only
     if those operands are not redefined in between.
  3. Otherwise keep the branch Partial.
- **Done when:** a hand-written test (`Ir.FlagsFromSinglePredecessorAreExact`)
  passes, and the corpus has no new WRONG.
- **Status:** DONE on x86-64 (GCC 13.3 and Clang 18.1, native). The rule is
  implemented as written, with one simplification: the block just before the
  successor must fall through or end in the conditional branch whose not-taken
  edge is the successor, and the successor must have no other CFG predecessor
  (calls and jumps from elsewhere count, and an unresolved indirect branch in
  the function rules the carry out). The last flag writer must be a two-operand
  `cmp` or `test` of registers and immediates, and nothing after it may write a
  register it reads. The compare is repeated from its own instruction at the
  successor's start. Evidence: `Ir.FlagsFromSinglePredecessorAreExact`, which
  also checks that a rewritten operand keeps the successor Partial. The GCC
  x86-64 corpus gains one Complete function at O2 and O3 and under
  `-march=x86-64-v2` (57/59, 51/59, 52/59), and no result is WRONG. The Clang
  x86-64 counts are unchanged. Not done: flags carried through a block with more
  than one predecessor, and flags across a block whose predecessor is a call.

### G03 AArch64 integer gaps [oracle]

**G03-T1 ccmp/ccmn**

- **Goal:** model conditional compare.
- **Steps:**
  1. Add IR op `CondCompare`: if the condition holds over the current flags,
     flags = compare(a, b); otherwise flags = the immediate nzcv. The
     interpreter must hold flags as an explicit NZCV value for this op. Store
     the `#nzcv` immediate (operand 3) on the statement.
  2. In `lift_aarch64.cpp`, `ccmp`/`ccmn` are modelled flag writers when
     `flags_exact` was already true. Read the `sets_flags` and
     `lift_conditional_select` code first.
- **Done when:** `c_both` and `c_collatz_steps` are Complete and verified at
  -O2 on GCC aarch64 and Apple Clang. Locally, use qemu (section 7).

**G03-T2 Division, high multiply, bit manipulation**

- **Steps:** lift `udiv`/`sdiv`, `umulh`/`smulh`, `umull`/`smull`,
  `clz`/`cls`, `rbit`, `rev`/`rev16`/`rev32`, `extr`, `bfi`/`bfxil`.
- **Pitfalls:**
  - AArch64 division by zero returns 0 and never faults; x86 faults.
  - `INT_MIN / -1` returns `INT_MIN` on AArch64.
  - The interpreter must branch on architecture for these.
- **Done when:** the corpus division functions from G02-T2 are Complete and
  verified on aarch64.
- **Note (added by G02-T2):** the IR ops `MulHighUnsigned`, `MulHighSigned`,
  `DivUnsigned`, `DivSigned`, `RemUnsigned` and `RemSigned` exist, with the
  divisor as the third operand `c`. They fault on a zero divisor or a quotient
  overflow, so AArch64 `udiv`/`sdiv` must guard the zero case in the IR (a
  compare and a conditional select to zero) to match AArch64's result. Do not
  lower them to the faulting op unguarded.

**G03-T3 AArch64 jump tables**

- **Files:**
  - `src/analysis/cfg.cpp` (read `resolve_jump_table` and `TableSlice`)
  - `tests/unit/decompiler_corpus_test.cpp`
- **Steps:**
  1. Recognise the GCC and Clang pattern:
     - `cmp wN, #K` / `b.hi default` bounds check
     - `adrp`/`add` table base
     - `ldrb`/`ldrh`/`ldr wM, [xT, wN, uxtw #s]`
     - `adr xL, label` / `add xL, xL, wM, sxtb|sxth|sxtw #2`
     - `br xL`
  2. Evaluate the table entries from the file bytes, in the same style as the
     x86 recogniser.
  3. Any doubt → leave the branch unresolved (Partial).
- **Tests:** make `DecompilerCorpus.JumpTableIsRecoveredWithEvidence` run on
  AArch64 instead of skipping.
- **Done when:** that test passes on `ubuntu-24.04-arm` and `macos-15`, and
  `c_switch_dense` is Complete and verified.

**G03-T4 AArch64 carry chain** (depends: G02-T1; added when G02-T1 landed)

- **Goal:** lift AArch64 `adc`, `adcs`, `sbc`, `sbcs`, `adds`, `subs`, `cmn`
  and `cmp` (`cmn` is `adds` into the zero register), with C and V from the
  existing NZCV model. The IR already has `AddCarry` and `SubBorrow`
  (G02-T1), and `condition_holds(Carry)` already gives AArch64 C.
- **Files:** `src/ir/lift_aarch64.cpp`, the corpus is unchanged.
- **Done when:** `c_add128_hi`, `c_sub128_hi` and `c_add_wraps` are Complete
  and verified on GCC aarch64 at O0, O2 and O3 under qemu. Record the
  counts in `docs/SUPPORT_MATRIX.md`.

### G04 Decompiler readability

The rule for every transformation in this gap: it must preserve meaning, and
the oracle must prove it. Add a mode to the corpus test that interprets the
IR before and after each pass on all 48 vectors. Any difference fails, even
for Partial functions.

**G04-T0 Transformation checker** (depends: none; do this first)

- **Files:** `tests/unit/decompiler_corpus_test.cpp`, `src/ir/ir.cpp`
- **Steps:**
  1. Add `donkey::run_ir_passes(IrFunction&, const PassOptions&)` with a hook
     that records the function after each pass.
  2. In the test, evaluate every recorded version and compare.
- **Tests:** `DecompilerCorpus.EveryPassPreservesSemantics`
- **Done when:** it runs with the current passes (signature inference, struct
  recovery) and passes.
- **Status:** DONE. Evidence: `DecompilerCorpus.EveryPassPreservesSemantics`
  (every pass, every corpus function, O0/O2/O3, 48 vectors) and
  `DecompilerCorpus.EveryPassCheckRejectsAChangedMeaning` (a pass that turns an
  addition into a subtraction is reported) and
  `DecompilerCorpus.EveryPassCheckRejectsAChangedPartialFlag` (setting or
  clearing `IrFunction::partial` alone is reported). Green `ci` run on the
  first G04-T0 commit, 7588286: https://github.com/palaashatri/donkey/actions/runs/41299348751
  (PR palaashatri/donkey#26). The current passes only annotate the function, so the
  checker confirms that they leave results unchanged; it does not yet cover
  passes that rewrite statements. The corpus outcome report is identical to
  before the change.

**G04-T1 Register alias canonicalisation**

- **Goal:** `eax`/`rax` and `w8`/`x8` become one variable with explicit
  widening and narrowing.
- **Files:** `src/ir/ir.cpp`, `src/ir/registers.h`
- **Steps:** rewrite each register operand to its family (`register_family`)
  with an explicit `ZeroExtend` where a 32-bit write zero-extends: x86-64
  `eax` writes and AArch64 `w` writes. 16- and 8-bit x86 writes merge: emit
  the merge explicitly.
- **Done when:** the note "register aliases are not canonicalised" is removed
  from both lifters, and G04-T0 passes.

**G04-T2 SSA, copy and constant propagation, dead code elimination**

- **Steps:**
  1. Build SSA. Dominators exist in the verifier; reuse them.
  2. Propagate copies and constants where the source has one definition and
     no intervening store can alias it. Treat every memory store as a barrier
     for loads from unknown addresses.
  3. Remove definitions with no uses and no side effects.
  4. Leave SSA by merging non-interfering variables.
- **Done when:** G04-T0 passes, and the median pseudocode line count across
  the corpus drops. Record before/after in the PR.

**G04-T3 Loop and condition recovery**

- **Steps:**
  1. Recognise `for (init; cond; step)` from a header with one back edge and
     an increment just before it.
  2. Make `break`/`continue` explicit.
  3. Simplify `!(a < b)` → `a >= b`, integer-only. Floating-point negation is
     not an inverse because of NaN; never do it for floats.
- **Done when:** G04-T0 passes and the corpus loop functions print a `for`.

**G04-T4 Names and locals from DWARF**

- **Steps:** when DWARF has a function's parameters and locals (DW_OP_fbreg
  locations), name the matching stack slots and arguments. Read
  `src/binary/dwarf.cpp` and `include/donkey/binary/debug_info.h`. Names are
  display-only; user renames (G12) always win.
- **Done when:** a test on the `-g` debuggee shows the real parameter names.

### G05 Type system and user types

**G05-T1 Type store** (depends: none)

- **Files:**
  - `include/donkey/project/types.h` (new)
  - `src/project/types.cpp` (new)
  - `src/project/project.cpp`
  - `CMakeLists.txt` (explicit source list)
  - `tests/unit/project_test.cpp`
- **Steps:**
  1. Define the types: `TypeId`; kinds integer (width, signedness), float,
     pointer, array (count), struct and union (fields: name, offset, type,
     bitfield optional), enum (width, members), typedef, function
     (return type, parameters, calling convention).
  2. Each type records its provenance: `user`, `dwarf`, `pdb`, `inferred`,
     `library`.
  3. Bump the project schema to v5: add `types`, `type_fields` and
     `type_applications(address, kind, type_id)`, with a migration from
     v1-v4.
  4. Map DWARF types (already parsed) into the store when debug info is
     attached.
- **Tests:**
  - `Types.RoundTripThroughTheProject`
  - `Types.MigratesFromSchemaV4`
  - `Types.RejectsCyclesWithoutPointer` (a struct containing itself by
    value)
  - `Types.SizeAndAlignmentFollowTheAbi`
- **Done when:** the tests pass; old projects open; the size and alignment of
  every DWARF struct in the debuggee match DWARF's `DW_AT_byte_size`.

**G05-T2 C declaration parser**

- **Steps:**
  1. Write a bounded parser for a C subset: struct, union, enum, typedef,
     pointers, arrays, function prototypes, and fixed-width integer names.
  2. Exclude the preprocessor, expressions other than integer constants, and
     C++.
  3. Limits: maximum input 1 MiB and maximum nesting 64.
- **Tests:** `Types.ParsesCDeclarations`, `Types.ParserErrorsAreLocated`
  (line and column), and a fuzz target `fuzz_cdecl`.
- **Done when:** the tests pass and the fuzz target runs 60 s clean.

**G05-T3 Apply types and propagate in the decompiler** [oracle-checked]

- **Steps:**
  1. A type applied to a function prototype changes the IR signature.
  2. A pointer-to-struct argument turns `*(a0 + 8)` into `a0->field`.
  3. Types flow forward through copies and loads.
  4. The printer uses the field names.
- **Done when:** G04-T0 still passes (types never change semantics), and a
  test applies `struct corpus_point *` to `c_point_sum` and prints `p->z`.

**G05-T4 UI and CLI**

- **Steps:**
  1. CLI: `donkey-cli project type add <db> <file.h>`,
     `project type list <db> [--json]`,
     `project type apply <db> <image-id> <address> <type-name>`.
  2. UI: a Types panel (list, edit the declaration text with parse errors
     shown) and "Set type…" on a function or stack slot. Use the shared
     components in `src/ui/components`.
  3. Undo and redo through the existing annotation history.
- **Tests:** CLI tests in `tests/CMakeLists.txt`, and a UI script
  `tests/ui/types.donkeyui` that applies a type with the keyboard and
  asserts the pseudocode.

### G06 PDB

Format references (public): the LLVM documentation "The PDB File Format"
and Microsoft's microsoft-pdb repository (MIT). Read them; implement in your
own code.

**G06-T1 MSF container**

- **Files:**
  - `include/donkey/binary/pdb.h` (new)
  - `src/binary/pdb.cpp` (new)
  - `fuzz/fuzz_pdb.cpp` (new)
  - `tests/unit/pdb_test.cpp` (new)
- **Steps:**
  1. Read the superblock, the block map and the stream directory.
  2. Reject any block index past the file, any stream that is too large,
     and any cyclic or overlapping block lists, with stable codes
     (`pdb.bad_block`, ...).
- **Fixtures:** build a tiny program with `clang-cl /Zi` or MSVC on the
  `windows-2022` runner at test time. Never commit a PDB from closed
  software. A tiny one you generated from `tests/fixtures/` sources can be
  committed, with provenance in `tests/fixtures/README` or the manifest.

**G06-T2 Symbols and matching**

- **Steps:**
  1. Read the PDB info stream (GUID, age) and match it to the PE's CodeView
     RSDS record in the debug directory (`src/binary/pe.cpp`). A mismatch is
     reported, never silently used.
  2. Read the DBI stream (modules, section contributions), the public and
     global symbol streams (`S_PUB32`, `S_GPROC32`, `S_LPROC32`) and their
     names. Give names to functions, with provenance "PDB <guid> <age>".
     They never override user renames.

**G06-T3 Types**

- **Steps:** read the TPI stream: `LF_STRUCTURE`, `LF_CLASS`, `LF_UNION`,
  `LF_ENUM`, `LF_POINTER`, `LF_ARRAY`, `LF_PROCEDURE`, `LF_FIELDLIST`,
  `LF_MEMBER`, `LF_MODIFIER`, and the base types. Map them into the G05 type
  store.
- **Depends:** G05-T1.
- **Done when:** a fixture struct's fields, offsets and sizes match the
  source.

### G07 Separate and compressed debug info

**G07-T1 Compressed DWARF**

- **Steps:**
  1. Add zlib (zlib licence, allowed) through the pinned-dependency mechanism
     in `cmake/`. Update `THIRD_PARTY_NOTICES` and the SBOM.
  2. Decompress SHF_COMPRESSED sections (`Elf64_Chdr`, ELFCOMPRESS_ZLIB) with
     an output cap of 256 MiB per section.
  3. ZSTD sections stay Unsupported unless zstd (BSD) is also added.
- **Tests:** build the debuggee with `-gz=zlib` in `tests/CMakeLists.txt`,
  then `DebugInfo.CompressedSectionsAreRead`.

**G07-T2 .dSYM, .gnu_debuglink, build-id**

- **Steps:**
  1. Given a binary, look for:
     - `<binary>.dSYM/Contents/Resources/DWARF/<name>`, matched by LC_UUID
     - `.gnu_debuglink` next to the binary, with its CRC32 checked
     - `/usr/lib/debug/.build-id/xx/rest.debug`
  2. Add a CLI flag `--debug-file PATH`.
  3. A mismatch is a diagnostic, never silently used.
- **Tests:** on macOS CI, build the debuggee and run `dsymutil`. On Linux,
  use `objcopy --only-keep-debug` and `--add-gnu-debuglink`.

### G08 SIMD (after G01)

- **G08-T1:** IR vector values of 16 bytes with lane operations: integer
  add/sub/mul/and/or/xor/shift per lane, compare-to-mask, horizontal add
  (`addv`, `phaddd`, `psadbw`-free subset), load/store, broadcast
  (`dup`/`pshufd` broadcast forms), zero. The interpreter executes them
  exactly.
- **G08-T2:** x86 SSE2 integer subset, `movdqa`/`movdqu`/`paddd`/`psubd`/
  `pand`/`por`/`pxor`/`pcmpeqd`/`pshufd`, plus AArch64 NEON
  `movi`/`dup`/`add`/`sub`/`mul`/`cmeq`/`addv`/`ld1`/`st1`/`ushll`/`uaddw`.
- **Done when:** the -O3 vectorised corpus functions (`c_sum_array`,
  `c_dot`, `c_count_eq`, `c_bytes_sum`, `c_fill`) are Complete and verified
  on at least one compiler per ISA. Pseudocode may show lane operations
  (`v_add_i32x4(a, b)`); it must not pretend they are scalar loops.

### G09 Library function identification

- **G09-T1 Signature format and matcher.**
  1. Design an original format, documented in `docs/SIGNATURES.md`: for each
     function, the first N bytes with a mask for relocated bytes, the length,
     a CRC32 of the remaining bytes up to the function end, the name, and the
     library name, version and licence.
  2. A match requires every masked byte and the CRC.
  3. A pattern that matches more than one name → no name ("ambiguous").
  4. Matches give names with provenance "signature <lib> <version>" and never
     override user renames.
- **G09-T2 Generator.** `donkey-cli sig make <archive.a|lib.so|.lib> --lib
  NAME --version V --out FILE`. Reads relocations to build the masks. Needs
  ELF relocatable support (G15-T1) for `.a`.
- **G09-T3 Signature sets.**
  - Generate sets only from libraries whose licence allows redistribution of
    derived data: musl (MIT), compiler-rt and libc++ (Apache-2.0 with LLVM
    exception), the MinGW-w64 CRT (check its notices), and FreeBSD libc
    (BSD).
  - **[owner decision]** before adding glibc (LGPL) or the MSVC runtime.
  - Store the sets under `signatures/` with provenance.
- **Tests:**
  - `Signatures.IdentifyMuslFunctionsInAStaticBinary`: build a static
    binary against musl in CI; at least 90 % of known functions named and
    0 wrong names.
  - `Signatures.AmbiguousPatternsNameNothing`
  - fuzz target `fuzz_sig`

### G10 C++

- **G10-T1 Itanium demangler.**
  - Write your own implementation of the Itanium C++ ABI mangling grammar
    (public spec).
  - Limits: maximum input 4 KiB, maximum recursion 256, maximum output
    16 KiB.
  - Do not copy libiberty (LGPL). LLVM's demangler is Apache-2.0 with the
    LLVM exception and is allowed if vendored with its notice. Writing your
    own is preferred for size.
  - Tests: `Demangle.ItaniumCorpus` with at least 300 mangled/expected
    pairs, generated by compiling `tests/fixtures/cpp/*.cpp` and recording
    `c++filt` output once, with provenance. Add a fuzz target.
- **G10-T2 MSVC demangler.** Same approach, using the public MSVC name
  decoration documentation.
- **G10-T3 RTTI and vtables.**
  - Parse Itanium `typeinfo` objects and vtables (offset-to-top, typeinfo
    pointer, function pointers), and MSVC RTTI Complete Object Locators.
  - Build a class hierarchy.
  - In the decompiler, resolve `call [reg + k]` where reg was loaded from an
    object whose vtable is known: show the method name, but keep the call
    indirect in the IR.
- **G10-T4 UI.** Show demangled names everywhere, with the raw name in the
  tooltip, and a class hierarchy panel.

### G11 Scripting and automation

The rules forbid mandatory Python and say the plugin boundary is a C ABI or
out-of-process RPC. So scripting is RPC.

- **G11-T1 `donkey-cli serve`.**
  - JSON-RPC 2.0 over stdin/stdout. Versioned (`donkey.rpc.v1`), with the
    schema in `docs/RPC.md`.
  - Methods: `open`, `info`, `functions`, `disasm`, `decompile`, `xrefs`,
    `callgraph`, `strings`, `annotations.list`.
  - Write methods (`rename`, `comment`, `type.apply`) need `--allow-write`
    and a project path.
  - Message size cap 16 MiB. Every request has an id; errors use stable
    codes.
- **G11-T2 Python client (optional package).** `bindings/python/donkey/`
  starts `donkey-cli serve`, has typed wrappers, and runs pytest against the
  built CLI. It is not part of the core build and never a dependency of it.
- **G11-T3 Batch mode.** `donkey-cli batch script.json` runs a list of RPC
  requests and writes the results.
- **Tests:** CTest cases that pipe requests into `serve` and match the
  responses; a fuzz target for the request parser.

### G12 Interactive edits

- **G12-T1 Make code / make data / undefine.**
  - New annotation kinds (schema bump): `CodeStart`, `DataRange(type, count)`
    and `Undefined`.
  - Analysis honours them: user data ranges are never decoded as code; user
    code starts are seeded like function starts.
  - Undo and redo work, and they persist.
  - UI keys, using the shared components: `C` (code), `D` (data), `U`
    (undefine), `A` (string).
- **G12-T2 Arrays and strings at an address.**
- **G12-T3 Rename and type locals in the decompiler.**
  - Stored per function and IR variable, keyed by stack offset or register
    and definition address. They survive re-analysis when the key still
    exists.
- **Tests:** session tests for each kind; a UI script `tests/ui/edits.donkeyui`
  covering keys, undo and persistence.

### G13 Processor coverage

Each ISA, in order: decoder → CFG → lifter → corpus under qemu-user (section
7 shows the method).

- **G13-T1 32-bit ARM and Thumb.**
  - Add `CS_ARCH_ARM` to `src/decode/decode.cpp`. Thumb mode comes from
    symbol bit 0 and the `$t`/`$a` mapping symbols (they are currently
    skipped in `src/binary/elf.cpp`; keep them as mode hints instead).
  - Lift the integer subset, conditional execution, and IT blocks in Thumb.
  - Corpus: `arm-linux-gnueabihf-gcc` plus qemu-arm.
- **G13-T2 RISC-V 64.** Requires Capstone 6 or a pinned newer Capstone:
  **[owner decision]** on upgrading Capstone. RV64GC integer subset, with
  the compressed instructions.
- **G13-T3 MIPS32/64 and PPC32/64.** Decoder and CFG first (delay slots for
  MIPS); lifting later.

### G14 Debugger coverage

Implement `DebugAdapter` (`include/donkey/debug/debug.h`). Copy the structure
of `src/debug/native_linux.cpp` and its tests in
`tests/unit/native_debug_test.cpp`. The same tests must pass on the new
platform; do not write new, weaker ones.

- **G14-T1 GDB remote serial protocol client.**
  - Connect to `gdbserver`, `qemu -g` or `lldb-server gdbserver`, which gives
    remote debugging and every ISA qemu supports.
  - Handle packet framing and checksums, and parse the target description
    XML for registers.
  - Packets: `qSupported`, `?`, `g`/`G`, `p`/`P`, `m`/`M`, `Z0`/`z0`, `c`,
    `s`, `vCont`, and `qXfer:libraries` / `qXfer:features`.
  - Network access needs `DONKEY_CAP_NETWORK`-style explicit user consent in
    the UI.
  - Tests: run `donkey_test_debuggee` under `gdbserver` on Linux CI and pass
    the NativeDebug test list through the new adapter.
- **G14-T2 FreeBSD.** `ptrace(PT_*)` with `kinfo_proc` for modules. Run the
  same tests in the FreeBSD VM job.
- **G14-T3 macOS.**
  - Mach task port and exception ports. `task_for_pid` needs the
    `com.apple.security.cs.debugger` entitlement or root; on CI, run the tests
    with `sudo`.
  - Document the entitlement in `docs/USER_GUIDE.md`.
- **G14-T4 Windows on Arm.** ARM64 `CONTEXT` in `native_windows.cpp`.
- **G14-T5 Hardware watchpoints and conditional breakpoints.** Use the debug
  registers (x86 DR0-DR7, AArch64 DBGWVR through ptrace) where the OS allows.

### G15 Loaders and multiple images

- **G15-T1 ELF relocatable objects and static archives.** Apply relocations
  for x86-64 and AArch64 (the common types; the rest → Partial), and list the
  `.a` members.
- **G15-T2 Several images in one project.** Load several binaries, resolve
  imports to exports by name and library, and add cross-image xrefs. This is
  acceptance project A14's gap.
- **G15-T3 Dumps and firmware.** ELF core files (show threads and memory),
  Windows minidumps (MIT-licensed format docs), Intel HEX and S-records as raw
  images.

### G16 Scale

- **G16-T1 Real-world benchmark.**
  - A CI job (`workflow_dispatch` only) downloads pinned, checksummed,
    redistributable large binaries and records analysis time, peak RSS and
    UI frame times with the UI scripts. Results go into
    `docs/BENCHMARKS.md`, labelled with the machine.
  - Candidates: a release build of LLVM `clang` (Apache-2.0), or Firefox's
    `libxul` (MPL-2.0; do not commit it, download it).
- **G16-T2 Incremental re-analysis.** After an edit, re-analyse only the
  affected functions. Measure on the benchmark.

### G17 UI breadth (P3)

- Byte, immediate and regex search; a cross-reference graph; a command
  palette; synchronised views (disassembly ↔ pseudocode ↔ hex already partly
  synchronised); theme editor.
- Each feature needs a UI script.

### G18 Signed releases (owner)

The owner provides an Apple Developer ID certificate and notarisation
credentials, and a Windows code-signing certificate, as repository secrets.
Then `.github/workflows/package.yml` signs and notarises (`codesign
--options runtime`, `notarytool submit --wait`, `stapler staple`; `signtool`
for the `.exe`). Agents must not create, guess or request these secrets.

### G19 Accessibility (research)

Dear ImGui has no accessibility tree. The options are:

- an accessibility bridge per platform that mirrors the shared components
  (`src/ui/components`): AT-SPI, NSAccessibility, UI Automation
- AccessKit (MIT/Apache-2.0, Rust; the rules forbid Rust for Donkey code, so
  this needs **[owner decision]**)

The first step is a written design in `docs/` only.

---

## 6. PR description template

```
Task: G0X-TY <title>

What changed:
- ...

Tested (commands and results):
- ctest --preset headless-linux: N/N passed
- clang-headless: N/N passed
- dev-linux UI under Xvfb: N/N passed
- corpus summary: O0 a/39, O2 b/39, O3 c/39 (before: ...)
- [aarch64 under qemu, if relevant]: ...

Not tested / not done:
- platforms not run locally (CI covers ...)
- parts of the task left Partial and why

Docs updated: SUPPORT_MATRIX.md, DESIGN.md §17.2, IDA_GAP_LEDGER.md row G0X
```

## 7. Verifying AArch64 code on an x86-64 machine

You can cross-build the headless suite for aarch64 and run it under
qemu-user, so the corpus oracle runs on real AArch64 code. This is how the
AArch64 lifter was verified on 2026-10-31.

1. Install the tools:

   ```bash
   sudo apt-get install -y qemu-user gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
   ```

2. Save this toolchain file as `/tmp/a64.cmake`:

   ```cmake
   set(CMAKE_SYSTEM_NAME Linux)
   set(CMAKE_SYSTEM_PROCESSOR aarch64)
   set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)   # or clang with CMAKE_C_COMPILER_TARGET
   set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)
   set(CMAKE_CROSSCOMPILING_EMULATOR qemu-aarch64;-L;/usr/aarch64-linux-gnu)
   set(CMAKE_FIND_ROOT_PATH /usr/aarch64-linux-gnu)
   set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
   set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
   set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
   ```

3. Configure, build and run:

   ```bash
   cmake -S . -B build/cross-a64 -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=/tmp/a64.cmake -DDONKEY_BUILD_UI=OFF
   cmake --build build/cross-a64 --parallel
   cd build/cross-a64/tests && qemu-aarch64 -L /usr/aarch64-linux-gnu ./donkey_unit_tests --gtest_filter='DecompilerCorpus.*:Ir.*'
   ```

   If a dependency download is blocked, point
   `FETCHCONTENT_SOURCE_DIR_CAPSTONE`, `_GOOGLETEST` and
   `_SQLITE_AMALGAMATION` at sources fetched by another build.

The ptrace debugger tests cannot run under qemu-user. They run natively on
the `ubuntu-24.04-arm` CI runner.

## 8. Suggested order for an unattended run

The tasks the oracle checks come first, because a wrong result fails CI
instead of slipping through:

1. G04-T0
2. G02-T1, G02-T2, G02-T3
3. G03-T2, G03-T1
4. G01-T1, G01-T2, G01-T3
5. G04-T1, G04-T2
6. G03-T3
7. G05-T1, G05-T2
8. G07-T1
9. G10-T1
10. G11-T1
11. Everything else

Do the tasks one at a time, each with its own PR and green CI, before the
next starts on top of it.
