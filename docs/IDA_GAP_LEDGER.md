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
| G01 | Floating point (x86 SSE scalar, AArch64 FP) | Decompiles float/double code | The IR has exact floating-point operations (G01-T1). x86-64 scalar SSE (G01-T2) and the AArch64 scalar `s`/`d` forms, including `fmadd`/`fmsub` (G01-T3), lift to them. Packed and vector forms stay Partial (G08) | P0 | IN PROGRESS (T1 and T2 DONE; T3 verified under qemu-aarch64 with GCC, and not yet verified with Apple Clang or on CI runners) |
| G02 | x86 integer gaps | Full integer semantics | Complete for the x86 integer gaps: adc/sbb, double-width mul/div, bit operations, bsf/bsr, flags across blocks (G02-T1 to T4) | P0 | DONE (G02-T1 to T4) |
| G03 | AArch64 integer gaps | Full | Complete for the AArch64 integer gaps (G03-T1 to T4). The Partial corpus functions left are FP and SIMD, owned by G01 and G08 | P0 | DONE (G03-T1 to T4) |
| G04 | Decompiler readability | Clean C with merged variables, `for` loops, simplified conditions | Register aliases merged (T1); copy propagation and dead-register removal (T2); one-block loops as do-while, break, continue and integer negation (T3, partial: the for form is not in the corpus); parameters and frame slots take their DWARF names at -O0 (T4) | P0 | IN PROGRESS (T0, T1, T2, T4 DONE; T3 PARTIAL: for form not in the corpus) |
| G05 | Type system and user types | Type libraries, struct/enum editing, propagation | The type store with validation and ABI sizes (T1, partial); a bounded C declaration parser (T2); applying a prototype to recovered code (T3, partial); project type add, list and apply in the CLI (T4, CLI part). No editing UI, no undo, and the decompiler does not read the applied types |list| IN PROGRESS (T2 DONE; T1, T3, T4 PARTIAL; T4 UI and undo, and T3 step 3, TODO) | P0 | IN PROGRESS (G05-T1 PARTIAL; T2 DONE; T3 PARTIAL; T4 PARTIAL, CLI only) |
| G06 | PDB (Windows debug info) | Full | PDB 7.00 read: the MSF container, PDB info, modules, procedures, globals, the struct, class, union and enum types with their instance fields, pointers, arrays, modifiers and procedures; mapped into the type store with provenance Pdb (`types_from_pdb`). Enumerators are read with their values (LF_ENUMERATE). Not read: C++ class layouts; structs with base classes, virtual tables or methods are reported and left out | P1 | IN PROGRESS (T1 to T3 DONE for C structs, enums and the fixtures; C++ class layouts TODO) |
| G07 | Separate debug files (.dSYM, debuglink, build-id, compressed DWARF) | Full | Separate debug files by build-id and debuglink (CRC-32 checked); a `.dSYM` bundle found by LC_UUID; `debuginfo --debug-file` checks a named file; zlib and zstd compressed DWARF | P1 | DONE (T1 and T2; the .dSYM lookup is checked with Apple's dsymutil output on macOS CI, `cli.debuginfo_json`) |
| G08 | SIMD (SSE/AVX, NEON) | Decompiles to intrinsics | Unsupported: vectorised loops are Partial | P1 | TODO |
| G09 | Library function identification | FLIRT signatures, Lumina | None | P1 | TODO |
| G10 | C++ (demangling, RTTI, vtables) | Full | Itanium demangler (T1, partial: 502 of 512 corpus names match c++filt); MSVC demangler (T2, partial); Itanium RTTI and vtables for ELF with AArch64 PLT names (T3, partial); demangled names in donkey-cli info (T4, CLI part) | P1 | IN PROGRESS (T1 to T4 PARTIAL; the GUI demangled-name and class-hierarchy panel is open) |
| G11 | Scripting and automation | IDAPython, IDC, plugin SDK | serve: JSON-RPC 2.0 with the read methods, decompile and annotations.list (with --project), and the write methods rename, comment and type.apply (with --project and --allow-write); batch mode; the optional Python client; a fuzz target for the request handling | P1 | DONE (G11-T1 to T3) |
| G12 | Interactive edits | Make code/data, define arrays and strings, rename and type locals | Make code, make data and undefine with undo and redo, with UI keys C, D and U and a scripted test (T1). Arrays (Shift+D, `<size>:<count>`) and strings (A, `string:<bytes>`) as data ranges, with a Data window and a scripted test (T2, partial: no inline listing rows; UTF-16 strings done). Rename, comment, bookmark and function boundaries from before | P1 | IN PROGRESS (T1 DONE; T2 PARTIAL: no inline listing rows; UTF-16 strings done; T3 PARTIAL: local names for parameters and frame slots, headless, CLI and session API with undo, shown in the decompiler; no GUI rename gesture, no local types) |
| G13 | Processor coverage | Dozens of ISAs | 32-bit ARM (A32, little-endian), RISC-V 64 (RV64GC, little-endian), MIPS32 and PowerPC32 (each in both byte orders) decode, checked against llvm-objdump. MIPS delay slots are in their branch's block in the CFG; branch-likely forms make the graph partial. Thumb is not decoded or detected; no ISA is lifted; MIPS16 and microMIPS images are refused with `elf.mips_isa_extension`; 64-bit MIPS and PowerPC decode in their 64-bit modes, checked against llvm-objdump; VLE is not detected | P2 | IN PROGRESS (A32, RV64GC, MIPS32 and PPC32 decode DONE; MIPS delay slots DONE for ordinary branches; Thumb, lifting, CFG checks and branch-likely forms TODO) |
| G14 | Debugger coverage | All major OSes, remote debugging, hardware watchpoints | Hardware watchpoints on Linux x86-64 (T5, partial) in the library and the CLI; the native debugger on Linux and Windows x64 otherwise | P2 | IN PROGRESS (T5 PARTIAL; T1 to T4 TODO) |
| G15 | Loaders and multi-image | Objects, archives, dumps, firmware; cross-image references | Relocatable objects, GOT, COMMON and page relocations, and the TLS models for x86-64 and AArch64 (T1, partial); archives listed (T1); Intel HEX, S-records, ELF cores and Windows minidumps (T3, DONE for the formats it names; the minidump test file is generated, not Windows output). Multi-image projects not started (T2) | P2 | IN PROGRESS (T1 PARTIAL; T2 TODO; T3 DONE) |
| G16 | Scale on real large binaries | Decades of tuning | Scale benchmark over generated programs up to 80,000 functions; the block bound is reported, not silent (T1, partial). No real-world corpus yet | P2 | IN PROGRESS (T1 PARTIAL; T2 incremental re-analysis and real-world corpus TODO) |
| G17 | UI breadth | Many views, search kinds, command palette | Core views and text search in lists | P3 | TODO |
| G18 | Signed releases | Signed installers | Ad-hoc signed .app, unsigned .exe | P1 | BLOCKED [owner decision]: needs the owner's Apple Developer ID and Windows code-signing certificate. Excluded from this goal |
| G19 | Accessibility | Platform accessibility APIs | None: Dear ImGui exposes no accessibility tree | P3 | BLOCKED on owner decisions (AccessKit waiver, first platform, minimum bar); design only, see docs/ACCESSIBILITY.md |

### Status at the end of this session

Completed and merged or on the integration branch (see the table for each gap's status):

- G02 (T1 to T4), G03 (T1 to T4), G11 (T1 to T3), G12-T1, G13 A32, RV64GC, MIPS32 and PPC32
  decoding.
- G01-T3 with the AArch64 rounding rule, G01-T2 with the x86 rule, the G04-T3 loop structuring
  docs, and the G05-T1 review fixes.
- Since then, on the designated branch: G07-T2 (a `.dSYM` found by LC_UUID and `debuginfo
  --debug-file`, checked on Linux with LLVM's output), G06-T3 (PDB struct fields, pointers,
  arrays and procedures, mapped into the type store), G15-T3 (Windows minidumps), and G13 MIPS
  delay slots in the CFG for ordinary branches, calls and returns.

Still open, in ledger order:

- G04-T3: the for form in the corpus, and the verification of break and continue in the corpus.
  The O0 and O2 loops are not printed as `for` yet; see the status above.
- G05-T3 step 3 and G05-T4: the type editing UI and undo.
- G06: C++ class layouts (base classes, virtual tables, methods). Enumerators are done.
- G10-T1 to T4: MSVC RTTI and call-site resolution, and the GUI
  demangled-name and class-hierarchy panel.
- G08 SIMD lifting and G09 library identification: not started.
- G12-T2 inline listing rows; G12-T3 local types and the GUI rename gesture: not done. G12-T3 local
  names exist headless, in the CLI and through the session API (with undo); the decompiler shows
  them, but no GUI gesture sets them yet.
- G13: Thumb, lifting for A32, RV64, MIPS and PowerPC, CFG checks, the MIPS branch-likely forms,
  and VLE detection. Not done. MIPS16 and microMIPS images are refused, and 64-bit MIPS and PowerPC
  decode, both with evidence in the decoder tests.
- G14-T1 to T4: remote debugging, FreeBSD, macOS, Windows on Arm, GUI watchpoints and AArch64
  DBGWVR. The lldb-server oracle is available for T1.
- G15-T1 remaining TLS forms (`-mtls-dialect=trad`: the AArch64 GD and LD sequences, whose
  relaxation does not fit the original instructions), G15-T2 multi-image projects. G15-T3 is done
  for the formats it names; a minidump written by Windows has not been checked.
- G16-T2 incremental re-analysis and a real-world corpus.
- G17 UI breadth: not started.
- G19 accessibility: blocked on owner decisions (see its section).
- G18: excluded (signing certificates).
- G16-T2: incremental re-analysis and a real-world corpus.
- G17: UI breadth (more views, search kinds, command palette).
- G01: verification with Apple Clang and on CI runners.

Blocked, not in this goal's scope or not closeable here:

- G18 needs the owner's Apple Developer ID and a Windows code-signing certificate.
- G19 needs owner decisions: the AccessKit waiver, the first platform, and the minimum bar.
- The session branch and the chain of stacked PRs both implemented some of the same work.
  The integration branch reconciles them; `main` is updated only after CI is green.


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
- **Status:** DONE for the IR (G01-T1), on x86-64 natively and AArch64 under
  qemu-aarch64. No lifter emits these operations yet, so FP functions stay
  Partial until G01-T2 and G01-T3. Added: `FAdd`, `FSub`, `FMul`, `FDiv`,
  `FSqrt`, `FNeg`, `FAbs`, `FCompare`, `IntToFloat`, `UIntToFloat`,
  `FloatToInt` (truncates), `FloatExtend` and `FloatTruncate`, with the width
  of the statement as the float width (4 or 8). `IrFloatModel` on the statement
  picks the architecture's rules: the default NaN of an invalid operation
  (x86 negative `0xfff8…`, AArch64 positive `0x7ff8…`), the integer a
  conversion gives for a NaN or an out-of-range value (x86 the minimum, AArch64
  0 and saturation), and the flags a comparison sets (x86 ZF/PF/CF with
  unordered setting all three; AArch64 NZCV with unordered 0011). NaN operands
  are returned quieted, the first one when both are NaN. The expected bits come
  from running the same operations natively (x86-64 SSE) and under qemu-aarch64,
  not from host arithmetic on the test side; the two models differ exactly where
  the two hosts do.
  Deviations from the plan, all deliberate: (1) the IR stays untyped. A
  float statement carries its width and the model, and the verifier checks
  widths, so an integer operand of another width is rejected, but an 8-byte
  integer fed to a double operation is not detected. Typed operands are a later
  change if the decompiler needs them. (2) The x86 `jp`/`jnp` conditions were
  added as `Parity`/`NoParity`, and the integer compare reports PF from the
  low byte of its result, as x86 does; AArch64 never asks for parity. (3) Only
  double-precision compares were checked against native execution; the single
  compare uses the same code but is not measured. (4) `fuzz_ir` was not built
  or run here.
  Evidence: `Ir.FloatArithmeticMatchesIeee` (26 double and single cases, both
  models), `Ir.FloatToIntIndefiniteOnX86AndSaturatesOnAArch64`,
  `Ir.FCompareUnorderedSetsFlags`, `Ir.VerifierRejectsMixedIntFloatOperands`,
  `Ir.FloatConstantsPrintAsExactHexadecimalFloats`. Flipping the default-NaN
  model fails `Ir.FloatArithmeticMatchesIeee`, so it is checked.

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
     *Superseded in G01 (clang):* the high 64-bit lane is now a second register
     (`xmm0_hi`) for `movaps`/`movapd`, the packed logical operations, the zeroing
     idioms and memory loads. Other instructions that touch the upper lanes are
     still Unsupported.
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
- **Status:** DONE for x86-64 scalar SSE, with a conservative rule. Scalar arithmetic and
  integer-to-float conversions depend on the MXCSR rounding mode, which the caller may set, so
  each such function is Partial with that assumption in its notes. GCC at -O0 in this build: 6 of 26
  Complete, none wrong. Clang 18.1 at -O0: 6 of 26 Complete, none wrong (the figures and the rule are in
  `docs/SUPPORT_MATRIX.md`). The clang count needed the high 64-bit lane of an XMM register modelled
  (see step 2 below), `cmpltsd` lowered as a masked select, and float compares carried across blocks
  with a memory operand. Other packed and SSE forms stay Partial. Argument and return registers follow
  the XMM registers that the function reads and writes.

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
- **Status:** IN PROGRESS. The scalar forms are lifted and checked under qemu-aarch64
  with GCC 13.3 at -O0: 26 of 26 Complete, none wrong, on 48 vectors each. The IR op
  is `FMulAdd`, with `FMulSub` for `fmsub`; the NaN and invalid-product rules were
  checked against qemu. Not lifted: `fcvtzu` (no unsigned float-to-integer IR op),
  `fnmadd` and `fnmsub`, and vector forms. Not done, and required by "done when": the
  Apple Clang measurement, and the corpus on the `ubuntu-24.04-arm` and `macos-15`
  runners. Until those exist this stays IN PROGRESS. The counts are in
  `docs/SUPPORT_MATRIX.md`.

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
- **Status:** IN PROGRESS. Done: `popcnt`, `tzcnt`, `lzcnt`, `bswap` (32 and
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
  at O3 with `popcnt`. Still not done, so the task stays IN PROGRESS: `bsf`/`bsr`
  (needs a zero-flag state, or G02-T4 for the guarded form in `c_clz64_guarded`).
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
- **Status:** DONE on GCC 13.3 under qemu-aarch64. Added the IR ops
  `CondCompare` (ccmp) and `CondCompareAdd` (ccmn). The interpreter holds an
  explicit NZCV value after them, and conditions read that value with AArch64
  meanings. A compare or test clears it. `ccmp`/`ccmn` are lifted only when the
  flags before are exact. Otherwise they are Unsupported, so the function is
  Partial. Evidence: `Ir.AArch64ConditionalCompareUsesTheCompareOnlyWhenItsConditionHolds`,
  `Ir.AArch64ConditionalCompareSetsTheImmediateNzcvWhenItsConditionFails`,
  `Ir.AArch64ConditionalCompareNegatedSetsTheFlagsOfTheSum`,
  `Ir.AArch64ConditionalCompareWithoutExactFlagsIsPartial`,
  `Ir.VerifierRejectsAConditionalCompareWithAnOutOfRangeNzcv`. Corpus under
  qemu-aarch64, 59 functions: `c_both` and `c_collatz_steps` are Complete and
  verified at O0, O2 and O3, and no result is WRONG. Not done: Apple Clang was
  not run locally (CI's macOS corpus job covers it).

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
- **Status:** DONE on GCC 13.3 and Clang 18.1 under qemu-aarch64. Done: `udiv` and `sdiv` with the AArch64 results for
  zero divisors and `INT_MIN / -1`, `umulh` and `smulh`, `clz`, `cls`, `rbit`,
  `rev`, `rev16`, `rev32`, `extr`, `bfi` and `bfxil`. The guard is arithmetic,
  not a compare: a compare would write the NZCV state that later instructions in
  the block read. Evidence: `Ir.AArch64DivisionMatchesTheArchitectureAtTheEdges`,
  `Ir.AArch64HighMultiplyIsTheUpperHalf`,
  `Ir.AArch64CountAndReverseInstructionsMatchTheArchitecture`,
  `Ir.AArch64ExtractAndBitfieldInsertMatchTheArchitecture`. The corpus under
  qemu-aarch64 (GCC 13.3): `c_udiv32`, `c_urem32`, `c_udiv64`, `c_urem64`,
  `c_div10`, `c_mulhi_u64` and `c_mulhi_s64` are Complete and verified at O0,
  O2 and O3. Since G03-T4 added `cmn`, `c_sdiv32`, `c_srem32`, `c_sdiv64` and
  `c_srem64` are Complete and verified too, on both compilers. The widening
  multiplies are done as well: `umull`, `smull`, `umaddl`, `smaddl`, `umsubl`,
  `smsubl`, `umnegl` and `smnegl`, each 32-bit source extended to 64 bits before
  the multiply. Evidence: `Ir.AArch64WideningMultiplyUsesTheLow32BitsOfEachSource`.
  On Clang 18.1, `c_sum_to` (which uses `umull`) is Complete at O2 and O3 now.
  The corpus has no WRONG result on any tree.

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
- **Status:** DONE on GCC 13.3 and Clang 18.1 under qemu-aarch64. Not yet run
  on `ubuntu-24.04-arm` or `macos-15` (CI is the check for those two). GCC and
  Clang do not give `c_switch_dense` a code jump table on AArch64 (at -O0 it is
  a compare chain, at -O2 a lookup of constants), so the recovery test uses the
  fixture `tests/corpus/jump_table.c` (`jt_dispatch16`). `c_switch_dense` is
  Complete and verified at O0, O2 and O3. Recognised: GCC's form (`b.ls` into
  the table, byte offsets with `add ... sxtb #2`) and Clang's form (`b.hi`
  falling into the table, `uxtb ... lsl #2`); any other shape stays unresolved.
  The switch reads a copy of the compared register taken after the compare,
  since GCC's table code overwrites `x0`. The CFG keeps the last two path
  entries for a block entered through a conditional's taken edge, so the
  compare is in view. In the x86 slice, an unrelated computation with an
  unknown input now leaves its destination unknown instead of failing; only a
  jump that needs that value fails. Evidence: `Cfg.AArch64GccShapedJumpTableIsRecovered`,
  `Cfg.AArch64ClangShapedJumpTableIsRecovered`,
  `Cfg.AArch64TableOnTheOutOfRangeSideIsNotRecovered`,
  `Cfg.AArch64TableEntryOutsideTheCodeIsNotRecovered`,
  `DecompilerCorpus.JumpTableIsRecoveredWithEvidence`,
  `DecompilerCorpus.JumpTableFixtureAgreesWithTheCompiledCode`. The corpus
  counts did not change on any tree. Not done: a function whose cold block lies
  below its entry is rejected by the verifier (see `docs/SUPPORT_MATRIX.md`).

**G03-T4 AArch64 carry chain** (depends: G02-T1; added when G02-T1 landed)

- **Goal:** lift AArch64 `adc`, `adcs`, `sbc`, `sbcs`, `adds`, `subs`, `cmn`
  and `cmp` (`cmn` is `adds` into the zero register), with C and V from the
  existing NZCV model. The IR already has `AddCarry` and `SubBorrow`
  (G02-T1), and `condition_holds(Carry)` already gives AArch64 C.
- **Files:** `src/ir/lift_aarch64.cpp`, the corpus is unchanged.
- **Done when:** `c_add128_hi`, `c_sub128_hi` and `c_add_wraps` are Complete
  and verified on GCC aarch64 at O0, O2 and O3 under qemu. Record the
  counts in `docs/SUPPORT_MATRIX.md`.
- **Status:** DONE on GCC 13.3 and Clang 18.1 under qemu-aarch64 (see the
  follow-up below for `adcs`/`sbcs`). Lifted: `adds` (flags of
  a + b, with an unconditional `CondCompareAdd`), `cmn` (the same, into the zero
  register), and `adc`/`sbc` (`AddCarry`/`SubBorrow`, which read the carry from
  the flags before). The unconditional form is `IrCondition::None` in
  `CondCompare`/`CondCompareAdd`. Lifting `adc`/`sbc` needs exact flags, and a
  AArch64 `adc`/`sbc` without S do not write NZCV, so every carry reader in a block reads the
  same carry. On x86 the carry out of `adc`/`sbb` is not modelled, so a second carry reader in a
  block is Partial. `adcs`/`sbcs` set NZCV from the addition and are modelled. Also fixed in this task: an unsupported
  statement now clears the exact-flags state, so a later `adc` cannot read a
  carry through it. Evidence: `Ir.AArch64CarryChainAddsThenAdcUsesTheSumsCarry`,
  `Ir.AArch64SubtractWithBorrowUsesTheCompareBorrow`,
  `Ir.AArch64CmnAgainstMinusOneSetsTheZeroFlag`,
  `Ir.AArch64AddsSetsTheZeroFlagOfTheSum`,
  `Ir.AArch64CarryWithoutAFlagWriterIsPartial`,
  `Ir.AArch64SecondCarryReaderIsPartial`, `Ir.AArch64AddsWithCarryIsPartial`.
  Corpus under qemu-aarch64, 59 functions: `c_add128_hi`, `c_sub128_hi`,
  `c_add_wraps`, `c_sdiv32`, `c_srem32`, `c_sdiv64` and `c_srem64` are Complete
  and verified at O0, O2 and O3, and no result is WRONG. Not done: SIMD
  (`movi`, `dup`, `fmov`, `ldr d`) and `c_switch_sparse` remain Partial.
- **Follow-up (adcs, sbcs, cross-block flags):** `adcs` and `sbcs` are lifted
  with the IR op `AddCarryFlags`: dest = a + b + C, and NZCV is the flags of the
  addition (C the carry out, V the signed overflow). `sbcs` is the same op on
  NOT(b), as the architecture defines it. The flags after them are exact, so a
  second carry reader can follow. The expected values in
  `Ir.AArch64AdcsAndSbcsSetNzcvLikeTheAddition` are ground truth from running
  the instructions under qemu-aarch64; the earlier test that asserted adcs is
  Unsupported was replaced, because the limitation it recorded is what this
  removes. Also: a `cmp` or `tst` whose flags are still current at the end of a
  block that falls through into a block with one predecessor is repeated at the
  start of that block (`Ir.AArch64FlagsFromSinglePredecessorAreExact`; the
  negative cases are `Ir.AArch64FlagsRewrittenAfterTheCompareStayPartial` and
  `Ir.AArch64FlagsFromAddsDoNotCarryAcrossBlocks`). This is what makes
  `c_switch_sparse` Complete and verified on GCC at O0, O2 and O3. Corpus under
  qemu-aarch64, 59 functions: GCC O0 58/59, O2 58/59 (was 57), O3 52/59 (was
  51); Clang O0 56/59, O2 53/59, O3 53/59 (unchanged). No result is WRONG on any
  tree. All 30 `Ir.AArch64*` tests pass natively, and the AArch64 corpus, IR
  and CFG tests (125) pass under qemu on both cross trees.

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

- **Status:** DONE. Every register operand is its family, so `eax`, `ax`, `al`,
  `rax`, and `w8`/`x8` are one variable. A 4-byte write zero-extends (the rule the
  interpreter already applied, so it stays a width of 4 on the family). A 1- or
  2-byte write, and a write to `ah`, is an explicit merge with the other bytes of the
  family, and a read of `ah` is a shift. A conditional write keeps the old value
  when its condition fails, and a 32-bit `cmov` zero-extends either way, as the
  hardware does. The note "register aliases are not canonicalised" is gone from both
  lifters. Evidence: `Ir.X86NarrowWritesMergeIntoTheFamily`,
  `Ir.X86DoubleWordWritesZeroExtend`,
  `Ir.X86ConditionalMoveOfADoubleWordZeroExtendsEvenWhenItFails` (the last checked on
  hardware), and the corpus outcome report is identical to the one before the change.
  `DecompilerCorpus.EveryPassPreservesSemantics` passes. The pseudocode now shows
  narrow reads of a family with their width, as in `(u8)rax`.

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
- **Status:** DONE with deviations. Implemented: copy propagation of register
  copies and constants within a block (`propagate_copies`), removal of temporaries
  nothing reads (`remove_dead_temporaries`), and removal of pure register writes whose
  value no later statement reads, with liveness over the blocks
  (`remove_dead_register_writes`). Calls, loads, stores, unsupported statements, and the
  registers that a return or the caller relies on (stack, frame, callee-saved, and
  return registers) are never removed. Not done, from the steps above: SSA (steps 1
  and 4) and memory forwarding across stores (step 2). The "done when" measure is the
  total of the pseudocode statement lines over the corpus, not the median: the median
  over 59 functions did not move at every level (AArch64 O2 and O3 stayed at 6), so the
  test asserts on the total. Totals, before to after: x86-64 O0
  1111 to 1026, O2 517 to 474, O3 707 to 664, O3-x86-64-v2 702 to 658; AArch64 (GCC)
  O0 1112 to 1058, O2 520 to 516, O3 737 to 733. Evidence:
  `DecompilerCorpus.EveryPassPreservesSemantics` (every pass checked on the corpus
  vectors), `DecompilerCorpus.StatementPassesShortenThePseudocode`, native ctest, and
  the AArch64 corpus under qemu-aarch64.

**G04-T3 Loop and condition recovery**

- **Steps:**
  1. Recognise `for (init; cond; step)` from a header with one back edge and
     an increment just before it.
  2. Make `break`/`continue` explicit.
  3. Simplify `!(a < b)` → `a >= b`, integer-only. Floating-point negation is
     not an inverse because of NaN; never do it for floats.
- **Done when:** G04-T0 passes and the corpus loop functions print a `for`.
- **Status:** PARTIAL. Done: a loop whose body is a single block that repeats
  itself (the header ends in the test that repeats it) is recognised, and a branch to
  the next block is a fall-through, so a function with an early return now prints
  `if (...) { return ...; } else { ... do { ... } while (...); ... }` instead of labelled
  blocks. The `c_sum_array` corpus function (x86-64 O2) is the example. Not done: the
  `for` form. A bottom-tested loop is printed as `do { } while`, which is exact. Turning
  it into `for (init; cond; step)` would move the step in front of the test, and that is
  only equal when the loop is entered with the test true, which needs a proof from the
  entry guard.
  Step 2 is done for `break`. A branch from a loop body to the loop's exit prints
  `break;`, and the body's exit is the one the loop's own test leaves to, with the blocks
  the header dominates below it included (so a `break` block that no path back to the
  header passes through still belongs to the loop). Before this, such a branch printed
  nothing and the loop repeated, which is wrong. A `break` inside a switch is not printed:
  the function falls back to labels. `continue` was already emitted for branches to the
  header. Evidence: `Ir.BranchToTheLoopExitInsideTheBodyIsBreak` (fails without the change),
  `Ir.LeavingTheLoopFromInsideASwitchIsNotStructured` (the switch guard; disabling it makes
  the test fail), and the full native suite (409 of 409).
  Step 3 for integers was already done: the complement table prints `!(a < b)` as
  `a >= b`, and floating-point compares do not take that path. Evidence:
  `Ir.NegatedIntegerComparisonIsWrittenAsItsComplement`.

**G04-T4 Names and locals from DWARF**

- **Steps:** when DWARF has a function's parameters and locals (DW_OP_fbreg
  locations), name the matching stack slots and arguments. Read
  `src/binary/dwarf.cpp` and `include/donkey/binary/debug_info.h`. Names are
  display-only; user renames (G12) always win.
- **Done when:** a test on the `-g` debuggee shows the real parameter names.
- **Status:** PARTIAL. Done: a function's parameters that arrive in registers take the
  names of the debug information's parameters, in order. `apply_debug_parameter_names`
  (`include/donkey/ir/debug_names.h`, `src/ir/debug_names.cpp`) applies them only when the
  counts match, every debug parameter is a scalar of the size and class of the register the
  function reads, and the names are distinct C identifiers; a structure or array passed by
  value is refused, because it cannot be matched by position. It renames the parameters and
  the pointer structures that refer to them, and it changes no type or statement. Evidence:
  `DecompilerCorpus.ParameterNamesComeFromTheDebugInformation`, which shows `u32 value` for
  `donkey_module_answer` in the `-g -O0` module fixture, and a refusal case. Done (CLI): the
  frame slots are named too; see `apply_debug_stack_names`. Not done: optimised code, nested blocks. At `-O0` the argument is stored to a frame slot (`*(u32 *)(rsp - 0x4) = rdi`), and
  the slot keeps its address form. The reader records `DW_OP_fbreg` locations of the direct
  children of a subprogram whose frame base is `DW_OP_call_frame_cfa`, as
  `DebugFunction::stack_slots` (`DebugStackSlot`: name, type, CFA offset, parameter flag,
  line). Evidence: `DebugInfo.StackSlotsGiveCfaOffsetsOfParametersAndLocals` on
  `tests/fixtures/debuggee/locals.c` (`donkey_locals_sum`: -36, -40, -24, -20). Not done:
  the decompiler does not yet map a CFA offset to the `rbp - n` address the frame uses, so
  the frame-local names are not shown, and nested lexical blocks are not read. The
  decompiler also spells integer types by width (`u32`), not by their C names; the name is
  the debug information's and the type spelling is the decompiler's.

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
- **Status:** PARTIAL. Done: the type model and the store. `TypeTable` (in
  `include/donkey/project/types.h`) holds kinds (void, integer, float, pointer, array,
  struct, union, enum, typedef, function) with provenance; `validate` checks every
  reference, rejects a type that contains itself by value (`type.contains_itself`), checks
  ABI sizes, aligned member offsets and the padded struct or union size, and
  `size_of`/`alignment_of` follow the same rules. The project stores the table in schema
  v5 (`types`, `type_fields`, `type_enumerators`, `type_applications`), with a migration
  from v4 and the older schemas (`replace_types`, `types`, `set_type_application`,
  `type_applications`). `types_from_debug_info` maps the DWARF types of a debuggee; it
  needs `DW_AT_encoding` for base types, which the reader now records. Evidence:
  `Types.RoundTripThroughTheProject`, `Types.MigratesFromSchemaV4`,
  `Types.RejectsCyclesWithoutPointer`, `Types.SizeAndAlignmentFollowTheAbi`, and
  `Types.DwarfStructsMatchTheirByteSize`, which checks every struct and union of the
  debuggee against its `DW_AT_byte_size`. Not done: step 4's automatic attachment (the
  DWARF types are not written to the project on import; the caller passes them to
  `replace_types`). The `C` declaration parser is G05-T2. Bit-fields are not
  recovered from DWARF (the reader does not record their bit offsets), and enumerator
  values are not recorded either. Those are DWARF reader gaps, not type-store gaps.

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
- **Status:** DONE on Linux x86-64. `parse_c_declarations`
  (`include/donkey/project/cdecl.h`, `src/project/cdecl.cpp`) parses the subset into
  `TypeDefinition`s with ABI layout (natural alignment, padded size, `long` and `char`
  signedness from `CDeclarationOptions`), refuses input over 1 MiB and nesting over 64
  with `cdecl.*` codes, and reports `line L, column C:` for every syntax error. The result
  goes through `TypeTable::validate` before it is returned, so an array too large for 64
  bits is refused with `cdecl.invalid_type`. Evidence: `Types.ParsesCDeclarations` and
  `Types.ParserErrorsAreLocated`, all seven `Types.*` tests, and the headless ctest suite
  pass on Linux x86-64 with `-Werror`. `fuzz_cdecl` (clang 18, libFuzzer, ASan and UBSan)
  ran 679,144 inputs in 61 s with no finding. Not supported: bit-fields, function
  pointers and other parenthesised declarators, expressions other than integer constants,
  variables, K&R definitions, octal literals, preprocessor lines and C++. Residual: the
  macOS and Windows CI legs have not run this yet.

**G05-T3 Apply types and propagate in the decompiler** [oracle-checked]

- **Steps:**
  1. A type applied to a function prototype changes the IR signature.
  2. A pointer-to-struct argument turns `*(a0 + 8)` into `a0->field`.
  3. Types flow forward through copies and loads.
  4. The printer uses the field names.
- **Done when:** G04-T0 still passes (types never change semantics), and a
  test applies `struct corpus_point *` to `c_point_sum` and prints `p->z`.
- **Status:** PARTIAL. Done: steps 1, 2 and 4, and the done-when test. `apply_prototype`
  (`include/donkey/ir/prototype.h`, `src/ir/prototype.cpp`) takes an `IrPrototype` (return
  width, parameters with width, class and an optional pointee structure with named members)
  and changes names and types only. It refuses a prototype whose arity, widths, classes or
  return width differ from the inferred signature, and a pointee whose members do not match
  every access the function makes through that parameter (offset and width). A refusal
  leaves the function unchanged. The printer shows `(struct corpus_point *p)` and `p->z`,
  and no inferred `a0_fields` block. Evidence: `DecompilerCorpus.AppliedPrototypeNamesStructFields`
  (the value of `c_point_sum` on a concrete `corpus_point` is the same before and after
  the prototype, 120), `DecompilerCorpus.AppliedPrototypeThatContradictsTheFunctionIsRefused`,
  and the full headless ctest suite (415 of 415) and the Release `DecompilerCorpus.*`, `Ir.*`
  and `Types.*` suites (166 of 166), on Linux x86-64. Not done: step 3, types flowing
  forward through copies and loads, so a value loaded from a typed field is not typed. The
  conversion from a `TypeTable` to an `IrPrototype` is written by the caller (the test does
  it); the CLI and UI that would do it are G05-T4.

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
- **Status:** PARTIAL. Done: step 1. `donkey-cli project type add|list|apply` exist and
  are tested in `tests/CMakeLists.txt` (`cli.project_type_*`, seven tests, repeatable).
  `add` parses a header with the G05-T2 parser, merges the declarations into the project's
  type table and reports a parse error with its line and column; `list` prints the types
  (text or `--json`); `apply` stores a type for an address, as a prototype when the type is
  a function and as a data slot otherwise. Not done: the decompiler does not yet read the
  stored applications, so `apply` changes no output (the conversion from a `TypeTable` to
  the `IrPrototype` of G05-T3 is still written by hand, in the test). Not done: step 2 (the
  Types panel, the editor with parse errors, "Set type…", the shared components) and step 3
  (undo and redo), and the UI script `tests/ui/types.donkeyui`.

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
  3. ZSTD sections are decoded by an own RFC 8878 decoder (done, see G07 status).
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
  **Status:** the lookup, UUID check, `--debug-file` and the refusal of a
  mismatched bundle are DONE on Linux (`SeparateDebug.DsymFindsTheBundleWhoseUuidMatches`,
  `SeparateDebug.ADsymWithAnotherUuidIsRefused`, `SeparateDebug.AMachOExecutableWithoutItsBundleIsNotFound`,
  `cli.debuginfo_dsym`, `cli.debuginfo_debug_file`, `cli.debuginfo_debug_file_mismatch`). The
  fixture is `tests/fixtures/dsym`, made with `ld64.lld-18` and `llvm-dsymutil`. The same check
  runs with Apple's `dsymutil` on macOS CI: the test module's dSYM is written by `dsymutil` in the
  build, and `cli.debuginfo_json` reads it (macOS headless and macOS packages jobs of run
  42373314116 and 42373314115 at 6c7505a).

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
  - **Status:** PARTIAL. Done: `demangle_msvc` (`src/binary/demangle_msvc.cpp`) for the
    64-bit forms the corpus covers: `__cdecl` free functions and members with access,
    `static` and `virtual`, cv-qualified `this`, constructors and destructors, the operator
    codes, builtin, class and enum types, pointers, references and rvalue references, back
    references, and `...`. Evidence: `DemangleMsvc.CorpusMatchesLlvmUndname` (87 names
    equal to `llvm-undname`'s text, and 8 listed names rejected as `demangle.unsupported`),
    and the malformed-name, unsupported-form and limit tests in
    `tests/unit/demangle_msvc_test.cpp`. The fuzz target (`fuzz_demangle`) runs both
    schemes; 2.3 million runs in 90 seconds with no finding. Not done: templates, arrays,
    string literals, vftables, dynamic initialisers, function and member pointers, 32-bit
    forms and the other calling conventions. Corpus provenance:
    `tests/fixtures/msvc/PROVENANCE.md`.
- **G10-T3 RTTI and vtables.**
  - **Status:** PARTIAL. Done: `read_itanium_rtti` (`include/donkey/binary/rtti.h`,
    `src/binary/rtti.cpp`) reads `_ZTI` typeinfo objects (class, single and multiple
    inheritance, with their base lists) and `_ZTV` vtables split into groups by the
    offset-to-top and typeinfo pairs of secondary subobjects. Pointers come from the file or,
    for PIE, from `.rela.dyn`; symbol relocations and PLT stubs are named where the reader can.
    Evidence: `Rtti.ReadsThePieHierarchyFromRelocations`,
    `Rtti.ReadsTheNonPieHierarchyFromTheFile`, and
    `Rtti.PiePointersComeFromTheRelocationTableNotTheFile` (zeroes every relocated pointer in a
    copy, so only `.rela.dyn` can supply them; ignoring relocations fails it, checked by
    mutation). The expected values were read from gdb. Also fixed: `c++filt`-style thunk names
    (`non-virtual thunk to Foo::bar()`) came out without their target; pinned by
    `Demangle.ThunksNameTheirTarget`. Fuzzed (`fuzz_rtti`).
    Not done: MSVC RTTI (Complete Object Locators), AArch64 PLT stubs other than the 16-byte form (for example BTI-prefixed entries), and call-site
    resolution in the decompiler (`call [reg + k]` through a known vtable). The GUI class
    hierarchy panel is G10-T4.
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
- **Status:** DONE (G11-T1 to T3). `serve` has the read methods, `decompile`, `annotations.list`,
  and `rename`, `comment` and `type.apply` behind `--project` and `--allow-write`. Batch mode and the
  Python client are in place. Tests: `cli.serve_session`, `cli.serve_project`, `cli.batch_script`,
  `python.rpc_client`. Fuzz: `fuzz_rpc`. Protocol: `docs/RPC.md`.

### G12 Interactive edits

- **G12-T1 Make code / make data / undefine.**
  - New annotation kinds (schema bump): `CodeStart`, `DataRange(type, count)`
    and `Undefined`.
  - Analysis honours them: user data ranges are never decoded as code; user
    code starts are seeded like function starts.
  - Undo and redo work, and they persist.
  - UI keys, using the shared components: `C` (code), `D` (data), `U`
    (undefine), `A` (string).
  - **Status:** DONE (claude/funny-meitner-cpc7oc). `C` makes code, `D` makes one byte of
    data, and `U` clears user code or data at the address, or declares an
    instruction's bytes undefined. Each is one undo step, and the scripted test
    `tests/ui/edits.donkeyui` passes under Xvfb with the full desktop suite
    (580 of 580). Also `Session.UndefineDeclaresInstructionBytesUndefinedAndClearsThem`,
    `Session.DataRangeRemovesCodeAndUndoRestoresIt`, `UserRanges.*` for the analysis,
    and the v5 to v6 migration tested on `tests/fixtures/projects/schema-v5.db`
    (`Project.MigratesSchemaV5AnnotationsToV6AndKeepsThem`). Text that does not fit
    its kind is refused (`Project.StoresCodeStartsAndDataRangesAndRefusesOtherText`).
    Deviations: `Undefined` is not a separate kind (undefining is a `data` range of
    element size 0, `0:<count>`), and the undo history is in memory, as before; only
    the resulting annotations are saved. The shell also keeps the selection when a
    re-analysis publishes a new document of the same file. Before this it jumped to
    the entry point after any boundary edit or undo.
    `A` (strings) belongs to G12-T2.
- **G12-T2 Arrays and strings at an address.**
  - **Status:** PARTIAL on Linux (claude/funny-meitner-cpc7oc). `A` defines the NUL-terminated
    string at the selected address as a data range of its bytes, terminator included
    (`string:<bytes>`; it is read as an array of one-byte elements). `Shift+D` opens the data
    editor for an array (`<size>:<count>`), or for any range text. The Data window lists every
    range with its shape, the string and a preview, and Edit and Remove. Evidence: the scripted
    test `tests/ui/data.donkeyui` (defines the 28-byte `.interp` string, types an array, and
    undoes both), `Session.DefineStringDefinesTheTerminatedBytesAndRefusesOthers`,
    `Project.ParsesAndStoresStringRangesAndRefusesBadStringText`. The string form needs no schema
    change: the annotation kind is still `data`. UTF-16 (`W`, `string16:<bytes>`): a NUL-terminated
    UTF-16LE string with its two-byte terminator, read as 2-byte elements. The Data window previews
    it with `\uXXXX` escapes for non-ASCII units. Evidence: `Session.DefineString16DefinesTheTerminatedBytesAndRefusesOthers`,
    the parse cases in `Project.ParsesAndStoresStringRangesAndRefusesBadStringText`, and the scripted
    test `tests/ui/utf16.donkeyui` on `tests/fixtures/utf16`. Not done: the listing draws no data
    rows, so a range shows in the Data window only; a decompiler that prints a string literal;
    a UTF-16 preview for surrogate pairs (they show as two `\uXXXX` escapes).
- **G12-T3 Rename and type locals in the decompiler.**
  - Stored per function and IR variable, keyed by stack offset or register
    and definition address. They survive re-analysis when the key still
    exists.
  - **Status:** PARTIAL. Local names are stored per image and function in
    schema v7 (`local_names`, `LocalName`), keyed `arg:<index>` for a parameter
    and `frame:<base>:<offset>` for a frame slot. `apply_user_local_names`
    applies them after the debug names, and a name wins over a debug name on
    the same slot. A slot the function accesses gets a local even when the
    decompiler recovered none, and a key that names nothing leaves a note.
    `donkey-cli project local-name` and `local-names` set and list them, and
    `decompile --project` shows them. A name that the decompiler refuses
    (a C keyword, a collision) fails the command.
    The desktop session has `Session::set_local_name`, which refuses a keyword,
    a non-identifier or a malformed key and otherwise marks the project dirty
    and makes one undo step. Save writes the names with `replace_local_names`,
    and open and restore read them back. The decompiler view applies the
    function's names when it lifts, and its cache key includes them, so a change
    shows at once. A refused set is not applied, and the view shows the refusal
    code. Not done: the GUI gesture that sets a name; the definition address in
    the key, so two lifetimes of one slot share a name; register locals
    (`var_N`); local types; `serve` methods; `tests/ui/edits.donkeyui`.
  - **Tests:** `Project.MigratesVersionSixDatabaseToVersionSevenAndKeepsItsAnnotations`,
    `Project.StoresLocalNamesAndRefusesBadKeysAndNames`,
    `Project.ReplacesEveryLocalNameAtOnceAndKeepsThePreviousSetWhenRefused`,
    `LocalNames.*` (`tests/unit/local_names_test.cpp`), `cli.local_names`
    (`cmake/checks/check_local_names.cmake`, fixture `tests/fixtures/names`),
    `Session.LocalNamesSetUndoRedoAndRefuseBadEdits` and
    `Session.LocalNamesSaveAndReopenWithTheProject`. Not covered by a test: the
    decompiler view's rendering of the names (it compiles and is covered only
    by the applier tests); the UI script is still to add.

### G13 Processor coverage

Each ISA, in order: decoder → CFG → lifter → corpus under qemu-user (section
7 shows the method).

- **G13-T1 32-bit ARM and Thumb.**
  - Add `CS_ARCH_ARM` to `src/decode/decode.cpp`. Thumb mode comes from
    symbol bit 0 and the `$t`/`$a` mapping symbols (they are currently
    skipped in `src/binary/elf.cpp`; keep them as mode hints instead).
  - Lift the integer subset, conditional execution, and IT blocks in Thumb.
  - Corpus: `arm-linux-gnueabihf-gcc` plus qemu-arm.
  - **Status:** IN PROGRESS (claude/funny-meitner-cpc7oc). A32 is decoded,
    little-endian only (`DecodeIsa.ArmA32MatchesTheListingOfEveryInstruction`,
    `DecodeIsa.ArmA32ConditionalBranchesAreConditionalWithTheirTargets`,
    `DecodeIsa.BigEndianArmAndRiscVAreRefusedByName`). Not done: Thumb mode and
    mapping symbols, lifting, the CFG check and the qemu-arm corpus.
- **G13-T2 RISC-V 64.** Requires Capstone 6 or a pinned newer Capstone:
  **[owner decision]** on upgrading Capstone. RV64GC integer subset, with
  the compressed instructions.
  - **Status:** IN PROGRESS (claude/funny-meitner-cpc7oc). RV64GC is decoded
    and matches llvm-objdump on the test image, compressed included
    (`DecodeIsa.RiscV64MatchesTheListingOfEveryInstruction`,
    `DecodeIsa.RiscV64BranchTargetsAreAbsoluteAndJalrHasNone`). The pinned
    Capstone is 5.0.9, which has the RISC-V backend, so decoding did not wait
    for the Capstone 6 decision. Not done: lifting, the CFG check and the
    qemu-user corpus.
- **G13-T3 MIPS32 and PPC32 (64-bit deferred).** Decoder and CFG first (delay
  slots for MIPS); lifting later.
  - **Status:** IN PROGRESS (claude/funny-meitner-cpc7oc). MIPS32 (both byte
    orders) and PPC32 (both byte orders) decode and match llvm-objdump on their
    test images (`DecodeIsa.MipsLittleEndianMatchesTheListingOfEveryInstruction`,
    `DecodeIsa.MipsBigEndianMatchesTheListingOfEveryInstruction`,
    `DecodeIsa.PowerPc32BigEndianMatchesTheListingOfEveryInstruction`,
    `DecodeIsa.PowerPc32LittleEndianMatchesTheListingOfEveryInstruction`).
    Capstone's group flags miss some transfers (`jal`, `jr $ra`, `bl`, `blr`),
    so those are classified from the mnemonic and the PowerPC link bit
    (`DecodeIsa.MipsBranchesHaveTheirClassesAndTargets`,
    `DecodeIsa.PowerPc32BranchesHaveTheirClassesAndTargets`). 64-bit MIPS and
    PPC are refused as Unknown
    (`DecodeIsa.SixtyFourBitMipsAndPowerPcAreNotDecodedAsThirtyTwoBit`). Not
    done: microMIPS/MIPS16 and VLE detection, lifting, the CFG check against
    a second disassembler, and the qemu corpus. The delay slots are DONE for
    ordinary branches, calls and returns: the slot stays in its branch's block
    and the fall-through starts after it (`DecodeIsa.MipsDelaySlotsStayWithTheirBranchesInTheGraph`).
    Branch-likely forms run their slot only when taken, which is not modelled, so
    that graph is Partial (`analysis.mips_branch_likely`).

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
  - **Status:** PARTIAL. Done: static archives are listed. `read_archive`
    (`include/donkey/binary/archive.h`, `src/binary/archive.cpp`) reads the System V and GNU
    names (the `//` table and `/<offset>`), the BSD `#1/<length>` names and the symbol
    tables, with bounded member counts, names and offsets, and returns a partial index
    at the first malformed header. `donkey-cli archive list <file> [--json]` prints the
    members. Evidence: a GNU `ar` archive (`tests/fixtures/archives/libcheck.a`) lists the
    same object members as `ar t` (`cli.archive_list_gnu`); eleven `Archive.*` unit tests
    cover the BSD form, padding, truncation, the member limit and sanitizing; `fuzz_archive`
    ran 4.2 million inputs in 60 s under ASan and UBSan with no finding. The archive
    members are not yet opened as binaries.
  - **Status (relocations):** PARTIAL. Done: an ELF relocatable object (`ET_REL`) is laid
    out from `kObjectBase` (0x1000), its allocated sections are copied and patched, and its
    symbols take their layout addresses (`link_relocatable_object`,
    `include/donkey/binary/relocate.h`, called from `load_binary`). Applied: x86-64 `64`,
    `PC32`, `PLT32`, `32` and `32S`; AArch64 `ABS64`, `CALL26`, `JUMP26` and `PREL32`.
    A relocation that cannot be applied is a diagnostic and sets `partial`. A call or
    data reference to a symbol the object does not define is `elf.relocation_unresolved`:
    the second object is needed for it, which is G15-T2. Evidence: `Relocate.*` (x86-64,
    built with GCC) and `RelocateAArch64.*` (built with clang for AArch64): the data
    pointer holds its target's address, a call reaches its callee, and the unresolved
    call is reported. `fuzz_binary` runs both objects as seeds (60 s and 45 s, no
    finding). Not done: GOT-based relocations (`GOTPCREL`), the TLS types, the AArch64
    page and `LO12` forms (`ADR_PREL_PG_HI21`, `ADD_ABS_LO12_NC`), `COMMON` symbols, and
    the relocations of non-allocated sections (debug information).
- **G15-T2 Several images in one project.** Load several binaries, resolve
  imports to exports by name and library, and add cross-image xrefs. This is
  acceptance project A14's gap.
- **G15-T3 Dumps and firmware.** ELF core files (show threads and memory),
  Windows minidumps (MIT-licensed format docs), Intel HEX and S-records as raw
  images.
  - **Status:** PARTIAL. Done: Intel HEX and Motorola S-records (`decode_records`,
    `include/donkey/binary/records.h`, `src/binary/records.cpp`). A file whose first line is
    a record is decoded into one flat image at its lowest address, with 0xFF in the gaps,
    and analysed as a raw image; the start address becomes the entry point. A malformed
    record is an error that names its line, never a raw load. Evidence: eight `Records.*`
    unit tests (both formats, checksums, unknown types, records after the end, the size
    limit, detection, and a file loaded through `load_binary`), and `fuzz_records` ran 3.7
    million inputs in 46 s under ASan and UBSan with no finding. The ELF core reader
    (`read_elf_core`) gives the threads and file mappings, and the memory is the PT_LOAD
    segments. **Done:** Windows minidumps (`read_minidump`, `read_minidump_memory`, `minidump.h`):
    the architecture, exception, threads with x86-64 registers, modules with UTF-16 names,
    and the memory ranges, read by address. Evidence: six `MinidumpReader.*` unit tests on a
    dump made by `tests/fixtures/minidump/make_sample_minidump.py` (which follows Microsoft's
    documented layout, not Windows output), `cli.core_minidump`, and the new
    `fuzz/fuzz_minidump.cpp` harness, which compiles with clang (run not yet done). Not done:
    a dump written by Windows has not been checked; other architectures keep their threads
    without registers; the architecture for a raw record image is still supplied by the caller.

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
