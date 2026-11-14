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
- **The goal is parity with IDA Pro and Ghidra** for everyday work.
  `docs/PARITY.md` has the scorecard (where `main` stands, area by area), how
  parity is measured, and the order of the work. G01 to G19 are planned task
  by task in section 5. G20 to G32 (section 5a) are planned at gap level, and
  each starts with a task that writes its detailed plan.

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
| G04 | Decompiler readability | Clean C with merged variables, `for` loops, simplified conditions | Register aliases merged (T1); copy propagation and dead-register removal (T2); one-block loops as do-while, break, continue and integer negation (T3, partial); a while loop whose counter is set just before it and stepped by a constant at the end of its latch prints as `for` (T3, unit-tested; O0 counted loops with counters in memory print as `for` (`c_sum_array`); O2 and O3 rotate loops into guarded do-while forms, which do not); parameters and frame slots take their DWARF names at -O0 (T4) | P0 | IN PROGRESS (T0, T1, T2, T4 DONE; T3 PARTIAL; T5 DONE with one open decision: no labelled functions on the 1,986 list, 997 printed with gotos, see G04-T5. Structuring (goal 8, branch): loops are natural loops, a reverse-postorder copy is structured when the layout fails, and `if (c) break;` prints. Measured labelled share on the fixed 1,986-function sample, on the branch: 50.2% (996; bar 52%, met). Done on the branch: post-dominators and a dominator-based fallback structurer, bounded copies of return blocks, node splitting of irreducible functions (106 irreducible remain; no split function is structured). Not done: a loop header with two entries after splitting, switch terminators in the splitter, and the remaining region shapes; see docs/AUDIT.md) |
| G05 | Type system and user types | Type libraries, struct/enum editing, propagation | The type store with validation and ABI sizes (T1, partial); a bounded C declaration parser (T2); applying a prototype to recovered code (T3, partial); project type add, list and apply in the CLI (T4, CLI part). No editing UI, no undo, and the decompiler does not read the applied types |list| IN PROGRESS (T2 DONE; T1, T3, T4 PARTIAL; T4 UI and undo, and T3 step 3, TODO) | P0 | IN PROGRESS (G05-T1 PARTIAL; T2 DONE; T3 PARTIAL; T4 PARTIAL, CLI only) |
| G06 | PDB (Windows debug info) | Full | PDB 7.00 read: the MSF container, PDB info, modules, procedures, globals, the struct, class, union and enum types with their instance fields, pointers, arrays, modifiers and procedures; mapped into the type store with provenance Pdb (`types_from_pdb`). Enumerators are read with their values (LF_ENUMERATE). Not read: C++ class layouts; structs with base classes, virtual tables or methods are reported and left out | P1 | IN PROGRESS (T1 to T3 DONE for C structs, enums and the fixtures; C++ class layouts TODO) |
| G07 | Separate debug files (.dSYM, debuglink, build-id, compressed DWARF) | Full | Separate debug files by build-id and debuglink (CRC-32 checked); a `.dSYM` bundle found by LC_UUID; `debuginfo --debug-file` checks a named file; zlib and zstd compressed DWARF | P1 | DONE (T1 and T2; the .dSYM lookup is checked with Apple's dsymutil output on macOS CI, `cli.debuginfo_json`) |
| G08 | SIMD (SSE/AVX, NEON) | Decompiles to intrinsics | Unsupported: vectorised loops are Partial | P1 | TODO |
| G09 | Library function identification | FLIRT signatures, Lumina | Signature format, reader, matcher and the naming rules (ambiguity, user names, provenance) in the library, with `docs/SIGNATURES.md` (T1, partial). The generator for x86-64 ELF objects and static archives, `donkey-cli sig make` (T2, partial: no shared objects, PE import libraries or AArch64). One shipped set, musl 1.2.4 (MIT), identifying 34 of 67 known functions of a static musl program, 0 named wrongly, 28 byte-identical aliases reported ambiguous (T3, partial; the 90 % named bar is an owner decision) | P1 | IN PROGRESS (T1 PARTIAL; T2 PARTIAL; T3 PARTIAL, owner decision open) |
| G10 | C++ (demangling, RTTI, vtables) | Full | Itanium demangler (T1, partial: 502 of 512 corpus names match c++filt); MSVC demangler (T2, partial); Itanium and x64 MSVC RTTI and vtables (T3, partial: AArch64 PLT stubs are named at any stride, BTI-prefixed ones included; 32-bit MSVC, virtual base classes and call-site resolution are open); demangled names in donkey-cli info, in the desktop app's function names, call targets, Xrefs, Xref Graph and debugger frames, and the Classes window (Itanium classes of ELF images only), with the raw symbol in a tooltip (T4, DONE; the decompiler's pseudocode body keeps the engine's identifiers by rule) | P1 | IN PROGRESS (T1 to T3 PARTIAL; T4 DONE) |
| G11 | Scripting and automation | IDAPython, IDC, plugin SDK | serve: JSON-RPC 2.0 with the read methods, decompile and annotations.list (with --project), and the write methods rename, comment and type.apply (with --project and --allow-write); batch mode; the optional Python client; a fuzz target for the request handling | P1 | DONE (G11-T1 to T3) |
| G12 | Interactive edits | Make code/data, define arrays and strings, rename and type locals | Make code, make data and undefine with undo and redo, with UI keys C, D and U and a scripted test (T1). Arrays (Shift+D, `<size>:<count>`) and strings (A, `string:<bytes>`) as data ranges, with a Data window and a scripted test; user strings print as literals in the command-line, RPC and desktop decompiler (T2, partial: no inline listing rows; UTF-16 strings done). Rename, comment, bookmark and function boundaries from before | P1 | IN PROGRESS (T1 DONE; T2 PARTIAL: no inline listing rows; UTF-16 strings done; T3 PARTIAL: local names for parameters and frame slots, headless, CLI and session API with undo, shown in the decompiler; no GUI rename gesture, no local types) |
| G13 | Processor coverage | Dozens of ISAs | 32-bit ARM (A32, little-endian), RISC-V 64 (RV64GC, little-endian), MIPS32 and PowerPC32 (each in both byte orders) decode, checked against llvm-objdump. MIPS delay slots are in their branch's block in the CFG; branch-likely forms make the graph partial. Thumb is not decoded or detected; no ISA is lifted; MIPS16 and microMIPS images are refused with `elf.mips_isa_extension`; 64-bit MIPS and PowerPC decode in their 64-bit modes, checked against llvm-objdump; VLE is not detected | P2 | IN PROGRESS (A32, RV64GC, MIPS32 and PPC32 decode DONE; MIPS delay slots DONE for ordinary branches; Thumb, lifting, CFG checks and branch-likely forms TODO) |
| G14 | Debugger coverage | All major OSes, remote debugging, hardware watchpoints, conditional breakpoints | Hardware watchpoints on Linux x86-64, with conditions, and conditional breakpoints on Linux (x86-64; AArch64 compiled, not run in this change), in the library and the CLI (T5, partial); the native debugger on Linux and Windows x64 otherwise | P2 | IN PROGRESS (T5 PARTIAL; T1 to T4 TODO) |
| G15 | Loaders and multi-image | Objects, archives, dumps, firmware; cross-image references | Relocatable objects, GOT, COMMON and page relocations, and the TLS models for x86-64 and AArch64 (T1, partial); archives listed (T1); Intel HEX, S-records, ELF cores and Windows minidumps (T3, DONE for the formats it names; the minidump test file is generated, not Windows output). Import resolution and calls through PLT stubs and, on x86-64, GOT slots read directly, across images (`donkey-cli link`, `project link`), done for ELF; calls through a register loaded from a GOT slot, AArch64 GOT calls, and PE and Mach-O references not done (T2) | P2 | IN PROGRESS (T1 PARTIAL; T2 PARTIAL; T3 DONE) |
| G16 | Scale on real large binaries | Decades of tuning | Scale benchmark over generated programs up to 80,000 functions and over one real large binary (LLVM's libLLVM.so.1, 123 MB), with time, peak memory and the status each run reports. The block bound is now exact. Memory is about 1 KB per decoded instruction (T1, partial: one real binary, no UI frame times). Incremental re-analysis not done (T2) | P2 | IN PROGRESS (T1 PARTIAL; T2 TODO. The CFG block bound is now one block per decoded instruction with a floor of 200,000 (it was a fixed 200,000, which cut a 3.6 MB AArch64 build; docs/AUDIT.md)) |
| G17 | UI breadth | Many views, search kinds, command palette | Core views and text search in lists; a command palette (Ctrl/Cmd+Shift+P) that runs the menu commands and shows each view (G17-T1, `ui.script_command_palette`); a Search window with byte, immediate and regular-expression searches run off the render thread (G17-T2, `search.*`, `ui.script_search`); a Symbols window (G17-T3, `ui.script_symbols`); a cross-reference graph window of the call neighbourhood (G17-T4, `ui.script_xref_graph`) | P3 | IN PROGRESS (T1 to T4 DONE; synchronised views and the theme editor TODO) |
| G18 | Signed releases | Signed installers | Ad-hoc signed .app, unsigned .exe | P1 | BLOCKED [owner decision]: needs the owner's Apple Developer ID and Windows code-signing certificate. Excluded from this goal |
| G19 | Accessibility | Platform accessibility APIs | None: Dear ImGui exposes no accessibility tree | P3 | BLOCKED on owner decisions (AccessKit waiver, first platform, minimum bar); design only, see docs/ACCESSIBILITY.md |
| G20 | Decompiler coverage on real programs | Decompiles nearly every function (Ghidra too) | Measured only on the differential corpus; no whole-program measurement | P0 | IN PROGRESS (T2 partial: whole-program measurement over a fixed sample of 1,986 system-binary functions in docs/AUDIT.md, with tools/audit/sample_list.py. Not done: the R1 corpus of G20-T1, the ratchet (T3), and the T4 execution of R1) |
| G21 | Call sites and calling conventions | `r = f(a, b)` with typed arguments | A call prints as `sub_x();` with no arguments or result, and every function that makes a call is Partial | P0 | IN PROGRESS (T0 DONE; T1 PARTIAL: x86-64 SysV clobber model, with the callee write set for a resolved call; the oracle runs the callee IR, not the real callee. T2 PARTIAL: integer arguments and result from the callee's inferred signature for same-image direct calls to Complete callees; AArch64 calls stay Partial; signature_inferred is always labelled. T3 to T6 TODO. Six call-heavy corpus functions verified at -O0 and -O2, and at -O3) |
| G22 | Type libraries | Type libraries (Ghidra: data type archives) for the major platforms | None bundled; the type store, C declaration parser and CLI apply exist (G05) | P1 | TODO (T2 needs an owner decision on header sources) |
| G23 | Unwind tables and exception handling | Reads `.eh_frame`, `.pdata`, LSDA and MSVC exception data | Not read | P1 | IN PROGRESS (T1 DONE for ELF .eh_frame, fuzzed (fuzz_eh_frame); T2 PARTIAL: PE x64 .pdata RUNTIME_FUNCTION entries, chained entries skipped (not tested with a fixture); .xdata and ARM64 TODO; T3 to T5 TODO) |
| G24 | Analysis of stripped binaries | Function discovery from several sources, no-return, thunks, stack analysis | Function seeds are the entry point, exported symbols and call targets only | P0 | IN PROGRESS (T1 measured in docs/AUDIT.md; T2 PARTIAL: unwind seeds (ELF and PE x64); seeds stop at jumps and fall-through into another function start, and at import stubs; T3 to T7 TODO) |
| G25 | Language runtimes (Go, Rust, Objective-C, Swift) | Runtime metadata and demangling for each | None | P1 | TODO |
| G26 | Processor strategy | Dozens of processors (Ghidra: through SLEIGH) | Three lifted instruction sets, four more decoded only (G13) | P1 | BLOCKED [owner decision] after the T0 spike |
| G27 | Emulation | Appcall, emulator plug-ins (Ghidra: p-code emulator) | The IR interpreter runs in tests only | P2 | TODO |
| G28 | Diffing and version tracking | Lumina, BinDiff, Diaphora (Ghidra: Version Tracking, BSim) | None | P2 | TODO (after G09) |
| G29 | Assembling for patches | Assemble an instruction | Byte patches only | P2 | TODO (T2 needs an owner decision) |
| G30 | More containers and managed code | Many loaders; Dalvik, .NET | None of these | P2 | TODO (T4 and T5 need an owner decision) |
| G31 | Scripting inside the app, full API coverage | IDAPython (Ghidra: Java and Python scripts) inside the tool | Out-of-process JSON-RPC and Python client; partial coverage of the UI's actions | P1 | TODO |
| G32 | Collaboration | IDA Teams (Ghidra: Ghidra Server) | Single-user projects | P3 | BLOCKED [owner decision] |

G20 to G32 were added on 2026-11-13 from `docs/PARITY.md`. Their plans are in
section 5a. In their rows the "IDA Pro" column also names what Ghidra has.

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
  A loop compiled with its test after its body and entered by a jump to the test
  (GCC and Clang at -O0) is now laid out with the test first and printed as a `while`: the
  pass `arrange_loop_tests` swaps the two blocks, negates the test and renumbers the
  references, which is exact, and `forward_compare_loads` reads a counter that a compare
  takes straight from memory when nothing else reads the register. `c_sum_array` at -O0
  prints `while (*(u32 *)(rbp - 0x8) < *(u32 *)(rbp - 0x1c)) { ... }` with no labels.
  Evidence: `Ir.StructuresRotatedLoopAsWhile` (its result is checked by the interpreter),
  `Ir.ACompareReadsTheMemoryOfALoadThatNothingElseReads`,
  `Ir.ALoadIsKeptWhenItsRegisterIsReadAfterTheCompare`, and
  `DecompilerCorpus.EveryPassPreservesSemantics` with the two passes in its list. Still not
  done. A counted loop whose counter is in memory, the -O0 form, now prints as `for`: the
  planner takes the init as a store or an assign, and the step as the three statements that
  an add to memory lifts to (a load into a temporary, the add, a store), printed as one
  update `M = M + c`. `c_sum_array` at -O0 prints `for (*(u32 *)(rsp - 0x8) = 0x0;
  *(u32 *)(rbp - 0x8) < ...; *(u32 *)(rbp - 0x8) = *(u32 *)(rbp - 0x8) + 0x1)`. Evidence:
  `Ir.StructuresCounterInMemoryAsFor`. The task stays PARTIAL: the -O2 loops are guarded
  do-while loops and do not print as `for`. The printed form is checked by the construction
  of the planner and by that test, not by the interpreter, which runs IR and not text.
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

**G04-T5 Goto structuring: no whole-function labels** (depends: G04-T3 and the goal 8 work in
`docs/AUDIT.md`; W1 branch `agent/ir/G04-T5-goto-structuring`)

- **Goal:** a function with verified IR prints as structured C. A `goto` is printed only for an
  edge that no structured form can express, and the printer says how many there are. A second
  oracle checks the printed control flow against the IR, edge for edge.
- **Why a dominator-based emitter and not region collapsing:** the brief allows a better design
  with an explanation. Collapsing a graph by rules needs a second graph rewrite each time a goto
  is chosen, and its termination depends on the rewrite. An emitter that prints each block once,
  with gotos as the only escape, terminates by construction (recursion is bounded by the block
  count), and its output is checked by the oracle below, so a wrong choice is caught either way.
- **Files:** `src/ir/structure.cpp` (tagged lines; the gate on the candidates),
  `src/ir/structure_goto.cpp` (new; the goto structurer, the last stage), `src/ir/structure_check.cpp`
  (new; the control-flow check), `src/ir/ir_internal.h` (line tags; the rule bits), the source list
  in the top-level `CMakeLists.txt` (explicit), `src/ir/ir.cpp` (the note),
  `apps/donkey-cli/commands.cpp` (the class name), `tests/unit/ir_test.cpp`,
  `tests/unit/decompiler_corpus_test.cpp`, `tools/audit/sample_list.py`.
- **Steps:**
  1. Tag every printed line with its structural role: statement of block b, if/else open or
     close (with the block and whether the printed condition is the complement of the IR
     condition), while or for open, switch open, case, default, break, continue, return, goto,
     label. The text is unchanged; `DecompilerCorpus.*` and `Ir.*` must stay green.
  2. The oracle: rebuild the control flow from the tags (sequence, if/else, while, break,
     continue, return, goto, switch with C fall-through between case arms) and compare each
     block's successors with the IR's, edge for edge, including which arm a condition's true
     side enters. Run it on every corpus function and, in the measurement, on all 1,986.
  3. The goto structurer, tried after the existing structurers (so a function that structures
     today keeps its goto-free output): an emitter that prints each block once. A branch to the
     next block by fall-through, to the innermost loop's header as `continue`, or to its follow
     as `break` is structured; anything else is `goto` to a label on the target. A conditional
     branch becomes if/else at its immediate post-dominator. A loop is the natural loop of its
     back edges, printed as `while (test)` when its header is a pure test, else `while (1)`.
     The rules are switchable for the tests (one bit each).
  4. The note: a function printed with gotos says `N goto(s) where control flow has no
     structured form`; a function printed without gotos has no structure note. The labelled
     whole-function form is kept only for invalid graphs, which verified IR does not produce.
- **Tests (each rule has one that fails with the rule switched off; the failure is shown once in
  a commit message):** a fall-through rule, if/else, if without else, while, while with a
  pure-test header, break, continue, switch, goto forward into a join with several predecessors,
  goto out of a loop, goto into a loop body (irreducible). `Ir.FallsBackToLabelsForIrreducibleControlFlow`
  is replaced by a test of the new note and gotos (it asserted the labelled form, which goal 4
  removes). The oracle has a test that fails on a deliberately broken rule (shown once).
- **Measurement:** the same 1,986 functions (`tools/audit/results/list_final.json`), Release
  build, before and after: whole-function labelled count (target 0), goto-free functions (must
  not drop), functions with gotos, total gotos and the largest per function, oracle mismatches
  (target 0), and the runtime (structuring may not make decompilation more than 25% slower).
- **Done when:** the measurement in `docs/AUDIT.md` (W1 section) shows the numbers above, the
  three build trees and the desktop UI suite pass, and the PARITY, SUPPORT_MATRIX and DESIGN
  §17.2 rows agree with the evidence.
- **Status:** DONE with one open decision, measured in `docs/AUDIT.md` (W1). No function of the
  fixed 1,986-function list is printed as labelled blocks (996 before), and every printed structure
  passes the control-flow check, on the corpus and on the list (0 candidates refused). Structured
  without goto: 990 before, 989 after. Two functions left that set (`openssl` `0xa9b70`, `libc`
  `0x97ec0`): their old output printed a switch's case blocks a second time, which the check now
  refuses; one function joined it (`libsqlite3`). Gotos: 997 functions, 16,476 in all, largest 394.
  The open decision is whether to copy small shared blocks and recover compound conditions to remove
  most of them (owner decision; not made here).

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
  and `Types.*` suites (166 of 166), on Linux x86-64. Step 3 is partly done: a parameter
  that an unoptimised build spills to the stack and reloads is still that parameter.
  `forward_slot_copies` turns an 8-byte reload of a slot into a copy of the register that
  was stored there, while neither the slot nor the register has changed; copy propagation
  then carries the copy into the accesses, and the pointer structure is recovered before the
  printer runs. A prototype applied to the -O0 `c_point_sum` prints `p->z` and keeps the
  value (`DecompilerCorpus.AppliedPrototypeReachesAnO0SpilledParameter`), and the forwarding
  is tested in `Ir.ASpilledParameterReloadedFromItsSlotIsAccessedThroughTheParameter` and
  `Ir.ASlotThatIsStoredAgainIsNotForwardedFromTheFirstStore`. This holds on x86-64 only. On
  AArch64 an unoptimised build reloads the parameter into `x0`, the register it arrived in, and
  then overwrites `x0`, so the slot is the only home of the pointer and nothing is forwarded:
  the member accesses stay untyped there (seen on the arm64 CI host; the corpus test asserts the
  member names on x86-64 only). Not done: that AArch64 case; a value loaded from a
  typed pointer member keeps no type, so a pointer member of a structure is not followed to
  its pointee; and the forwarding does not cross a block boundary. The
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
  - **Status:** PARTIAL. Done: the format and its strict reader and writer, the matcher, and the
    naming rules (`include/donkey/analysis/signatures.h`, `src/analysis/signatures.cpp`). Evidence:
    `Signatures.*` (thirteen unit tests, with three mutations checked), and `fuzz_sig`. The library-level
    match test is `Signatures.IdentifyMuslFunctionsInAStaticBinary` (G09-T3). Not done: a CLI command that
    matches a set against a binary.
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
  - **Status:** PARTIAL. Done: `generate_signatures` (`include/donkey/analysis/signature_gen.h`,
    `src/analysis/signature_gen.cpp`) reads the raw bytes of x86-64 ELF relocatable objects and of the
    relocatable members of static archives, without laying them out. The global and weak functions with a
    size are named. Each relocation inside a function makes a wildcard of its width, and a function that
    cannot be described exactly (an unknown relocation type, a relocation past its end, a compressed or
    out-of-file section) is skipped with a note. `donkey-cli sig make` writes the set, with `--license`
    required because the format requires it. Local (static) functions are named as well as global and weak
    ones: a static body identical to a global one is then ambiguous, not named after the global (see
    `docs/SIGNATURES.md`, "Which functions"). Evidence: `SignatureGen.*` (ten tests, on
    `tests/fixtures/sig/gen/`), whose match test links the library into `sig_static` and checks that the
    five library functions (four global, one static) are named and nothing else is;
    `cli.sig_make_writes_a_set_from_an_archive` and `cli.sig_make_refuses_an_executable`;
    `fuzz_sig_object`. Mutations checked: ignoring relocations fails three tests; dropping the local
    functions fails `Signatures.IdentifyMuslFunctionsInAStaticBinary` with two wrong names, and restoring
    them passes. Not done: shared objects (`.so`), PE import libraries, an AArch64 generator, and the
    `--lib` name taken from the file itself. Known gap: the wildcards do not cover a linker's relaxation of
    an opcode (GOTPCRELX `mov` to `lea`), which leaves some functions unmatched.
- **G09-T3 Signature sets.** Status: PARTIAL, one set shipped and an owner decision open.
  - Shipped: `signatures/musl-1.2.4.json` (musl 1.2.4, MIT, 2,096 signatures), with its provenance in
    `signatures/PROVENANCE.md`. Identification on a static musl program (`tests/fixtures/sig/musl/`):
    of 67 known functions, 34 named and correct, 28 ambiguous byte-identical aliases (named nothing, by
    the rule of G09-T1 point 3), 5 unmatched, and 0 named wrongly. Matching uses the new start-address
    mode, `identify_at_starts`, because the analysis's extents of this stripped program are wrong for
    many functions (checked on the 47 known global functions of the first measurement: 10 had the wrong extent,
    and 16 were not found as functions by the analysis).
  - **[owner decision]** The plan asks for at least 90 % of the known functions named. Under the
    ambiguity rule, a byte-identical alias is never named, and 28 of 67 have one, so that bar cannot be
    met soundly. The options are: accept 90 % identified (named or flagged ambiguous, 62 of 67 here,
    which the test asserts) with at least half named, or allow an alias to be named after one of its
    names, which can name a function wrongly. The test holds the first.
  - The plan also asks for a CI build of a musl binary. The fixture is committed instead, with its
    ground truth (`tests/fixtures/sig/musl/symbols.txt`), so CI does not need `musl-gcc`.
  - Not yet: the other libraries of the plan (compiler-rt, libc++, MinGW CRT, FreeBSD libc).
- **G09-T3 Signature sets.** (The plan below is the original; the status above records what was done.)
  - Generate sets only from libraries whose licence allows redistribution of
    derived data: musl (MIT), compiler-rt and libc++ (Apache-2.0 with LLVM
    exception), the MinGW-w64 CRT (check its notices), and FreeBSD libc
    (BSD).
  - **[owner decision]** before adding glibc (LGPL) or the MSVC runtime.
  - Store the sets under `signatures/` with provenance.
- **Tests:**
  - `Signatures.IdentifyMuslFunctionsInAStaticBinary`: build a static
    binary against musl in CI; at least 90 % of known functions named and
    0 wrong names. (Measured: 0 wrong; 92 % identified; 51 % named. See the
    owner decision above.)
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
    Done since: MSVC RTTI for x64 PE images (`read_msvc_rtti`: complete object locators, type
    descriptors, class hierarchy descriptors and the vtables they name; checked on a fixture against
    the source, `RttiMsvc.*`, and fuzzed by `fuzz_rtti`, which now dispatches by format).
    AArch64 PLT stubs are named at any stride, BTI-prefixed ones included (`PltStubsAArch64.*`,
    fixtures in `tests/fixtures/link/aarch64/`). The PLT stub reader is shared with the cross-image
    call resolution of G15-T2 (`src/binary/plt.cpp`).
    Not done: 32-bit MSVC and virtual base classes, and call-site resolution in the decompiler
    (`call [reg + k]` through a known vtable). The GUI class hierarchy panel is G10-T4.
  - Parse Itanium `typeinfo` objects and vtables (offset-to-top, typeinfo
    pointer, function pointers), and MSVC RTTI Complete Object Locators.
  - Build a class hierarchy.
  - In the decompiler, resolve `call [reg + k]` where reg was loaded from an
    object whose vtable is known: show the method name, but keep the call
    indirect in the IR.
- **G10-T4 UI.** Show demangled names everywhere, with the raw name in the
  tooltip, and a class hierarchy panel.
  - **Status:** DONE, with one stated exception. Done in the desktop app:
    - The Classes window (`views::classes`) lists each class of the image's C++ RTTI with its kind,
      direct bases in order, vtable address and primary slot count. Selecting a class navigates to
      its vtable, or its typeinfo when it has none. The RTTI is read on the worker when a document
      opens (`attach_rtti`); an image without it shows why. Each class's raw symbol is its tooltip.
      Evidence: `ui.script_classes` (`assert_rtti_class` and `assert_rtti_bases` on
      `donkey_test_hierarchy`; a mutated expected base fails it).
    - A function's readable name (`readable_name`, `src/ui/names.cpp`, from the core demangler; the
      raw symbol is kept) is shown in the Functions list, the call graph header and its caller and
      callee lists, the disassembly call-target column, the Xrefs window (the function containing each
      end of a reference), the Xref Graph header, the decompiler header and progress line, and the
      debugger's stack frames. Each shows the raw symbol as its tooltip when the two differ. A user
      rename is shown as typed, and the Rename prompt starts from the raw name. Evidence:
      `ui.script_readable_names` (`_ZN5ShapeD2Ev` shows `Shape::~Shape()`), `ui.script_xref_graph`
      (containing-function checks; a mutated lookup fails it).
    - The full desktop suite passes (663 of 663); the headless Debug and Release suites pass.
  - **The exception, by rule:** the decompiler's pseudocode body keeps the symbols as C identifiers.
    The pseudocode is the engine's output from verified IR, and AGENTS.md forbids generating
    pseudocode by string formatting, so the readable name is not written into it. A demangled name
    inside a call would not be valid C in any case. The readable name is in the decompiler header.
    MSVC RTTI and call-site resolution are G10-T3 items, not part of this entry.

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
    test `tests/ui/utf16.donkeyui` on `tests/fixtures/utf16`.
    Printed literals (command line and RPC): a user-defined one-byte string prints as its C literal
    in the pseudocode, where its address is loaded by a `lea` or by a 4- or 8-byte constant
    assignment (a `mov` of an absolute address, as non-PIE builds emit). `donkey-cli project string
    <db> <image-id> <address>` defines the string from the saved binary, after its SHA-256 check, and
    `decompile --project` and the RPC `decompile` method print it. Evidence: `Ir.ALeaOfAUserString*`,
    `Ir.AStringLiteralIsPrintedInStructuredCodeToo`, `Ir.AMovOfAStringAddressPrintsTheLiteral`,
    `StringLiterals.*`, and the CTest cases `cli.project_string_*` on the fixture
    `tests/fixtures/strings/hello-x86_64` (`rdi = (u64)("hello, donkey");`, and the address without
    the project). Mutation checked: disabling the constant lookup fails the unit test and the CLI test.
    The desktop decompiler view prints them too: the literals come from the annotation snapshot, travel
    with each lift request, and are part of its cache key; `tests/ui/strings.donkeyui` (Linux x86-64,
    run under Xvfb) defines the string, checks the literal, undoes it and checks the address again.
    Not done: the listing draws no data rows, so a range shows in the Data window only;
    a UTF-16 preview for surrogate pairs (they show as two `\uXXXX` escapes); a literal is printed for
    any NUL-terminated bytes the user defines, which is the user's choice, not a check that they are text.
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
  - **Status:** PARTIAL. Done on Linux x86-64: hardware watchpoints in DR0-DR3 and DR7
    (`set_watchpoint`, `donkey-cli debug launch --watch`). Done on Linux (x86-64 and
    AArch64): conditional software breakpoints. `set_conditional_breakpoint` takes a condition
    `<operand> <op> <value>` (`include/donkey/debug/condition.h`, `src/debug/condition.cpp`): the
    operand is a host register (`rsp`, `x0`) or the 8-byte word at an address (`*0x4010`), the
    operator is one of `== != < <= > >=`, and the value is decimal or hex. A condition is parsed
    when it is set, and a register the host does not have is refused. A trap whose conditions are
    all false is passed over: the thread steps off the breakpoint with every other thread stopped,
    the breakpoint goes back in, and the target runs on. No hit is counted and nothing is
    reported. A condition that cannot be read stops the target and says why. A breakpoint that
    already exists at the address is refused, because attaching a condition would change it.
    `donkey-cli debug launch --break-if SYMBOL|ADDR CONDITION` takes the same syntax; a `*SYMBOL`
    operand names a data symbol, and the address is a file address that is translated to runtime.
    Evidence: `BreakCondition.*` (parser and comparison truth tables), `NativeDebug.Conditional*`
    and `NativeDebug.ConditionOnARegisterIsReadAtTheHit` against `donkey_test_debuggee` (the stop
    comes at the third call, the hit count is 1, a false condition never stops and the program
    exits 42), `cli.debug_native_condition_json`, `cli.debug_mock_condition_is_unsupported` and
    `cli.debug_break_if_rejects_a_malformed_condition`. Mutations checked: never passing a trap
    fails two native tests; not reinserting the breakpoint after the silent step fails the
    counting test. The AArch64 path is compiled but not run: the test host is x86-64.
    Done on Linux x86-64: conditions on hardware watchpoints (`set_conditional_watchpoint`, and
    `donkey-cli debug launch --watch-if SYMBOL|ADDR[:LEN][:rw] CONDITION`). The condition is parsed
    and its register checked when the watch is set, so a refused one takes no debug register. It is
    evaluated after the access, so the stop reports the value written. A watch trap whose
    conditions are all false is passed over: no hit is counted, nothing is reported, and the target
    runs on. Evidence: `NativeDebug.ConditionalWatchpointStopsOnlyWhereItsConditionHolds` (the
    counter is written 1, 2 and 3, and the target stops only at 2),
    `NativeDebug.ConditionalWatchpointRefusesABadConditionBeforeAnySlotIsUsed`, and
    `cli.debug_native_watch_if_json` (one watch stop, then exit 42). Mutation checked: disabling
    the pass-over branch fails the stop test.
    Not done: conditions with more than one comparison; a condition on a register of a thread
    other than the one that hit; remote debugging (T1);
    FreeBSD, macOS and Windows on Arm (T2 to T4).

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
    finding).
  - **Later additions:** the TLS relocations named in the G15-T1 task are done, x86-64
    local-exec included. Also applied: GOT-based relocations
    (`GOTPCREL`, `GOTPCRELX`, `REX_GOTPCRELX`), the AArch64 page and `LO12` forms
    (`ADR_PREL_PG_HI21`, `ADD_ABS_LO12_NC`), `COMMON` symbols placed in zero-filled `.bss`,
    and TLS: x86-64 local-exec, initial-exec, global-dynamic and local-dynamic (relaxed as `ld`
    does), and AArch64 local-exec, initial-exec and TLSDESC. Evidence: `RelocateTls.*`,
    `RelocateGot.*`, `RelocateCommon.*` and `RelocateAArch64.*`. Not done, and recorded as
    follow-ups: the classic AArch64 global- and local-dynamic sequences (`-mtls-dialect=trad`,
    which need `__tls_get_addr`), and the relocations of non-allocated sections (debug
    information), which the code leaves unapplied on purpose.
- **G15-T2 Several images in one project.** Load several binaries, resolve
  imports to exports by name and library, and add cross-image xrefs. This is
  acceptance project A14's gap.
  - **Status:** PARTIAL. Done for ELF:
    - `resolve_imports` (`include/donkey/binary/link.h`, `src/binary/link.cpp`) binds each import
      of an image to the first other image, in link order, that exports the name and is one of
      the libraries the importer names: DT_NEEDED (matched against the provider's DT_SONAME or
      file name), or the DLL named by a PE import (matched by file name). Unbound imports are
      counted.
    - `plt_stub_imports` (`include/donkey/binary/plt.h`, `src/binary/plt.cpp`) names each PLT stub
      by the import its JUMP_SLOT relocation calls. x86-64 stubs and AArch64 stubs are read; the
      AArch64 scan tries every 4-byte position, because lld 18's BTI stubs are 24 bytes apart
      (16-byte scanning named one of the two imports in the fixture and missed the other).
    - `resolve_import_calls` (`include/donkey/analysis/link_calls.h`, `src/analysis/link_calls.cpp`)
      binds each call or jump the analysis finds through a stub to the export `resolve_imports`
      chose, so a call to `provided_fn@plt` names the provider's address. A call to an import no
      input exports is listed as unbound.
    - `donkey-cli link <executable> <library>... [--json]` prints the bindings, the calls and the
      unbound counts, and reports when an analysis was partial.
    - `donkey-cli project link <database> [--json]` links the images of a project in the order they
      were saved (the first is the executable). Each file must still match the SHA-256 the project
      recorded; a changed file is refused with `project.image_changed`.
    - Evidence: `Link.*` (5), `LinkCalls.*` (3), `PltStubs.*` (3), `PltStubsAArch64.*` and
      `LinkCallsAArch64.*` on the BTI fixtures in `tests/fixtures/link/aarch64/`; CTest
      `cli.link_*`, `cli.project_link_*`, and `cli.project_link_refusals` (a changed file and a
      one-image project are refused). Mutations checked: removing the library rule fails two
      `Link.*` tests; looking up stubs by the call site fails two `LinkCalls.*` tests; removing
      the SHA-256 check fails `cli.project_link_refusals`.
    - Done (x86-64 ELF): calls that read a GOT slot directly (`call *slot(%rip)`, which `-fno-plt`
      code makes) are bound like PLT calls. `got_import_slots` (`include/donkey/binary/plt.h`)
      names each GLOB_DAT slot of an import, and a Data xref from an indirect call or jump to such
      a slot is an `ImportCall`; a plain load of the slot is not listed. A symbol the image defines
      is not an import, so neither its PLT stub nor its GOT slot is named (this was a bug in the
      PLT reader, found by the fixture: the stub of an interposable own function was listed as an
      unbound import). Evidence: `GotSlots.*` (2), `LinkCalls.ACallThroughAGotSlot*` (2),
      `LinkCalls.ALoadOfAGotSlot*`, `LinkCalls.ACallThroughARegisterLoaded*`,
      `LinkCalls.ACallToAFunctionTheImageDefinesIsNotListed`, `PltStubs.AStubForAFunction*`, and
      `cli.link_reports_calls_through_got_slots`, on `libconsumer_got.so` (built with `-fno-plt`,
      see `tests/fixtures/link/PROVENANCE.md`). Mutations checked: removing the indirect-transfer
      check fails the two negative `LinkCalls` tests; removing the imported-name filter from the
      GOT reader fails `GotSlots.ASymbolTheImageDefinesIsNotAnImportSlot`; removing it from the PLT
      reader fails the two own-function tests.
    - Not done: a call through a register that code loaded from a GOT slot first (the call does
      not read the slot itself, so it is not bound; `libconsumer_got.so`'s `_init` is the
      fixture for this); imports used as data pointers (their xrefs are data, not calls); PE and
      Mach-O cross-image calls (the PE import is an IAT slot, not a stub); AArch64 GOT calls
      (`adrp`/`ldr`/`blr`); ordinal imports and forwarded exports. The project does not store the
      cross-image results: `project link` recomputes them.
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
    `fuzz/fuzz_minidump.cpp` harness: 319,333 runs in 61 s under clang with ASan and UBSan,
    no finding. Not done: a dump written by Windows has not been checked; other architectures
    keep their threads without registers; the architecture for a raw record image is still
    supplied by the caller.

### G16 Scale

- **G16-T1 Real-world benchmark.**
  - **Status:** PARTIAL. Done: `tools/bench/scale_benchmark.py --binary PATH` measures
    `donkey-cli analyze` on an existing binary, with its SHA-256, wall time and peak RSS. The manual
    workflow's `real-binary` job runs it on libLLVM.so.1 from the pinned package
    `libllvm18=1:18.1.3-1ubuntu1` at 1M and 10M instructions. It ran on the hosted runner (run
    42467464472: both jobs succeeded and uploaded their artifacts). The
    local series, with the machine and the diagnostics, is in `docs/BENCHMARKS.md`. Every run is
    Partial, because each budget or the block bound stops it first. Two defects found by this
    benchmark were fixed: the block bound was exceeded (`Cfg.TheBlockBoundHoldsAcrossFunctions`),
    and the instruction-budget diagnostic was repeated per function
    (`Cfg.TheInstructionLimitIsReportedOnceForAllFunctions`). Not done: UI frame times with the UI
    scripts; a second real binary (Firefox `libxul` is not redistributable, so it is not committed).
  - Design (kept for reference): A CI job (`workflow_dispatch` only) downloads pinned, checksummed,
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

## 5a. Parity gaps G20 to G32

These gaps were added on 2026-11-13 from the scorecard in `docs/PARITY.md`.
G01 to G19 came from comparing features with IDA Pro. G20 to G32 come from
asking what a user still has to leave Donkey for, in IDA Pro or in Ghidra.

They are written at gap level, not yet at the file-by-file level of G01 to
G07. **The first task of each gap is T0: write the task-level plan** (files,
steps, test names, done-when, pitfalls) in this file, in its own PR, after
reading the code the gap touches. Do not start T1 of a gap whose T0 is not
merged. "Donkey today" in each entry was checked against `main` at `eb9fa61`.

Shared terms:

- **R1** is the reference corpus of real programs that G20-T1 defines.
- **[ground truth]** marks a task measured against the unstripped build of
  the same program, with no reference tool (see `docs/PARITY.md` section 2).
- A threshold marked "proposed" is fixed by the owner after the first
  measured baseline. Never lower one to pass.

### G20 Decompiler coverage on real programs (P0)

**Why.** The differential corpus proves the decompiler correct on a small set
of functions. IDA Pro and Ghidra decompile nearly every function of a real
program. Nothing measures Donkey on whole programs, so the order of the
decompiler work is a guess.

**Donkey today.** The corpus in `tests/corpus/*.c` (see
`docs/SUPPORT_MATRIX.md`). No whole-program measurement in the ledger's own plan. Baseline
(`main` at `1a92abf`, [`AUDIT.md`](AUDIT.md)): on 1,893 sampled functions, Complete 11.0%,
Partial 58.1%, InvalidIR 25.8%, Unsupported 4.7%, crash 0.3%.

**Tasks.**

- **T0.** Task-level plan.
- **T1 [ground truth].** Define R1: permissively licensed programs (proposed:
  zlib, Lua, SQLite, and a static musl libc program) fetched in CI from
  pinned URLs with SHA-256, built at `-O0` and `-O2` for x86-64, each as an
  unstripped and a stripped binary. AArch64 follows through the cross
  compiler. Record the provenance as `docs/DESIGN.md` §11.5 requires.
- **T2.** A batch run over R1 that records for every function: Complete,
  Partial with its first note, Unsupported, or error. Publish the counts and
  the 20 most frequent Partial reasons as a CI artifact and as a table in
  `docs/SUPPORT_MATRIX.md`.
- **T3.** A ratchet: the Complete count per program and level is stored in
  the repository, and CI fails when it drops.
- **T4 [oracle].** Extend the execution comparison to the R1 functions that
  can be called in isolation (a manifest of pure functions), so Complete on
  R1 is verified as it is on the corpus.

**Done when.** The ratchet runs in CI, and the reason table is used to order
G21, G01, G08 and G04. Proposed parity threshold for scorecard row 6: at
least 90% of R1 functions are Complete or Partial with a full body, and no
verified function disagrees with the compiled code.

**Pitfalls.** Do not commit built binaries. Keep the job inside the CI time
budget (sample large programs, and say that you sampled). A function that is
Complete but not executed is not verified: report the two counts separately.

### G21 Call sites and calling conventions (P0)

**Why.** Both reference tools print `r = f(a, b);`. Donkey prints
`sub_401000();`, with no arguments and no result.

**Donkey today.** `lift_call` in `src/ir/lift.cpp` and
`src/ir/lift_aarch64.cpp` keeps only the target and marks the function
Partial ("outgoing call arguments and return values follow no modelled ABI").
So every function that makes a call is Partial. Baseline ([`AUDIT.md`](AUDIT.md)): 1,009 of
the 1,893 sampled functions carry that note.

**Tasks.**

- **T0.** Task-level plan, including the IR change (a call with explicit
  argument and result operands) and its verifier rules.
- **T1 [oracle].** The clobber model. After a call the caller-saved registers
  are undefined and the callee-saved ones are preserved (System V x86-64 and
  AAPCS64 first, Windows x64 next). The interpreter calls the real callee in
  the differential harness.
- **T2 [oracle].** Arguments and results from a known prototype: the callee's
  recovered signature inside the image, DWARF or PDB, an applied type (G05)
  or a type library (G22). Integer and pointer arguments in registers first.
- **T3.** Stack arguments, structures by value and through a hidden pointer,
  floating-point arguments (after G01).
- **T4.** Variadic calls. Count arguments only from a constant format string;
  otherwise the call is Partial.
- **T5.** A call to a no-return function ends the block (needs G24-T3).
- **T6.** Indirect calls: function pointers, vtable slots (the G10-T3
  call-site work), import stubs.

**Done when.** No R1 function is Partial only because it calls, and the
corpus has call-heavy functions verified by execution.

**Pitfalls.** An argument count taken from register liveness is an inference.
Label it as one (`signature_inferred`) and never print it as certain. A wrong
prototype must fail the oracle, not print plausible code.

#### G21-T0 task-level plan (written 2026-11-14, before any G21 code)

Checked against: `src/ir/lift.cpp` (`lift_call`, the Call handling that marks the function Partial
with "outgoing call arguments and return values follow no modelled ABI"), `src/ir/eval.cpp` (the
`IrOp::Call` case, which fails with "calls are not interpreted"), `src/ir/ir.cpp` (verifier and
printer), `src/ir/abi.cpp` (ABI register tables), and `tests/unit/decompiler_corpus_test.cpp`
(the oracle; `tests/corpus/corpus.c` holds 3 files today).

**IR change.** `IrStatement` gains `std::vector<IrOperand> call_arguments` (in ABI order) and
`IrOperand call_result` (a register, or `None` when the callee's return is not used). A `Call`
keeps `a` as the target. The statement's `signature_inferred` flag (new bool) is set when the
argument count comes from the callee's inferred parameters rather than from a debug or type
source. Every printed call names the inference when it is one.

**Lifter (x86-64 SysV first).** `lift_call` resolves a direct target T to a function of the same
image in the CFG (a jump-stub or import is not resolved). It lifts T once with calls to other
functions not resolved (depth 1; the callee's own calls stay Partial), reads T's inferred
`parameters` (ABI register names) and its return width and return register, and emits the call
with those operands. Calls with an unresolved target keep today's form and stay Partial.

**Clobber model (T1).** After any call, caller-saved registers (rax, rcx, rdx, rsi, rdi, r8-r11,
xmm0-15) are unknown. Callee-saved (rbx, rbp, rsp, r12-r15) are preserved. A later read of an
unknown register marks the function Partial, not Complete. Windows x64 is a second table (T1
second step).

**Verifier rules.** Every argument operand has a width matching its ABI register; `call_result`
is a register that the clobber model defines; a call with arguments but no resolved signature is
rejected (`ir.call_signature`). A call's arguments are reads: the verifier checks that they are
defined on every path (an undefined argument marks the function Partial, it does not fail).

**Interpreter (the oracle's part).** `eval.cpp`'s Call case evaluates the callee's IR recursively
with the arguments, up to a depth of 8, and returns its result; a depth or an unresolved callee
fails with `ir.eval_call` as today. This is what lets the differential harness execute a caller.

**Printer.** `r = f(a, b);` when a result is used, `f(a, b);` otherwise, with the callee's name
from the function table. A `signature_inferred` call prints a trailing comment
`/* arguments inferred from callee */`.

**Corpus (T2 oracle).** At least six call-heavy functions added to `tests/corpus/corpus.c`:
arguments of 0 to 6 integer or pointer values, a result used and unused, a call inside a loop,
a call chain of depth 2, a recursive call (must stay Partial), and a call through a function
pointer (must stay Partial). The oracle compiles them at -O0 and -O2 on x86-64. A corpus function
is Complete only when the interpreter's result equals the compiled code's on every input.

**Tests (names to add).**
- `Ir.CallCarriesItsArgumentsFromTheCalleeSignature` (unit, from bytes: a caller of a two-argument
  callee in the same image)
- `Ir.CallToAnUnresolvedTargetStaysPartial` (unit)
- `Ir.CallerSavedRegistersAreUnknownAfterACall` (unit: a read of rax after a call is Partial)
- `Ir.VerifierRejectsACallWithoutASignature` (unit, hand-built IR)
- `DecompilerCorpus.CallHeavyFunctionsAgreeWithTheCompiledCode` (oracle, -O0 and -O2)
- `cli.decompile_prints_call_arguments` (CLI, a committed fixture with a two-argument call)

**Done when.** (1) the six corpus functions verify (Complete: executed and equal) at -O0 and -O2;
(2) every existing corpus result still agrees with the compiled code; (3) the CLI test prints a
call with arguments; (4) the count of sampled functions carrying "outgoing call arguments and
return values follow no modelled ABI" is measured before and after with `tools/audit`, both in
the PR. A function that still calls an unknown or recursive callee is Partial, and that is
reported as such.

**Pitfalls.** An argument count from register use is an inference: label it, never print it as
certain (`signature_inferred`). A wrong signature must fail the oracle, not print plausible code:
the oracle must run each call-heavy function with several inputs. The clobber model must not let
a value that a call changed be printed as the old one. Do not widen the subset by guessing at
callee-saved registers. Mutual recursion stops at depth 1 in the lifter, so the cost is bounded.

### G22 Type libraries (P1)

**Why.** IDA Pro's type libraries and Ghidra's data type archives give every
imported function a prototype and every system structure a layout before the
user does anything.

**Donkey today.** A type store, a bounded C declaration parser and prototype
application from the CLI (G05). No bundled declarations.

**Tasks.**

- **T0.** Task-level plan.
- **T1.** A versioned library file: C declarations for one platform and ABI,
  read by a bounded reader with a fuzz target.
- **T2 [owner decision].** A generator that builds libraries from headers
  whose licence is on the allowed list, with provenance. Candidates: musl
  (MIT) for libc and POSIX, Microsoft's win32metadata (MIT) for the Windows
  API. Headers under other licences need a decision before use.
- **T3.** Apply prototypes to imports by name, and to functions identified by
  G09, with provenance `TypeLibrary`. A user edit always wins.
- **T4.** The decompiler shows typed arguments at calls (needs G21-T2).

**Done when.** The libc calls of R1 show prototypes with no user action, and
each applied type records where it came from.

**Pitfalls.** Never copy an IDA type library or a Ghidra data type archive.
Generate from headers and record the header version.

### G23 Unwind tables and exception handling (P1)

**Why.** `.eh_frame` and `.pdata` give the exact start and length of almost
every function in a stripped binary. Exception tables give the `try` and
`catch` regions. Both reference tools read them.

**Donkey today.** Not read. Baseline ([`AUDIT.md`](AUDIT.md)): the FDE starts of `.eh_frame` are
not used as seeds, so function-start recall against them is 33.0% (`python3.12`) to 88.5%
(`bash`) on the audited system binaries.

**Tasks.**

- **T0.** Task-level plan.
- **T1.** `.eh_frame` and `.eh_frame_hdr`: CIE and FDE records as function
  ranges with provenance. Bounded and fuzzed. Oracle: `readelf
  --debug-dump=frames`.
- **T2.** PE x64 `.pdata` and `.xdata` (`RUNTIME_FUNCTION`, `UNWIND_INFO`,
  chained entries), then the ARM64 forms. Oracle: `llvm-readobj --unwind`.
- **T3.** Mach-O `__unwind_info` and `LC_FUNCTION_STARTS`.
- **T4.** The Itanium LSDA (`.gcc_except_table`): landing pads become CFG
  edges, and the decompiler marks the protected region. The result stays
  Partial until the handler semantics are modelled.
- **T5.** MSVC C++ exception data and SEH scope tables.

**Done when.** G24-T1 shows the gain in function-start recall on stripped R1
binaries, and a C++ fixture with `try`/`catch` shows its regions.

### G24 Analysis of stripped binaries (P0)

**Why.** Finding the functions of a stripped binary is the core of both
reference tools. Everything else works on what this step finds.

**Donkey today.** `src/analysis/analysis.cpp` seeds functions from the entry
point, exported function symbols and call targets. There is no prologue scan,
no no-return analysis, no thunk classification and no stack-depth analysis.
Baseline ([`AUDIT.md`](AUDIT.md)): function-start recall 85.8% on the stripped own CLI against
its symbols (precision 100.0%); against `.eh_frame` entries, 68.0% on the stripped CLI, and
33.0% to 88.5% on the system binaries, with precision 98.9% to 100%.

**Tasks.**

- **T0.** Task-level plan.
- **T1 [ground truth].** The measurement: for each R1 program, compare the
  function starts found in the stripped binary with the symbols and DWARF of
  the unstripped one. Report precision and recall, and ratchet them in CI.
- **T2.** More seeds, most reliable first: unwind tables (G23), code
  addresses stored in data and relocations (function-pointer tables, vtables,
  `.init_array`), tail-call targets, and prologue patterns last. A function
  found by a heuristic carries that provenance.
- **T3.** No-return functions: known names first (`exit`, `abort`,
  `__stack_chk_fail` and the like), then propagation through the call graph.
- **T4.** Thunks and import stubs are named for their targets; a jump is
  classified as a tail call or a branch.
- **T5.** Data in code: jump tables in `.text`, literal pools, padding. Bytes
  that are not proven code are not decoded silently.
- **T6.** The stack-pointer delta at every instruction (needed by G21-T3 and
  by frame locals without a frame pointer).
- **T7.** Bounded value propagation for indirect branch and call targets.

**Done when.** Proposed thresholds on stripped x86-64 R1: recall and
precision of function starts both at least 98%.

**Pitfalls.** Recall bought with false functions is worse than a gap. Measure
precision in the same run.

### G25 Language runtimes: Go, Rust, Objective-C, Swift (P1)

**Why.** A stripped Go binary still names every function in its runtime
tables. Objective-C binaries describe every class. Both reference tools use
this; Donkey ignores it.

**Donkey today.** None of the four.

**Tasks.**

- **T0.** Task-level plan.
- **T1 [ground truth].** Go: `.gopclntab` (the 1.2, 1.16, 1.18 and 1.20
  layouts) for function names and ranges, module data, build information.
  Compare with the unstripped build.
- **T2.** Rust: the legacy and v0 mangling schemes (RFC 2603). Oracle:
  `rustfilt` output on a list of names.
- **T3.** Objective-C: class lists, method lists and selector references, so
  methods are named and `objc_msgSend` calls with a constant selector get a
  cross-reference. Oracle: `llvm-objdump --objc-meta-data`.
- **T4.** Swift: demangling (oracle: `swift demangle`). Type metadata later.

**Pitfalls.** These are parsers of untrusted bytes: bounded, with fuzz
targets.

### G26 Processor strategy (P1) [owner decision]

**Why.** G13 decodes four more instruction sets but lifts none of them. A
hand-written, verified lifter per instruction set is the bottleneck between
three architectures and the dozens the reference tools cover.

**Options.**

- **A. Hand-written lifters**, each checked by the differential oracle under
  `qemu-user`. Consistent with today's design. Slow.
- **B. SLEIGH specifications.** Ghidra's processor descriptions are
  Apache-2.0. A C++ SLEIGH engine turns bytes into p-code, and a translator
  turns p-code into Donkey IR, checked by the same oracle. This is the
  fastest route to breadth. It adds a large third-party component and a
  second IR to keep honest.
- **C. Both.** Hand-written for the instruction sets that matter most
  (x86-64, AArch64, then ARM and RISC-V), SLEIGH for the rest.

**Tasks.**

- **T0.** A spike on one instruction set that Donkey decodes but does not
  lift (RV64 or A32): corpus functions to p-code, to Donkey IR, through the
  oracle. Report coverage, binary size, build time, the licence inventory,
  and whether the engine builds without a JVM. No product code is merged.
- The decision is recorded in `AGENTS.md` under "Settled decisions". The
  tasks after T0 are written then.

**Until the decision.** G13 continues by hand: Thumb decoding, then A32 and
RV64 lifting.

**Pitfalls.** "Verified IR" does not bend. Whatever produces the IR, a
Complete result is one that the oracle executed.

### G27 Emulation (P2)

**Why.** Ghidra has a p-code emulator, and IDA Pro has Appcall and emulator
plug-ins. Users decrypt strings and unpack code with them.

**Donkey today.** The IR interpreter (`include/donkey/ir/eval.h`) runs in the
tests only.

**Tasks.**

- **T0.** Task-level plan.
- **T1.** Emulate one function from the CLI with given register and memory
  inputs over the image's bytes. Bounded steps and memory. An unmodelled
  operation stops the run with a diagnostic.
- **T2.** A memory model (sections copy-on-write, a stack, a stub heap) and
  hooks for imported functions.
- **T3.** In the desktop app: emulate a selection and keep the result as a
  comment or a data definition.
- **T4.** Start from a debugger stop (registers and memory of the live
  target).

**Pitfalls.** Emulation never runs native code. Opening a file still never
executes it.

### G28 Diffing and version tracking (P2)

**Why.** Ghidra has Version Tracking, Program Diff and BSim. IDA Pro users
have Lumina, BinDiff and Diaphora. Analysts carry their work from one build
of a program to the next.

**Donkey today.** None.

**Tasks.**

- **T0.** Task-level plan.
- **T1 [ground truth].** Match the functions of two images: masked byte
  hashes first (the masking G09 defines), then call-graph and CFG structure.
  Report matched, changed, added and removed, as JSON from the CLI. The
  oracle is two builds of one source with known changes.
- **T2.** Carry names, comments and types from a project to a new build, with
  provenance and a list for review.
- **T3.** A side-by-side view in the desktop app.

**Depends on.** G09.

### G29 Assembling for patches (P2) [owner decision]

**Why.** Both reference tools let the user type an instruction to patch.

**Donkey today.** Byte patches only. Keystone is GPL-2 and forbidden.

**Tasks.**

- **T0.** Task-level plan.
- **T1.** Patch helpers that need no assembler: invert a conditional branch,
  replace an instruction with no-ops, force a jump, change an immediate. Each
  result is decoded again and compared before it is staged.
- **T2 [owner decision].** A text assembler: LLVM MC (Apache-2.0 with the
  LLVM exception, large), a small own encoder for the common forms, or the
  SLEIGH assembler if G26 chooses SLEIGH.

### G30 More containers and managed code (P2)

**Tasks.**

- **T0.** Task-level plan.
- **T1.** COFF objects and import libraries (extends G15-T1).
- **T2.** The dyld shared cache and Mach-O kernel collections: open one image
  out of the container, bounded and memory-mapped.
- **T3.** Firmware: a raw loader with a user memory map and a vector table
  for Cortex-M, and peripheral names from a user-supplied CMSIS-SVD file.
- **T4 [owner decision].** WebAssembly.
- **T5 [owner decision].** DEX, Java class files and .NET metadata. These are
  not native code and need their own IR. Decide the scope first.

### G31 Scripting inside the app and full API coverage (P1)

**Why.** IDAPython and Ghidra scripts reach everything the user interface
can do, from inside the tool.

**Donkey today.** A JSON-RPC server with read methods, decompile, rename,
comment and type application; a batch mode; an optional Python client; C ABI
plugins. Scripts run out of process only, and the API covers part of what the
desktop app does.

**Tasks.**

- **T0.** Task-level plan.
- **T1.** An API coverage table in `docs/RPC.md`: every user action (make
  code and data, patch, bookmark, navigate, cross-references, types, debugger
  control) against its RPC method, with a test per method. Missing methods
  become tasks.
- **T2.** A script runner and console in the desktop app that talks to the
  live session through the same RPC, never on the render thread.
- **T3.** Read access to the verified IR for scripts, as versioned JSON.
- **T4.** Batch analysis of a directory with a script before and after each
  file.

**Pitfalls.** Python stays optional (`AGENTS.md`, "Settled decisions").

### G32 Collaboration (P3) [owner decision]

**Why.** IDA Teams and Ghidra Server let several analysts share one project.

**Donkey today.** Single-user projects.

**Tasks.**

- **T0.** A written design: a deterministic text export of names, comments,
  types and bookmarks that merges three ways and reports conflicts (so it
  works with any version control), against a server. The owner chooses.

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

### Order from 2026-11-13

Most of the list above is done (see the table in section 4). From here the
order is the waves in `docs/PARITY.md` section 4:

1. **Wave 1.** G20-T0 to T3 first, because it measures what the rest is
   ordered by. Then G21, G24, G23-T1 to T3, and the open tasks of G04, G05
   and G01.
2. **Wave 2.** G09, G22, the open tasks of G10 and G06, G23-T4 and T5, G25.
3. **Wave 3.** G26-T0 (a spike, then an owner decision), G13, G08, G15-T2,
   G30.
4. **Wave 4.** G14, G27.
5. **Wave 5.** G12, G17, G31, G29, G28, G32.

Inside a wave, take an **[oracle]** or **[ground truth]** task before one
without a machine check. Take T0 of a G20 to G32 gap before any other task of
that gap.

Branch hygiene, so that `main` stays the one place where work lives:

- At most three task branches are open at once, and each has an open PR.
- Do not stack a branch on an unmerged branch unless the task depends on it.
  If you do, say so in both PRs.
- When a PR merges, delete its branch in the same session. When work is
  superseded, close its PR with a link to what replaced it, check that every
  commit on the branch is in `main` or in the replacement (`git cherry
  origin/main <branch>`), and then delete the branch.
- Never leave pushed work without an open PR. A branch with neither a PR nor
  a line in an open PR's description is lost work waiting to happen.
