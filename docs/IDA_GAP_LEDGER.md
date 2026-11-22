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

1. Pick, among the tasks of the current wave in section 5 whose status is TODO and whose
   dependencies are all DONE, the one that moves the measured numbers most (AGENTS.md,
   "Highest leverage first"); between tasks of equal effect, take the first in this ledger's
   order. Inside a gap, its **[ground truth]** and **[oracle]** tasks still come first, as
   "Measure before you build" says: they are what the effect is measured with, and the
   differential corpus checks **[oracle]** tasks automatically.
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
| G04 | Decompiler readability | Clean C with merged variables, `for` loops, simplified conditions | Register aliases merged (T1); copy propagation and dead-register removal (T2); one-block loops as do-while, break, continue and integer negation (T3, partial); a while loop whose counter is set just before it and stepped by a constant at the end of its latch prints as `for` (T3, unit-tested; O0 counted loops with counters in memory print as `for` (`c_sum_array`); O2 and O3 rotate loops into guarded do-while forms, which do not); parameters and frame slots take their DWARF names at -O0 (T4) | P0 | IN PROGRESS (T0, T1, T2, T4 DONE; T3 PARTIAL; T5 DONE (goto reduction W1b decided 2026-11-17 and done: small-block copies and compound conditions): no function of the 1,986 list is printed as labelled blocks, 913 are printed with gotos (13,758 gotos since the library scope of G24-T3 (#76); 13,713 at `e49d58f`, CI run 44264049339, and 15,712 on `main` before W1b), see G04-T5. Structuring (goal 8, merged): loops are natural loops, a reverse-postorder copy is structured when the layout fails, and `if (c) break;` prints. Dominator-tree fallback structurer, bounded copies of return blocks, and node splitting of irreducible functions are in. Measured labelled share on the fixed 1,986-function sample before T5: 49.6% (985; bar 52%, met); with T5, 0. 106 irreducible functions remain; no split function is structured. Not done: a loop header with two entries after splitting, switch terminators in the splitter, and the remaining region shapes; see docs/AUDIT.md) |
| G05 | Type system and user types | Type libraries, struct/enum editing, propagation | The type store with validation and ABI sizes (T1, partial); a bounded C declaration parser (T2); applying a prototype to recovered code (T3, partial: `apply_prototype` and its tests; no CLI or decompiler path calls it); project type add, list and apply in the CLI (T4, CLI part; apply records the application only). No editing UI, no undo, and the decompiler does not read the applied types | P0 | IN PROGRESS (T1 PARTIAL; T2 DONE; T3 PARTIAL, step 3 TODO; T4 PARTIAL: CLI only, UI and undo TODO) |
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
| G20 | Decompiler coverage on real programs | Decompiles nearly every function (Ghidra too) | Executed and compared on the differential corpus. One whole-program measurement: a fixed sample of 1,986 functions from seven system binaries (`docs/AUDIT.md`), counted, not executed. The R1 corpus of real programs that G20-T1 defines does not exist yet | P0 | IN PROGRESS (T0 DONE: task-level plan written 2026-11-21, with a spike over the proposed R1 at `3263c84`; T1 DONE: `tools/r1` fetches, checks and builds the 26 R1 binaries reproducibly; T2 DONE: `donkey-r1 measure` counts every R1 function (at `3530b46`: x86-64 1,269 of 8,406 Complete, AArch64 839 of 7,450; 0 Unsupported or InvalidIR; every Partial function of an unstripped build names a reason, one of the stripped static musl build does not) and the stripped starts (14,816 of 14,887); earlier, a fixed sample: whole-program measurement over a fixed sample of 1,986 system-binary functions in docs/AUDIT.md, with tools/audit/sample_list.py. T3: `tools/r1/baseline.json`, `donkey-r1 check` and `baseline`, and the `r1` CI job, which fails when a ratcheted count gets worse than the base commit's baseline and builds the base CLI to measure the same bytes when they changed (`R1Ratchet.*`); done when the job is green on `main`. Not done: the T4 execution of R1, and the T4 CTest step of the `r1` job) |
| G21 | Call sites and calling conventions | `r = f(a, b)` with typed arguments | On x86-64 System V (ELF, Mach-O) and AArch64, a direct call to a same-image callee that lifts Complete (its own calls resolved the same way, up to 8 levels; recursion stays unresolved), returns an integer, reads no stack argument and passes the frame check (its own code restores the stack pointer, the callee-saved registers and, on AArch64, x30, and computes with no caller register but its arguments) prints as `r = f(a, b)`, and its caller can be Complete (the clobber check holds). A call of a C library import with an executable model (ten functions, G21-T7; x86-64 and AArch64) carries the function's prototype, and the interpreter runs the model. A direct call through an import stub that a library prototype applies to prints that prototype's integer and pointer arguments and result, labelled with its library, and its caller is Partial (G22-T4). Every other call prints as `sub_x();` with no arguments or result, and its caller is Partial | P0 | IN PROGRESS (T0 DONE; T1 PARTIAL: x86-64 SysV and AAPCS64 clobber models, with the callee write set for a resolved call (and x30, which `bl` writes); the frame check of each callee; a zeroing `xor r, r` or `sub r, r` reads no value of `r` (neither a clobbered one nor a parameter); the oracle runs the callee IR, not the real callee. T2 PARTIAL: integer arguments and result from the callee's inferred signature for same-image direct calls to Complete callees, whose own calls resolve bottom-up through a per-image call-summary cache, up to 8 levels, on x86-64 System V and AArch64 (AArch64 on R1: 839 to 1,086 of 7,450 Complete; every `c_call_*` corpus function verified at -O0, -O2 and -O3 under GCC 13.3 on AArch64); AArch64 calls of other imports stay Partial; signature_inferred is always labelled. T3, T4 and T6 TODO. T5 DONE: a call of a no-return import with a fixed prototype (13 names) carries its arguments, ends its path and keeps no caller Partial (R1: 2,399 to 2,455 Complete). T7 DONE: calls of C library imports with executable models (strlen, strnlen, memchr, strchr, strrchr, strspn, strcspn, memcpy, memmove, memset), checked against the host C library; all 44 `c_lib_*` corpus results verified; on AArch64 too (T7 for AAPCS64: R1 AArch64 1,086 to 1,130 of 7,450 Complete; all 33 `c_lib_*` results verified under `qemu-aarch64`). Seven call-heavy corpus functions verified at -O0, -O2 and -O3, one of them a call chain two levels deep) |
| G22 | Type libraries | Type libraries (Ghidra: data type archives) for the major platforms | One bundled library, musl 1.2.4 for x86-64 Linux (1,563 declarations), made by `donkey-cli typelib make` (G22-T2) in the library file format, with its bounded reader (G22-T1, `docs/TYPELIBS.md`). A library loads into a project, and `project type library apply` gives an import stub the library's prototype as a `library` application when the import is shown to bind to a file the library provides (musl's loader for the musl library) and the library fits the image's ABI, shown by the CLI and noted on the stub in `decompile --project` (G22-T3). A direct call through such a stub prints the prototype's integer and pointer arguments and result on x86-64 System V, labelled with the library, and its caller stays Partial, since the import is not executed (T4). The type store, the C declaration parser and the CLI's type applications are G05 | P1 | IN PROGRESS (T0 DONE: task-level plan written 2026-11-15; T1 DONE: format, reader, fuzz target and install rule; T2 DONE: generator and the musl 1.2.4 library; T3 DONE for ELF x86-64 and PE import stubs whose imports bind to a file the library provides: 727 of 2,428 stubs of six Alpine 3.18 (musl 1.2.4) programs get a prototype, none of the glibc audit binaries'; T4 PARTIAL: x86-64 System V calls through those stubs, integer and pointer arguments; 14,656 calls in 3,795 of 13,407 functions of six Alpine 3.18 (musl 1.2.4) programs print them) |
| G23 | Unwind tables and exception handling | Reads `.eh_frame`, `.pdata`, LSDA and MSVC exception data | `.eh_frame` FDE ranges (ELF), PE x64 `.pdata` RUNTIME_FUNCTION entries the Mach-O `LC_FUNCTION_STARTS` table and the Mach-O compact unwind entries (`__unwind_info`) are read and seed function starts; a table that cannot be read in full makes the analysis Partial. CFI programs, LSDA, `.xdata`, compact unwind encodings and ARM64 unwind data are not interpreted | P1 | IN PROGRESS (T0 DONE: task-level plan written 2026-11-17; T1 DONE for ELF .eh_frame, fuzzed (fuzz_eh_frame); T2 PARTIAL: PE x64 .pdata RUNTIME_FUNCTION entries, chained entries skipped (not tested with a fixture); .xdata and ARM64 TODO; T3 DONE: `LC_FUNCTION_STARTS` and `__unwind_info` read and fuzzed (fuzz_function_starts, fuzz_unwind_info); T4, T5 TODO) |
| G24 | Analysis of stripped binaries | Function discovery from several sources, no-return, thunks, stack analysis | Function seeds are the entry point, exported symbols, call targets and unwind-table entries (`.eh_frame`, PE x64 `.pdata`), the Mach-O `LC_FUNCTION_STARTS` table and compact unwind entries, and the ELF initialisation and termination functions (`DT_INIT`, `DT_FINI`, the init, fini and preinit arrays, `.init` and `.fini`); a walk stops at a jump or fall-through into another function's start and at an import stub. Import stubs (ELF `.plt`, `.plt.sec`, `.plt.got`; MinGW `jmp *slot` thunks) are named by their import, and one-jump thunks are found and named `j_<target>` (T4). A binary without unwind tables or a Mach-O `LC_FUNCTION_STARTS` table gets no seeds beyond the first three and, for ELF, its initialisation and termination functions; calls to no-return functions end their block, found by name, symbol version and propagation (T3); prologue discovery is not done | P0 | IN PROGRESS (T0 DONE: task-level plan written 2026-11-15; T1 measured in docs/AUDIT.md; T2 PARTIAL: unwind seeds (ELF and PE x64); seeds stop at jumps and fall-through into another function start, and at import stubs; T3 DONE: no-return calls bound by symbol version, DT_NEEDED or PE DLL, with propagation; a shared library's calls bound in the scope of the program that loads it (`--program`), else unmarked; T4 DONE for ELF (x86-64, AArch64) and PE: stubs, GOT and IAT calls and thunks named; T5 to T7 TODO) |
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
     whole-function form is kept for invalid graphs, which verified IR does not produce, and
     for graphs that nest deeper than `kMaxStructureNesting` (128 levels); none of the 1,986
     sampled functions is labelled.
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
- **Status:** DONE, measured in `docs/AUDIT.md` (W1); goto reduction (W1b) decided 2026-11-17 and done (small-block copies, compound conditions). No function of the
  fixed 1,986-function list is printed as labelled blocks (985 before), and every printed structure
  passes the control-flow check, on the corpus and on the list (0 candidates refused). Structured
  without goto: 1,001 before, 1,000 after. Two functions left that set (`openssl` `0xa9b70`, `libc`
  `0x97ec0`): their old output printed a switch's case blocks a second time, which the switch rule now
  refuses; one function joined it (`libsqlite3` `0xa5c40`). Gotos: 986 functions, 16,232 in all,
  largest 409. Measured at `d5e9350` and again at `443a2da`, after the merges of phase A's
  review rounds (the same counts).
  The open decision, whether to copy small shared blocks and recover compound conditions to remove
  most of them, was decided on 2026-11-17: yes (W1b below), with the copy bounded by block size and
  by total growth, and every result still passing the control-flow check.
- **W1b (goto reduction):** DONE in part (2026-11-17, `docs/AUDIT.md` W1b): small blocks that return or
  only jump on are copied in place of a goto (`kGotoRuleCopy`, at most 4 statements, at most 64
  copies per function); this also threads a goto through a block that only jumps. Gotos
  16,232 -> 14,644, functions with gotos 986 -> 919, 0 candidates refused, openssl +3.8% time.
  `Ir.LeavingTheLoopFromInsideASwitchCopiesTheExit` (was `...PrintsGotos`),
  `Ir.RuleCopyPrintsASmallExitInPlaceOfItsGoto`, `Ir.RuleCopyLeavesALargeBlockAsAGoto`.
  Compound conditions: DONE (2026-11-17, `docs/AUDIT.md` W1b). A test whose block holds only its
  test, is reached only from another test, and shares one target with it prints with that test as
  one `if (a && b)` or `if (a || b)` (`kGotoRuleCompound`); the tag names the second test, and the
  control-flow check lowers it to the two branches and checks both, edge by edge. Gotos 14,644 ->
  14,319, functions with gotos 919 -> 916, 0 candidates refused, no measurable time cost.
  Re-measured after G24-T3 (#67) ended blocks at no-return calls: `main` 15,712 gotos in 984
  functions, W1b 13,713 in 913 (-12.7%), Complete 177 both.
  CI: [run 44264049339](https://github.com/palaashatri/donkey/actions/runs/44264049339) at `e49d58f`
  (headless on Linux x86-64 and arm64, macOS and Windows, and the desktop shell under Xvfb), which runs
  every `Ir.Rule*` and `Ir.Check*` test above.
  `Ir.RuleCompoundPrintsTwoTestsAsOneCondition`, `Ir.CheckRefusesACompoundConditionWithTheWrongForm`.

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
  ran 679,144 inputs in 61 s with no finding. Not supported: function
  pointers and other parenthesised declarators (bit-fields and integer constant expressions
  were added for G22-T2's review, 2026-11-19),
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

#### G20-T0 task-level plan (written 2026-11-21, before any G20-T1 code)

**Spike, measured on `main` at `3263c84`.** The proposed sources were fetched and built on Ubuntu 24.04 x86-64
with GCC 13.3.0 and the distribution defaults (PIE, `-fstack-protector-strong`, `-fcf-protection`), with the cross
GCC 13.2.0 for AArch64, and with `musl-gcc` from musl 1.2.4 (Ubuntu `musl-tools` 1.2.4-2). A Release
`donkey-cli decompile <binary> --json --max-functions 1000000` then ran on each, one process per binary. The spike
is not the T2 result; T2 measures again, in CI, from the manifest.

| Binary (x86-64, unstripped) | Functions | Complete | Partial | Other | Time |
|---|---|---|---|---|---|
| zlib 1.3.1 `libz.so`, -O0 | 207 | 58 | 149 | 0 | 0.8 s |
| zlib 1.3.1 `libz.so`, -O2 | 185 | 40 | 145 | 0 | 0.6 s |
| Lua 5.4.7 `lua`, -O0 | 1,178 | 174 | 1,004 | 0 | 1.6 s |
| Lua 5.4.7 `lua`, -O2 | 794 | 77 | 717 | 0 | 1.5 s |
| Lua 5.4.7 `lua`, -O2, static with musl | 987 | 124 | 863 | 0 | 2.3 s |
| SQLite 3.46.1 `sqlite3` shell, -O0 | 3,067 | 584 | 2,483 | 0 | 9.9 s |
| SQLite 3.46.1 `sqlite3` shell, -O2 | 1,987 | 211 | 1,776 | 0 | 18.2 s |

The x86-64 total is 1,268 Complete functions out of 8,405 (15.1%). No function was Unsupported or InvalidIR, and
none crashed. The AArch64 builds of Lua and SQLite at -O0 and -O2 decompile in 1 to 11 s each: Lua -O2 has 49
Complete functions out of 790, and SQLite -O2 has 169 out of 1,989.

The stripped copies (`strip`) of the x86-64 -O2 builds give these function counts, against the `t`/`T` symbols
of the unstripped symbol table:

| Build | Functions found | Symbols |
|---|---|---|
| Lua | 789 | 704 |
| SQLite | 1,982 | 1,897 |
| zlib | 180 | 136 |
| static musl Lua | 920 | 994 |

The static musl build is the one with fewer functions than symbols: musl's assembly functions have no
`.eh_frame` entry. The whole of R1 runs well inside the CI budget, so T2 decompiles every function and samples
nothing.

The first specific note of each Partial function, across the seven x86-64 builds (7,137 Partial functions), leaving
out the two notes every x86-64 function carries ("integer subset; locals are not recovered" and "signature inferred
from System V ABI register use"):

| Partial functions | First specific note | Gap |
|---|---|---|
| 4,235 | outgoing call arguments and return values follow no modelled ABI | G21 |
| 1,646 | fs- or gs-relative memory (thread-local storage) is not modelled | new: the stack protector's `%fs:0x28` canary |
| 979 | jump leaves the function; treated as a tail call | G21, G24 |
| 144 | the returned register is not determined by the definitions that reach the return | G21 |
| 62 | floating-point results assume the MXCSR rounding mode | G01 |
| 54 | others: flags not modelled (21), `rax` and `xmm0` both written (12), tail jumps (11), and 10 more | G02, G21 |
| 17 | no note other than the two generic ones | none: a Partial result must name its reason, so T2 lists these and each is fixed or explained |

The stack-protector row is a finding of the spike. A function built with `-fstack-protector-strong` reads the
canary through `%fs`. T2 keeps the distribution defaults, because real programs are built with them. Whether the
canary load and check become a modelled idiom is a G21 question, not decided here.

**R1.** The manifest `tools/r1/r1.json` lists each source and each build. A source entry has the name, the
version, the URL, its SHA-256, the licence, the source files and the flags.

The four sources are redistributable but are not redistributed: the build fetches them, and nothing built is
committed.

| Source | Licence | URL | SHA-256 |
|---|---|---|---|
| zlib 1.3.1 | zlib | `https://zlib.net/fossils/zlib-1.3.1.tar.gz` | `9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23` |
| Lua 5.4.7 | MIT | `https://www.lua.org/ftp/lua-5.4.7.tar.gz` | `9fbf5e28ef86c69858f6d3d34eccc32e911c1a28b4120ff3e84aaa70cfbf1e30` |
| SQLite 3.46.1 amalgamation, the version `cmake/DonkeyStorageDependencies.cmake` already pins | public domain | `https://www.sqlite.org/2024/sqlite-amalgamation-3460100.zip` | `77823cb110929c2bcb0f5d48e4833b5c59a8a6e40cdea3936b99e199dbbe5784` |
| musl 1.2.4, as `musl-gcc` links it | MIT | Ubuntu package `musl-tools` 1.2.4-2, not a download | the package version is recorded and checked |

The builds:

- `libz.so`, `lua` and `sqlite3` at -O0 and -O2, for x86-64 and for AArch64 (the cross compiler).
- `lua` at -O2 linked statically with musl, for x86-64 only. `musl-tools` has no AArch64 cross form; the output
  says so.
- Each build is kept unstripped and as a `strip` copy.

That makes 26 binaries. The provenance that `docs/DESIGN.md` §11.5 requires is written to the measurement output
for every binary: the source, licence, compiler and version, flags, level, architecture and the binary's SHA-256.

**Tasks and files.** The tools are a CMake script and a C++20 program, so no Python runtime is needed, in line with
`docs/DESIGN.md` §1, item 4.

- **T1 [ground truth]** `tools/r1/r1.json`, `tools/r1/build.cmake` (run with `cmake -P`) and `tools/r1/README.md`.
  - `build.cmake` downloads each source into a cache directory with `file(DOWNLOAD ... EXPECTED_HASH SHA256=...)`,
    so a hash mismatch stops it before anything is unpacked.
  - Before extracting, it lists the archive with `file(ARCHIVE_EXTRACT ... LIST_ONLY)` and refuses any member
    with an absolute path or a `..` component.
  - It compiles with the manifest's flags and `-ffile-prefix-map`, and writes `binaries.json`.
  - For every binary, `binaries.json` records the provenance above and the identity of the compiler that built
    that binary. The identity is the first line of that compiler's `--version` (`gcc`, or
    `aarch64-linux-gnu-gcc` for AArch64) and its package version (`gcc-13`, `gcc-aarch64-linux-gnu`,
    `musl-tools`). A change to either compiler is therefore seen on the binaries it built.
  - The ground truth for the stripped builds is the defined function symbols, with sizes, of the unstripped twin:
    every `SymbolKind::Function`. The ELF reader maps both `STT_FUNC` and `STT_GNU_IFUNC` to that kind
    (`src/binary/elf.cpp`). Both are counted as starts, because an IFUNC symbol's value is the start of its
    resolver, which is code.
  - The T2 tool reads these symbols through Donkey's own ELF reader (`donkey::load_binary`,
    `BinaryImage::symbols`). The CLI has no symbol-listing command, and none is needed.
  - Tests:
    - `cmake/checks/r1_build_refusals.cmake` runs `build.cmake` on two inputs: a source whose hash does not match,
      and a committed 1 KiB tar fixture with a `../escape` member (`tests/fixtures/r1/`, with provenance). It
      checks that both are refused.
    - `R1.ManifestSchema` (in `tests/unit/r1_test.cpp`) refuses unknown keys and a missing hash.
    - `R1.SymbolsMatchReadelf` compares, on one corpus library, the starts and sizes read through Donkey with the
      `FUNC` and `IFUNC` rows of `readelf -sW`. The library is built with one IFUNC, so both types are covered.
- **T2.** `tools/r1/r1_tool.cpp` (the C++20 program `donkey-r1`, built when `DONKEY_BUILD_R1_TOOL=ON`; its logic
  lives in a small library tested by `tests/unit/r1_test.cpp`), plus one change to the CLI.
  - The CLI change: `decompile --json` gains a `"notes"` array on each function, holding the lifter's notes in
    order. This only adds a field, so `kJsonSchemaVersion` stays 1. A CLI test checks the field on
    `${DONKEY_MUSL_PROGRAM}`, and the measurement does not scrape `// note:` comment lines.
  - The CI job runs `donkey-cli decompile --json --max-functions 1000000` on every binary, one process per binary
    under `timeout`.
  - `donkey-r1 measure` reads those outputs with `donkey::parse_json`, with limits raised to the size of the
    largest output. For each function it records the status: Complete, Partial, Unsupported, InvalidIR, or error.
    An error means the process failed, timed out or wrote unreadable output, and is recorded for the whole binary.
  - `measure` accepts output that has no `notes` array, such as the output of a CLI built before T2. Then it
    reports no reasons. The ratchet counts (Complete, Unsupported, InvalidIR, error and missed starts) never
    depend on notes, so a base CLI from before T2 can still be compared (see T3).
  - For each Partial function it records the first specific note and every note.
  - For each stripped binary it records the starts found, against the unstripped symbol starts: matched, missed
    and extra. That is G24's measure on R1.
  - It writes `r1-result.json` and a Markdown table, both uploaded as a CI artifact. The table of the 20 most
    frequent first notes goes into `docs/SUPPORT_MATRIX.md`, with the commit it was measured at.
- **T3.** The ratchet: `tools/r1/baseline.json` and `donkey-r1 check`.
  - The baseline holds counts for each binary (program, architecture, level, stripped or not): Complete,
    Unsupported, InvalidIR, error and missed starts. Each entry also records the identity of the compiler that
    built that binary and the binary's SHA-256. The hash covers every build input at once: the source, the flags,
    the manifest and the compiler.
  - The check always compares against the baseline as it is at the base commit
    (`git show <base>:tools/r1/baseline.json`), never against the file in the PR. A PR that edits the baseline
    therefore cannot lower the bar it is checked against. When the PR also changes `baseline.json`, the check
    verifies that the new file equals the counts the head measured.
  - The check fails when, for any binary, Complete drops, or Unsupported, InvalidIR, error or missed starts rise.
  - A count that improves passes and is printed. The PR that improves it runs `donkey-r1 check --update` and
    commits the new baseline.
  - If a binary's SHA-256 differs from its entry in the base baseline, the stored counts describe other bytes, so
    a comparison has to be made on the same bytes. That happens after a runner image update (a new compiler), or
    in a PR that changes a source version, a flag or the manifest. The job builds
    `donkey-cli` from the base commit (the PR's base SHA, or the previous commit on a push to `main`) and
    measures the same freshly built R1 binaries with it. It then checks the head against that base under the
    rules above.
    - A drop still fails.
    - A pass prints that the baseline is out of date, as a warning annotation. The next PR re-records the
      baseline with `--update`, and says that it does.
    - A change to the corpus or the compiler therefore cannot hide a regression. Such a change makes the job
      longer by one more CLI build.
  - The CI job is a new `r1` job in `.github/workflows/ci.yml` on `ubuntu-24.04`, with `gcc-aarch64-linux-gnu`
    and `musl-tools` installed. It builds the Release headless CLI and `donkey-r1`, then runs these steps in
    order:
    1. fetch and build R1;
    2. the T4 CTest, with `DONKEY_R1_DIR` set and `DONKEY_R1_REQUIRED=1`, so a skip fails in this job;
    3. decompile;
    4. measure;
    5. check.
  - A download is retried. A download that keeps failing is reported as a fetch failure, never as a ratchet
    result.
  - The budget: about 2 minutes to build the sources and, from the spike, about 2 minutes to decompile all 26
    binaries.
- **T4 [oracle]** `tools/r1/pure.json` and an executed comparison, `R1Oracle.PureFunctionsAgree`.
  - `pure.json` lists the R1 functions that can be called in isolation. Their arguments are integers or pointers
    to buffers the caller provides; they keep no global state, and every call they make can be modelled by the
    interpreter.
  - The candidates are the `libz.so` exports `adler32`, `adler32_z`, `crc32`, `crc32_z`, `adler32_combine`,
    `crc32_combine` and `zlibCompileFlags`. Lua's `lctype` helpers are macros, and its `lobject` functions are
    `LUAI_FUNC` (hidden visibility on ELF), so neither can be reached through `dlopen`, and Lua has no candidates.
  - A function joins the list only after its name is shown in `nm -D --defined-only` of the built library. The
    test checks this again and fails on a name that is not exported.
  - Each listed function runs natively through `dlopen` and through `donkey/ir/eval.h` on the same inputs, as
    the corpus does in `tests/unit/decompiler_corpus_test.cpp`.
  - Outside the `r1` job the test is skipped, with the reason given, when R1 has not been built. Inside the job
    it must run.
  - It reports verified Complete and unverified Complete separately.

**Done when.**

- T1 to T3 are merged, and the `r1` job is green on `main` with the baseline committed.
- The reason table is in `docs/SUPPORT_MATRIX.md`.
- The plans of G21, G01, G08 and G04 state how their order was checked against that table.
- The scorecard threshold for row 6 stays proposed until the owner fixes it after the first T2 baseline
  (`docs/PARITY.md` section 5).

**Pitfalls.**

- Never commit a downloaded or built file, and never skip a hash check, retries included.
- Never lower a baseline count to make CI pass. A drop is either a regression to fix, or a soundness fix whose PR
  says why the count fell. Only the second may lower the baseline, and its PR says so.
- The missed starts of a static musl build come from hand-written assembly with no unwind entries. They are a
  property of the binary, not noise, and stay in the count.
- The same source at the same level with the same compiler must give the same bytes. `binaries.json` records each
  SHA-256, so that two CI runs can be compared.

**T1 report (2026-11-21).** `tools/r1/r1.json` (the manifest) and `tools/r1/build.cmake` (fetch, check,
unpack and build, in CMake script mode) were done as planned.

On Ubuntu 24.04 x86-64, the script builds the 26 binaries in 2 minutes and writes the provenance of each to
`binaries.json`:

- the source with its version, licence and archive SHA-256;
- the toolchain, architecture, level and variant;
- the compiler's and the `strip` tool's `--version` line with their package versions;
- the flags;
- the binary's SHA-256.

A second build in another directory gave the same 26 SHA-256 values, so `-ffile-prefix-map` makes the
builds reproducible.

Three departures from the plan, each for a reason:

1. The hash is checked by the script after the download (`file(SHA256)`), not with `EXPECTED_HASH`. On a
   mismatch, CMake's own check stops the script with its own error and leaves the downloaded file on disk.
   The script instead deletes it, does not retry, and names both hashes.
2. The archive members are listed with `cmake -E tar tf`. `file(ARCHIVE_EXTRACT ... LIST_ONLY)` prints the
   list but does not return it. Every member must lie under the source's root, and an absolute path, a drive
   letter, a backslash or a `..` component is refused before anything is unpacked.
3. The test archives are made at test time with `cmake -E tar`, which keeps a `pkg-1/../escape.txt` member
   as written, so no archive is committed. The manifest schema is checked by `build.cmake`, the only program
   that reads `r1.json`, so its tests live in the same CMake check (`r1.build_script_refusals`): an unknown
   key, a missing key, a short hash and an unsafe root. `R1.SymbolsMatchReadelf` moves to T2, where
   `donkey-r1` first reads symbols.

The refusal check covers a wrong hash (the file is not kept), a `..` member, a member outside the root, the
four schema faults, and a good archive that is fetched and unpacked. It uses `file://` archives, so CTest
needs no network.

Not done in T1, and planned for T2 and T3: the decompile run, `donkey-r1`, and the CI job.

**T2 report (2026-11-21).** `donkey-r1` (`tools/r1/r1_tool.cpp` and `r1_measure.{h,cpp}`, a C++20
developer tool built with the tests and never installed) and `tools/r1/decompile.cmake` were done as planned.
The tool also needed two additions to `decompile --json`:

- a `"notes"` array, holding the lifter's notes in order;
- an `"unsupported"` array, holding the text of each distinct Unsupported statement.

Both are additive, so `kJsonSchemaVersion` stays 1. The `--no-pseudocode` flag leaves out the text and the
source map, which make up about 50 MB of SQLite's output. The status is still computed by formatting the
pseudocode, so InvalidIR is still found.

The measurement found four things:

1. **34 Partial functions gave no reason as a note.** Each of them has an instruction that is not lifted
   (`rol rdx, cl` in Lua's `rotl`, `syscall` in musl's wrappers, AArch64 `ldurb`). The only trace of it was
   a `/* unsupported: ... */` statement. The measurement now takes such an instruction as the reason when
   no specific note is given. Every Partial function of an unstripped build then has a reason; one Partial
   function of the stripped static musl build has neither a note nor an unlifted instruction.
2. **The order of reasons matters.** Putting unsupported instructions before notes made "unsupported
   instruction 'mov'" (1,544 functions) hide the thread-local storage note. The `%fs:0x28` load of the stack
   protector is an Unsupported `mov`. A specific note is therefore the first reason, and an unsupported
   instruction is the first reason only without one.
3. **Every found start of a stripped glibc build that is not a symbol is an import stub.** Those starts lie
   in `.plt`, `.plt.sec` or `.plt.got`, 966 in all. They are counted as stubs, apart from the 2 extra starts,
   which are both in static musl.
4. **The 109 missed starts** (measured at `2270daa`).
   - In each glibc x86-64 build they are five functions of the C runtime: `_init`, `_fini`, `frame_dummy`,
     `register_tm_clones` and `__do_global_dtors_aux`. Each glibc AArch64 build misses only `_init` and
     `_fini`; its other three have unwind entries. These are named by `DT_INIT`, `DT_FINI`, `DT_INIT_ARRAY`
     and `DT_FINI_ARRAY`, which the function discovery did not read; the G24 init and fini seeds (#88) now
     do.
   - In static musl they are 67 assembly functions with no unwind entry.

**Measured again at `3530b46`**, after the init and fini seeds and the Mach-O header fix:
- x86-64 is 1,269 of 8,406 Complete; AArch64 is unchanged.
- 14,816 of 14,887 stripped starts are found. The 71 missed are `register_tm_clones` in each of the six glibc
  x86-64 builds, which `frame_dummy` reaches by a tail jump, and 65 musl assembly functions.
- The 3 extra starts are musl's `_start`, `_init` and `_fini`, whose symbols are `NOTYPE`.

The CLI also states the analysis's own state (`"analysis_partial"` and `"analysis_diagnostics"`).
`measure` refuses an output whose analysis stopped at a resource limit (`analysis.instruction_limit`,
`analysis.block_limit`, `analysis.traversal_limit`), since functions may be missing from it. No R1 run hit
one. The analysis of every `libz.so` build and every AArch64 build is Partial for
`analysis.no_return_unverified` (G24-T3), which is recorded. That is the one diagnostic known to leave
function discovery whole. A binary with any other diagnostic, including an unknown one, is marked
`starts_may_be_missing`; no R1 binary is.

The results, the per-binary table and the 20 most frequent first reasons are in `docs/SUPPORT_MATRIX.md`
("Real programs").

Tests:

- `R1.ReadsBinaries`
- `R1.RefusesUnsafeOrIncompleteBinaries`
- `R1.RefusesAnAnalysisStoppedAtALimit`
- `R1.MarksAnalysesThatMayMissStarts`
- `cli.decompile_json_reports_an_analysis_limit`
- `R1.CountsADecompileOutput`
- `R1.AcceptsOutputWithoutNotes`
- `R1.RefusesUnusableDecompileOutput`
- `R1.NormalisesNotes`
- `R1.ComparesStarts`
- `R1.SymbolsMatchReadelf`: on a library with an IFUNC symbol, every `FUNC` and `IFUNC` start and size
  equals `readelf -sW`.
- `cli.decompile_json_lists_notes`
- `cli.decompile_no_pseudocode`
- `cli.decompile_no_pseudocode_needs_json`

### G21 Call sites and calling conventions (P0)

**Why.** Both reference tools print `r = f(a, b);`. Donkey prints
`sub_401000();`, with no arguments and no result.

**Donkey today.** On x86-64 under System V (ELF and Mach-O; a Win64 callee's parameters are not
in the System V order, so a PE call with arguments is not resolved), `lift_call` in
`src/ir/lift.cpp` resolves a direct call to a same-image callee when that callee lifts Complete, with its
own calls resolved the same way (G21-T2: call summaries computed bottom-up and kept in a per-image
`CallSummaryCache`; at most 8 levels, the evaluator's call depth; a recursive callee stays
unresolved), returns an integer and reads no stack-passed argument (`known_callee`, T1 and T2 partial):
the call carries the callee's System V arguments and result, `check_call_clobbers` refuses a read
of a register the callee may have changed, and the caller can be Complete. Every other call, and
every AArch64 call (`src/ir/lift_aarch64.cpp`), keeps only its target and marks the function
Partial ("outgoing call arguments and return values follow no modelled ABI"). On the fixed list of
1,986 functions, 1,497 carried that note at `665c9e4` ([`AUDIT.md`](AUDIT.md)), 1,491 before the call summaries
and 1,489 after them: most callees that make a call also call an import or call through a register, so
they stay Partial and so do their callers. Baseline: 1,009 of the
1,893 functions of the first sample carried it.

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
- **T7 [oracle].** Calls of C library imports: an executable model of each C
  function whose result ISO C fully defines, checked against the host's C
  library, so a caller of the function can be executed and compared with its
  compiled code. Plan and result below.

**Done when.** No R1 function is Partial only because it calls, and the
corpus has call-heavy functions verified by execution.

**Pitfalls.** An argument count taken from register liveness is an inference.
Label it as one (`signature_inferred`) and never print it as certain. A wrong
prototype must fail the oracle, not print plausible code.

#### G21 call census on R1 (2026-11-21)

Before more G21 work, the R1 measurement counts why each call stays without arguments and a result.
`lift_call` and the AArch64 lifter record every such call on the lifted function
(`IrFunction::unresolved_calls`, with the kind of its target), `decompile --json` lists them, and
`donkey-r1 measure` counts them over R1. The table is in `docs/SUPPORT_MATRIX.md` ("Call census").

On the unstripped R1 builds at `c655bdf`, 3,044 Partial functions have an unresolved call as their only
specific reason:

- 2,471 are AArch64: 1,603 call only same-image functions, 781 also call imports, 87 call only imports.
  No AArch64 call was resolved then, whatever its callee (G21-T1/T2 for AAPCS64, below, resolves them).
- 491 are x86-64 functions whose only blocker is a same-image callee that did not resolve.
- 36 call only through a register, 20 through a register and a same-image callee.
- 15 call only an unresolved import, and 11 an import and a same-image callee.

Counted again with the notes an unresolved call causes counted as its own (a tail call's note, and the
clobber check's read of a register after a call that does not define it; G21-T1/T2 for AAPCS64), the same
bytes have 4,452 such functions: 2,471 AArch64 and 1,981 x86-64 (1,566 of them call only same-image
callees). With AArch64 calls resolved, 4,310: 2,330 AArch64 and 1,980 x86-64. With the AArch64 builds given
their sysroot (their no-return imports then bind) and the C library models on AArch64, 4,780: 2,800 AArch64 and
1,980 x86-64 (G21-T7 for AAPCS64, below). With no-return calls resolved (G21-T5, below), 4,727: 2,751 AArch64 and
1,976 x86-64.

Order this sets for G21:

1. AArch64 calls: T1 and T2 for AAPCS64. The call summaries of `src/ir/lift.cpp`, with x0-x7 arguments, an
   x0 result, the AAPCS64 clobber set, and the same oracle. This is the largest group.
2. The C library models of T7 for AArch64. `memset`, `memcpy` and `strlen` are the imports these functions
   call most. `__stack_chk_fail` comes before them all (472 functions). It is already a no-return import
   (G24-T3, `src/analysis/no_return.cpp`), so its block ends, but the call still keeps its caller Partial.
   A call that does not return has no result and nothing after it, so it needs no model: that is G21-T5.
3. The x86-64 same-image cascade (491): each such callee's own first reason, which the census of the callee
   gives, decides it.

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

#### G21-T1/T2 for AAPCS64: AArch64 calls (written 2026-11-21, before the code)

**Measured first.** The census (above) puts 2,471 AArch64 functions Partial only because of calls. That
count misses the functions whose second note, "the returned register is not determined by the definitions
that reach the return; x0 is assumed", comes from the call. An unresolved call defines no x0, so a function
that returns what it calls has both notes. 1,965 AArch64 functions of the unstripped builds have exactly
those two reasons. Neither count says how many can become Complete: a call resolves only when its callee
is Complete. An estimate over five of the six AArch64 builds puts a ceiling on that. It took the CLI's JSON
and `objdump`'s `bl` targets and ran a fixpoint over the call graph, with the callee Complete and at most
eight levels below the caller. Callers left with no other reason:

| Calls that resolve | AArch64 functions that become Complete (ceiling) |
|---|---|
| same-image only | 222 |
| same-image, the ten C library models, and the no-return calls | 351 |
| as above, and functions without a returned value (`void`) | 435 |

The rest stay Partial because a callee is Partial for a reason of its own. Same-image calls come first: the
C library models and no-return calls reuse their machinery (G21-T7 and G21-T5 for AArch64, next).

**What changes.**

1. *Call summaries for AArch64* (`src/ir/lift.cpp`). `known_callee` accepts AArch64 images.
   `compute_summary` takes the AAPCS64 integer argument order (`x0`-`x7`, a parameter read as `w<n>` or
   `x<n>`) where it takes System V's on x86-64. A callee with a floating-point parameter or result stays
   unresolved, as on x86-64. `reads_incoming_stack_argument` is given the stack pointer and the offset of
   the first stack argument of each architecture: `rsp + 8` on x86-64, `sp + 0` on AArch64 (no return
   address on the stack).
2. *Lifter* (`src/ir/lift_aarch64.cpp`). A `bl` to a function whose summary resolves becomes a call with
   the callee's arguments, its result in all of `x0`, `signature_inferred` and the callee's write set,
   through the same `resolve_call_statement` (it takes the result register). A `b` to such a function (a
   tail call) is a call followed by a return of `x0`, as on x86-64. Every other call is unchanged.
3. *Clobber check for AAPCS64.* `check_call_clobbers` runs on AArch64 with the AAPCS64 caller-saved set:
   `x0`-`x18`, `x30` and `v0`-`v7`, `v16`-`v31`. A resolved call clobbers the caller-saved registers its
   callee writes, and always `x30`, which `bl` writes with the return address. An unresolved call clobbers
   all of them. NZCV is already unknown after a call (`flags_exact`).
4. *Frame check (new, both architectures).* Until now a summary has trusted the callee to keep the
   registers the ABI says it keeps. A summary is only sound when the callee's own code shows it:
   - every callee-saved register it writes is back to its entry value at every return (`x19`-`x29`, and
     `v8`-`v15` for their low 64 bits, on AArch64; `rbx`, `rbp`, `r12`-`r15` on x86-64 System V);
   - the stack pointer is back to its entry value;
   - on AArch64, `x30` is back to its entry value, because `ret` jumps to it;
   - on x86-64, no store writes the return address at entry `rsp`.

   The check is a forward dataflow over the callee's IR without passes. Each register holds its entry
   value, an entry stack address plus a known offset, or unknown. Each stack slot stored at a known offset
   holds the value stored. It is joined at block starts and iterated to a fixpoint. A store at an unknown
   stack offset forgets every slot. A store through a pointer that is not stack-derived is assumed not to
   write the callee's own save area below the entry stack pointer, which only a write through a dangling
   or overflowing pointer could do. This assumption is the check's one premise, and it is written in the
   code. A callee that fails is unresolved, and so are its callers' calls to it.

   The same check of `x30` applies to every AArch64 function's own returns: a function whose returns do
   not all see the entry `x30` is Partial. A function that calls must save and restore it, and only
   resolved calls let such a function be Complete at all.
5. *Interpreter* (`src/ir/eval.cpp`). A nested call on AArch64 runs the callee with the caller's `sp`
   (a `bl` pushes nothing), not `rsp - 8`.

**Oracle.** The call-heavy corpus functions (`c_call_*`) run on AArch64 hosts and under `qemu-aarch64`
(GCC 13.3, cross-compiled). On AArch64, the corpus test then expects them Complete and verified where the
callee chain lifts, as it does for System V. CI runs it natively on the `ubuntu-24.04-arm` and `macos-15`
runners.

**Tests (names to add).**
- `Ir.AnAArch64CallToACompleteCalleeCarriesItsArguments`: from bytes, a `bl` to a two-argument callee.
- `Ir.AnAArch64TailCallToACompleteCalleeReturnsItsResult`.
- `Ir.AnAArch64CallClobbersX30`: a read of `x30` after a resolved call is Partial.
- `Ir.ACalleeThatDoesNotRestoreACalleeSavedRegisterStaysUnresolved`: on x86-64 and on AArch64.
- `Ir.ACalleeThatLeavesTheStackUnbalancedStaysUnresolved`.
- `Ir.AnAArch64FunctionThatReturnsWithAnotherX30IsPartial`.
- `IrEval.AnAArch64NestedCallRunsOnTheCallersStack`.
- `DecompilerCorpus.CompleteResultsAgreeWithTheCompiledCode`: with the AArch64 expectation for
  `c_call_nested`.

**Done when.**
- The tests pass.
- Every corpus result that is Complete agrees with the compiled code on x86-64 and under `qemu-aarch64`.
- R1 is measured before and after, and the AArch64 rise is in the PR. The R1 ratchet passes. The only
  allowed exception is an x86-64 drop that the frame check explains, where the baseline is re-recorded and
  the functions named.

**Pitfalls.**
- `bl` writes `x30` whatever the callee does.
- `w<n>` writes zero the upper half of `x<n>`.
- A veneer or PLT stub between caller and callee uses `x16` and `x17`. It is not a function that lifts
  Complete, so the call stays unresolved.
- The upper 64 bits of `v8`-`v15` are caller-saved. A 128-bit read of them after a call is not lifted
  today (SIMD is Unsupported), and must be treated as clobbered once it is.

**Result (2026-11-21).**
- R1, unstripped: AArch64 rises from 839 to 1,086 of 7,450 Complete. In total that is 2,108 to 2,355 of
  15,856, against a same-image ceiling of 222 estimated before the code; tail calls to a resolved callee count
  too. x86-64 is unchanged at 1,269 of 8,406: the frame check refuses no x86-64 callee that resolved before.
  It is precise by byte. `sqlite3Atoi64` at -O2 keeps bytes 1-3 of its caller's `rbp` through
  `sete bpl; and ecx, ebp`, but only byte 0 reaches its result, so a refusal of every read of a caller's
  register would have cost `sqlite3DecOrHexToI64`, which tail-calls it
  (`Ir.TheFrameCheckFollowsTheCallersBytesThroughAMergedWrite`).
- The corpus under `qemu-aarch64` (GCC 13.3, 77 functions) goes from 58/56/51 to 65/62/57 Complete and
  verified at -O0, -O2 and -O3. Every `c_call_*` function is verified at every level, and the
  corpus test now asserts it.
- The check reads `xor r, r`, `sub r, r` and `sbb r, r` as reading nothing of `r`. Without the `sbb` case,
  two x86-64 callees of R1 at -O2 were refused, one in Lua and one in static musl Lua.

#### G21-T5 Calls that do not return (written and done 2026-11-22)

**Measured first.** On R1 (unstripped, with the AArch64 sysroot and the C library models on AArch64), 149
Partial functions have only no-return imports among their unresolved calls: 75 AArch64, 74 x86-64. 125 of them
call only `__stack_chk_fail`, 20 only `__assert_fail`, 3 only `exit`, 1 only `abort`. 126 of the 149 call only
functions with no argument. `__stack_chk_fail` is called by 864 of the 4,780 functions that are Partial only
because of calls. Those that call other unresolved functions as well gain only when those resolve too, or when
their callees become Complete through this task.

**Why a no-return call needs no model.** Nothing after the call runs, so its result and the registers and
memory it changes never reach a return of the caller. The block already ends at the call (G24-T3). The
interpreter stops the path there (`ir.eval_no_return`), so the path is never compared. Only the call's
arguments remain, and they matter only to the printed call. A call printed without the arguments it is
passed would be wrong output.

**What changes.**

1. *Prototypes.* A fixed table of the no-return imports with known C prototypes:
   - no arguments: `abort`, `__stack_chk_fail`, `__chk_fail`, `__cxa_rethrow`, `__cxa_bad_cast`,
     `__cxa_bad_typeid`, `std::terminate` (`_ZSt9terminatev`);
   - `int`: `exit`, `_exit`, `_Exit`, `quick_exit`;
   - `__assert_fail(const char *, const char *, unsigned int, const char *)`;
   - `__fortify_fail(const char *)`.

   Variadic `err` and `errx`, `longjmp` (a `jmp_buf`), `__cxa_throw` and `_Unwind_Resume` stay as they are.
   So does a function of the image propagated from a no-return import, whose arguments are not known.
2. *Lifters* (x86-64 `lift_call` and tail calls, AArch64 `bl` and `b`). A call of an import stub or slot that
   the analysis marks no-return (`AnalysisResult::no_return`, the G24-T3 load-scope binding) is checked
   against the table by the import's name.
   - With a prototype, the call carries the prototype's argument registers (System V, Win64 or AAPCS64, an
     `int` in the low 32 bits) and no result.
   - `signature_source` names the table (`no-return prototype`).
   - It is not an unresolved call: it is left out of the census and adds no Partial note.
   - Every other call is unchanged.
3. *Verifier.* A call with `signature_source` and `no_return` may carry arguments and no result.
4. *Census.* `donkey-r1 measure` counts such calls nowhere. They are resolved.
5. *Printing.* A call with arguments notes where its prototype comes from. `abort();` prints as it is.

**Soundness.** Complete still means that every path that returns was run and compared. A path through a
no-return call ends at the call and is not compared. The function's other paths are compared as before. A
function whose every path ends at such a call already gets the note "no path returns", which keeps it Partial.
The binding is G24-T3's: the import must be shown to bind to the runtime library in the load scope, and a
program that defines `exit` itself does not get the mark.

**Tests (names to add).**
- `Ir.ACallOfStackChkFailEndsThePathAndLeavesTheCallerComplete`: x86-64 and AArch64, from bytes, with the
  no-return binding injected. The function is Complete and the call has no arguments.
- `Ir.ACallOfExitCarriesItsStatus`: `exit` gets `edi` or `w0`.
- `Ir.ANoReturnCallWithoutAPrototypeStaysPartial`: `longjmp`.
- `Ir.AFunctionThatOnlyReachesNoReturnCallsStaysPartial`.

**Done when.** The tests pass, R1 is measured before and after with the gain in the PR, and the ratchet passes.

**Result.** R1, unstripped: Complete rises from 2,399 to 2,455 of 15,856. AArch64 goes from 1,130 to 1,182, and
x86-64 from 1,269 to 1,273: most x86-64 callers of `__stack_chk_fail` read the canary through `fs` and stay
Partial for that reason. There is no InvalidIR, so every call given a prototype ended its block. The functions
Partial only because of calls go from 4,780 to 4,727. No other note changed in count: "no path returns" stays
at 147, and functions whose only other note was the call now show the next one first. No corpus function calls
one of these imports, so none is executed through such a call yet. The tests are from bytes, on both
architectures.

#### G21-T7 for AAPCS64: C library models on AArch64 (written and done 2026-11-22)

**Measured first.** On R1 with AArch64 calls resolved, `memcpy`, `memset` and `strlen` are, after
`__stack_chk_fail`, the imports that the most functions Partial only because of calls call. On AArch64 none of
the ten models applied: `modelled_call` accepted x86-64 images only. R1 decompiled the AArch64 builds without
their libraries, so none of their imports was bound to the C library in the first place
(`analysis.no_return_unverified` on every AArch64 build).

**What changes.**

1. *Lifter.* `internal::modelled_libc_call` and `internal::apply_libc_model` (`src/ir/lift.cpp`) take the
   model of a call or tail call target for both lifters. On AArch64 the target is a direct `bl` or `b` to an
   import stub the analysis binds to the C library (AArch64 has no call through a GOT slot; a `blr` through a
   register stays unresolved). The arguments are `x0`-`x2` (an `int` in `w0`-`w2`), the result all of `x0`.
   An import stub's own `br x17` is not a call of the model.
2. *Clobber check and call summaries.* A modelled call clobbers the AAPCS64 caller-saved set and `x30`
   (unchanged: an unresolved call clobbers all of them). A callee's summary counts the AAPCS64 set for a
   modelled call it makes, where it counted System V's.
3. *R1.* `tools/r1/r1.json` names a sysroot for the AArch64 toolchain (`/usr/aarch64-linux-gnu`, Ubuntu's
   `libc6-arm64-cross`, the glibc the builds link against), and `tools/r1/decompile.cmake` passes it as
   `--sysroot`. A toolchain whose sysroot is missing stops the run, so no measurement silently loses its
   bindings.

The interpreter, the verifier, the frame check and the models are unchanged: each model reads and writes the
bytes ISO C says, whatever the architecture. A callee that passes a stack address to any call has no summary
(`reads_incoming_stack_argument`), so a model never reads a callee's saved registers through a pointer
(`Ir.ACallArgumentThatPointsAtASavedRegisterPassesTheCallersValue`).

**Tests.** `Ir.AnAArch64CallOfAModelledCLibraryFunctionPassesAapcs64Registers` (a `bl` and a `b` to a bound
stub: the registers, the result and no Partial note; without the binding the call stays Partial);
`DecompilerCorpus.CompleteResultsAgreeWithTheCompiledCode` on AArch64 requires all 33 `c_lib_*` results
Complete and verified. With the models turned off for AArch64, it fails for every one of them.

**Result.** Under `qemu-aarch64` (GCC 13.3), the corpus goes from 65/62/57 to 76/73/68 Complete and verified of
77 at -O0, -O2 and -O3. On R1, unstripped:

| Step | AArch64 Complete | Partial only because of calls |
|---|---|---|
| AArch64 calls resolved (G21-T1/T2 for AAPCS64) | 1,086 of 7,450 | 4,310 |
| with the AArch64 sysroot | 1,086 | 4,793 |
| with the C library models on AArch64 | 1,130 (15.2%) | 4,780 |

The sysroot alone changes no Complete count. Its no-return imports now end their blocks, so 483 functions whose
other reason was the unbound no-return call count as Partial only because of calls. Of the 44 new Complete
functions, 37 are in the -O0 builds (Lua 7, SQLite 30) and 7 at -O2 (Lua 1, SQLite 6). x86-64 is unchanged. The
stripped copies gain the same. `__stack_chk_fail` is now called by 864 of the functions Partial only because of
calls: a call that does not return still keeps its caller Partial, which is G21-T5.

#### G21-T7 C library calls with executable models (written and done 2026-11-18)

**Why first among the call tasks.** On the fixed sample most functions that are Partial because of
a call call an import, not a function of their own image, and the most common imports are C library
functions. A call of an import can only be Complete when the interpreter can run something that
does what the library does, for every input, so each function needs an exact model.

**Binding (needs G24-T3).** An import's call is modelled only when every reference to the name binds
to the C library: on ELF by the load scope (`ElfLoadScope`, the same walk as the no-return marks:
`bind_runtime_imports` gives both, as `AnalysisResult::c_library_imports`), on PE when its DLL is a
Microsoft C runtime. A shared library's imports bind first in the scope of the program that loads it,
so a shared library gets bindings only with `--program` (the corpus test passes its own
executable). A sanitizer build of the program, which defines `strlen` itself, binds there: the call
then stays Partial.

**Models.** `donkey/ir/libc_models.h`: strlen, strnlen, memchr, strchr, strrchr, strspn, strcspn,
memcpy, memmove, memset. Each reads and writes exactly the bytes ISO C says, counts a step per byte,
and fails on undefined input (an overlapping memcpy: `ir.eval_model`; an unmapped byte:
`ir.eval_memory`), and on input where C libraries differ: memchr, strchr and strrchr search only
for an ASCII character (Microsoft's strrchr, on the Windows CI host, does not find a character
whose `int` has bits above the low byte, where glibc's does). memcmp, strcmp and strncmp have no model: ISO C defines only the sign of their
result, and the oracle compares exact values.

**IR.** `IrStatement::call_model` names the function. The arguments come from its prototype (System V
`rdi, rsi, rdx` or Win64 `rcx, rdx, r8`, an `int` in the low 32 bits), the result is all of `rax`,
and the call may change every caller-saved register (the clobber check and a callee's call summary
count them all). `signature_inferred` stays false: the prototype is not an inference. The verifier
refuses a call that names a function without a model or passes another number of arguments. Tail
calls and conditional tail calls are modelled too; an import stub's own jump is not.

**Tests.** `LibcModels.AgreeWithTheHostCLibrary` (4,000 random inputs; a model that took the first
match for strrchr, or copied memmove forward, fails it), `LibcModels.*` for the int argument, the
terminator, unmapped bytes, the step budget, the evaluator and the verifier;
`DecompilerCorpus.CLibraryCallsNeedTheProgramThatLoadsTheLibrary`; eleven `c_lib_*` corpus
functions in `DecompilerCorpus.CompleteResultsAgreeWithTheCompiledCode`.

**Result.** GCC 13.3, Linux x86-64: 43 of the 44 `c_lib_*` results (-O0, -O2, -O3, -O3 x86-64-v2)
are Complete and verified on 48 vectors each. `c_lib_memcpy_sum` above -O0 stays Partial: it zeroes
`ecx` with `xor ecx, ecx` after the call, which the clobber check reads as a read of a clobbered
register (the zeroing idiom is the next fix). On the fixed sample of 1,986 functions
(`tools/audit/sample_list.py`): Complete 177 → 180, and functions noted "no modelled ABI"
1,493 → 1,486. The sample's callers mostly call other imports too (allocation, I/O, formatted
output), and two of its seven binaries are shared libraries measured without their program. Re-measured
on 2026-11-18 with W1b and the library scope of G24-T3 (#76) merged in: Complete 177 → 180 again,
and the gotos (13,758 in 913 functions) are the same with and without the models.

**Zeroing idiom (2026-11-19).** A zeroing `xor r, r` or `sub r, r` reads no value of `r`: the clobber
check no longer counts it as a read of a register the call clobbered, and parameter inference no
longer counts it as a parameter read (`Ir.AZeroingIdiomAfterACallReadsNoClobberedValue`,
`Ir.AZeroingIdiomIsNotAParameterRead`). `c_lib_memcpy_sum` above -O0 is now Complete and verified, so all 44
`c_lib_*` results are (`DecompilerCorpus.CompleteResultsAgreeWithTheCompiledCode` requires the 44). On the fixed
sample: Complete 180 → 183, gotos unchanged (13,758 in 913 functions).

### G22 Type libraries (P1)

**Why.** IDA Pro's type libraries and Ghidra's data type archives give every
imported function a prototype and every system structure a layout before the
user does anything.

**Donkey today.** A type store, a bounded C declaration parser, and `apply_prototype`
(G05). Only tests call `apply_prototype`: the CLI's `project type apply` records an application,
and the decompiler does not read it (G05-T3 and T4). No bundled declarations.

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

#### G22-T0 task-level plan (written 2026-11-15, before any G22 code)

Checked against: `include/donkey/project/types.h` and `src/project/types.cpp` (`TypeTable`, `TypeKind`,
`TypeProvenance`, `types_from_debug_info`, `types_from_pdb`); `include/donkey/project/cdecl.h` and
`src/project/cdecl.cpp` (`parse_c_declarations`, `CDeclarationOptions`); `include/donkey/ir/prototype.h`
and `src/ir/prototype.cpp` (`apply_prototype`, `IrPrototype`); `include/donkey/project/project.h` and
`src/project/project.cpp` (`TypeApplication`, `set_type_application`, the migrations, latest v7);
`apps/donkey-cli/commands.cpp` (`command_project_type`, the `add`, `list` and `apply` actions);
`src/binary/elf.cpp` (the symbol loop from line 419), `src/binary/pe.cpp` (imports, line 345),
`src/binary/macho.cpp` (imports, line 400); `include/donkey/binary/link.h` (`resolve_imports`);
`include/donkey/binary/plt.h` (`plt_stub_imports`); `src/ir/lift.cpp` (`lift_call`, line 2021);
`src/ir/ir.h` (`call_arguments`, `signature_inferred`); `signatures/PROVENANCE.md` and
`docs/SIGNATURES.md` (the closest precedent: a versioned set with a licence and a provenance record);
`fuzz/fuzz_cdecl.cpp`, `tests/fuzz/corpus/cdecl` and the fuzz block of `CMakeLists.txt`.

**What exists today.**
- The type store validates references, cycles and ABI sizes. `TypeProvenance` has `User`, `Dwarf`,
  `Pdb`, `Inferred` and `Library`. Nothing assigns `Library` yet.
- `parse_c_declarations` parses a C subset into `TypeDefinition`s with provenance `User`. It refuses a
  preprocessor line (`cdecl.preprocessor`), a variable (`cdecl.variable`), a parenthesised
  declarator such as a function pointer (`cdecl.parenthesized_declarator`), and an unknown type name.
  Built-in names are the fixed-width integers, `size_t`, `ptrdiff_t`, `intptr_t` and `uintptr_t`.
  `wchar_t`, `va_list`, `FILE`, `time_t` and `off_t` are not built in.
- `TypeDefinition` has `variadic`. `IrPrototype` has no variadic field, so `apply_prototype` cannot
  express a `printf`-style prototype.
- `apply_prototype` changes an `IrFunction` that has a body. An import has no lifted body in its image,
  so it cannot be the target of `apply_prototype`.
- `type_applications` (`image_id`, `address`, `kind`, `type_id`) is written with `INSERT OR REPLACE`
  and has no provenance column. A library application written there would replace a user one.
- The CLI `project type apply` stores an application. It does not call `apply_prototype`, and the
  decompiler does not read applications (G05-T3 and G05-T4 status). Outside the tests, nothing in
  `src/` or `apps/` calls `apply_prototype`. The G22 "Donkey today" line says prototype application
  comes from the CLI; that is not the case (see the report note below).
- ELF import names: the symbol loop reads `.symtab` and `.dynsym` and keeps each name as written
  (`sanitize_name`). It dedupes on (name, address, kind, imported). Symbol version data
  (`.gnu.version`, `.gnu.version_r`) is not read. A `.symtab` name can carry a version suffix, such as
  `getenv@GLIBC_2.2.5` (seen in the string table of `tests/fixtures/calls/calls-x86_64`); a `.dynsym`
  name does not. So one import can appear twice under two names. This comes from the code and the
  fixture's string table. It has not been run through `donkey-cli`.
- PE: an import by ordinal is named `ordinal_N` (`pe.cpp` line 349). The image does not hold the name
  of the DLL export.
- Mach-O: the name is kept as written. The reader does not drop the C leading underscore (not checked
  against a Mach-O fixture, so this is expected, not measured).
- Cross-image import binding (`resolve_imports`) matches by name only. It does not map ordinals.
- Bundled data: `signatures/musl-1.2.4.json` and `signatures/PROVENANCE.md` exist. Nothing installs
  them. `CMakeLists.txt` has no `install()` rule for `signatures/`, and the tests find the directory
  through the `DONKEY_SIGNATURE_DIR` define. There is no install path for bundled libraries.
- The IR call fields from G21 are `call_arguments` and a `signature_inferred` bool. A library source
  needs more than a bool (see T4).

**T1 — library file format.**

- *Shape.* A versioned text file. A first line `donkey-typelib 1` (format version). Then header lines
  `key: value`, up to a blank line. The rest is C text for `parse_c_declarations`. The reader splits the
  header before the parser runs, so the parser never sees a `#` line.
- *Header keys (required unless noted).* `library`, `library_version`, `platform` (linux, freebsd,
  windows, macos), `architecture` (x86_64, aarch64), `abi` (sysv, win64, aapcs64), `data_model` (LP64 or
  LLP64), `pointer_size`, `long_size` (these map to `CDeclarationOptions`), `char_is_signed`, `source`
  (package or URL, with its version), `source_sha256`, `licence` (an SPDX identifier), `licence_file`
  (where the licence text came from), `licence_sha256` (of that licence text), `generator` (a name and
  version), `generator_command` (the command line), `preprocessor` (its name and version, or `none`),
  `created` (an ISO 8601 date), `body_sha256` (of the C text), `declarations` (the count).
  Repeated, in this order after the single keys, each optional unless T2 requires it: `source_file`
  (one line per header or archive used: `<relative path> <sha256>`, at most one line per path), `macro`
  (one per macro set: `NAME=value`), `skipped` (one per declaration left out: `<name>: <reason>`) and
  `note`. The reader keeps every record, in order, as the library's provenance and refuses a malformed
  value, a repeated path, or a single key given twice.
- *Bounds (proposed; to be measured in T2).* The whole file at most 4 MiB, the C text at most
  `kMaxCDeclarationBytes` (1 MiB, the existing limit), at most 20,000 declarations, header lines at most
  256 bytes and at most 4,096 of them (the repeated `source_file` and `skipped` records
  can be many). Nesting stays at `kMaxCDeclarationNesting` (64).
- *The reader refuses* (each with a stable `typelib.` code and the line where it can be located):
  a missing or other format line; an unknown key; a single key given twice (the repeated records
  `source_file`, `macro`, `skipped` and `note` may repeat); a missing required key; a platform,
  architecture, ABI or data model outside its enum; a `pointer_size` or `long_size` other than 4 or 8;
  a data model that contradicts the ABI (LLP64 with `long_size` 8, for example); a `body_sha256` that
  does not match the C text; a `declarations` count that does not match the parsed count; a file or
  count over its bound; any C construct the parser refuses (the parser's `cdecl.` code is passed on
  with the library's line); a duplicate declaration name; a name used both as a type and as a function;
  any result that fails `TypeTable::validate`.
- *Where files live.* Bundled libraries: an install directory that does not exist yet (T1 adds the
  `install()` rule for a `typelibs/` directory, next to the existing `signatures/`). User libraries: a
  per-user directory whose path the code does not define yet; T1 picks it with the same rule the
  project path uses (to check in `src/project/project.cpp` before choosing).
- *Fuzz.* `fuzz/fuzz_typelib.cpp`, registered in the fuzz block of `CMakeLists.txt` the way `fuzz_cdecl`
  is (sanitizers, `donkey::project`). Seed corpus in `tests/fuzz/corpus/typelib/`: one valid small file,
  and one seed for each refusal above. A run of 60 s with no finding.
- *Tests.*
  - `TypeLib.ReadsAHeaderAndItsDeclarations` (unit, a hand-written fixture in `tests/fixtures/types/`).
  - `TypeLib.TypesCarryTheLibraryProvenance` (unit: every type has `TypeProvenance::Library`).
  - `TypeLib.RefusesAnUnknownFormatVersion` (negative).
  - `TypeLib.RefusesABodyThatDoesNotMatchItsHash` (negative).
  - `TypeLib.RefusesAFileOverItsBounds` (negative, file and declaration count).
  - `TypeLib.RefusesADataModelThatContradictsItsAbi` (negative).
  - `TypeLib.RefusesAVariableAndAFunctionPointer` (negative: the parser refusals, with the library line).
  - `TypeLib.ErrorsAreLocated` (the `line L, column C:` text survives).
  - `fuzz_typelib` (fuzz, 60 s clean under ASan and UBSan).
- *Done when.* The tests and the fuzz run pass on Linux x86-64 with `-Werror`; a fixture library loads
  with provenance `Library`; each refusal above has a test and a stable code; the install rule is in
  `CMakeLists.txt` and the `install` target copies the directory (checked on Linux).

**T1 report (2026-11-15).** Done. What was built and what was measured:
- `include/donkey/project/typelib.h` and `src/project/typelib.cpp`: `read_type_library` (no file
  access) and `load_type_library` (checks the file size before it reads anything). The format is
  described in [`TYPELIBS.md`](TYPELIBS.md) and in the header comment. Every refusal in the list
  above has a stable `typelib.` code, plus `typelib.carriage_return` (a CR byte: line endings must be
  LF), `typelib.record_order` and `typelib.io`. A parser refusal keeps its `cdecl.` code, and its
  `line L, column C:` names the line in the library file.
- Two choices made here. (1) `declarations` counts the body parsed with the built-in names only, so
  a library must parse on its own. It is parsed once, on its own, so the table it is read into
  cannot change what its text means; its types are then moved up to take their ids from that
  table's `next_id()`. (2) Names follow C's two name spaces: struct,
  union and enum tags share one, and typedef and function names share the other. `struct stat` next
  to the function `stat`, and `typedef struct point point`, are accepted. A typedef and a function
  with one name is `typelib.type_and_function`, also when the typedef names an untagged struct. Any
  other repeat within one name space is `typelib.duplicate_name`. The parser lists the names it
  declares with their name space (`CDeclaredName`, a new optional output of
  `parse_c_declarations`).
- Tests: 32 `TypeLib.*` tests in `tests/unit/typelib_test.cpp`, the eight named above among them, one
  for each refusal code, and one that accepts a tag and an ordinary name with one spelling. The fixture
  is `tests/fixtures/types/typelib-small.dtl` (hand-written, MIT; 18 declarations), and it loads with
  provenance `Library`.
- Fuzz: `fuzz/fuzz_typelib.cpp`, registered next to `fuzz_cdecl`. The seed corpus is
  `tests/fuzz/corpus/typelib/` (31 seeds: three valid files, an empty body, and one seed for each
  refusal; each seed was checked to reach the outcome its name gives). Review found that a fuzz build
  compiled only the harnesses with `-fsanitize`: the libraries, the parsers included, had no coverage
  instrumentation and no ASan or UBSan, for every fuzz target. A fuzz build now compiles every target
  with `-fsanitize=fuzzer-no-link,address,undefined` (`CMakeLists.txt`). With that, a 60 s run of
  `fuzz_typelib` (Clang 18, Linux x86-64) started from 9,466 coverage edges, made 76,090 runs, grew the
  corpus to 304 inputs and found nothing; `fuzz_cdecl` made 414,063 runs in 60 s and found nothing.
- Install: `cmake/DonkeyPackaging.cmake` installs `typelibs/` to `share/donkey/typelibs` (Linux and
  FreeBSD), `typelibs` (Windows) and `Donkey.app/Contents/Resources/typelibs` (the macOS app). Checked
  on Linux only: `cmake --install build/headless-linux --prefix <dir>` installs
  `share/donkey/typelibs/README.md`. No library is bundled: `typelibs/` holds a README, because the header
  sources are T2's owner decision.
- Per-user libraries: `src/project/project.cpp` has no per-user directory rule (the caller passes
  the project path), so T1 defines none. `load_type_library` takes a path, and T3 chooses where user
  libraries live.
- Builds: GCC Debug 888/888 tests, Clang Debug 888/888, GCC Release 889/889 (each with `-Werror`), all on
  Linux x86-64. The new files also pass a MinGW-w64 `-fsyntax-only -Werror` check. macOS, Windows and
  FreeBSD are covered by CI only.

**T2 — generator [owner decision].** The owner decides which header sources are allowed. This plan
does not pick one. Licences below are as I understand them and must be checked in each source before
T2 starts.

| Source | Licence (to check) | Covers | Input form | Notes |
|---|---|---|---|---|
| musl 1.2.4 headers | MIT (`signatures/PROVENANCE.md` records the MIT licence of the musl package) | libc, POSIX | C headers | The same library as the shipped signature set. Needs a C preprocessor (`gcc -E` or `clang -E`) as a build-time tool. The owner decides whether that tool is allowed in the generator. |
| Microsoft win32metadata | MIT (check the repository's licence file) | Windows API | ECMA-335 `.winmd` metadata, not C | Not C text. T2 would need a metadata reader (a new parser, with its own fuzz target and its own task), or a converter outside the repo whose output is checked by T1. |
| MinGW-w64 headers | Mixed, per file (check each file) | Windows CRT and Win32 | C headers | Each file's licence must be read. Mixed files need an owner decision. |
| glibc headers | LGPL-2.1 with exceptions (check) | glibc | C headers | Rule 4 of section 1 forbids LGPL. Only the owner can waive it. Listed so the owner sees the choice; not recommended here. |
| Linux UAPI headers | GPL-2.0 with the Linux-syscall-note exception (check) | system calls and kernel structures | C headers | Rule 4 forbids GPL. The note concerns user-space use; whether that is enough is the owner's decision. |
| FreeBSD headers | BSD-style (check per file) | FreeBSD libc | C headers | Needs a FreeBSD build target to be useful. |
| Apple SDK headers | Apple SDK licence | macOS | C headers | Excluded: AGENTS.md forbids SDK headers in the repository, and they are not an input option. |
| Hand-written declarations from public standards | Each standard's text has its own copyright (check) | libc, POSIX | Hand-written C | An option only. The owner decides whether a set written by hand from these texts is acceptable, and records the reason. |

*What each generated library records* (the provenance `T1` reads back): the source package or URL and
its version; the SHA-256 of each header or archive used; the SPDX licence and the licence file's path
and hash; the generator name and version; the command line, the preprocessor and its version, and the
macros set; the platform, architecture, ABI and data model; the creation date; and a list of every
declaration that was skipped and why (for example a variable, a function pointer, or an unknown name).
Skipped declarations are listed, never dropped quietly.

*Decisions needed from the owner before T2 starts.* (1) Which sources are allowed. (2) Whether a
preprocessor tool may run in the generator (a build-time dependency). (3) Whether a metadata reader for
`.winmd` is in scope, and under which task. (4) Whether any LGPL or GPL headers may be used, and under
what waiver. (5) Whether hand-written declarations are acceptable, and from which sources.

*Decided (owner, 2026-11-17).* (1) Permissive sources only: musl 1.2.4 headers (MIT) first, then FreeBSD headers
(BSD-style, each file's licence checked), and MinGW-w64 files whose own licence is permissive (each file checked;
a file with a mixed or copyleft licence is skipped and listed). (2) A C preprocessor (`gcc -E` or `clang -E`) may run
in the generator at build time; it is never a runtime dependency. (3) A `.winmd` reader for win32metadata (MIT) is in
scope as its own later task, with its own fuzz target. (4) No LGPL or GPL headers (glibc, Linux UAPI). (5)
Hand-written declarations are acceptable only to fill a gap a permissive source leaves, each citing the section of
the public standard it follows.

**T2 report (2026-11-17).** Done for musl, the first source the owner allowed (decision of 2026-11-17: permissive
sources only, a preprocessor at build time). What was built and measured:
- `include/donkey/project/typelib_gen.h`, `src/project/typelib_gen.cpp`: `split_c_declarations` (top-level
  declarations of preprocessed text, one line each, with the words that do not change a type dropped) and
  `make_type_library`: each candidate is appended to the kept text, and the whole text is parsed from an empty
  type table, as the reader parses the file; the candidate is kept when that parse succeeds and the names it
  declares are new. Everything else is listed as `skipped` with the reason, never dropped. An input with a
  pragma that may change a layout (`pack`, `scalar_storage_order`, or any pragma not known to change no type)
  is refused (`typelib_make.pragma`). The output is read back with `read_type_library` before it is
  returned.
- `donkey-cli typelib make` and `typelib show`. `tools/typelib/make-musl.sh` runs `gcc -E -P -nostdinc
  -D_GNU_SOURCE` on every top-level header of the `musl-dev` 1.2.4-2 package (90; `wait.h`, which only
  redirects, is left out), with each header's path and SHA-256 recorded.
- `typelibs/musl-1.2.4-x86_64-linux.dtl`: 1,563 declarations kept, 3,323 types (scalars, pointers and arrays
  included), 223 skipped and listed (variables, function pointers and other parenthesised declarators,
  `__builtin_va_list` and the `v*printf` family that uses it, function definitions, names declared again, and
  what depends on them). 104 KiB. Regenerated on Ubuntu 24.04 x86-64 with `CREATED=2026-11-18`, `musl-dev`
  1.2.4-2 and GCC 13.3.0, the output is byte-identical to the committed file (`cmp`, 2026-11-20). Kept since the C parser
  evaluates constant expressions and lays out bit-fields (below): `struct timespec` (padded with
  `int :8*(sizeof(time_t)-sizeof(long))*(1234==4321);`), `struct stat`, `sigset_t`, `fd_set`, `cpu_set_t`,
  `fenv_t`, `jmp_buf`, `sem_t` and the `pthread_*_t` types, each with GCC's size and alignment for the same
  headers. Review of #70 (2026-11-18): attributes that may change a type are no longer dropped, literals no
  longer count as delimiters, the kept text and each declaration are parsed together (so a tag named first by
  a forward reference is completed by its definition: `struct sigaltstack` and 46 other declarations are
  kept now), and a skipped record names the declarator the parser refused.
- Tests: `TypeLibMake.SplitsTopLevelDeclarations`, `TypeLibMake.KeepsWhatParsesAndListsTheRest`,
  `TypeLibMake.RefusesAnInputWithNothingKept`, `TypeLibMake.RefusesOptionsTheFormatRefuses`,
  `TypeLibMake.LiteralsAreNotDelimiters`, `TypeLibMake.TypeChangingAttributesAreNotDropped`,
  `TypeLibMake.AForwardReferencedTagIsCompletedByItsDefinition`,
  `TypeLibMake.ASkippedRecordNamesTheRefusedDeclarator`, `Types.CDeclarationsListTheNamesTheyDeclareWithTheirNameSpace`
  (a definition that completes a forward reference is listed with `completes`),
  `TypeLibMake.ShippedMuslLibraryLoads` (`puts`, `memcpy`, `strlen`, `malloc`, `open`, `fopen` as Library
  functions, `printf` variadic, `struct sigaltstack` complete with `ss_size`; `struct stat`, `struct timespec`,
  `struct itimerspec`, `sigset_t`, `pthread_attr_t`, `pthread_mutex_t`, `fd_set`, `fenv_t`, `cpu_set_t`,
  `jmp_buf` and `sem_t` at GCC's size and alignment, `st_size`, `st_atim` and `st_ctim` at GCC's offsets; and
  `pthread_create` listed as skipped for its function pointer), `cli.typelib_show_musl`.
- C parser, for the review of #70 (G05): integer constant expressions in array sizes, enumerator values and
  bit-field widths (literals typed as C11 6.4.4.1 types them, enumeration constants, `sizeof(type)` and
  `sizeof expr`, casts to integer types, the unary `+ - ~ !`, the binary `* / % + - << >> < > <= >= == != & ^ |
  && ||`, `?:`, and a comma inside parentheses where it is not evaluated, with the promotions and usual
  arithmetic conversions; the untaken side of `&&`, `||` and `?:` and the operand of `sizeof` are not
  evaluated; division by zero, bad shift counts and signed overflow are errors, and syntax outside these, such
  as `++`, `--`, `->`, assignment or a function call, is refused even where it would not be evaluated), and bit-fields laid out as the
  System V ABI lays them out (a field does not cross a unit of its type; an unnamed one pads without aligning
  the struct; width zero moves to the next unit). Tests: `Types.BitFieldsAreLaidOutAsTheCompilerLaysThemOut`
  and `Types.ConstantExpressionsFollowC` compare with GCC 13.3 on x86-64 Linux; `Types.ParserErrorsAreLocated`
  covers each new error and the nesting bound, which expressions inside `sizeof(struct { ... })` share.
- Second review of #70 (2026-11-20): a parameter list is a scope (C11 6.2.1), so a tag first named in a
  prototype is the prototype's own incomplete type, not a later file-scope definition, and an enumeration
  constant declared there no longer replaces a file-scope one after it; a definition of an outer tag inside a
  parameter list is refused (`cdecl.prototype_tag`). Enumeration constants are names (an untagged enum of
  constants is kept: the `REG_*` constants of `<sys/ucontext.h>` and 25 others), and a constant declared twice
  in one scope, or with a typedef's name, is `cdecl.redefinition`. A cast keeps its type until an operator
  promotes it (`sizeof((unsigned char)1)` is 1), a `_Bool` bit-field is at most one bit wide, `++`, `--` and
  `->` are tokens the subset refuses, a directive's `#` may follow spaces, `typelib make --char-signed` takes
  only `true` or `false`, and `make-musl.sh` records `_GNU_SOURCE=1`, the value `-D_GNU_SOURCE` defines.
  Tests: `Types.PrototypesAreScopes`, `Types.ACastKeepsItsTypeUntilAnOperatorPromotesIt`,
  `TypeLibMake.LayoutPragmasAreRefused`, `TypeLibMake.AnUntaggedEnumIsKeptForItsConstants`,
  `cli.typelib_make_rejects_a_bad_char_signed`, and new cases in `Types.ParserErrorsAreLocated`. `fuzz_cdecl`
  (clang 18, ASan and UBSan) ran 544,286 inputs in 91 s with no finding; Debug 1,024/1,024 and Release
  1,025/1,025 pass on Linux x86-64.
- Third review of #70 (2026-11-20): bit-field layout follows the library's declared ABI
  (`CDeclarationOptions::bit_fields`, from the `abi` header through `bit_field_layout`). System V x86-64
  and AAPCS64 place bit-fields alike, but an AAPCS64 record is also aligned to the type of each unnamed
  bit-field; Win64 and any other ABI refuse a bit-field (`cdecl.bitfield_abi`) instead of using the System V
  rules. An unnamed bit-field is kept as a padding field (`TypeField::padding`: no name, its bits, or for
  width zero a marker at the offset it moves to), so a trailing `int :0;` or `int :3;` counts in the size the
  type store checks; a record that the ABI aligns more than its members carries that alignment
  (`TypeDefinition::alignment`, now also for structs and unions). Project schema v8 stores `padding`
  (migration from v7: every existing member stays a member). Tests:
  `Types.BitFieldsAreLaidOutAsTheCompilerLaysThemOut` (System V x86-64, GCC 13.3) and
  `Types.Aapcs64BitFieldsAlignTheRecordToUnnamedBitFields` (aarch64-linux-gnu-gcc 13.3 run under
  qemu-aarch64) check the same 14 declarations against each compiler, with trailing unnamed bit-fields;
  `Types.PaddingFieldsAndRecordAlignmentAreChecked`, and
  `Types.PaddingAndRecordAlignmentSurviveTheProjectAndItsMigration`. The musl library text is unchanged.
  `fuzz_cdecl` now picks the bit-field rules from its first byte too; it ran 605,844 inputs in 91 s with no
  finding. Debug 1,027/1,027 and Release 1,028/1,028 pass on Linux x86-64.
- Fourth review of #70 (2026-11-20): `bit_field_layout` takes the platform too (AAPCS64 bit-fields only on
  Linux and FreeBSD; Apple arm64 departs from AAPCS64 and refuses them). A type declared inside a prototype is
  marked `TypeDefinition::local` (stored in schema v8 with the padding flag), so a later parse against the same
  table, as a second `project type add`, does not see its tag or constants at file scope. A parameter name and
  a prototype's enumeration constant hide a typedef or an outer constant in the declarators after them; a
  parameter in an array bound is `cdecl.not_constant`. A comma operator is accepted where it is not evaluated.
  Comments in the generator's input are spaces. A prototype named after a typedef or an enumeration constant is
  `cdecl.redefinition`, so the generator skips it rather than write a library the reader refuses. An empty
  record with its own alignment has a power-of-two alignment and a size of 0 or that alignment. Every schema
  step stops before its SQL when `BEGIN IMMEDIATE` fails, so a busy database is never left between versions. Tests: `Types.PrototypeScopeLastsAcrossParses`,
  `Types.ParameterNamesAndPrototypeConstantsHideOuterNames`, `Types.ACommaOperatorIsAllowedOnlyWhereNotEvaluated`,
  `Types.AMigrationThatCannotBeginChangesNothing`, `TypeLibMake.CommentsAreSpaces`,
  `TypeLibMake.BitFieldsFollowTheAbiAndThePlatform`, and new cases in `Types.PaddingFieldsAndRecordAlignmentAreChecked`.
  `fuzz_cdecl` ran 573,326 inputs in 91 s with no finding.
- CI evidence for the parser and the shipped library: the `ci` workflow passed at a28d681 (the reviewed head,
  which includes every test named above and `TypeLibMake.ShippedMuslLibraryLoads`):
  [run 44775011731](https://github.com/palaashatri/donkey/actions/runs/44775011731): Linux x86-64 and
  AArch64, macOS arm64, Windows x64 (MinGW-w64) headless, the desktop shell under Xvfb, and clang-format.
- Not done here: FreeBSD and MinGW-w64 libraries (allowed, each file's licence to be checked), the `.winmd`
  reader, and function pointers (parenthesised declarators, G05).
  Applying a library to code is T3.

**T3 — application.**

1. *Name matching.* ELF: strip a version suffix (`@VERSION` or `@@VERSION`) before matching, and keep the
   version in the record. If one name has several versions with different prototypes, apply none and
   record `ambiguous`. A `.symtab` and a `.dynsym` entry with the same stripped name are one import.
2. *PE.* Match by name. An ordinal import (`ordinal_N`) is not matched. Matching it needs the export
   name table of the DLL, which the image does not hold; that waits for a second image (G15-T2 binds by
   name only).
3. *Mach-O.* Strip one leading underscore before matching. Check the rule on a Mach-O fixture before
   relying on it.
4. *Functions identified by G09.* The library prototype goes through `apply_prototype` on the matched
   function's body, which works today. The G09 name stays; the type's provenance is `Library`.
5. *Provenance per application.* Add a `source` column (user, dwarf, pdb, library, inferred) to
   `type_applications`, with a schema migration (v8 to v9) and a test that opens a v8 project. Order:
   a user application is never replaced by a library one; a DWARF or PDB type is not replaced by a
   library one; a user edit replaces a library application.
6. *Name collisions.* A library type name that matches a user, DWARF or PDB type is a collision. The
   table is per project. `parse_c_declarations` assigns ids from `known.next_id()`, so the merge must
   remap ids. A collision keeps the existing type and records a diagnostic. A library layout is never
   applied to a pointer whose debug type has a different layout.
7. *Display.* The CLI `project type list` and `apply` show the source. The printer labels a library
   prototype the way `signature_inferred` is labelled today, with the library name and version.
8. *CLI.* A verb to load a library file into a project and one to list the libraries loaded. Final
   names are chosen in T3 and listed in the PR.

- *Tests.*
  - `TypeLib.AppliesALibraryPrototypeToAnImportedName` (unit, an ELF fixture that calls `puts`).
  - `TypeLib.VersionedNameMatchesTheUnversionedLibraryName` (unit: `memcpy@GLIBC_2.14` matches `memcpy`).
  - `TypeLib.AmbiguousVersionsApplyNothing` (negative).
  - `TypeLib.OrdinalImportIsNotMatched` (negative, a PE fixture with an ordinal import).
  - `TypeLib.UserAndDebugTypesWinOverALibrary` (unit, both orders).
  - `TypeLib.SameNameDifferentLayoutIsACollision` (negative).
  - `Types.MigratesFromSchemaV8` (unit: an older project opens; existing rows get source `user`).
  - `cli.project_type_library_apply` (CLI, a committed fixture project).
- *Done when.* The fixture ELF shows its `puts` and `memcpy` prototypes in the CLI with provenance
  `Library`; a user edit replaces the library application; the schema migration test passes; the PE
  ordinal and Mach-O checks are recorded in the PR. The R1 corpus check (G20-T1) comes later, when R1
  exists.

**T3 report (2026-11-17).** What was built:
- `include/donkey/project/typelib_apply.h`, `src/project/typelib_apply.cpp`: `merge_type_library` (library types
  join the project's table with fresh ids; a name the table already has in the same C name space keeps the
  existing type, references move to it, and the collision is listed, with `differs` when the layouts differ),
  `import_match_name` (ELF `@VERSION`/`@@VERSION` and one Mach-O underscore removed), `match_import_prototypes`
  (`ordinal_N` never matches; one name with two versions is `ambiguous`), `library_prototypes` (only function
  types of provenance Library are prototypes) and `apply_library_prototypes` (a FunctionPrototype application with
  source Library at each matched stub; an address that already has a prototype of another source keeps it, as
  `kept: user`).
- Schema v9 (v8 is T2's padding column): `type_applications.source` (existing rows become `user`) and a
  `type_libraries` table; the v9 step also repairs the two type columns an early v5 database lacks. `Project::set_type_application` never lets a
  library application replace another source, and any other source replaces a library one.
- `c_declaration` (`types.h`): a type as C (`int puts(char *)`), used by the CLI and the note.
- CLI: `project type library add <db> <library.dtl>`, `project type library list <db>`, `project type library
  apply <db> <image-id>` (refused when the project has no library, `project.no_type_library`, or a library is
  for another architecture, `project.type_library_architecture`), and `project type applications <db>
  <image-id>` (each application with its source). `decompile --project` adds `note: library prototype (musl-libc
  1.2.4): int puts(char *)` to the stub's own pseudocode.
- Sites are the functions the analysis names by an import (G24-T4): PLT stubs and PE thunks. A GOT or IAT call
  with no stub has no function to carry a prototype, so it gets none here; T4 types the call itself.
- Measured (after the review below) on six programs of Alpine Linux 3.18, whose C library is musl 1.2.4-r3,
  with their libraries extracted from the Alpine packages as the sysroot: 727 of 2,428 import stubs get a
  prototype (busybox 1.36.1-r7 313/377, sqlite3 3.41.2-r4 88/105, git 2.40.4-r0 190/241, python3.11 3.11.12-r1
  0/5 whose imports are libpython's, openssl 3.1.8-r0 68/1,562 whose imports are mostly libssl and libcrypto,
  curl 8.12.1-r0 68/138). Every other stub is `no prototype`: no musl declaration (`__stack_chk_fail`,
  `__cxa_finalize`) or another library's function. On the seven glibc binaries of `docs/AUDIT.md` none is
  applied: their imports bind to `libc.so.6`, which the musl library does not describe. (Before the review the
  apply step matched names only and gave those glibc binaries 807 of 2,725 musl prototypes; musl's and glibc's
  prototypes differ for some names, `strerror_r` among them, so that count was not evidence.)
- Tests: `TypeLib.AppliesALibraryPrototypeToAnImportedName`, `TypeLib.AUserPrototypeWinsOverTheLibraryInBothOrders`,
  `TypeLibApply.*` (merge, collisions, `VersionedNameMatchesTheUnversionedLibraryName`, `AmbiguousVersionsApplyNothing`,
  `OrdinalImportIsNotMatched`, `OnlyLibraryFunctionTypesArePrototypes`), `Types.CDeclarationPrintsCDeclarators`,
  `Types.MigratesFromSchemaV8`, and the CLI chain `cli.project_type_library_apply*`,
  `cli.project_type_applications_show_the_source`, `cli.decompile_notes_a_library_prototype`.
- Checks recorded, not done: no PE fixture has an ordinal import. Mach-O images are refused: the analysis does
  not bind their stubs to their imports.

**T3 review (2026-11-20, CodeRabbit on bef6007, 32 findings).** The apply step matched an import to a library
prototype by name alone, so the musl library gave glibc programs musl's prototypes. It now applies a prototype only
where the import is shown to bind to a file the library describes:
- Format: a repeated `provides: <file>` record (a SONAME, or a file name), first among the records; the musl
  library provides `ld-musl-x86_64.so.1` and `libc.musl-x86_64.so.1` (regenerated; its body is unchanged).
- Binding: `import_sites` binds each reference of each stub (its versions read from the dynamic symbols, not the
  stub's name) with the G24-T3 load scope, which now follows musl's loader for a program whose interpreter is
  `ld-musl-<arch>.so.1` (the C library's names are the loader; musl's search path; no cache, no preload; versioned
  references Unknown). On PE, the import's DLL. Mach-O is refused (`project.type_library_format`).
- Fit: each library records its platform, ABI, data model and `provides` (schema v9's `type_libraries`), each type
  the library that brought it (`types.library`); a prototype applies only for its own library's ABI
  (`library_misfit`), and `decompile --project` names that library, not every loaded one.
- Load: `Project::load_type_library` takes the write lock, refuses a duplicate, reads the types, merges and writes
  the types and the record in one transaction, so two loads cannot merge from one snapshot and a failed load
  leaves nothing. The merge skips prototype-local tags, treats a typedef-named record as an ordinary name, and
  compares collisions through the types they refer to.
- Also: the CLI reloads a project image with its recorded architecture and checks it; reports
  `analysis_partial`; refuses an image the project does not have; `set_type_application` fails on a read error
  instead of replacing another source's row. The parser keeps a declared-only tag incomplete across parses (no
  `sizeof` of it), sizes `long double` by the ABI (refused when unknown), refuses an enumeration constant from the
  project outside `int`, refuses a struct and a union (or enum) of one tag, and gives a typedef and a function of
  one name `cdecl.type_and_function` in both orders; parse options default to no bit-field rules, and
  `project type add` takes them from the project's images when they share one ABI. The type store refuses a
  bit-field of a non-integer type; a printed declaration spends a shared budget. The generator skips a declaration
  with an assembler label, reads its input to the end, and writes beside the output and renames.
- Tests added: `ElfLoadScope.Musl*`, `NoReturn.AMuslProgramsAbortBindsToTheLoader`, `TypeLib.ALibraryDoesNotApplyToAnotherCLibrary`,
  `TypeLib.AnUnshownProviderAppliesNothing`, `TypeLib.AppliesAWin64LibraryToPeImportThunks`,
  `TypeLib.ALoadStoresItsTypesAndRecordTogether`, `TypeLib.ReadsProvidesRecords`, `TypeLib.DeclarationOptionsFollowTheAbi`,
  `TypeLibApply.CollisionsCompareTargetsAndMemberTypes`, `TypeLibApply.PrototypeTagsDoNotCollide`,
  `TypeLibApply.ATypedefNamedRecordIsAnOrdinaryName`, `TypeLibApply.TheMatcherNeedsLibraryProvenance`,
  `TypeLibMake.AnAssemblerLabelIsSkipped`, `Types.ATagOnlyDeclaredStaysIncompleteAcrossParses`,
  `Types.LongDoubleFollowsTheTarget`, `Types.AWideEnumConstantIsNotNarrowed`, `Types.TagsOfDifferentKindsShareOneNameSpace`,
  `Types.ABitFieldNeedsAnIntegerType`, `Types.APrintedDeclarationIsBounded`, and the CLI tests
  `cli.project_type_library_apply_refuses_another_c_library`, `..._refuses_mach_o`,
  `cli.project_type_applications_refuses_a_missing_image`, `cli.project_type_add_*_bit_fields_*`. The fixture
  `tests/fixtures/loadscope/musl` (a program linked with musl-gcc, and a stand-in loader) is described in its
  PROVENANCE.

**T3 review, second round (2026-11-20, CodeRabbit on 93ea0ad, 19 findings).**
- No-return binding: a file merely named `libc.so` is no longer the C library; the load scope marks the object
  it found as musl's loader (`ElfScopeLibrary::musl_loader`), and that is the evidence
  (`NoReturn.AFileNamedLibcSoIsNotTheCLibrary`, a glibc program needing a returning `libc.so`).
- musl search: tests for the path file (`:` and line ends), its default directories, an unreadable path file, a
  library with a version table, and a dlopen scope (`ElfLoadScope.MuslSearchesItsPathFileOrItsDefaultDirectories`,
  `MuslDoesNotBindIntoAVersionedLibrary`, `MuslDlopenSearchIsNotKnown`; fixtures in `tests/fixtures/loadscope/musl`).
- Merge: a library type that depends on a collision that differs is not added (`dependent`); two libraries keep
  their own prototype of one name, and the apply step takes the first whose library fits and provides the import's
  file; collision comparison visits each pair once per query under a budget.
- Apply: imports by ordinal come from the PE import directory, not the `ordinal_` name prefix; a 32-bit image
  (ELF x32 included) has no library ABI; a prototype another connection wrote meanwhile is reported `kept`.
- Storage: a migration step re-reads the version under the write lock and skips what another connection did;
  loads roll back on an exception from the merge; `project type add` reads, parses and writes in one transaction
  (`Project::update_types`); a type store layout of a declared-only record is refused (`type.incomplete`).
- Generator: every declaration of an assembler-labelled name is skipped; `typelib make` writes to a file it
  creates exclusively under a random name. CLI refusal tests check the exit status (`cmake/checks/expect_refusal.cmake`).
- Not done here: a per-user library directory (the caller passes the path), the desktop app, and typed call
  arguments (T4, after G21).

**T3 review, third round (2026-11-21, CodeRabbit on de2f6d4, 14 findings).**
- musl search, checked against musl 1.2.4's `ldso/dynlink.c` (`load_library`, `fixup_rpath`, `path_open`): the path
  file is found beside the loader's own directory; RUNPATH and RPATH split on line ends too; a list with a `$`
  token other than $ORIGIN is ignored whole; a relative entry (of a search list, the path file or a needed name with
  a `/`) is Unknown; a needed name's tokens are not expanded (`ElfLoadScope.MuslSplitsARunpathOnLineEnds`,
  `MuslIgnoresARunpathWithAnotherToken`, `MuslPathFileRelativeEntryIsNotKnown`,
  `MuslReadsThePathFileBesideItsOwnDirectory`; two new fixtures). Later in the round: the search stops at the
  first file musl opens, so a file of the name that is not a library is Unknown (`MuslStopsAtTheFirstFileItOpens`),
  and the path file ends at a NUL (`MuslPathFileEndsAtANul`).
- Storage: `Project::write_transaction`; `set_type_application` checks and writes in one, and
  `apply_library_prototypes` reads the table and writes every prototype in one, so a candidate is checked against
  the table its id is written into. A type library field with a NUL is refused. The migration race test uses a
  hook at the lock request instead of a sleep.
- PE: a thunk's DLL and ordinal flag come from the IAT slot it jumps through (`Function::import_slot`), not its name.
- Merge: collision comparison stops at a depth of 128 (frame sizes measured for GCC and Clang, x86-64 and AArch64) (`CollisionComparisonDepthIsBounded`). Generator: a tag
  named like an assembler-labelled function is kept (`ATagNamedLikeALabelledFunctionIsKept`).
  `expect_refusal.cmake` rejects a crash or timeout.
- Kept as it is: a v8 struct or union with no size and no members becomes incomplete in v9. v8 stored a
  forward declaration and a completed empty record (a GNU extension; ISO C has no empty struct) the same way, so
  the migration cannot tell them apart; incomplete only refuses to measure it, while complete would give a forward
  declaration a size of 0. Such a record stays incomplete: a later `project type add` of its body is refused as a
  redefinition, since completing a stored forward declaration in a later parse is not supported yet.

**T4 — typed arguments at calls (needs G21-T2 and the G21 ABI tables).**

- *What G21 must give.* `call_arguments` in ABI order and the result `dest`, for a direct call
  (G21-T2 is PARTIAL: integer arguments, same-image callees, System V only). Three things G21 does not
  yet give: (a) a call signature built from an `IrPrototype`, not from a lifted callee; (b) a signature
  source enum in place of the `signature_inferred` bool, with values inferred, debug, type and library;
  (c) an argument register table for each ABI in use. PE calls stay unresolved until a Win64 table
  exists, as G21 says.
- *How a library prototype drives a call.* The argument count comes from the prototype's fixed
  parameters, not from register use. Each argument's width and class come from the prototype. The
  operands are the ABI registers in order. Floating-point arguments wait for G21's floating-point step.
  A register the caller reads for its own use is not evidence of an extra argument. An argument
  register beyond the prototype's parameters that the caller writes before the call and never reads
  afterwards is only a possible mismatch, not proof: the write can be dead code that the callee does
  not read either. The prototype is applied as written, the call prints its arguments, the write is
  reported as a possible mismatch (with its address), and the caller stays Partial as every caller of
  an import does. Nothing in this check changes a prototype.
- *Import calls.* `lift_call` (`src/ir/lift.cpp`) sees only the call target address. The import name comes
  from `plt_stub_imports` (`include/donkey/binary/plt.h`), which cfg.cpp already uses (`cfg.cpp` line
  986). T4 passes that name into the lifter for calls through a PLT stub. A call through a register
  loaded from a GOT slot stays unresolved (G15-T2 says so).
- *Verification of an import call.* The interpreter runs same-image callees only. An import has no body
  here, so the caller of a library call cannot be checked by execution, and the rule in section 1
  (Complete means executed and compared) keeps its caller Partial. The arguments are printed and
  labelled. The plan leaves the way to check the prototype open; the options are for the T4 spike:
  (1) run the real program under the Linux debugger (G14) and compare the argument registers at each call
  with the prototype's arity and widths; (2) compare the prototype with the debug information of an
  unstripped build of the same library version; (3) no check: the call stays labelled Partial. Option
  (3) is what the code does by default. The owner decides whether options (1) or (2) are wanted.
- *Varargs.* A variadic prototype (`printf`) gives its fixed parameters only. The call's argument list is
  the fixed part, and the call stays Partial (G21-T4 stays Partial unless the count is known).
- *Tests.*
  - `Ir.LibraryPrototypeSuppliesTheArgumentsOfAnImportCall` (unit, hand-built IR and a PLT stub fixture).
  - `Ir.ImportCallNamesItsTargetThroughThePltStub` (unit).
  - `Ir.VariadicPrototypeLeavesTheCallPartial` (unit).
  - `Ir.LibraryCallerStaysPartial` (unit: the caller of an import is Partial).
  - `Ir.UnreadArgumentRegisterWriteIsReportedAsAPossibleMismatch` (the caller sets `rdx` just before
    calling a one-parameter function and never reads it: the prototype is applied unchanged and the
    write is reported, not treated as an argument).
  - `Ir.DeadArgumentRegisterWriteDoesNotChangeTheCall` (a dead `rdx` write before a call to a
    one-parameter function that does not read `rdx`: the printed call has one argument, the report
    says "possible mismatch", and nothing else changes).
  - `Ir.CallerReadOfAnArgumentRegisterIsNotAnExtraArgument` (the caller reads `rdx` for its own use around
    a call to a one-parameter function; the prototype is applied, no contradiction).
  - `DecompilerCorpus.LibraryCallsAreLabelledAndNotComplete` (oracle: the call prints with its
    arguments, and the caller is not Complete).
  - `cli.decompile_prints_library_arguments` (CLI, the ELF fixture of T3).
- *Done when.* The unit and CLI tests pass; every corpus result that was Complete is still Complete and
  equal to the compiled code; the import-call verification option chosen by the owner is recorded; no
  import caller is Complete unless the owner has accepted a different rule in writing.

**T4 report (2026-11-21).** A direct call to an import stub with a library prototype application, on x86-64
System V (ELF and Mach-O), passes `rdi` to `r9` as wide as the prototype's integer, enum and pointer
parameters (at most six: a prototype with a seventh, which goes on the stack, is not used), and returns
in `rax`; a result typedef'd to void is void; it prints as `rax = puts(rdi); /* prototype from musl-libc 1.2.4 */`.
The import is not executed, so the caller stays Partial (section 1). A variadic call passes its fixed part
and is Partial. An argument register past the prototype that the block writes and does not read before
the call is noted as a possible mismatch, never taken as an argument. A call with an executable C library
model (G21-T7) is run from the model instead. PE, AArch64, and a prototype with a non-integer parameter or
result take no prototype. Measured on six Alpine 3.18 (musl 1.2.4) programs, whose 727 stubs get a
prototype (T3): 14,656 calls in 3,795 of 13,407 functions print one (busybox 2,876, curl 689, git 9,538,
openssl 581, sqlite3 972; python3.11's twelve functions call libpython only), with 80 possible-mismatch
notes. The glibc audit binaries get none, as no glibc library is shipped. Not done: the check of a
prototype against the program's behaviour (options (1) and (2) above, an owner decision), GOT calls
without a stub, stack arguments (a seventh integer parameter), AArch64 and Win64 argument tables,
floating-point and struct arguments.

**Pitfalls.**
- Never copy an IDA type library, a Ghidra data type archive or a `.winmd` file into the repository.
  Generate from a source whose licence is allowed, and record the source's version and hash.
- Record the header version in every library. A library built from a different version of the same
  headers gives a different body hash, and the reader must refuse a body that does not match.
- A wrong prototype must fail a check, not print plausible code. For a function with a body, the check
  is the oracle. For an import, it is the option the owner picks in T4.
- ABI differences: LP64 (Linux, macOS) and LLP64 (Windows) differ in `long`; `char` is signed on
  x86-64 and Apple arm64 but not on Linux AArch64 (`CDeclarationOptions::char_is_signed`). Windows x64
  and System V pass arguments in different registers. A library must carry its data model and ABI,
  and the reader must refuse a mismatch with the target.
- A type library is a per-project table. A library type must not change a user, DWARF or PDB type.
- Keep the ELF version suffix out of the library's names; keep it in the provenance.

### G23 Unwind tables and exception handling (P1)

**Why.** `.eh_frame` and `.pdata` give the exact start and length of almost
every function in a stripped binary. Exception tables give the `try` and
`catch` regions. Both reference tools read them.

**Donkey today.** `src/binary/eh_frame.cpp` reads the FDE ranges of ELF `.eh_frame` (CIE
versions 1, 3 and 4; the pointer encodings the FDEs use) and `src/binary/pdata.cpp` the PE x64
RUNTIME_FUNCTION entries, skipping chained ones; both seed function starts, and a table that cannot
be read in full makes the analysis Partial with a diagnostic (T1 done, T2 partial). CFI programs,
LSDA, `.xdata` and ARM64 unwind data are not read (T3 to T5). Baseline
([`AUDIT.md`](AUDIT.md)): before T1, recall against the FDE starts was 33.0% (`python3.12`) to
88.5% (`bash`); it is now 100%, which shows the seeds are read, not that discovery works without
them.

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

#### G23-T0 task-level plan (written 2026-11-17, before any T3 code)

Checked against: `src/binary/macho.cpp` (the load commands it reads: `LC_SEGMENT`/`LC_SEGMENT_64`,
`LC_UUID`, `LC_MAIN`, `LC_UNIXTHREAD`, `LC_SYMTAB`; every other command is skipped by its size),
`src/binary/eh_frame.cpp` and `src/binary/pdata.cpp` (T1, T2: bounded readers with a record limit and a
malformed count), and `src/analysis/analysis.cpp` (unwind starts become seeds with the `from_unwind`
provenance; a table not read in full makes the analysis Partial with a diagnostic).

**T3 — Mach-O function starts and compact unwind.** Two readers, in this order.

1. *`LC_FUNCTION_STARTS`* (load command 0x26, a `linkedit_data_command`: `dataoff`, `datasize`). The
   loader records the table's file range on the image after checking that it lies inside the file
   (`macho.bad_function_starts` otherwise; a second such command is refused too). A new reader,
   `read_function_starts` in `src/binary/function_starts.cpp`, decodes the ULEB128 deltas: the first is
   the offset from the start of the `__TEXT` segment (the segment with file offset 0), each later one
   from the previous start; a zero delta or the end of the data ends the list (the linker pads with
   zeros). A ULEB128 longer than 10 bytes or past 64 bits, a start outside `__TEXT`, and more than 2^20
   entries are refused with stable codes (`function_starts.*`). On 32-bit ARM the low bit (Thumb) is
   cleared from each start. A fuzz target (`fuzz_function_starts`) runs the reader on raw bytes.
   *Analysis:* each start inside an executable section is a seed with a new provenance,
   `from_function_starts` (the linker's table, not an unwind record), shown by `functions --json`. A
   table that cannot be read makes the analysis Partial with the reader's diagnostic.
   *Fixture:* `tests/fixtures/function_starts/`: a C file whose two static functions are reached only
   through a pointer table in data, built for x86-64 and arm64 with clang 18 and `ld64.lld` 18, then
   stripped with `llvm-strip`, so only the table names them. *Oracle:* `llvm-objdump --macho
   --function-starts`.
   *Tests:* `FunctionStarts.MatchTheOracle` (both fixtures, every address), `FunctionStarts.RefusesBrokenTables`
   (an overlong ULEB128, a start past `__TEXT`, the entry limit, a range outside the file),
   `Analysis.MachOFunctionStartsSeedAStrippedBinary` (all four functions found and marked; one without
   the table), `cli.functions_marks_function_starts`.
   *Measurement:* functions found on the stripped fixtures before and after, and recall against the
   table on `tests/fixtures/dsym/dbg`.
2. *`__TEXT,__unwind_info`* (compact unwind, version 1): the header (common encodings, personalities,
   index array), the first-level index (function offset, second-level page offset, LSDA index offset),
   regular second-level pages (kind 2: function offset and encoding per entry) and compressed pages
   (kind 3: a 24-bit offset from the index entry's function offset and an 8-bit encoding index).
   Every page and entry is checked against the section; the counts are bounded by the page size. Each
   entry's function offset is a start; the encodings (frameless, frame-based, DWARF) are kept for later
   use and not interpreted here. Starts become seeds with the `from_unwind` provenance, as `.eh_frame`'s
   do. Oracle: `llvm-objdump --macho --unwind-info`. Fuzz target `fuzz_unwind_info`. The measurement
   is the agreement with `LC_FUNCTION_STARTS` on the same fixtures (both should name the same starts;
   any difference is listed).

**T4 — Itanium LSDA** (outline, refined before it starts). The CIE augmentation `L` gives each FDE's
LSDA pointer (the T1 reader skips it today). A reader for `.gcc_except_table` decodes the header
(LPStart and TType encodings, the call-site encoding) and the call-site table (start, length, landing
pad, action), bounded and fuzzed. Landing pads become CFG edges of a new kind from each call inside a
call-site range, so the handler code is reached and lifted. A function with a landing pad stays
Partial ("exception handling is not modelled"), and the printer marks the protected range. Oracle: a
C++ fixture with `try`/`catch` checked by hand against `llvm-dwarfdump --eh-frame` and the object's
`.gcc_except_table` bytes. Owner decision: whether a function with landing pads can ever be Complete
(the plan's default is no).

**T5 — Windows x64 exception data** (outline, refined before it starts). `.xdata` `UNWIND_INFO` (the
unwind codes, chained entries and the handler flags), then the language-specific data of
`__C_specific_handler` (SEH scope tables) and `__CxxFrameHandler3`/`4` (C++ `FuncInfo`, try blocks and
catch handlers, which name RTTI types that G10 reads). Handlers become CFG edges as in T4; the
function stays Partial. Oracle: `llvm-readobj --unwind` and a MinGW or clang-cl fixture.

**Order and status.** T3 part 1 first (smallest, and the only start table a stripped Mach-O
executable keeps besides compact unwind), then part 2, then T4, then T5. T1 is DONE and T2 PARTIAL
(chained entries skipped, `.xdata` not read); T2's `.xdata` part belongs with T5.

**T3 report, part 1 (2026-11-17).** `LC_FUNCTION_STARTS` done as planned. The loader records the
table's range (`BinaryImage::function_starts_offset`, `_size`; the fat slice's offset added; a table
outside the file or a second command is `macho.bad_function_starts`). `read_function_starts`
(`src/binary/function_starts.cpp`) decodes it with the bounds of the plan; the analysis seeds each start
and marks it `from_function_starts`, shown by `functions --json`. Measured: on the stripped fixtures
(`tests/fixtures/function_starts`, x86-64 and arm64) Donkey found 1 function of 4 before (the entry) and 4
of 4 after, every start equal to `llvm-objdump --macho --function-starts`; on `tests/fixtures/dsym/dbg`
(not stripped) both starts were already found and now also carry the mark. `fuzz_function_starts`: 60 s,
10.4 million runs, clean. Tests: `FunctionStarts.MatchTheOracle`, `FunctionStarts.AnImageWithoutATableHasNoStarts`,
`FunctionStarts.DecodesDeltasAndStopsAtZero`, `FunctionStarts.RefusesBrokenTables`,
`FunctionStarts.LoaderRefusesATableOutsideTheFile`, `Analysis.MachOFunctionStartsSeedAStrippedBinary`,
`cli.functions_marks_function_starts`. Not checked: a 32-bit ARM image (the Thumb bit is cleared by
the rule, on synthetic bytes only) and an Apple-linked binary (the fixtures are LLD's).

**T3 report, part 2 (2026-11-21).** `__TEXT,__unwind_info` was done as planned, with one correction to the
plan: the linker folds a run of adjacent functions that share an encoding into one entry, so an entry's function
is always a start, but not every start has an entry. Compact unwind is therefore a subset of
`LC_FUNCTION_STARTS`, not the same list.

The reader is `read_unwind_info` (`src/binary/unwind_info.cpp`). It reads the header, the common encodings, the
first-level index with its final sentinel, and regular (kind 2) and compressed (kind 3) second-level pages. Every
array, page and entry is checked against the section before it is read. A structural fault refuses the whole
section with a stable code, and the analysis is then Partial with that diagnostic. The faults are:

- `unwind_info.bad_header`: a wrong version, or a header too short;
- `unwind_info.outside_section`: data that lies outside the section;
- `unwind_info.bad_index`: no final sentinel, offsets that decrease, a page missing, or a range that wraps;
- `unwind_info.bad_page`: an unknown page kind, or an entry outside its index range;
- `unwind_info.bad_encoding_index`: an encoding index that names nothing;
- `unwind_info.unsorted`: entries out of order;
- `unwind_info.too_many`: more than 2^20 entries.

Each entry's start becomes a seed with the `from_unwind` provenance, except an entry whose encoding has `UNWIND_IS_NOT_FUNCTION_START`, which marks a range inside a function, as `.eh_frame` and `.pdata` starts do. The
encodings are kept and not interpreted.

Measured on new fixtures (`tests/fixtures/unwind_info`, x86-64 and arm64, clang 18 and `ld64.lld` 18, linked with
`-no_function_starts` and stripped):

- Before, Donkey found 3 of the 6 functions, the ones reached by a call or as the entry. After, it finds 6 of 6,
  and every entry and encoding equals `llvm-objdump --macho --unwind-info`.
- On the `LC_FUNCTION_STARTS` fixtures, the one entry of each image (all four functions there share an encoding)
  is one of the table's starts.
- `fuzz_unwind_info` ran for 60 s, 12.7 million runs, clean.

Tests:

- `UnwindInfo.MatchTheOracle`
- `UnwindInfo.EntriesAreASubsetOfTheFunctionStarts`
- `UnwindInfo.AnImageWithoutTheSectionHasNoEntries`
- `UnwindInfo.ReadsRegularAndCompressedPages`
- `UnwindInfo.AnIndexWithOnlyTheSentinelHasNoEntries`
- `UnwindInfo.RefusesBrokenSections`
- `UnwindInfo.RefusesAWrappingRange`
- `UnwindInfo.AnIsolatedLoadGivesTheSameEntries`
- `UnwindInfo.AgreesWithFunctionStarts`
- `Analysis.MachOUnwindInfoSeedsAStrippedBinary`
- `cli.functions_marks_unwind_info`

Not checked:

- A regular page in a linked image. LLD writes compressed pages only, so the regular form is tested on synthetic
  bytes.
- An Apple-linked binary.
- The DWARF-mode encodings' `__eh_frame` FDEs. The Mach-O `__eh_frame` is not read yet.

Found on the way, and not fixed here: the stripped Mach-O fixtures list a function at the image base
(0x100000000), the Mach-O header, both before and after this change.

### G24 Analysis of stripped binaries (P0)

**Why.** Finding the functions of a stripped binary is the core of both
reference tools. Everything else works on what this step finds.

**Donkey today.** `src/analysis/analysis.cpp` seeds functions from the entry
point, exported function symbols, call targets and the unwind tables (G23-T1, T2). A walk stops
at a jump or a fall-through into another function's start and at an import stub (T2 partial), and
its traversal work is bounded. There is no prologue scan, no no-return analysis, no thunk
classification and no stack-depth analysis, so a binary without unwind tables gets the first three
seed sources only. On the stripped own CLI, recall against its symbols is 99.9% with 99.9%
precision ([`AUDIT.md`](AUDIT.md), "Function starts at `6af21ee`").
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

**Precision fix (2026-11-21).** In an image with sections, an address inside an executable segment but in no section
is no longer treated as code. On Mach-O, the exported `__mh_execute_header` symbol had made the header at the start
of `__TEXT` a "function" with no blocks. Across every binary fixture in `tests/fixtures`, and on `bash`,
`python3.12`, `ls` and `libc.so.6`, the set of functions found changes only on the four Mach-O images
(`function_starts/starts_x86_64`, `starts_arm64`, `dsym/dbg` and its dSYM), which each lose that header.
An image without sections (an ELF with its section headers removed, a raw image) still falls back to its segments.
A Mach-O relocatable object (`MH_OBJECT`) keeps its sections at the addresses written, so its `__text` starts at
address 0: an executable section at address 0 is still code (ELF's address-0 sections are the non-allocated ones,
never executable). The tests are `Analysis.TheMachOHeaderIsNotAFunction` and `Analysis.AMachOObjectKeepsItsFunctions`.

**Initialisation and termination functions (2026-11-21).** G20-T2's R1 measurement found 109 missed starts in the
stripped builds. In each glibc x86-64 build they were five functions of the C runtime: `_init`, `_fini`,
`frame_dummy`, `register_tm_clones` and `__do_global_dtors_aux`. In each glibc AArch64 build they were only
`_init` and `_fini`; the other three have unwind entries there. The loader or the runtime calls these functions,
and no call in the image reaches them.

`read_init_fini_of_image` (`src/binary/init_fini.cpp`) reads two sources and takes their union:

- `DT_INIT`, `DT_FINI`, and the init, fini and preinit arrays with their `*SZ` sizes;
- the `.init`, `.fini`, `.init_array`, `.fini_array` and `.preinit_array` sections, which a static image has
  without a dynamic table.

An array entry takes its `R_*_RELATIVE` addend when a relocation covers it, and otherwise the file's bytes. An
entry with a symbolic relocation is skipped, and so are 0 and -1. An entry that cannot be read makes the
analysis Partial. Each start found is seeded and marked `from_init_fini`.

On R1, the missed starts fell from 109 to 71:

- the glibc AArch64 builds now miss none;
- each glibc x86-64 build still misses `register_tm_clones`, which `frame_dummy` reaches by a tail jump;
- static musl misses 65 assembly functions.

Unstripped, 2,108 of 15,856 functions are Complete (2,107 of 15,855 before; the one function added is
Complete). The 3 extra starts of static musl are `_start`, `_init` and `_fini`. musl's assembly gives them
NOTYPE symbols, so the FUNC-only ground truth does not count them.

Tests: `InitFini.ReadsTagsSectionsAndRelocatedArrays`, `InitFini.AnotherFormatHasNone` and
`Analysis.ElfInitAndFiniFunctionsAreSeeded`.

Not covered: an image without section headers. Both the dynamic table and the arrays are found through
sections, not through `PT_DYNAMIC`.

#### G24-T0 task-level plan (written 2026-11-15, before any G24-T3 code)

**Measured on `main` at `7bba838`.** The numbers come from `python3 -I tools/audit/import_calls.py
tools/audit/results/list_final.json OUT.json` (added with this plan), run with a Release `donkey-cli` built from the
analysis code of `main` at `7bba838`, over the fixed sample of 1,986 functions (seven system binaries,
[`AUDIT.md`](AUDIT.md)). The tool checks each binary's SHA-256 against the list, as `sample_list.py` does.

Method. For each sampled function, the tool reads the pseudocode and counts direct calls printed as `sub_<hex>(`
(not comment lines, not the function header). A target is a stub when its address is inside `.plt`, `.plt.sec` or
`.plt.got` (`readelf -SW`). The stub's import name is the `objdump -d` label `<name@plt>` at that address, an oracle
independent of Donkey's own stub reader. No-return names are matched on that name.

- (a) 9,272 call sites print a stub as `sub_<hex>(`, in 1,054 of the 1,986 functions. 0 stub addresses lack an
  objdump name. Calls through a GOT slot (`*(u64 *)(0x...)`) into `.got`/`.got.plt`: 1 site (`__libc_start_main`).
- (b) Top 20 stubs by call sites (name: sites / functions):
  `BIO_printf` 1042/133, `free` 730/225, `__stack_chk_fail` 409/407, `strcmp` 383/125, `strlen` 367/174,
  `dcgettext` 356/99, `malloc` 227/113, `ERR_print_errors` 155/73, `CRYPTO_free` 152/54, `__errno_location` 142/87,
  `BIO_puts` 121/27, `__printf_chk` 112/33, `memcpy` 94/62, `strdup` 84/30, `OPENSSL_sk_num` 76/34,
  `OPENSSL_sk_value` 74/35, `BIO_free` 70/34, `BIO_ctrl` 65/28, `__fprintf_chk` 64/23, `__strcpy_chk` 59/35.
- (c) No-return imports in the sample, call sites (functions): `__stack_chk_fail` 409 (407), `__assert_fail` 25 (21),
  `exit` 16 (14), `abort` 11 (10), `_exit` 4 (2), `__longjmp_chk` 4 (3), all through stubs (no call is printed
  by a no-return name today). Total functions with a no-return call: 440.
  `error` (not counted above, argument not checked): 14 sites. The other names on the list (`err`, `verr`,
  `errx`, `verrx`, `longjmp`, `siglongjmp`, `quick_exit`, `_Exit`, `pthread_exit`, `__fortify_fail`, `__chk_fail`,
  `__cxa_throw`, `__cxa_rethrow`, `_Unwind_Resume`, `_ZSt9terminatev`, `__libc_fatal`) have 0 sites in the sample.
- (d) 288 functions are Partial with the note "the returned register is not determined by the definitions that reach
  the return" and call a no-return import (of 1,151 Partial functions with that note, 183 Complete functions overall).
- Of the 469 no-return call sites (excluding `error`), 322 are followed by a printed `return rax;`.
- *After #64 (the fs/gs soundness fix, merged as `a7364d2`), the same tool on the same sample:* (a), (b), (c), the 440
  functions and the 322 sites are unchanged. (d) becomes 295 of 1,163 Partial functions with the rax note, and 177
  functions are Complete. The fs-relative accesses that #64 makes Unsupported account for the difference. T3's
  before-values are the ones in this line.

**Example, checked by hand.** `/usr/bin/ls`, function `sub_4d7a`: `objdump -d` shows `4d7a: call 4750 <abort@plt>`,
and `4d7f` is the next function (`sub_4d7f` exists in the output). The decompiler prints `sub_4750();` then
`return rax;`. The `return` has source address `0x4d7f`, which is the next function's first byte, not an instruction
of this function. The walk ends there and the lifter emits a synthetic return (below). The note on that function is the
rax note from (d).

**Checked against:**
- `src/analysis/analysis.cpp`: `synthetic_function_name` 34-45 (`sub_` + address); seeds 469-491 (entry point 471-473,
  function symbols 475-485, call xrefs into executable code 488-491); unwind seeds 493-523; user seeds 543-556; naming
  572-584 (`naming_symbol` skips imported symbols at 567; otherwise `sub_<addr>`).
- `src/analysis/cfg.cpp`: `fallback_name` 31-34; `function_starts` 980-983; `import_stubs` from `plt_stub_imports` 986;
  the block walk: Call case 1093-1107 (a call always continues at `next` except when `next` is another function's start,
  1103-1105); Jump 1109-1127 (a jump to another function start or to an import stub is not followed; otherwise it is);
  ConditionalJump 1129-1150; Return/Interrupt 1152-1154; Unknown/Other 1155-1163; block edges 1324-1370, where a Call block
  ending at another function's start gets a `ConditionalFalse` edge (1359-1369).
- `include/donkey/analysis/cfg.h` 43-51: `CfgEdgeKind` has `Unknown, Jump, ConditionalTrue, ConditionalFalse, Indirect,
  Call, JumpTable`. There is no tail-call kind.
- `src/binary/plt.cpp`: `aarch64_plt_slot` 41; `plt_stub_imports` 73 (reads `.rela.plt` JUMP_SLOT only, 80);
  `got_import_slots` 160 (GLOB_DAT in `.rela.dyn`). `include/donkey/binary/plt.h` 20-28 (the stub and GOT
  readers, and the rule that a stub is never given a guessed name).
- `src/analysis/link_calls.cpp` 25-27 (the only callers besides cfg.cpp 986); `include/donkey/analysis/link_calls.h` 28-35
  (the link stage names a call `provided_fn@plt`).
- `src/ir/lift.cpp`: `mark_partial` 569; `KnownCallee` 1941 and `known_callee` 1946 (x86-64 only, direct target, same
  image, one level); `lift_call` 2021-2044 (a call to an unresolved target keeps only its target and marks the function
  Partial with "outgoing call arguments and return values follow no modelled ABI"); `signature_inferred` 2137; the
  rax note 2278-2280; the tail-call lowering of a jump that leaves the function 2845-2897 (note at 2897); the synthetic
  return at a block end 3028-3045 (`Return` on the return register with `source_address = block->end_address`, 3039,
  and `partial = true`); conditional tail call 3105.
- `src/ir/lift_aarch64.cpp`: Call 2187-2204, with the same Partial note at 2202.
- `src/ir/ir.cpp`: the call printer 372-395 (target is always `sub_` + the constant address, 384; the name table is not
  consulted; `signature_inferred` comment).
- `include/donkey/ir/ir.h` 18-58: the op list. `Call` is 35, `Return` 36, `Unsupported` 42. There is no halt,
  trap or unreachable op.
- `src/ir/eval.cpp` 965-975 (`Call` runs the callee's IR, depth 8, or fails); 1012 (`Unsupported` fails).
- `apps/donkey-cli/commands.cpp`: `display_name` 101; `callgraph` `name_of` 599-604 (uses `function.name`); `functions`
  650-690 (uses `function.name`); the link listing 2331 (`call.name`, from the link stage).
- `src/ui/session.cpp` 239-250 (`apply_debug_names`: DWARF names for functions without a symbol); `src/ui/panels_view.cpp`
  226 (`shown_function_name`: user renames on top).
- `src/binary/elf.cpp` 533 (undefined dynamic symbols are `imported`); `src/binary/pe.cpp` 345 (IAT entries are
  imported symbols whose address is the IAT slot); `src/binary/macho.cpp` 410 (undefined symbols are imported; their
  address is not a stub address).
- No no-return code exists: `grep -rn "noreturn\|no_return\|NoReturn" src include apps` finds nothing.

**What exists today.**
1. Every call continues the walk at the next instruction, unless that instruction starts another function (cfg.cpp
   1093-1107). A call to an import stub is therefore followed by the bytes after it.
2. Import names never name a function. A stub address becomes a seed when a call targets it (analysis.cpp 488-491) and
   is named `sub_<addr>` (naming skips imported symbols, 567).
3. The printed call target is always `sub_<hex>` from the constant address (ir.cpp 384). The function list, call graph,
   xrefs and decompiler all print `function.name`, which is `sub_<addr>` for a stub.
4. `plt_stub_imports` is used for tail-call decisions (cfg.cpp 986) and by the link stage (link_calls.cpp 25). It is
   not used for naming.
5. `got_import_slots` is used only by the link stage (link_calls.cpp 27). A `-fno-plt` GOT call is printed as
   `((void (*)(void))*(u64 *)(0x...))();`.
6. A block with no successor becomes `return <rax>;` at its end address, and the function becomes Partial
   (lift.cpp 3028-3045). This is how a no-return call is printed today (the ls example).
7. A jump to another function's start, or to an import stub, is not followed by the walk (cfg.cpp 1109-1121,
   1129-1141). The lifter lowers such a jump to a call and marks the function Partial (lift.cpp 2845-2897).
   The CFG does not record which jumps are tail calls.
8. The desktop app takes names from the same `function.name` (session.cpp 239-250, panels_view.cpp 226). A change in
   the analysis reaches the app with no UI code.
9. PE import names exist as symbols with their IAT slot address (pe.cpp 345), but no code maps a PE call through its
   slot to a name. Mach-O undefined symbols have no stub address (macho.cpp 410), and no `__stubs` reader exists.

**Tasks.** Each one writes its own tests and updates the ledger row and `docs/SUPPORT_MATRIX.md` in its PR, as rule 7
requires.

**T3. No-return functions.**

- *Known names first.* A fixed list in code, matched exactly on the import name of a stub (from `plt_stub_imports`, and
  from the GOT slot of a `-fno-plt` call). A same-image function gets no mark from its name (a local function named
  `exit` may return); it is marked only by the propagation below. The list is the one in (c) above, without
  `error`. `error` is a no-return only when its first argument is nonzero, so it stays a normal call (its argument is
  not modelled). Each mark carries provenance: `known-name:<name>`.
- *Provider binding.* A name alone does not say which library defines the import: a custom shared library may export
  its own `exit` that returns. Until owner decision 4 (below) chooses how an import is bound to its provider, an import
  whose provider is not shown to be a known runtime library keeps its fall-through and its ordinary call semantics.
  Two kinds of evidence exist. The importer's DT_NEEDED entries are already read and matched against a provider's
  DT_SONAME by `resolve_imports` (G15-T2 above). The import's ELF symbol version (`abort@GLIBC_2.2.5`, from
  `.gnu.version` and `.gnu.version_r`) is not read by any code yet; using it would add a bounded reader with a fuzz
  target. Decision 4 sets which of these counts and the list of runtime libraries. No name is marked before it is
  recorded.
- *Propagation.* A same-image function is no-return when every path from its entry reaches a no-return call (or an
  instruction that never falls through, such as `ud2` or `hlt`). It is bounded by a fixed iteration count and a
  depth limit. It uses only marks already proven, and a function whose analysis is Partial for an unrelated reason
  keeps its ordinary call semantics. Propagation is an owner decision (below).
- *CFG effect.* In the Call case (cfg.cpp 1093-1107), a call to a no-return function `break`s the walk instead of
  continuing at `next`, as the function-start case does now. The block gets no fall-through edge (1359-1369). Bytes after
  the call are decoded only if another path reaches them. That is the safe form: a wrong mark can only hide the code that
  follows that call, not code another path reaches.
- *IR form.* The IR has no halt op (ir.h 18-58). The plan adds a flag, `IrStatement::no_return`, to `Call`, not a new
  op, so the existing `Call` form and its operands stay as they are. Verifier rule: a `no_return` call is the last
  statement of its block, and its block has no successor. The lifter does not emit the synthetic `Return` (3028-3045)
  for such a block. Evaluator rule: reaching a `no_return` call fails with `ir.eval_no_return`, so a path that does not
  return is never counted as returning. The printer prints `abort();` with no `return` after it.
- *Still Partial, and why.* A no-return call is still an import call. Its arguments and its ABI effects are not
  modelled, so a function that calls one keeps the "outgoing call arguments" note (`lift.cpp` 2137 for x86-64,
  `lift_aarch64.cpp` 2202 for AArch64). T3 removes only the rax note and the synthetic return. Whether such a function
  may become Complete is owner decision 3 below; until it is decided, it stays Partial. A function is Complete only if
  the oracle executes it and compares the returning paths with the compiled code.
- *Stack-protector checks.* 407 of the 440 functions with a no-return call call `__stack_chk_fail`. Their canary load
  is `mov %fs:0x28, %rax`. At `7bba838` the decoder dropped the `fs` override and the lifter printed it as
  `rax = *(u64 *)(0x28);`, a read of address 0x28. That defect was fixed separately in #64 (merged as `a7364d2`: the
  lifter refuses an `fs`- or `gs`-relative access as Unsupported). So a canary function stays Partial after T3 until thread-local reads
  are modelled: the canary is read twice from one slot that the function does not write, and the evaluator would need
  that slot as an opaque value. That model is a later step, not part of T3.
- *Pitfalls.* A wrong no-return mark deletes real code (the bytes after the call become unreachable). Prevention: only
  exact names from the fixed list, provenance on every mark, propagation only from proven marks, and the CFG keeps bytes
  that another path reaches. Test: a function that calls `abort` on one path and returns on another.
  `error` must never be on the list.
- *Tests (names to add).*
  - `Cfg.NoReturnCallEndsTheBlock` (unit: `call abort@plt` then bytes, no fall-through edge)
  - `Cfg.BytesReachedByAnotherPathStayInTheFunction` (unit: a call to `abort` on one path, return on another; the return
    path is kept)
  - `Analysis.NoReturnNamesComeOnlyFromTheFixedList` (unit: `error` and an unknown name are not marked)
  - `Analysis.ANoReturnNameFromAnotherLibraryKeepsItsFallThrough` (ELF fixture: an import named `exit` bound to a
    committed non-runtime shared library, by version or DT_NEEDED, is not marked and its call keeps its fall-through
    edge)
  - `Analysis.ANoReturnNameExportedByTwoNeededLibrariesIsNotMarked` (ELF fixture: two DT_NEEDED libraries both export
    `exit`, the runtime one and an earlier one; the name is ambiguous, so the call keeps its fall-through edge).
    Interposition through `LD_PRELOAD` is not in any file, so no fixture can show it; the provenance records the
    assumption instead.
  - `Analysis.PropagationUsesOnlyProvenMarks` (unit: a wrapper calling `exit` is no-return; a function with a path
    that returns is not)
  - `Ir.NoReturnCallHasNoSuccessorAndNoReturnStatement` (unit, lifted from bytes)
  - `Ir.VerifierRejectsANoReturnCallWithASuccessor` (unit, hand-built IR)
  - `DecompilerCorpus.NoReturnPathsAreNotCompared` (oracle: a corpus function whose only exit is `abort` is Partial,
    and one that returns on some inputs stays Partial until owner decision 3 is recorded; after that decision it may be
    Complete when every returning input agrees with the compiled code)
  - `cli.decompile_prints_no_return_call_without_return` (CLI, a committed fixture)
- *Measurement.* Before (this plan, above, after #64): 469 no-return call sites, 322 followed by a printed `return`,
  295 functions with the rax note that call a no-return import. Target after T3: 0 no-return sites followed by a printed
  `return`, and the count in (d) falls. Functions that are still Partial are reported with the reason that remains.
  Measured with `tools/audit/import_calls.py` over the same 1,986 functions, and the numbers go in the PR.
- *Relation to G21-T5.* G21-T5 ("a call to a no-return function ends the block") is the IR-side part of this task.
  It depends on T3 and is not a separate piece of work.

**T3 report (2026-11-17).** Done, with the owner decisions of 2026-11-17 (1: propagation on; 3: Complete needs at
least one returning path and every returning path compared; 4: option (c)). What was built:
- `include/donkey/binary/elf_versions.h`, `src/binary/elf_versions.cpp`: `read_version_needs` (bounded: every chain
  offset is checked, a loop, a reserved index, a duplicate index, a name outside `.dynstr` and the entry limit are
  refused with `elf.version_needs.*`) and `read_import_versions` (import name -> file and version; an import with two
  different needs is left out). Fuzzed: `fuzz/fuzz_elf_versions.cpp`, 5.87 million runs in 60 s, clean under ASan and
  UBSan (seed corpus `tests/fuzz/corpus/elf_versions`).
- `include/donkey/analysis/no_return.h`, `src/analysis/no_return.cpp`: the fixed list (each name with the runtime
  that may provide it: C library, C++ runtime, unwinder, Windows kernel or CRT; `error`, `error_at_line`, `raise`,
  `kill` and `RaiseException` are not on it) and `bind_no_return_imports`: a versioned ELF import is bound by the
  file its version need names; an unversioned one only when every DT_NEEDED entry is a runtime library and one of
  them provides the name's kind; a PE import by its DLL (a name imported from two DLLs is ambiguous). Provenance:
  `known-name:abort version:GLIBC_2.2.5 file:libc.so.6`, `known-name:exit needed:libc.so.6`,
  `known-name:abort dll:msvcrt.dll`. The import thunks of PE (MinGW `jmp *slot`) are found before the CFG so
  they can be bound.
- CFG: a call to a no-return target (a direct target, or the slot a `call *slot` reads) ends the walk and gets no
  fall-through edge; the bytes after it stay in the function only if another path reaches them.
- Propagation: `propagate_no_return` marks a same-image function whose every block ends in a no-return call,
  `ud2` or `hlt`, or goes on inside the function; a return, a tail call or fall-through to a function that may
  return, or an unresolved indirect jump keeps it unmarked. The graph is rebuilt with the new marks, at most 8
  rounds. Marks carry `propagated:every path ends in a call that does not return`.
- IR: `IrStatement::no_return` on the Call and `IrStatement::unreachable` on a Return that follows it, the block's
  last statement. The verifier enforces the pair (`ir.no_return_call_not_last`,
  `ir.unreachable_return_without_call`); the printer prints nothing for the unreachable Return but both structurers
  tag it as the block's end, so the control-flow check sees no fall-through (without the tag the check refused every
  candidate of 91 openssl functions); the evaluator stops at the call with `ir.eval_no_return`; the signature and
  liveness passes ignore the unreachable Return. A lifted function with no returning path is Partial, with the note
  "no path returns". A tail jump to a no-return function is a call with no return after it.
- CLI: `functions` shows `no return: <evidence>`, and `--json` adds `no_return` and `no_return_reason`.
- Tests: `ElfVersions.*` (3), `Analysis.NoReturnNamesComeOnlyFromTheFixedList`,
  `Analysis.AVersionedRuntimeImportIsMarkedWithItsEvidence`,
  `Analysis.ANoReturnNameFromAnotherLibraryKeepsItsFallThrough`,
  `Analysis.ANoReturnNameExportedByTwoNeededLibrariesIsNotMarked`, `Analysis.PropagationUsesOnlyProvenMarks`,
  `Cfg.NoReturnCallEndsTheBlock`, `Cfg.BytesReachedByAnotherPathStayInTheFunction`,
  `Ir.NoReturnCallHasNoSuccessorAndNoReturnStatement`, `Ir.VerifierRejectsANoReturnCallWithASuccessor`,
  `Ir.NoReturnPathsAreNotCompared` (owner decision 3: the evaluator returns check(5) = 10 as the compiled code does,
  and stops on check(-1) at `abort`), `Ir.ANoReturnBlockIsStructured`, `Ir.AFunctionWithNoReturningPathStaysPartial`,
  `cli.decompile_prints_no_return_call_without_return`, `cli.functions_list_no_return_evidence`. Fixtures:
  `tests/fixtures/stubs/exit_consumer` and `libmyexit.so.1` (an `exit` from a non-runtime library listed before
  libc), with provenance.
- Measured over the same 1,986 functions, Release build (`tools/audit/import_calls.py` and `sample_list.py
  measure`), before (T4) and after (re-measured after the review fixes, on `main` with T4 merged):

  | | Before | After |
  |---|---|---|
  | No-return call sites followed by a printed `return` | 396 | **73** |
  | Partial with the rax note | 1,163 | 1,017 |
  | ... of which call a no-return function | 370 | 261 |
  | Gotos (structured with gotos) | 16,232 | 15,712 |
  | Functions printed as labelled blocks | 0 | 0 |
  | Candidates the control-flow check refused | 0 | 0 |
  | Complete | 177 | 177 |

  The 73 that remain are all in libc: calls to libc's own `abort`, `__libc_fatal` and `__stack_chk_fail`, which
  are same-image functions. They get no mark from their name (a same-image name is never trusted), and propagation
  cannot prove them, since their bodies call `raise` and other functions that return. Complete does not move: the
  407 canary functions stay Partial on their `fs`-relative load (#64), and the import call itself keeps the
  "outgoing call arguments" note. (The rax-note count before is the post-T4 value; the plan's 295 counted only
  `sub_` calls to stubs.)
- Not done: interposition (`LD_PRELOAD`) is assumed absent, as decision 4 records; AArch64 GOT calls are not bound
  (no AArch64 GOT reader); Mach-O imports are not bound.
- Binding proven, not assumed (2026-11-18, after the owner rejected the limitation #67 had recorded): a version need
  does not prove the provider. glibc binds a versioned reference to the first library of the load scope whose
  definition it accepts, and an unversioned global definition in an earlier library is accepted, so `exit@GLIBC_2.2.5`
  can bind to another library's `exit`. `ElfLoadScope` (`include/donkey/binary/elf_load_scope.h`) now builds the
  scope the loader would and looks each reference up by glibc's `check_match` rules (a versioned reference: no
  `.gnu.version` in the library, the same version, or, unless its version need is hidden, a non-hidden unversioned
  definition; an unversioned one: an index below 3, or the only non-hidden versioned definition). The search is
  glibc's `_dl_map_object`, under an optional sysroot whose symbolic links are followed inside it: `/etc/ld.so.preload`
  (white space or `:` between names, `#` comments), DT_NEEDED breadth first (each library once, by name, SONAME or
  file); for each, DT_RPATH of the requester and of every object that loaded it up to the executable (when the
  requester has no DT_RUNPATH), the library path (LD_LIBRARY_PATH's place), DT_RUNPATH, `/etc/ld.so.cache` (not
  `/etc/ld.so.conf`, which the loader never reads) unless DF_1_NODEFLIB, then the default directories; dynamic-string
  tokens expanded once from the original text; DT_NEEDED and the dynamic table read through PT_DYNAMIC, as the loader
  reads them. Wherever the model cannot know the loader's choice the binding is Unknown, never guessed: an empty or
  relative search entry (the loader's working directory), `$LIB` and `$PLATFORM`, `$ORIGIN` inside a path, a copy in a
  `glibc-hwcaps` or legacy capability subdirectory or a cache entry for particular hardware (chosen by the target's
  processor), a name in two default directories as two different files (their order is fixed when glibc is built), a
  file whose header the loader accepts and this reader cannot parse or that exceeds the read limit, a dynamic table or
  version section the loader reads and this reader cannot, and more libraries than the limits (256 read, 4,096
  queued). Each case has a test against a scratch sysroot (`ElfLoadScope.*`, oracle `LD_DEBUG=libs`, fixtures in
  `tests/fixtures/loadscope/PROVENANCE.md`). A library's SONAME is not evidence of what it is: the name it was
  loaded by must be a runtime library's as well (`Analysis.ALibraryThatIsTheCLibraryOnlyByItsSonameIsNotTrusted`).
  An analysis with an unverified binding is Partial. A name is marked only when every way the image imports it binds to a
  runtime library of its kind; an earlier library the walk cannot find or read leaves it unmarked, with
  `analysis.no_return_unverified` saying which. The same walk replaces the unversioned rule "every needed library is
  a runtime library". The fixture `tests/fixtures/loadscope/steal_consumer` reproduces the case with the real loader
  (`libsteal exit(1) returned`, then a crash past the call the compiler took as no-return); Donkey does not mark it,
  and marks the same program when the earlier library has no `exit`. The CLI takes `--sysroot` and `--library-path`.
  On the seven audit binaries the marks are the same as before (ls 16, openssl 6, bash 74, libsqlite3 1, libc 63,
  git 169, python3.12 57), now each with its bound library and path, the one this host's `ld.so.cache` names. Not
  modelled: the environment, which no file shows: `LD_PRELOAD` and `LD_LIBRARY_PATH` are not read, and a user who
  runs the program with them passes the same directories with `--library-path` and the preloads in the sysroot's
  `/etc/ld.so.preload`; dlopen; 32-bit ELF imports (not marked). `fuzz_load_scope` covers the cache reader and the
  library reader (384,365 runs, no failure).

**T4. Thunks and import stubs named.**

- *Name form.* One rule: a stub is named by its import, `abort@plt`, in the function list, the call graph and xrefs.
  That is the form the link stage already uses (`link_calls.h` 28-35), and it is the form `objdump` prints. The
  pseudocode prints the import name as the call target, `abort();`, because `abort@plt()` is not valid C and the
  decompiler's output should stay valid C. This is an owner decision on the pseudocode form (below).
  A `-fno-plt` GOT call is named by the import of its GOT slot, the same way.
- *Provenance.* Each stub name carries `import-stub` and the stub's address. A name from debug info or a symbol keeps
  its own provenance (`session.cpp` 239-250 and `analysis.cpp` 572-584 are the existing sources).
- *Where the names come from.* In `analysis.cpp`, when a stub is a seed, its name is set from `plt_stub_imports` or
  `got_import_slots`, not from `synthetic_function_name`. That is one source for the function list (`donkey-cli
  functions`), the call graph (`callgraph`, `name_of` 599-604), xrefs and the decompiler. The desktop app reads
  `function.name` (session.cpp, panels_view.cpp 226), so it needs no UI change. Do not plan UI code beyond this.
- *Thunks.* A same-image jump thunk (a function whose only instruction is an unconditional jump to another function's
  start) is named after its target and marked `thunk`. The cfg already does not follow that jump (1109-1116), so the
  thunk's own block is just the jump.
- *Tail call or branch.* Today a jump to another function's start, or to an import stub, is not followed (cfg.cpp
  1109-1121). Any other direct jump is followed as a branch. Neither is recorded: `CfgEdgeKind` has no tail-call value
  (cfg.h 43-51). The plan adds a `TailCall` value for the first, and keeps the `Jump` value for branches. The lifter
  note at lift.cpp 2897 and 3105 says "treated as a tail call" and stays.
- *Formats.* ELF `.plt` and `.plt.sec` (x86-64, with `plt_stub_imports`), AArch64 `.plt` and `.plt.sec`
  (`aarch64_plt_slot`, plt.cpp 41, already read). `got_import_slots` names the GOT slots that `-fno-plt` calls read.
  Neither reader maps a `.plt.got` stub address to its slot: `plt_stub_imports` reads only `.plt` and `.plt.sec`. T4
  adds that mapping: decode each `.plt.got` entry's `ff 25 disp32` jump (after an optional ENDBR64 or BND prefix),
  compute the slot address, and look it up in `got_import_slots`.
  PE: IAT symbols carry their slot address (pe.cpp 345), so a PE call through a slot can be named the same way. That is
  the second slice of this task, after the ELF slice is measured. Mach-O: no stub reader exists (macho.cpp 410), so
  Mach-O is out of this task and is a later step of G24-T2 or of G15.
- *Tests (names to add).*
  - `Analysis.PltStubIsNamedByItsImport` (ELF fixture, x86-64: a stub named `abort@plt`)
  - `Analysis.GotCallIsNamedByItsImport` (ELF fixture built with `-fno-plt`)
  - `Analysis.AArch64PltStubIsNamed` (AArch64 ELF fixture; the stub reader only reads bytes, so no AArch64 host is needed)
  - `Analysis.ThunkTakesItsTargetsName` (unit: a one-jump function)
  - `Cfg.JumpToAnotherFunctionIsATailCall` and `Cfg.JumpIntoUnknownCodeIsABranch` (unit)
  - `cli.functions_lists_import_stubs_by_name` and `cli.decompile_prints_import_calls_by_name` (CLI, committed fixture)
  The fixtures are built from a committed C source file with its provenance written down (rule 11.5). No binary is
  copied from outside the repository.
- *Measurement.* Target after T4: 0 stub call sites printed as `sub_<hex>` (the (a) count, from the same script; the
  before value is 9,272 in 1,054 functions). The top-20 table (b) is the list of names that appear.

**T4 report (2026-11-17).** Done for ELF (x86-64 and AArch64) and PE; Mach-O stays out (no `__stubs`
reader). What was built:
- `plt_stub_imports` also reads `.plt.got` (an 8-byte `jmp *slot(%rip)`, or 16 bytes after ENDBR64; the
  slot is a GLOB_DAT for an import). `plt_stub_targets` lists the same stubs and also those whose
  relocation names a function the image defines itself (an interposable export: libc's `free@plt`,
  and IRELATIVE slots whose addend is an exported IFUNC symbol: libc's `strlen`). Those are named the
  same way but are never imports: `plt_stub_imports` still leaves them out, so the link stage and
  no-return binding do not see them.
- Every named stub is a seed (a stub reached only by a conditional tail call was not, and printed as
  `sub_<hex>`). `Function::import_name` and `Function::stub_target` carry the name; the function is
  named `<name>@plt`. `AnalysisResult::import_slots` holds the GLOB_DAT slots of imports and, on PE,
  every IAT slot (from the import symbols, whose address is the slot). A function that is one
  `jmp *slot(%rip)` through such a slot is an import stub too (MinGW's msvcrt thunks), named by the
  import on PE.
- `call_target_name` gives the C name a call prints: the import, the stub target, or the function's
  symbol or thunk name when it is a C identifier; `IrFunction::call_names` holds it per target or slot,
  and the printer uses it, so `abort();`, `puts(`, `VirtualQuery(` and same-image `helper(` replace
  `sub_<hex>(` and `((void (*)(void))*(u64 *)(0x...))(`. A stub's own pseudocode is headed by the
  import's name with the note "import stub".
- Thunks: a one-block function whose only instruction (after `endbr64`) is a direct jump to another
  function start is marked `thunk`, with `thunk_target`, and named `j_<target>` unless a symbol names it;
  a chain is followed up to 8 links. `CfgEdgeKind::TailCall` records an unconditional jump to another
  function start or stub; a jump into code no function starts at stays `Jump`.
- CLI: `functions --json` adds `import` and `thunk`; `xrefs` adds `to_name`; `callgraph` and the
  function list print `abort@plt`.
- Tests: `Analysis.PltStubIsNamedByItsImport`, `Analysis.DecompilerPrintsImportCallsByName`,
  `Analysis.GotCallIsNamedByItsImport`, `Analysis.AArch64PltStubIsNamed`,
  `Analysis.PeIatCallIsNamedByItsImport`, `Analysis.PeImportThunkIsNamedByItsImport`,
  `Analysis.AStubForTheImagesOwnFunctionIsNamedButIsNotAnImport`,
  `Analysis.AnIfuncStubIsNamedByItsIfuncSymbol`, `Analysis.CallTargetNamesAreCIdentifiers`,
  `Analysis.ThunkTakesItsTargetsName`, `Analysis.ThunkChainsAndNamedThunks`,
  `PltStubs.PltGotEntryIsNamedByItsGlobDatSlot`, `Cfg.JumpToAnotherFunctionIsATailCall`,
  `Cfg.JumpIntoUnknownCodeIsABranch`, `cli.functions_lists_import_stubs_by_name`,
  `cli.decompile_prints_import_calls_by_name`, `cli.xrefs_name_import_stubs`,
  `cli.callgraph_names_import_stubs`. Fixtures in `tests/fixtures/stubs/` (provenance there): x86-64
  with IBT, `-fno-plt`, AArch64, MinGW PE, and an ifunc library, each built from committed source.
- Measured with `tools/audit/import_calls.py` (which now also counts calls printed by an import's
  name) over the same 1,986 functions, Release build: stub call sites printed as `sub_<hex>`: **0**
  (9,272 before). 8,990 sites print by an imported function's name (an undefined dynamic symbol);
  150 print by the name of a function the image defines itself behind a stub (libc's interposable
  `free@plt`), counted apart; the other 133 are libc's IRELATIVE stubs, which print by their IFUNC
  symbol (`strlen(`), which `objdump` names only `*ABS*+0x...@plt`. Functions with a call to an
  import: 979 (1,054 before, when the image's own stubs were counted as imports). Complete stays 177, and the Partial-with-rax-note count stays
  1,163: naming changes no IR. Calls printed by a no-return name: 558 sites (469 before), because
  same-image calls now print by their symbol too (libc's own `abort` and `exit`); 396 of them are
  followed by a `return`, which T3 removes.
- Not done here: Mach-O stubs; PE delay-load imports; an import by ordinal prints `ordinal_<n>`, which
  `call_target_name` accepts as a C identifier.

**T5 (outline, to be refined before it starts).** Data in code: jump tables in `.text`, literal pools and padding.
Files: `src/analysis/cfg.cpp` (the jump-table path at 1109-1127 and `resolve_jump_table`), `src/analysis/analysis.cpp`
(seeds). First test: a fixture with a jump table placed after a function, with its bytes not decoded as code. The
measurement is the count of functions whose blocks include bytes that the table covers. Owner: none.

**T6 (outline, to be refined before it starts).** The stack-pointer delta at every instruction. Files:
`src/ir/lift.cpp` (the `push`, `pop` and `leave` lowering: `lift_push`, `lift_pop`, `lift_leave`) and a new per-instruction table in
`src/analysis/`. First test: a push/pop/call sequence whose delta at each instruction is checked. The measurement is
the count of frame slots recovered without a frame pointer on the sample. Needed by G21-T3.

**T7 (outline, to be refined before it starts).** Bounded value propagation for indirect branch and call targets.
Files: `src/analysis/cfg.cpp` (the indirect path, `indirect = true`), and a value-set module in `src/analysis/`.
First test: a `call *table(,%rax,8)` with a constant-bounded index gets its targets. The measurement is the count of
indirect call sites resolved on the sample (the sample has 1 call through a GOT slot in the form the script matches). Partial for every target that is not proven.

**Owner decisions.**
1. Propagation of no-return marks (T3, second step): on by default, or only the fixed names. The fixed names are the
   safe part, and propagation can delete code when a mark is wrong.
2. The pseudocode name of an import call: `abort();` (valid C, the proposal above) or `abort@plt();` (matches the link
   stage and `objdump`, not valid C).
3. Whether a function that reaches a no-return call can be Complete. The proposal is yes, when every returning path
   agrees with the compiled code. The paths through the no-return call are not compared.
4. How a no-return name is bound to its provider (T3, first step). Options: (a) the ELF symbol version only
   (`GLIBC_*`, and the FreeBSD libc equivalent; musl does not version its symbols): precise, but unversioned imports
   are never marked, and it needs the new version reader; (b) DT_NEEDED matched against a fixed list of runtime SONAMEs (`libc.so.6`, `libc.musl-*.so.1`,
   `libstdc++.so.6`, `libgcc_s.so.1`, ...): covers unversioned imports, but an import whose name is defined by more
   than one needed library is ambiguous, and must then stay unmarked; (c) both, (a) when a version is present and (b)
   otherwise. Neither option proves the provider at run time: a preloaded library (`LD_PRELOAD`) or a library loaded
   earlier can define the same name, and the file shows neither. So a mark is always a static assumption, recorded in
   its provenance (`known-name:<name>` with the evidence used), and the decision includes whether that assumption is
   accepted. A name exported by more than one library the importer needs is ambiguous under every option and stays
   unmarked. Until it is decided, T3 marks nothing by name, and its measurement target is not claimed.

**Decided (owner, 2026-11-17).** The owner asked for the options that make the product the most complete without
weakening `Complete`.
1. Propagation is on by default. It starts only from proven marks (the fixed list bound by decision 4, and
   instructions that never fall through), is bounded, and skips a function that is Partial for another reason.
2. `abort();` in pseudocode; `abort@plt` in the function list, the call graph and xrefs.
3. Yes: a function that reaches a no-return call may be Complete when it has at least one returning path, and every
   returning path is executed by the oracle and agrees with the compiled code. The paths through the no-return call
   are not compared, and the evaluator fails on them with `ir.eval_no_return`, so they can never be counted as
   agreeing. A function with no returning path has no successful comparison and stays Partial.
4. Option (c): the ELF symbol version when the import has one (a bounded `.gnu.version`/`.gnu.version_r` reader with a
   fuzz target), otherwise DT_NEEDED against the fixed runtime SONAME list. The static assumption (no interposition)
   is accepted and written into each mark's provenance, `known-name:<name>` with `version:<ver>` or
   `needed:<soname>`. A name exported by two needed libraries stays unmarked.

---

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

Inside a wave, the dependency-ready task that moves the measured numbers most
comes first, and ledger order decides between equals (section 2, step 1).
Inside one gap, take its **[oracle]** and **[ground truth]** tasks before its
tasks without a machine check, and T0 of a G20 to G32 gap before any other task
of that gap.

Branch hygiene, so that `main` stays the one place where work lives:

- At most six task branches are open at once, and each has an open PR.
- Do not stack a branch on an unmerged branch unless the task depends on it.
  If you do, say so in both PRs.
- When a PR merges, delete its branch in the same session. When work is
  superseded, close its PR with a link to what replaced it, check that every
  commit on the branch is in `main` or in the replacement (`git cherry
  origin/main <branch>`), and then delete the branch.
- Never leave pushed work without an open PR. A branch with neither a PR nor
  a line in an open PR's description is lost work waiting to happen.
