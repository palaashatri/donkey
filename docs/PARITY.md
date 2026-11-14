# Parity with IDA Pro and Ghidra: scorecard and roadmap

Donkey's goal past v1.0 is to be a tool a working reverse engineer can use in place of IDA Pro or
Ghidra for everyday work. This file says what that means, how it is measured, where `main` stands
today, and in which order the gaps are closed. The task-level plans are in
[`IDA_GAP_LEDGER.md`](IDA_GAP_LEDGER.md) (gaps G01 to G32).

**This file is a target and a measurement. It is not a capability list.** A row is "Parity" only
when its measure passes in CI on every platform the row claims. Never cite a planned row, here or
in the ledger, as something Donkey does. What Donkey does today is recorded in
[`DESIGN.md` §17.2](DESIGN.md) and [`SUPPORT_MATRIX.md`](SUPPORT_MATRIX.md).

Donkey is far from parity today. Section 3 says where, row by row.

---

## 1. What parity means

Parity is not a feature count. A capability is at parity when a user doing ordinary work does not
have to leave Donkey for it. Each area has one of four levels:

| Level | Meaning |
|---|---|
| **None** | Not present on `main`. |
| **Basic** | Works on the test fixtures or a narrow subset. A real program hits the limits quickly. |
| **Usable** | Works on real programs in the common case. The limits are stated and show as `Partial` or `Unsupported`, never as a wrong answer. |
| **Parity** | The area's measure (section 2) meets its threshold on the reference corpus, on every claimed platform, in CI. |

Two things Donkey keeps even where the reference tools do not have them:

- **Verified output.** The decompiler prints only IR that passed the verifier, and every result
  marked `Complete` on the differential corpus is executed and compared with the compiled code.
  Parity work must not trade this away for coverage. A wider subset that is sometimes wrong is a
  regression.
- **A headless core.** Everything the desktop app does is available from `donkey-cli` and the RPC
  server.

## 2. How parity is measured

A level changes only on evidence. The evidence is, in order of preference:

1. **Ground truth from the build.** Build an open-source program with symbols and DWARF, keep a
   stripped copy, analyse the stripped copy, and compare with the unstripped one. This measures
   function discovery, names, prototypes, types and ranges with no reference tool at all.
2. **Execution.** The differential corpus interprets lifted IR and compares it with the compiled
   function. This is the only accepted proof that a decompiled result is correct.
3. **An open reference tool's output on the same input**: `llvm-objdump`, `readelf`, `c++filt`,
   `gdb`, `lldb`, `dsymutil`, `qemu-user`, and Ghidra (Apache-2.0) run as an external program.
   Running Ghidra in CI is an **[owner decision]** (download size and time); until then it is a
   local comparison recorded in the PR.
4. **Public documentation** of IDA Pro and Ghidra, for what a capability is expected to do.

Rules for reference tools:

- IDA Pro cannot run in CI, and its files, signatures, type libraries, SDK headers and output
  cannot be committed. It is compared from its public documentation only.
- Ghidra's source and data are Apache-2.0. Comparing with its output is allowed. Vendoring any of
  it (for example SLEIGH processor specifications) is a new dependency and needs the decision in
  G26.
- A measure never depends on a proprietary file. Fixtures are redistributable, with provenance.

**The measured baseline of Donkey on real binaries, with the commands and the reference tool used, is in
[`AUDIT.md`](AUDIT.md). It is the "before" for every row that cites it.

**The reference corpus (R1)** is defined by G20-T1: permissively licensed programs built in CI
from pinned sources, at `-O0` and `-O2`, for x86-64 first and AArch64 second, each as an
unstripped and a stripped binary. Thresholds are proposed in the ledger and fixed by the owner
after the first measured baseline. A threshold is never lowered to make a row pass.

## 3. Scorecard

State on 2026-11-13, with the work integrated that day (ledger rows G09, G10, G12, G14, G15,
G16 and G17). The measured baseline of the audit that began the Wave 1 work is in
[`AUDIT.md`](AUDIT.md) (measured on `main` at `1a92abf`). On 2026-11-14 the branch
`claude/funny-meitner-cpc7oc` (not merged) changed rows 4, 6 and 22 as described there; the levels
did not change. The IDA Pro and Ghidra columns are short
summaries from their public documentation; check the current documentation before relying on a
detail. "Gaps" names the ledger entries that move the row.

| # | Area | IDA Pro | Ghidra | Donkey on `main` | Level | Gaps |
|---|---|---|---|---|---|---|
| 1 | Executable formats | ELF, PE, Mach-O and many more; loader SDK | ELF, PE, Mach-O, COFF, DEX, raw, Intel HEX, S-records, dyld shared cache and more | ELF, PE, Mach-O (32/64-bit, fat), raw; relocatable objects; archives listed; Intel HEX, S-records; ELF cores, Windows minidumps. Imports are bound across ELF images from the CLI; one image per project in the desktop app | Usable | G15, G30 |
| 2 | Processors: disassembly | Dozens of processor families | Dozens, described in SLEIGH | Full pipeline for x86, x86-64, AArch64. Decode only for 32-bit ARM (A32), RV64GC, MIPS and PowerPC. No Thumb | Basic | G13, G26 |
| 3 | Processors: decompilation | Hex-Rays decompilers for x86, x64, ARM, ARM64, PowerPC, MIPS, RISC-V, ARC | Every SLEIGH processor, through p-code | x86-64, x86-32 and AArch64, a verified subset | Basic | G13, G26 |
| 4 | Analysis of stripped code | Function discovery from prologues, unwind data and heuristics; no-return, thunks, stack analysis | The same, as a pipeline of analyzers | Functions start at the entry point, exported symbols and call targets. x86 and AArch64 jump tables. No no-return analysis, no prologue scan. The branch seeds functions from the ELF `.eh_frame` and the PE x64 `.pdata` (G23-T1, T2): own stripped CLI against its symbols 99.8% recall and 99.9% precision; `bash` and `python3.12` against their `.eh_frame` starts 100% and 100%. Baseline on `main` ([AUDIT.md](AUDIT.md)): 85.8% recall on the stripped own CLI, 33.0% to 88.5% against `.eh_frame` | Basic | G23, G24 |
| 5 | Decompiler: correctness | Not machine-checked | Not machine-checked | Every `Complete` result on the differential corpus is executed against the compiled code | Donkey's strength | G20 |
| 6 | Decompiler: coverage of real code | Nearly every function | Nearly every function | Integer and scalar floating-point subset. On `main`, a function that makes a call is `Partial`. On the branch, a direct call to a same-image integer callee that is Complete carries its inferred arguments and result (x86-64 only; AArch64 calls stay `Partial`); other calls stay `Partial`. No SIMD, no varargs. Baseline on `main` ([AUDIT.md](AUDIT.md)): Complete 11.0%, InvalidIR 25.8%. On the branch, 1,786 fixed sampled functions: 0 InvalidIR, 0 Unsupported, Complete 10.1%; 73.7% carry the "not fully structured" note, the largest open gap | Basic | G20, G21, G01, G08 |
| 7 | Decompiler: readability | Merged variables, `for` loops, simplified conditions | Similar | Register aliases merged, copy propagation, `do`/`while`, `break`, `continue`; `for` only for register counters; DWARF names at `-O0` | Basic | G04 |
| 8 | Types | Type libraries for the major platforms; struct, enum and union editors; propagation | Data type archives, C parser, Data Type Manager; propagation | Type store, bounded C declaration parser, prototypes applied from the CLI, struct layouts behind pointer arguments. No type libraries, no editing UI | Basic | G05, G22 |
| 9 | Debug information | DWARF, PDB | DWARF, PDB | DWARF 2-5; PDB 7.00 for C structs, enums, procedures and globals; separate debug files, `.dSYM` lookup, compressed DWARF. No C++ class layouts from PDB | Usable | G06 |
| 10 | Library function identification | FLIRT signatures, Lumina | Function ID, BSim | A signature format, a matcher with naming rules, and a generator for x86-64 ELF objects and archives. One shipped set (musl 1.2.4): it names 34 of 67 known functions of a static musl program and none wrongly. Not wired into the desktop app | Basic | G09 |
| 11 | C++ | Demangling, RTTI, vtables, exception handling | The same | Itanium and MSVC demanglers (both partial); Itanium RTTI and vtables for ELF and MSVC RTTI for x64 PE; readable names and a Classes window (Itanium classes of ELF images) in the desktop app. No call-site resolution, no exception tables | Basic | G10, G23 |
| 12 | Other language runtimes | Objective-C metadata; Swift, Rust and Go support | Objective-C, Swift, Rust and Go support | None | None | G25 |
| 13 | Debugger | Local and remote debuggers for Windows, Linux and macOS; GDB remote, WinDbg and others | GDB, LLDB and dbgeng connectors; recorded traces | Native on Linux x86-64 and AArch64 and on Windows x64. Hardware watchpoints on Linux x86-64 and conditional breakpoints on Linux (library and CLI). No remote targets, no macOS, FreeBSD or Windows on Arm | Basic | G14 |
| 14 | Emulation | Appcall, Bochs, plugins | P-code emulator | The IR interpreter exists and is used only by the tests | None | G27 |
| 15 | Scripting and API | IDAPython, IDC, C++ SDK | Java and Python scripts, headless analyzer | JSON-RPC server (read methods, decompile, rename, comment, apply type), batch mode, optional Python client, C ABI plugins. No scripts inside the desktop app | Basic | G31 |
| 16 | Interactive editing | Make code and data, arrays, strings, structures; rename and retype anywhere | The same | Make code, data and undefine with undo; arrays and strings as data ranges, and a user-defined string prints as a literal in the decompiler; rename, comment, bookmark, function boundaries. No local types, no inline listing rows | Basic | G12 |
| 17 | Desktop views | Many views and search kinds, command palette | Many views, configurable tools | Overview, sections, functions, disassembly, graph, decompiler, hex editor, strings, xrefs, bookmarks, debugger, diagnostics; a command palette; search for bytes, immediates and regular expressions; symbols; a cross-reference graph; classes. No synchronised views | Basic | G17 |
| 18 | Patching | Byte patches; assembling an instruction | Byte patches; instruction assembler | Byte patches with original-byte checks and export to a new file. No assembler | Usable (bytes) | G29 |
| 19 | Diffing and version tracking | Lumina; third-party BinDiff and Diaphora | Version Tracking, Program Diff, BSim | None | None | G28 |
| 20 | Collaboration | IDA Teams | Ghidra Server shared projects | Single-user SQLite projects with crash-safe backup and restore | None | G32 |
| 21 | Managed code and other containers | Dalvik, .NET and more | DEX, Java class files and more | None | None | G30 |
| 22 | Scale | Tuned for very large binaries | Tuned for very large binaries | Files of 64 MiB and more are memory-mapped; generated programs up to 80,000 functions and one real 123 MB library benchmarked. No incremental re-analysis. On the branch the CFG block bound follows the decoded instruction count (with a floor of 200,000); the AArch64 cross build of donkey-cli has 0 functions Unsupported (was 745). The stripped 8.3 MB own CLI analyses in 2.15 s and 645 MiB peak RSS ([AUDIT.md](AUDIT.md)) | Basic | G16 |
| 23 | Signed releases | Signed installers | Unsigned archive | Packages for four operating systems; ad-hoc signed `.app`, unsigned `.exe` | Blocked | G18 |
| 24 | Accessibility | Platform accessibility APIs | Java accessibility | Keyboard-only use; no screen reader | Blocked | G19 |

## 4. Roadmap

The order is by leverage: what makes the most functions of a real program readable first. Inside a
wave, take tasks in ledger order. A wave is not a release.

**Wave 1. Every function decompiles to something useful.**
G20 (measure real programs first, so the rest is ordered by evidence), then G21 (call arguments
and results), G24 (function discovery, no-return, stack depth), G23-T1 to T3 (unwind tables as
function seeds), and the open parts of G04, G05 and G01.

**Wave 2. Names and types appear without the user typing them.**
G09 (library signatures), G22 (type libraries), the open parts of G10 and G06, G23-T4 and T5
(exception tables), G25 (Go, Rust, Objective-C, Swift).

**Wave 3. Breadth.**
G26 (the processor strategy decision), then G13 lifting, G08 (SIMD), G15-T2 (several images in one
project), G30 (more containers).

**Wave 4. Dynamic analysis.**
G14 (remote targets through the GDB remote protocol first, then the missing hosts), G27
(emulation).

**Wave 5. Workflow.**
G12, G17, G31 (scripting inside the app and full API coverage), G29 (assembler), G28 (diffing),
G32 (collaboration).

**Always.** G16 (scale) is measured on every wave: a feature that makes analysis of a large binary
unusable is not done. G18 and G19 wait for the owner.

## 5. Owner decisions that gate parity

These are not for an agent to settle. Stop and report when a task needs one.

| Decision | Blocks | Options are written in |
|---|---|---|
| Processor strategy: hand-written lifters, SLEIGH specifications, or both | Rows 2 and 3 beyond three or four ISAs | G26 |
| Thresholds for the measures, after the first baseline | Calling any row "Parity" | G20, G24 |
| Running Ghidra as a reference in CI | Row-by-row comparison in CI | Section 2 |
| Header sources for type libraries, by licence | G22-T2 | G22 |
| Assembler: LLVM MC, a small own encoder, or SLEIGH | G29-T2 | G29 |
| Scope of managed code (DEX, Java, .NET, WebAssembly) | G30-T4 and T5 | G30 |
| Collaboration model | G32 | G32 |
| Signing certificates; accessibility waiver | Rows 23 and 24 | G18, G19 |

## 6. Keeping this file true

- The PR that moves a row updates this scorecard, the ledger row, `SUPPORT_MATRIX.md` and
  `DESIGN.md` §17.2 together.
- The "Donkey on `main`" column describes `main` only. Work on a branch does not count.
- Update the date at the top of section 3 whenever a row changes.
- If a reference tool gains a capability that matters, add a row and a ledger gap. Do not delete a
  row because it is hard.
