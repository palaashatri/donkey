# AGENTS.md — Donkey

Donkey is a free, open-source, native binary reverse-engineering suite (disassembler, analysis graphs, decompiler, debugger) written in C++20 with a Dear ImGui + SDL3 desktop shell and a headless core. **Its goal is parity with IDA Pro and Ghidra for everyday work. It is far from that today**; [`docs/PARITY.md`](docs/PARITY.md) says where, area by area.

**Implementation started on 2026-10-30. The v1.0 scope (M0-M11) is implemented for the features and platforms it claims.** Working on `main` today (see `docs/DESIGN.md` §17.2 and `docs/SUPPORT_MATRIX.md` for evidence): bounded ELF/PE/Mach-O/raw import with optional process isolation, and readers for relocatable objects, Intel HEX, S-records, ELF cores and Windows minidumps (archives are listed); Capstone disassembly, CFG and xrefs, with x86 and AArch64 jump-table recovery; a verified-IR decompiler subset (x86-64, x86-32, AArch64) for integer code and scalar floating point (AArch64 scalar floating point is verified under `qemu-user` with GCC only); SQLite projects with crash-safe backup/restore; safe patching (CLI and GUI hex editor); process-isolated C ABI plugins on POSIX; a JSON-RPC server with a batch mode and an optional Python client; a **native debugger on Linux (ptrace, x86-64/AArch64) and Windows (Win32 debug API, x64)**, with hardware watchpoints on Linux x86-64 and conditional breakpoints on Linux in the library and CLI; and the SDL3 + Dear ImGui desktop app, packaged as .deb/.rpm/.tar.gz, .dmg/.zip, NSIS setup/.zip and FreeBSD .pkg by `.github/workflows/package.yml`. Also working: DWARF 2-5 import with provenance, PDB 7.00 for C structures, enums, procedures and globals, separate and compressed debug files with `.dSYM` lookup, Itanium and MSVC demangling (both partial), Itanium RTTI and vtables for ELF and MSVC RTTI for x64 PE, library function signatures (format, matcher, a generator for x86-64 ELF objects and archives, one shipped set for musl 1.2.4), import binding across ELF images from the CLI, a type store with a bounded C declaration parser, make-code/data/array/string edits with undo, struct layouts behind pointer arguments, desktop windows for search, symbols, the cross-reference graph and classes with a command palette, a differential decompiler corpus (`DecompilerCorpus.*`, interpreter in `donkey/ir/eval.h`), scripted UI tests (`docs/UI_TESTING.md`), memory-mapped loading of large files, and an SPDX SBOM in every package. Decoded but not lifted: 32-bit ARM (A32), RV64GC, MIPS and PowerPC.

Not implemented on `main`: structuring beyond the layout-based structurer (on the unmerged branch, 50.2% of 1,986 sampled functions stay labelled, under the 52% bar; 106 irreducible functions remain irreducible after node splitting and none of the split functions is structured; see `docs/AUDIT.md`). Not implemented on `main`: call arguments and results in the decompiler (every function that makes a call is `Partial`; the unmerged branch `claude/funny-meitner-cpc7oc` resolves direct calls to same-image integer callees on x86-64, and AArch64 calls stay `Partial`), SIMD and varargs decompilation, Thumb, lifting for any instruction set beyond x86 and AArch64, signature sets beyond musl and signatures in the desktop app, type libraries, unwind and exception tables, function discovery beyond the entry point, exported symbols and call targets, Go/Rust/Objective-C/Swift metadata, native debugging on macOS, FreeBSD and Windows on Arm, remote debug adapters, emulation as a user feature, an assembler, binary diffing, PDB C++ class layouts, a type editing UI, several images in one desktop project, cross-image references for PE and Mach-O, screen readers, signed/notarised packages. Do not describe unverified platforms or unfinished milestones as working in READMEs, PRs or release notes. Check the truth table in `docs/DESIGN.md` §17.2 before claiming anything works. When this paragraph and the truth table disagree, the truth table wins: fix this paragraph in the same PR.

The full design — architecture, module rules, decompiler pipeline, debugger model, milestones M0–M12, acceptance tests and backlog — is in [`docs/DESIGN.md`](docs/DESIGN.md). This file is the short instruction sheet.

## Mission: parity with IDA Pro and Ghidra

Three documents direct the work past v1.0. Read them in this order.

1. [`docs/PARITY.md`](docs/PARITY.md): the scorecard (24 areas, each with what IDA Pro has, what Ghidra has, what `main` has, and a level), how parity is measured, the order of the work in five waves, and the decisions only the owner can make.
2. [`docs/IDA_GAP_LEDGER.md`](docs/IDA_GAP_LEDGER.md): gaps G01-G32. G01-G19 have task-sized plans with the files to touch and the tests that prove each task. G20-G32 are planned at gap level; the first task of each (T0) writes its detailed plan. Read sections 1-3 (rules, workflow, verification) before taking a task, and update the task's status row in the same PR.
3. `docs/DESIGN.md`, for the architecture a task must fit.

All three are plans and measurements, not capability lists: never cite them as something Donkey does.

Rules for parity work, on top of the ledger's rules:

- **Measure before you build.** A gap with a `[ground truth]` or `[oracle]` task gets that task first. The measurement decides the order of the rest, and its number goes in the PR.
- **Coverage never costs correctness.** The decompiler's `Complete` means executed and compared with the compiled code. Widening the subset by guessing is a regression, even if the output looks better. Unknown stays `Partial` or `Unsupported`.
- **Ground truth beats a reference tool.** Prefer comparing a stripped binary's analysis with its own unstripped build. Use open tools (`llvm-objdump`, `readelf`, `c++filt`, `gdb`, `qemu-user`, Ghidra run as an external program) as oracles second. IDA Pro is compared from its public documentation only.
- **Nothing proprietary enters the repository**: no IDA or Hex-Rays files, signatures, type libraries, SDK headers or output. Ghidra is Apache-2.0, so reading it and comparing with its output is allowed; vendoring any of it is a new dependency and needs the owner (ledger G26).
- **Stop for an owner decision.** `docs/PARITY.md` section 5 lists them. Do the spike or write the options; do not choose.
- **A level moves only on evidence.** The PR that moves a scorecard row updates `docs/PARITY.md`, the ledger row, `docs/SUPPORT_MATRIX.md` and `docs/DESIGN.md` §17.2 together.

## Where to start

The first-wave backlog of `docs/DESIGN.md` §16 (T000-T010 and the milestones through M11) is done. Do not restart it.

1. Read `docs/PARITY.md` sections 3 and 4, then the ledger's sections 1-3.
2. Take the first task that is TODO, whose dependencies are DONE, in the current wave. Today that is **Wave 1**: G20 (measure the decompiler on real programs), then G21 (call arguments and results), G24 (function discovery in stripped binaries), G23-T1 to T3 (unwind tables), and the open tasks of G04, G05 and G01.
3. For a G20-G32 gap, T0 comes first: write the task-level plan in the ledger, in its own PR, after reading the code the gap touches.
4. Before starting, check that no open PR or pushed branch already does the task (`git branch -r`, the open PR list). Finish or supersede existing work instead of starting a second copy.

## Commands

Validated hosts: macOS arm64 (AppleClang), Linux x86-64 (GCC 12/13, Ninja), and Windows x64 via MinGW-w64 GCC; FreeBSD presets are exercised in CI.

```bash
cmake --preset headless-macos       # core + CLI, no SDL/ImGui (also -linux, -windows, -freebsd)
cmake --build --preset headless-macos --parallel
ctest --preset headless-macos --output-on-failure --parallel 4

cmake --preset dev-macos            # core + CLI + desktop shell (also dev-linux, dev-windows)
cmake --build --preset dev-macos --parallel

# Desktop smoke tests need a display; on Linux CI they run under Xvfb:
cmake --preset dev-linux -DDONKEY_UI_SMOKE_TEST=ON
cmake --build --preset dev-linux --parallel
xvfb-run -a ctest --preset dev-linux --output-on-failure

# Release packages (static runtime, UI, smoke tests); then run cpack in the build dir:
cmake --preset package-linux        # DEB, RPM, TGZ (also package-macos, -windows, -freebsd)
cmake --build --preset package-linux --parallel
(cd build/package-linux && cpack)
sh packaging/freebsd/make-pkg.sh build/package-freebsd dist   # FreeBSD .pkg

# libFuzzer targets (Homebrew LLVM; AppleClang has no libFuzzer runtime):
cmake --preset fuzz-macos
cmake --build build/fuzz-macos --parallel
./build/fuzz-macos/fuzz_binary tests/fuzz/corpus/binary -max_total_time=60
./build/fuzz-macos/fuzz_ir tests/fuzz/corpus/ir -max_total_time=60
```

`-DDONKEY_USE_SYSTEM_SQLITE=ON` builds against the system SQLite when sqlite.org is unreachable. `.github/workflows/package.yml` is the reference for each platform's dependencies and release steps.

When you add or change presets, update this section in the same PR so it always lists commands that actually work.

## Settled decisions

| Concern | Choice |
|---|---|
| Language | ISO C++20 for all Donkey-owned code (Objective-C++ only for minimal macOS shims). No Qt, Electron, web UI, JVM, Rust or mandatory Python. |
| Build | CMake + Ninja + `CMakePresets.json`; explicit source lists (no `GLOB_RECURSE`) |
| UI | Dear ImGui **docking** branch, SDL3, SDL_GPU (`imgui_impl_sdl3` + `imgui_impl_sdlgpu3`), pinned revisions |
| Storage | SQLite with migrations |
| Decoding | Capstone (stable release) first; Zydis optional for differential testing |
| Tests | GoogleTest + CTest; libFuzzer + ASan/UBSan for parsers |
| Licence | MIT for Donkey code; MIT/BSD/Apache-2.0 dependencies; no GPL/AGPL without an explicit decision |

## Architecture rules

- **The headless core is the product.** `libdonkey` (formats, decode, analysis, IR, decompiler, project, scheduler) must build and run without SDL, ImGui, a display or a GPU. The GUI, CLI, debugger adapters and plugins are clients of its API.
- Module dependency direction and target names are in `docs/DESIGN.md` §2.3 and §11.2. UI code never parses binaries or writes SQL directly.
- **Untrusted input.** Every reader is bounds-checked and returns a status; no file is ever executed because it was opened. Truncated, overlapping or overflowing headers produce deterministic errors, never crashes or unbounded allocation. Add fuzz targets for each parser.
- **Responsive UI.** File I/O, analysis, decompilation and database writes never run on the render thread.
- **Shared UI components first.** Buttons, tables, trees, search fields and modals come from `src/ui/components`; features don't restyle their own.
- Public plugin boundary is a versioned C ABI or out-of-process RPC; C++ exceptions never cross it.

## Honesty rules

- A feature is done only when its acceptance tests pass on the platforms it claims (`docs/DESIGN.md` §12, §18). Unknown or partially-analysed results are shown as `Partial`/`Unsupported`, never as `Complete`.
- Never generate pseudocode by string formatting or an LLM; the decompiler works from verified IR (§6).
- Don't commit proprietary binaries, SDKs or code from IDA, Hex-Rays, Binary Ninja or other closed tools. Test fixtures must be redistributable, with provenance recorded (§11.5).
- Keep the milestone truth table in `docs/DESIGN.md` §17.2 accurate; update it in the PR that changes a milestone's state.

## Git workflow

- Never push to `main`. Branch as `agent/<area>/<milestone>-<topic>` (e.g. `agent/elf/M1-bounded-loader`), one backlog task per PR.
- PR description: task ID, what was tested (commands + results), platforms not tested.
- No warning-suppression blankets on project sources; build both Debug and Release before opening a PR.
- **`main` is the only place finished work lives.** Every pushed branch has an open PR, or is named in the open PR that carries its commits. Never leave pushed work with neither.
- Keep at most three task branches open at once. Do not stack a branch on an unmerged one unless the task depends on it, and say so in both PRs.
- When a PR merges, delete its branch in the same session. Before deleting a branch that was not merged as it stands, prove that nothing is lost: `git cherry origin/main <branch>` must list no `+` commit that is not in the replacement. Close the superseded PR with a link to what replaced it.
- Before ending a session, list what is unmerged (`git branch -r --no-merged origin/main`) and report each branch as: has an open PR, superseded (with proof), or needs a decision.

## Future SLOPOS/PARAMA platforms and Raspberry Pi Zero 2 W efficiency

**FUTURE DESIGN TARGET / NOT IMPLEMENTED.** donkey is an independently authored candidate for the **optional first-party SLOPOS developer/reverse-engineering workbench**. Preserve planned C++20 headless analysis core and Dear ImGui/SDL3 shell, currently design-only. No present SLOPOS package, Linux AArch64 Pi validation or PARAMA native port is implied. Maintain existing milestone/tech-stack rules and inspect all imported code, fonts, runtime libraries and models for license/provenance before first-party distribution.

- **SLOPOS/Linux:** Future SLOPOS Linux app integration: file-open associations, process debugger permissions, scoped executable inspection, native themes/icons by adapter, focus/clipboard and reproducible offline database export. No current code or packaged release exists.
- **Edge efficiency on 4× Cortex-A53 and 512 MB shared memory:** Architect lazy disassembly by on-demand pages/functions, bounded decoded instruction caches, streamed file reads and symbol enumeration, incremental CFG/index construction and deterministic eviction. Put heavy decompilation/debugger analyses into cancelable, memory-budgeted worker jobs, with accurate partial results and original binary unchanged. Idle should perform no full-binary scan, and analysis failure must not corrupt the project. Avoid needless editor/graphics heavyweight libraries.
- **Native PARAMA / SURYA:** Future PARAMA host requires C++ runtime/allocator/threads/files, SDL3/Dear ImGui graphics/input backend for SURYA, loader/debug hooks and explicit capability-controlled process inspection. Debugger may be unavailable even if offline disassembly works; never bypass PARAMA isolation.
- **Acceptance:** Once implementation exists, test Pi Zero 2 W reading tiny ELF/PE and moderately sized binaries on actual AArch64 hardware with bounded RAM/CPU, scrolling latency, incremental index cancellation and corrupt-binary fuzz fixtures; no status claims from design only.
- **Instrumentation and boundaries:** Each target documents actual distro/ABI/OS, hardware, dependencies, model versions, cold/warm launch, idle CPU, process tree PSS and peak RSS, whole-system `MemAvailable`, UI input p95, output fidelity and negative/OOM/restart tests. Use bounded streaming work, progress/backpressure, cancellation and clean recovery instead of UI-blocking calls; network/disk delay may take longer but should not block control inputs. Real Pi board acceptance differs from cross-compilation/QEMU. Optional model/runtime downloads are not part of SLOPOS's minimal 512 MB image. PARAMA native readiness must be tested separately from Linux compatibility personality research.
