# AGENTS.md — Donkey

Donkey is a planned free, open-source, native binary reverse-engineering suite (disassembler, analysis graphs, decompiler, debugger) written in C++20 with a Dear ImGui + SDL3 desktop shell and a headless core.

**Implementation started on 2026-10-30.** The build system, foundation contracts and CLI `--version` work on macOS arm64; binary parsing, decoding and the GUI are not implemented yet. Do not describe unverified platforms or unfinished milestones as working in READMEs, PRs or release notes. Check the truth table in `docs/DESIGN.md` §17.2 before claiming anything works.

The full design — architecture, module rules, decompiler pipeline, debugger model, milestones M0–M12, acceptance tests and backlog — is in [`docs/DESIGN.md`](docs/DESIGN.md). This file is the short instruction sheet.

## Where to start

Implement the first-wave backlog in order (`docs/DESIGN.md` §16):

1. **T000** monorepo skeleton: `CMakeLists.txt`, `CMakePresets.json` (`dev-linux`, `dev-macos`, `dev-windows`, `headless-*`, `asan-linux`), GoogleTest + CTest, `.clang-format`, CI.
2. **T001** pinned dependencies (pick vcpkg manifest mode *or* pinned `FetchContent`, not both) and a third-party licence inventory.
3. **T002** `foundation`: `Result`/`Diagnostic`, IDs, checked integer helpers.
4. **T004** SDL3 + SDL_GPU + Dear ImGui (docking branch) shell that opens, renders a dockspace and closes.

Then T003 (checked binary reader), T005–T007, and the ELF/PE/Mach-O readers (T008–T010). A useful first milestone for a solo developer is **M2**: open an ELF/PE/Mach-O file, show sections, symbols, strings, hex and Capstone disassembly with xrefs, from both the GUI and `donkey-cli`. Do not start the decompiler or debugger before M2 is real.

## Commands

macOS arm64 is the currently validated host (CMake + Ninja + AppleClang):

```bash
cmake --preset headless-macos       # core + CLI, no SDL/ImGui
cmake --build --preset headless-macos --parallel
ctest --preset headless-macos --output-on-failure

cmake --preset dev-macos            # core + CLI + desktop shell (once the shell lands)
cmake --build --preset dev-macos --parallel

# Linux/Windows presets exist but are not yet validated:
cmake --preset headless-linux
cmake --preset headless-windows
```

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

## Future SLOPOS/PARAMA platforms and Raspberry Pi Zero 2 W efficiency

**FUTURE DESIGN TARGET / NOT IMPLEMENTED.** donkey is an independently authored candidate for the **optional first-party SLOPOS developer/reverse-engineering workbench**. Preserve planned C++20 headless analysis core and Dear ImGui/SDL3 shell, currently design-only. No present SLOPOS package, Linux AArch64 Pi validation or PARAMA native port is implied. Maintain existing milestone/tech-stack rules and inspect all imported code, fonts, runtime libraries and models for license/provenance before first-party distribution.

- **SLOPOS/Linux:** Future SLOPOS Linux app integration: file-open associations, process debugger permissions, scoped executable inspection, native themes/icons by adapter, focus/clipboard and reproducible offline database export. No current code or packaged release exists.
- **Edge efficiency on 4× Cortex-A53 and 512 MB shared memory:** Architect lazy disassembly by on-demand pages/functions, bounded decoded instruction caches, streamed file reads and symbol enumeration, incremental CFG/index construction and deterministic eviction. Put heavy decompilation/debugger analyses into cancelable, memory-budgeted worker jobs, with accurate partial results and original binary unchanged. Idle should perform no full-binary scan, and analysis failure must not corrupt the project. Avoid needless editor/graphics heavyweight libraries.
- **Native PARAMA / SURYA:** Future PARAMA host requires C++ runtime/allocator/threads/files, SDL3/Dear ImGui graphics/input backend for SURYA, loader/debug hooks and explicit capability-controlled process inspection. Debugger may be unavailable even if offline disassembly works; never bypass PARAMA isolation.
- **Acceptance:** Once implementation exists, test Pi Zero 2 W reading tiny ELF/PE and moderately sized binaries on actual AArch64 hardware with bounded RAM/CPU, scrolling latency, incremental index cancellation and corrupt-binary fuzz fixtures; no status claims from design only.
- **Instrumentation and boundaries:** Each target documents actual distro/ABI/OS, hardware, dependencies, model versions, cold/warm launch, idle CPU, process tree PSS and peak RSS, whole-system `MemAvailable`, UI input p95, output fidelity and negative/OOM/restart tests. Use bounded streaming work, progress/backpressure, cancellation and clean recovery instead of UI-blocking calls; network/disk delay may take longer but should not block control inputs. Real Pi board acceptance differs from cross-compilation/QEMU. Optional model/runtime downloads are not part of SLOPOS's minimal 512 MB image. PARAMA native readiness must be tested separately from Linux compatibility personality research.
