# Donkey

A planned free, open-source, native binary reverse-engineering suite: disassembler, analysis graphs, decompiler and debugger, written in C++20 with a Dear ImGui + SDL3 desktop shell and a headless core that also runs from the command line.

**Status: early implementation.** On macOS arm64 the following work today:

- `donkey-cli --version`, `--help`, `info <binary> [--json]`, `disasm`, `strings`, `functions`, `cfg`, `decompile`, `xrefs`, `analyze` and `project save|info|rename|comment|annotations` (all with `--json`).
- Bounds-checked ELF64, PE32/PE32+ and 64-bit Mach-O (including fat slices) metadata import: format, architecture, segments, sections, entry point, SHA-256, imports and exports.
- Capstone 5.0.9 decoding for x86, x86-64 and AArch64, call/jump/return classification, direct call targets and x86 RIP-relative data references.
- Deterministic analysis: instructions, call/data xrefs, ASCII and UTF-16LE strings, seeded functions, and a bounded control-flow graph with basic blocks, branch edges and estimated per-function extents. Indirect branches mark results `Partial`/`estimated`.
- IR-based decompiler for a documented x86-64 subset and an AArch64 subset: instructions are lifted into typed IR that a verifier checks (operand widths, block targets, terminators, statement shape) before a C-like printer runs. Reducible control flow is structured into indented `if`/`else`, `while`, `do`/`while` and nested forms; graphs that do not match a modelled shape fall back to labeled blocks with explicit `goto` and a note. Unsupported instructions and architectures return explicit `Unsupported`/`Partial` results, never guessed pseudocode. The AArch64 subset covers the common integer load/store (including pre/post-index writeback and pairs), arithmetic, shift, extend, multiply and branch forms; register aliases are not canonicalised and ABI/locals recovery is not done.
- SQLite project storage (pinned 3.46.1 amalgamation): `PRAGMA user_version` migrations, transactional image/section/function import with re-import replacing stale derived rows, address-keyed renames and comments that survive re-import, integrity checks, and rejection of corrupt or newer-schema databases without mutating them.
- A SDL3 + Dear ImGui desktop shell (`donkey [binary]`) with a docked workspace: overview, sections, functions, disassembly, a CFG graph with pan/zoom and block selection, decompiler, hex, strings, xrefs and diagnostics panels. Loading and analysis run on a worker thread so the UI stays responsive.
- Truncated and mutated headers return deterministic diagnostics in tests; opened files are never executed.
- libFuzzer harnesses for the parse→analyze→lift→verify→print pipeline and for verifier/printer agreement, with a persisted corpus; fuzzing has already found and fixed three real lifter defects.

Not implemented yet: project backup/restore, native project picker beyond the path dialog, debugger, switch/struct/array recovery for the decompiler, parameter/type recovery, 32-bit x86/ARM lifting, and the rest of the AArch64 instruction set. Anything not covered by the test suite should be treated as unverified.

- Design, architecture and milestones: [docs/DESIGN.md](docs/DESIGN.md)
- Contributor and coding-agent instructions: [AGENTS.md](AGENTS.md)

## Build

Requires CMake ≥ 3.25, Ninja, and a C++20 compiler (AppleClang 16+ verified so far). Dependencies are fetched with `FetchContent` at pinned commits.

```bash
cmake --preset headless-macos
cmake --build --preset headless-macos --parallel
ctest --preset headless-macos --output-on-failure
./build/headless-macos/apps/donkey-cli/donkey-cli info tests/fixtures/binaries/tiny-macho-arm64
./build/headless-macos/apps/donkey-cli/donkey-cli info tests/fixtures/binaries/tiny-elf-x86_64 --json
```

Linux and Windows presets exist but have not been validated.

## Roadmap

The first useful release is a fast native **binary viewer**, not a decompiler. In order:

1. **Project skeleton** (milestone M0): CMake presets, CI on Linux, macOS and Windows, a window that opens, and `donkey-cli --version`.
2. **Open any executable safely** (M1): ELF, PE and Mach-O files show their format, architecture, sections, entry point and hash; malformed files produce a clear error instead of a crash.
3. **Read the code** (M2): Capstone disassembly for x86-64 and AArch64, a hex view, strings, imports/exports and cross-references, all navigable, plus `donkey-cli info` / `analyze` with JSON output.
4. **Follow the control flow** (M3): function discovery, control-flow and call graphs, renaming and comments that survive save and reopen.
5. **First honest decompiler output** (M4–M5) for a documented subset of x86-64, clearly marking anything it can't handle.

Ghidra, Cutter/Rizin, ImHex and Binary Ninja's free tier already cover milestones 2–4; Donkey's reason to exist is a faster native UI and, later, a better decompiler. Keep that in view when deciding how much to invest.

## Licence

Intended licence: MIT for Donkey's own code, subject to a third-party licence inventory (see [docs/DESIGN.md](docs/DESIGN.md) §1).

## Planned SLOPOS, PARAMA and edge-device support

donkey is an original project considered for SLOPOS's **optional first-party catalog**, not required in its minimal image. Linux/SLOPOS GUI support must be demonstrated through real desktop integration; **PARAMA remains a conditional native source-port goal** after its actual process, graphics, files, ABI and toolkit dependencies exist. This is a platform roadmap, not a build/compatibility claim.

**Raspberry Pi Zero 2 W efficiency:** Architect lazy disassembly by on-demand pages/functions, bounded decoded instruction caches, streamed file reads and symbol enumeration, incremental CFG/index construction and deterministic eviction. Put heavy decompilation/debugger analyses into cancelable, memory-budgeted worker jobs, with accurate partial results and original binary unchanged. Idle should perform no full-binary scan, and analysis failure must not corrupt the project. Avoid needless editor/graphics heavyweight libraries.

See [AGENTS.md](AGENTS.md#future-sloposparama-platforms-and-raspberry-pi-zero-2-w-efficiency) for measurable acceptance and restrictions. No actual Pi Zero 2 W or PARAMA acceptance has been performed.
