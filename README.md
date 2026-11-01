# Donkey

A planned free, open-source, native binary reverse-engineering suite: disassembler, analysis graphs, decompiler and debugger, written in C++20 with a Dear ImGui + SDL3 desktop shell and a headless core that also runs from the command line.

**Status: Alpha stage (Not release-ready).** Donkey is an open-source binary analysis workbench in active development. On macOS arm64 the following work today:

- `donkey-cli --version`, `--help`, `info <binary> [--json]`, `disasm`, `strings`, `functions`, `cfg`, `decompile`, `xrefs`, `analyze`, `project save|info|rename|comment|bookmark|annotations|backup|restore`, `debug launch`, `patch apply`, and `plugin info|run` (all with `--json`).
- Bounds-checked ELF32/ELF64, PE32/PE32+ and 32/64-bit Mach-O (including multi-slice fat Mach-O with `--arch` selection and explicit `--raw --arch --base --entry` raw binary import) metadata import: format, architecture, segments, sections, entry point, SHA-256, imports and exports. High-risk and untrusted file parsing can run inside a real OS process boundary (`load_binary_isolated` / `donkey-cli info --isolate`) with CPU/memory resource limits, protecting host applications from malformed-input crashes.
- Capstone 5.0.9 decoding for x86, x86-64 and AArch64, call/jump/return classification, direct call targets, x86 RIP-relative data references, and folded AArch64 ADRP+ADD/LDR data references.
- Deterministic analysis: instructions, call/data xrefs, ASCII and UTF-16LE strings, seeded functions, and a bounded control-flow graph with basic blocks, branch edges and estimated per-function extents. Indirect branches mark results `Partial`/`estimated`.
- IR-based decompiler for a documented x86-64, x86-32 (subset) and AArch64 (subset): instructions are lifted into typed IR that a verifier checks (operand widths, SSA temporaries, use-before-def ordering, dominator tree invariants, block targets, reachability, terminators, statement shape) before a C-like printer runs. An independent bit-vector arithmetic/flags semantic oracle (`A15`) asserts mathematical ground truth across 8/16/32/64-bit operations. Reducible control flow is structured into indented `if`/`else`, `while`, `do`/`while`, `switch` statements and nested forms; graphs that do not match a modelled shape fall back to labeled blocks with explicit `goto` and a note. Signatures are inferred from ABI register use (System V AMD64 `rdi..r9`, Microsoft x64 `rcx..r9` for PE binaries, and AAPCS64 `x0..x7`): integer arguments are registers read before their first write, and the return width comes from the last write to the return register. Stack frame local variable and argument recovery (`recover_stack_variables`) derives `local_X` and `arg_X`, emitting typed declarations at the function header. Array and pointer expressions render with typed index syntax (`reg[index]`). Source-to-assembly address map is tracked per line (`source_map` in CLI JSON and interactive click navigation in GUI). Evidence-backed jump tables and unresolved indirect jumps (`A17`) are handled gracefully with diagnostic notes instead of guessing targets.
- SQLite project storage (pinned 3.46.1 amalgamation): `PRAGMA user_version` migrations across v0, v1, v2, and v3 schemas, transactional image/section/function import with re-import replacing stale derived rows, address-keyed renames, comments, and bookmarks that survive re-import, integrity checks, rejection of corrupt or newer-schema databases without mutating them, and consistent `project backup|restore` copies through SQLite's online backup API (temporary file plus rename, so a failed copy never damages an existing project), exposed in both `donkey-cli` and the GUI (`File -> Backup Project…` / `File -> Restore Project…`).
- Debugger architectural scaffold with `DebugAdapter` interface (`donkey-cli debug launch --mock`, mock simulation adapter, breakpoint tracking, and ASLR runtime-to-static address translation). **Note:** Native OS execution control (Mach VM / ptrace / Win32) is not yet implemented; the GUI Debugger panel connects to the simulation adapter.
- Safe binary patch manager with original-byte verification, equal-size replacement enforcement, integer overflow safety, patch overlap detection, diff preview, audit history, invalidation callbacks, and safe export (`ExportPatchedBinary`, `donkey-cli patch apply`) that refuses to overwrite source binaries without `--force` and emits signature invalidation warnings for signed Mach-O and PE images (`A21`).
- Versioned C ABI plugin framework (`donkey_plugin_abi.h`, `DONKEY_PLUGIN_ABI_VERSION_MAJOR 1`) with capability negotiation, trusted in-process execution, and process-isolated untrusted plugin execution (`PluginHost::execute_isolated`, `donkey-cli plugin run --isolate`) where worker processes are forked before library loading to protect the parent process from untrusted static constructors.
- A SDL3 + Dear ImGui desktop shell (`donkey [binary]`) with a docked workspace: overview, sections, functions, disassembly, a CFG graph with pan/zoom and block selection, decompiler, hex, strings, xrefs, bookmarks, debugger, and diagnostics panels. Loading and analysis run on a worker thread with cooperative cancellation (`CancellationToken`), in-memory undo/redo for annotation edits, and full bidirectional navigation history (`NavigationHistory`) synchronizing selection across disassembly, graph, and pseudocode views.
- Truncated and mutated headers return deterministic diagnostics in tests; opened files are never executed.
- libFuzzer harnesses for the parse→analyze→lift→verify→print pipeline and for verifier/printer agreement, with a persisted corpus; fuzzing has already found and fixed three real lifter defects.

## Workbench Showcase

Donkey provides a fast, native Dear ImGui + SDL3 docked desktop workbench on macOS with synchronised disassembly, control flow graphs, an SSA-based decompiler, hex editor, debugger panel, and SQLite project annotations:

### Mach-O AArch64 Reverse Engineering Workspace
![Mach-O AArch64 Workspace](docs/images/donkey-overview-macho.png)
*Mach-O AArch64 binary loaded in Donkey: docked panels showing Binary Overview, Functions, Interactive Disassembly with call/jump xrefs, Control-Flow Graph with block highlights, Decompiler pseudocode, and Debugger controls with runtime-to-static ASLR translation.*

### ELF x86-64 SSA Decompiler & Stack Frame Variable Recovery
![ELF x86-64 Decompiler & Disassembly](docs/images/donkey-decompiler-x86.png)
*ELF x86-64 binary decompiled in Donkey: C-like decompilation with SSA form, dominator-verified control flow, recovered local stack variables (`local_X`), parameter inference, address-linked source mapping, synchronized hex inspection, and cross references.*

Not implemented yet: native OS-level debugging (Mach VM / ptrace / Win32), native project picker beyond the path dialog, target memory writes, remote debug protocols, struct widening, floating-point/vector and stack-passed parameters, varargs, 32-bit ARM lifting, streamed large-file reading, and the rest of the x86 and AArch64 instruction sets. Multi-platform CI (Linux/Windows) is in active progress. Anything not covered by the test suite should be treated as unverified.

- Design, architecture and milestones: [docs/DESIGN.md](docs/DESIGN.md)
- Contributor and coding-agent instructions: [AGENTS.md](AGENTS.md)

## Build

Requires CMake ≥ 3.25, Ninja, and a C++20 compiler (AppleClang 16+ verified so far). Dependencies are fetched with `FetchContent` at pinned commits.

```bash
# Headless core and CLI:
cmake --preset headless-macos
cmake --build --preset headless-macos --parallel
ctest --preset headless-macos --output-on-failure
./build/headless-macos/apps/donkey-cli/donkey-cli info tests/fixtures/binaries/tiny-macho-arm64
./build/headless-macos/apps/donkey-cli/donkey-cli info tests/fixtures/binaries/tiny-elf-x86_64 --json

# Desktop workbench (Dear ImGui + SDL3 GUI):
cmake --preset dev-macos
cmake --build --preset dev-macos --parallel
ctest --preset dev-macos --output-on-failure
./build/dev-macos/apps/donkey/donkey tests/fixtures/binaries/tiny-macho-arm64
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
