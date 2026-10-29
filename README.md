# Donkey

<img src="assets/brand/app-icon.svg" alt="Donkey icon" width="96" align="right" />

[Icon, wordmark, and brand assets](assets/brand/README.md)


A planned free, open-source, native binary reverse-engineering suite: disassembler, analysis graphs, decompiler and debugger, written in C++20 with a Dear ImGui + SDL3 desktop shell and a headless core that also runs from the command line.

**Status: design only — there is no code yet.** Nothing here can be built or run today.

- Design, architecture and milestones: [docs/DESIGN.md](docs/DESIGN.md)
- Contributor and coding-agent instructions: [AGENTS.md](AGENTS.md)

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
