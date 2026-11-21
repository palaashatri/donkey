# R1, the reference corpus of real programs (G20)

R1 is the set of real, permissively licensed programs on which the decompiler is measured
(`docs/IDA_GAP_LEDGER.md`, G20 and its T0 plan). This directory holds the manifest and the tools.
Nothing fetched or built here is committed.

- `r1.json` is the manifest. It lists the toolchains, the pinned sources (URL, SHA-256 and licence) and
  the builds (files, flags, levels and toolchains).
- `build.cmake` fetches, checks, unpacks and builds R1. It needs CMake 3.25 or later. No Python is
  needed.

## Sources

| Source | Licence | Archive SHA-256 |
|---|---|---|
| zlib 1.3.1 | Zlib | `9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23` |
| Lua 5.4.7 | MIT | `9fbf5e28ef86c69858f6d3d34eccc32e911c1a28b4120ff3e84aaa70cfbf1e30` |
| SQLite 3.46.1 (amalgamation) | blessing (public domain) | `77823cb110929c2bcb0f5d48e4833b5c59a8a6e40cdea3936b99e199dbbe5784` |
| musl 1.2.4, as `musl-gcc` links it | MIT | Ubuntu package `musl-tools` 1.2.4-2 |

## Builds

The builds are 13 binaries, and each is also kept as a `strip` copy, which makes 26:

- `libz.so`, `lua` and `sqlite3` at -O0 and -O2, for x86-64 (`gcc`) and AArch64 (`aarch64-linux-gnu-gcc`);
- `lua` at -O2 linked statically with musl (`musl-gcc`, x86-64 only).

The builds use the distribution's default flags (PIE, `-fstack-protector-strong`, `-fcf-protection`),
plus `-g` and `-ffile-prefix-map`. With the same compiler, the same inputs give the same bytes in any
directory. That was checked by building twice in two directories and comparing all 26 SHA-256 values.

On Ubuntu 24.04 the build needs the `gcc`, `gcc-aarch64-linux-gnu`, `binutils-aarch64-linux-gnu` and
`musl-tools` packages.

## Use

Build everything:

```bash
cmake -DR1_WORK=/path/to/work -P tools/r1/build.cmake
```

`R1_WORK` may be relative; it is taken from the directory cmake runs in.

To fetch only, or build from sources already fetched:

```bash
cmake -DR1_WORK=/path/to/work -DR1_STEP=fetch -P tools/r1/build.cmake
```

```bash
cmake -DR1_WORK=/path/to/work -DR1_STEP=build -P tools/r1/build.cmake
```

The work directory holds:

- `downloads/`: the archives, reused only while they still match their hash;
- `src/`;
- `out/`: the binaries and their `.stripped` copies;
- `binaries.json`.

Then decompile and measure every binary (G20-T2). `donkey-r1` is built with the tests
(`DONKEY_BUILD_R1_TOOL`):

```bash
cmake -DR1_WORK=/path/to/work -DDONKEY_CLI=build/release-headless/apps/donkey-cli/donkey-cli -DOUT=/path/to/decompiled -P tools/r1/decompile.cmake
```

```bash
build/release-headless/donkey-r1 measure /path/to/work /path/to/decompiled r1-result.json r1-table.md
```

`decompile.cmake` runs one `donkey-cli decompile --json --no-pseudocode` per binary, under a time limit.
`donkey-r1 measure` counts, for each binary, the functions by status and the reasons of the Partial ones.
For a stripped binary it also compares the starts found with the function symbols of its unstripped twin:
matched, missed, import stubs, and extra. A binary has no usable output when the run failed or timed out,
when the output was cut by `--max-functions`, or when the analysis stopped at a resource limit
(`analysis.instruction_limit` and the like), since functions may then be missing. Other analysis
diagnostics are recorded with the binary. The exit status is 2 when any binary has no usable output.

`binaries.json` records the provenance of each binary that `docs/DESIGN.md` §11.5 asks for:

- the file name, the build, and the source with its version, licence and archive SHA-256;
- the toolchain and the architecture;
- the level and the variant (unstripped or stripped), with the unstripped twin of a stripped copy;
- the compiler's and the `strip` tool's `--version` line with their package versions;
- the flags, in the order the compiler was given them, with the source tree written as `<src>` (its absolute
  path depends on the work directory, and `-ffile-prefix-map` removes it from the binary);
- the binary's SHA-256.

## What the script refuses

`cmake/checks/r1_build_refusals.cmake` tests each of these refusals (CTest: `r1.build_script_refusals`):

- A download whose SHA-256 is not the pinned one. The file is deleted and the download is not retried. A
  network failure is retried twice, then reported as a fetch failure.
- An archive larger than 64 MiB.
- An archive member with an absolute path, a drive letter, a backslash or a `..` component, and a member
  outside the source's root directory. Every member is listed and checked before anything is unpacked.
- An archive member that is not a regular file or a directory, such as a symbolic or hard link: a later
  member could be written through it to a place outside the source tree. The pinned archives hold no links.
- A manifest outside its schema:
  - an unknown or missing key in any object;
  - a hash that is not 64 hex digits;
  - an unsafe source, root or build name (one plain path component, never `.` or `..`);
  - an unknown source, kind, level or toolchain;
  - a file path that is absolute or contains `..`.

The member check works on member names. It is a defence in depth on top of the pinned hash, which already
fixes every byte of the archive.
