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

On Ubuntu 24.04 the build needs the `gcc`, `gcc-aarch64-linux-gnu`, `binutils-aarch64-linux-gnu`,
`libc6-dev-arm64-cross` and `musl-tools` packages. `gcc-aarch64-linux-gnu` only recommends
`libc6-dev-arm64-cross` (the AArch64 glibc headers), so an install with `--no-install-recommends` must name it.

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
diagnostics are recorded with the binary. Each one except `analysis.no_return_unverified` also marks the binary
`starts_may_be_missing`, and the table says so. The exit status is 2 when any binary has no usable output.

## The ratchet (G20-T3)

`baseline.json` holds, for each of the 26 binaries, the counts that may only get better: Complete,
Unsupported, InvalidIR, whether the measurement had an error, and, for a stripped binary, the function
starts it missed. Each entry also records the compiler and the binary's SHA-256, because the counts
describe those bytes only. The `r1` job of `.github/workflows/ci.yml` runs the whole measurement on
`ubuntu-24.04` and then `tools/r1/ci-check.sh`, which applies these rules:

- The reference is `baseline.json` as it is at the base commit (the pull request's base, or the
  previous commit on a push), never the file in the change. A change cannot lower the bar it is
  checked against.
- The check fails when, for any binary, Complete drops, or Unsupported, InvalidIR, an error or the
  missed starts rise. A count that gets better passes and is printed.
- A change that edits `baseline.json` must make it equal to the counts the job measured. A change
  that improves a count re-records it:

  ```bash
  build/release-headless/donkey-r1 baseline r1-result.json tools/r1/baseline.json
  ```

- A binary whose SHA-256 differs from its baseline entry (a new compiler on the runner, or a change
  to a source, a flag or the manifest), and a binary the baseline does not list, are compared with
  the base commit's `donkey-cli`. The script builds it in a worktree and measures the same bytes with
  it. A drop still fails. A pass warns that the baseline is out of date.
- A binary in the baseline that is no longer measured fails the check, unless the change
  re-records the baseline without it.

The check by itself:

```bash
build/release-headless/donkey-r1 check r1-result.json --baseline <base baseline.json, or none> --head-baseline tools/r1/baseline.json [--base-result base-result.json]
```

Its exit status is 0 when the check passes and 3 when it fails. It is 4 when a base measurement is
needed and was not given. With `--baseline none` (a base commit without the file) every binary needs one.

The script runs the base commit's CLI with this checkout's `decompile.cmake`, so the base commit
must have `--no-pseudocode` (G20-T2). Every commit with a baseline has it.

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
