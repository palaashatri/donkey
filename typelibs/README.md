# Bundled type libraries

This directory is installed with Donkey. It holds type libraries: C declarations for one platform
and ABI, in the format read by `donkey/project/typelib.h` (see `docs/TYPELIBS.md`).

| Library | Made by | Source and licence |
|---|---|---|
| `musl-1.2.4-x86_64-linux.dtl` | `CREATED=2026-11-18 sh tools/typelib/make-musl.sh build/.../donkey-cli`, with GCC 13.3.0 | the headers of the Ubuntu 24.04 `musl-dev` package 1.2.4-2; musl is MIT, its public headers public domain with a permission grant |

The header sources allowed are recorded in `docs/IDA_GAP_LEDGER.md` (G22-T2, decided 2026-11-17):
permissive sources only. A library is added here only with its provenance record, which the file
itself carries: the source, its licence and hash, each top-level header and its hash (the headers they
include have no hash of their own; `source_sha256` covers the whole preprocessed text), the generator
and its command, the preprocessor, and every declaration that was skipped with the reason.

Regenerating gives the same bytes only with the same inputs: `musl-dev` 1.2.4-2, GCC 13.3.0 (its
version is in the `preprocessor` record, and another version can preprocess differently), the same
generator, and `CREATED` set to the recorded date (the script uses today's date otherwise). That was
checked once, on Ubuntu 24.04 x86-64, by generating twice and comparing the files.

Do not add a library made from IDA, Hex-Rays or Binary Ninja output, or from an SDK header whose
licence does not allow it.
