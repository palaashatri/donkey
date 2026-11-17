# Bundled type libraries

This directory is installed with Donkey. It holds type libraries: C declarations for one platform
and ABI, in the format read by `donkey/project/typelib.h` (see `docs/TYPELIBS.md`).

| Library | Made by | Source and licence |
|---|---|---|
| `musl-1.2.4-x86_64-linux.dtl` | `sh tools/typelib/make-musl.sh build/.../donkey-cli` (`CREATED=2026-11-17`) | the headers of the Ubuntu 24.04 `musl-dev` package 1.2.4-2; musl is MIT, its public headers public domain with a permission grant |

The header sources allowed are recorded in `docs/IDA_GAP_LEDGER.md` (G22-T2, decided 2026-11-17):
permissive sources only. A library is added here only with its provenance record, which the file
itself carries: the source, its licence and hash, every header and its hash, the generator and its
command, the preprocessor, and every declaration that was skipped with the reason. Regenerating
with the same package and date gives the same bytes.

Do not add a library made from IDA, Hex-Rays or Binary Ninja output, or from an SDK header whose
licence does not allow it.
