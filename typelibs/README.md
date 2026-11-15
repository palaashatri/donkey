# Bundled type libraries

This directory is installed with Donkey. It holds type libraries: C declarations for one platform
and ABI, in the format read by `donkey/project/typelib.h` (see `docs/TYPELIBS.md`).

No library is shipped yet. Which header sources may be used is an owner decision (`docs/IDA_GAP_LEDGER.md`,
G22-T2), so this directory is empty except for this file. A library is added here only with its
provenance record: the source, its licence and hash, the generator and the skipped declarations.

Do not add a library made from IDA, Hex-Rays or Binary Ninja output, or from an SDK header whose
licence does not allow it.
