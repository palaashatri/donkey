# Fixture provenance

All binaries in `tests/fixtures/binaries/` are generated from first principles by
[`tools/make_fixtures.py`](../../../tools/make_fixtures.py). No third-party or
proprietary executable is copied, and no fixture is executed by the test suite.

Regenerate deterministically:

```bash
python3 tools/make_fixtures.py
```

The generator writes `generated.json` next to this file with the size and
SHA-256 of every fixture. `ctest` asserts that each parsed image reports the
same hash (`Binary.PublicFixturesMatchRecordedHash`).

| Fixture | Purpose | SHA-256 |
|---|---|---|
| `tiny-elf-x86_64` | ELF64 `ET_EXEC`, x86-64, one PT_LOAD, `.text`/`.rodata`, symtab with defined and undefined symbols | `cb2f08393b7c54eb793cf315f56fe51e974372d1e1c9dba2a04af2d9991bcb43` |
| `tiny-elf-i386` | ELF32 `ET_EXEC`, i386, one PT_LOAD, `.text`/`.rodata`, Elf32 symtab with defined and undefined symbols | `12b48c5ce6669b9d2d98c438199bac760fd4d57d44c4d35f01ea04ad8c9e3659` |
| `tiny-pe-x86_64.exe` | PE32+, x86-64, two sections, one export, one `KERNEL32.dll` import | `486ea4e73369d4c2f0ce16a23ee8e95a0a5ce22cbff2e225a7b29c45715760e2` |
| `tiny-macho-arm64` | Mach-O 64 `MH_EXECUTE`, arm64, `__TEXT,__text`, `LC_MAIN`, `LC_SYMTAB` | `fc5e8b09d25a30cdd1abc9071d64abaf0429381be3989b7f642291003847490f` |

Malformed inputs used by the hostile-input tests (truncation at every length
and 256 deterministic header mutations per fixture) are derived in memory from
these files; they are not committed separately.
