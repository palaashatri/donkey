# Library function signatures (G09)

Status: **G09-T1 partial, G09-T2 partial, G09-T3 partial.** The format, the reader and writer, and the
matcher are implemented and tested (`include/donkey/analysis/signatures.h`,
`src/analysis/signatures.cpp`). The generator (G09-T2, `include/donkey/analysis/signature_gen.h`,
`src/analysis/signature_gen.cpp`, `donkey-cli sig make`) makes a set from x86-64 ELF relocatable objects
and static archives. One set is shipped: musl 1.2.4 (`signatures/musl-1.2.4.json`, MIT), identified in a
static program by `Signatures.IdentifyMuslFunctionsInAStaticBinary`; see "Shipped set: musl 1.2.4".
Not yet: shared objects, PE import libraries, an AArch64 generator, a CLI command that matches a set
against a binary, the other libraries of the plan (compiler-rt, libc++, MinGW CRT, FreeBSD libc), and the
owner's decision on the naming bar (see below). Nothing is named from signatures unless a user loads a set.

## The format: `donkey.signatures.v1`

A signature set is a JSON object (RFC 8259, read with the strict reader that the RPC front end uses):

```json
{
  "format": "donkey.signatures.v1",
  "library": "testlib",
  "version": "1.0",
  "license": "MIT",
  "architecture": "x86_64",
  "signatures": [
    {"name": "plain", "length": 40, "prefix": "<64 hex digits>", "wildcards": [], "crc32": 3405691582},
    {"name": "relocated", "length": 48, "prefix": "<64 hex digits>", "wildcards": [[20, 4], [36, 4]], "crc32": 305419896}
  ]
}
```

- `format` must be exactly `donkey.signatures.v1`; any other value is refused with `sig.format`.
- `library`, `version`, `license` and `architecture` are required and not empty. `architecture` is the
  name `architecture_name()` gives (for example `x86_64`); a set for another architecture is refused
  with `sig.architecture`.
- Each signature has a `name` (1 to 4096 bytes), a `length` (the function's size in bytes, 1 to
  16 MiB), a `prefix`, the `wildcards` and a `crc32`.
- `prefix` is the first `min(32, length)` bytes of the function, as hex. Its length must be exactly
  that many bytes.
- `wildcards` is a list of `[offset, length]` pairs: the bytes a build may change (a relocated
  address, for example). They are sorted, non-overlapping, non-empty and inside the function.
- `crc32` is the IEEE CRC-32 (the zlib one) of the bytes after the prefix, with every wildcard byte
  replaced by zero.

Anything else is refused with a diagnostic that names the field (`sig.field` or `sig.value`); nothing is
returned partially. The writer produces the canonical form (fixed key order, one signature per line),
and reading that back gives the same set.

## How a function matches

A function (its start address and the address just past its last byte, from the analysis) matches a
signature when all of these hold:

1. Its length equals the signature's `length`.
2. Every prefix byte that is not a wildcard equals the signature's prefix byte.
3. The CRC-32 of its bytes after the prefix, with the wildcard bytes zeroed, equals `crc32`.

A match requires every masked byte and the CRC; a change to any other byte of the function is a
different function.

### Names and provenance

- **One name:** every matching signature names the same function. The match names it, with the
  provenance `signature <library> <version>`.
- **Ambiguous:** two or more matching signatures name different functions. The match names nothing,
  is marked `ambiguous`, and lists how many signatures matched. Ambiguity is never resolved by guessing.
- **User names are never replaced.** The caller passes the addresses the user has named, and those
  functions are skipped entirely. A name the user gave always wins over a name from a signature.
- **Unreadable functions are skipped**: a function whose bytes are outside the file, or whose length is
  zero, is not matched and is not reported.
- A function with no matching signature gets no entry at all.

## Generating a set (G09-T2)

    donkey-cli sig make libfoo.a --lib foo --version 1.2 --license MIT --out foo.sig.json [--json]

The input is an ELF relocatable object (`.o`, x86-64, 64-bit little-endian) or a static archive whose
relocatable members are read one by one. The file is read as the compiler wrote it. It is not laid out
or relocated, and nothing is run.

- **Which functions:** the `FUNC` symbols that have a size and are in an executable section, global,
  weak and local (`static`) alike. An alias (two names for one body, in the same or in another member)
  gives two signatures with identical bytes, which the matcher reports as ambiguous and names nothing.
  Local functions are included because a static body that is byte-identical to a global one would
  otherwise be named after the global, which is a wrong name for the linked binary; with both in the
  set the two are ambiguous instead. This reversed the first design, which named only global functions
  (see Verification).
- **Wildcards:** each relocation in a function's section that patches bytes inside the function makes
  a wildcard of the width its type patches (for example 4 bytes for `R_X86_64_PLT32`, 8 for
  `R_X86_64_64`). Overlapping wildcards are merged.
- **Skipped, with a note:** a function whose relocation has a type the generator does not know, whose
  relocation runs past its end, whose section is compressed or has no bytes in the file, or whose
  bytes lie outside the file. The skipped count and the notes say which, and at most 64 notes are kept.
- **Refused:** the whole file, with a code, when it is not an ELF object or an archive
  (`sig.input`), is another ELF type (`sig.not_relocatable`), is not x86-64 (`sig.machine`), or has a
  header or table that lies outside the file (`sig.truncated`). A member of an archive that cannot be
  read is skipped with a note instead, and the rest of the archive is still read.
- **Licence and provenance:** the library, version and licence are required, and they become the
  set's fields. The matcher reports them as the provenance of each match.

Tests: `SignatureGen.*` (ten tests) and `cli.sig_make_*` (two) on a fixture library, `sig/gen/` (provenance in
`tests/fixtures/sig/gen/PROVENANCE.md`). They check the names, the lengths against the object's own
symbol sizes, the wildcard offsets against `readelf -r`, a match of the library's functions in a program
that links it (with no other name), the refusals, and a function with an unknown relocation type.
Mutations checked: ignoring the relocations fails three tests, including the linked-program match.
Dropping the local functions from the set (the first design) fails `Signatures.IdentifyMuslFunctionsInAStaticBinary`
with two wrong names (`0x401700` named `__libc_malloc_impl`, which is the body of the static
`__simple_malloc`, and `0x4051b0` named `__syscall_cp_c`, the body of the static `sccp`), and restoring the
local functions passes it again. `fuzz_sig_object` checks that every accepted set meets the format and
reads back to the same text.

## Two ways to match

- `identify_functions` takes each function's start and end from the caller (the analysis). A signature
  is compared only with a function of its own length.
- `identify_at_starts` takes candidate starts only. Each start is compared with every distinct signature
  length, and the longest length whose signatures match is reported, with that length in
  `SignatureMatch::length`. The extents are not needed, because each signature carries its length.
  The cost is at most starts x distinct lengths comparisons. A start that the user named is skipped.

## Shipped set: musl 1.2.4 (G09-T3)

`signatures/musl-1.2.4.json` is generated by `donkey-cli sig make` from the `libc.a` of the Ubuntu 24.04
`musl-dev` package (1.2.4-2), a MIT-licensed library. It has 2,096 signatures, 1,653 of them with
wildcards, and no skipped function. Its provenance and hashes are in `signatures/PROVENANCE.md`.

The test program is `tests/fixtures/sig/musl/sig_musl.c`, linked statically against musl and stripped.
`symbols.txt` lists the symbols of the unstripped build. The test finds the functions with the analysis,
gives every 16-byte boundary in an executable section as a candidate start, and compares the names with
the symbols. Measured on the fixture, with 67 known functions (the symbols the set has a signature for):

| Outcome | Functions |
|---|---|
| Named, and correct | 34 |
| Ambiguous (byte-identical alias of another library function; named nothing) | 28 |
| No signature matched | 5 |
| Named wrongly | 0 |

The ledger asks for at least 90 % of the known functions named. That is not reached, and it cannot be
reached by a rule that is sound here: under the ambiguity rule above, a function with a byte-identical
alias is never named, and 28 of the 67 have one (for example `strtol` and `strtoll`, whose signatures match
the same bytes). The owner decides whether a byte-identical alias may be named after one of its
names, or whether 90 % identified (named or flagged ambiguous, 62 of 67 here) is the bar. The test
asserts the properties that hold: no wrong name, at least 90 % identified, and at least half named.

Two of the five unmatched functions were checked byte by byte: `__init_libc` and `__init_ssp` match
their signature's prefix, and the bytes differ in the tail, outside the wildcards. That fits a linker
relaxation (for example GOTPCRELX, which rewrites `mov` to `lea`) that the generator does not mask.
The other three are not examined yet. A missed name is the safe direction, and the gap is in the
generator's wildcards, not in the matcher.

## Limits

- **The wildcards are what the generator must find.** Relocated bytes are the only bytes a build may
  change in a matching function. A function that differs in any other byte is not identified, which
  is the safe direction: a missed name is better than a wrong one. The generator (G09-T2) will read the
  relocations to find them.
- **The start mode looks only at candidate starts** (the analysis's functions and each 16-byte boundary
  in an executable section). Code that starts at another offset is not searched; a byte-by-byte scan
  would cost one comparison per byte and is not done.
- **The CRC covers the whole tail.** A signature cannot match a function that is the same code with a
  different length or a different ending.
- **Only the names in the set are known.** A set from one library does not say what other code is
  there. Ambiguity between libraries is detected only when both sets are loaded.
- **Architectures** are matched by name; there is no check that the bytes decode as that architecture.

## Verification

- `Signatures.*` (thirteen unit tests): the CRC check value; a function matches its own signature with the
  provenance; wildcards leave relocated bytes out (in the prefix and in the tail) and nothing else;
  ambiguity names nothing; user-named functions are skipped; another architecture is refused; the
  canonical text round-trips; malformed sets are refused, each with its reason; bad inputs to the
  builder are refused; the start mode matches at its start with the signature's own length, skips
  user-named starts and reports the longest of several matching lengths; and the musl identification
  described above.
- Mutation checks: naming the first candidate when names differ fails the ambiguity test; not skipping
  user-named functions fails the user-name test; not zeroing the wildcard bytes in the tail fails the
  wildcard test. (The first form of the wildcard test put its only wildcard in the prefix, and the
  tail mutation survived it; the test now has a wildcard in the tail as well.)
- `fuzz_sig` (`fuzz/fuzz_sig.cpp`, corpus `tests/fuzz/corpus/sig`): 2,277,135 runs in 91 seconds under
  ASan and UBSan with no finding. An accepted set must write back to the same canonical text, and each
  signature's prefix, length and wildcards must agree.
