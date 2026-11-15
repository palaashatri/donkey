# Type library format (G22-T1)

A type library is a text file of C declarations for one platform and ABI, with the provenance of
its source. The reader is `read_type_library` in `include/donkey/project/typelib.h`; the file is
read, not applied: no code gets a type from a library yet (G22-T3 does that).

**Status.** The reader and its format exist and are tested (`TypeLib.*` in
`tests/unit/typelib_test.cpp`, fuzzed by `fuzz/fuzz_typelib.cpp`). No library is bundled
(`typelibs/` holds a README only; the sources are an owner decision, G22-T2). A library's types do
not appear in the decompiler or the CLI yet.

## File layout

```
donkey-typelib 1
library: donkey-typelib-fixture
library_version: 1
...                                  (one line for each single key, in any order)
note: a hand-written fixture
<empty line>
<C text>
```

- The first line is the format line. Version 1 is the only one. Another version is refused.
- Header lines are `key: value`. Every single key is required and may appear once. The keys and
  their values are in the header comment of `typelib.h`.
- Repeated records come after the single keys, in this order: `source_file`, `macro`, `skipped`,
  `note`. Each keeps its order in the library.
- The C text is parsed by `parse_c_declarations` (`include/donkey/project/cdecl.h`, G05-T2). It may name
  the built-in names only, and its own declarations: a library parses on its own. The types a
  library returns take their ids from the `known` table, so they do not collide with it.
- `body_sha256` is the SHA-256 of the C text: the bytes after the empty line, to the end of the file,
  as stored. `declarations` counts the body parsed with only the built-in names: the number of
  type definitions that parse returns, scalar, pointer and array types included. It does not depend
  on the table the library is read into.

## Bounds

| What | Limit | Refusal |
|---|---|---|
| The file | 4 MiB, checked from its size before it is read | `typelib.too_large` (ResourceLimit) |
| Header lines | 4,096 before the empty line | `typelib.too_many_lines` (ResourceLimit) |
| A header line | 256 bytes | `typelib.line_too_long` (ResourceLimit) |
| Declarations | 20,000 | `typelib.too_many_declarations` (ResourceLimit) |
| The C text | 1 MiB (the parser's limit) | `cdecl.too_large` (ResourceLimit) |

## Names

C keeps two name spaces apart, and so does the reader: the tags of structs, unions and enums share
one, and typedef and function names share the other. One spelling may be both a tag and an
ordinary name (`struct stat` and the function `stat`, or `typedef struct point point`). Within one
name space a name is declared once: a typedef and a function with one name is
`typelib.type_and_function`, and any other repeat (two prototypes, or a struct and an enum with one
tag) is `typelib.duplicate_name`. Scalar, pointer and array types are not declarations and are not
checked.

The parser's final whole-set check (`cdecl.invalid_type`) is reported as `typelib.invalid_types`,
because the parser runs that check first on the same set.

Line endings must be LF. A CR byte anywhere is refused (`typelib.carriage_return`).

## Refusals

The reader refuses with a stable `typelib.` code. A header error's message begins `line L:`, with
the line in the library file. A refusal from the C text keeps the parser's `cdecl.` code, and its
`line L, column C:` is moved to the library file's line. The codes are listed in the header comment
of `typelib.h`.

## Where libraries live

The caller passes the path (`load_type_library`). Bundled libraries are installed from `typelibs/`
to `share/donkey/typelibs` on Linux, FreeBSD and a macOS install without the app, `typelibs` next to the executable on Windows, and
`Donkey.app/Contents/Resources/typelibs` in the macOS app. No per-user library directory is defined:
the project path is chosen by the caller too, so G22-T3 decides the user location.
