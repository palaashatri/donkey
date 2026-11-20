# Type library format (G22-T1)

A type library is a text file of C declarations for one platform and ABI, with the provenance of
its source. The reader is `read_type_library` in `include/donkey/project/typelib.h`; the file is
read, not applied: no code gets a type from a library yet (G22-T3 does that).

**Status.** The reader and its format exist and are tested (`TypeLib.*` in
`tests/unit/typelib_test.cpp`, fuzzed by `fuzz/fuzz_typelib.cpp`). One library is bundled:
`typelibs/musl-1.2.4-x86_64-linux.dtl`, generated from the musl 1.2.4 headers (G22-T2, see
"Generating a library" below). A library's types do not appear in the decompiler yet (G22-T3);
`donkey-cli typelib show` reads one and summarises it.

## Generating a library

`donkey-cli typelib make <preprocessed.i> --out FILE` and these options, each with one value
(`apps/donkey-cli/commands.cpp`, `include/donkey/project/typelib_gen.h`):

- The library: `--library`, `--library-version`, `--platform`, `--architecture`, `--abi`,
  `--data-model` (`LP64` or `LLP64`; it sets `long_size`), `--char-signed` (`true` or `false`).
- Provenance: `--source`, `--source-sha256`, `--licence`, `--licence-file`, `--licence-sha256`,
  `--command` (the `generator_command` record), `--preprocessor`, `--created` (`YYYY-MM-DD`).
- Repeated records: `--source-file 'PATH SHA256'`, `--macro NAME=VALUE`, `--note TEXT`.

The generator writes the other header values itself: `pointer_size` (8), `generator`,
`body_sha256`, `declarations` and one `skipped` record per declaration it did not keep. For example,
for a header `mylib.h` preprocessed into `all.i`, with its licence in `LICENSE`:

```sh
source_hash=$(sha256sum all.i | cut -d' ' -f1)
licence_hash=$(sha256sum LICENSE | cut -d' ' -f1)
header_hash=$(sha256sum mylib.h | cut -d' ' -f1)
donkey-cli typelib make all.i --out mine.dtl \
  --library mylib --library-version 1.0 --platform linux --architecture x86_64 --abi sysv \
  --data-model LP64 --char-signed true --source "mylib 1.0 headers" --source-sha256 "$source_hash" \
  --licence MIT --licence-file LICENSE --licence-sha256 "$licence_hash" --command "make-mylib.sh" \
  --preprocessor "gcc 13.3.0 -E -P" --created 2026-11-18 --source-file "mylib.h $header_hash"
```

The input is the preprocessor's output: a script runs the
preprocessor at build time (`tools/typelib/make-musl.sh` runs `gcc -E -P -nostdinc` on musl's own
headers), never Donkey at run time. The generator keeps each top-level declaration that Donkey's C
parser accepts together with every declaration kept before it, and lists each other one as
`skipped: <name>: <reason>`: a variable, a function definition, a name declared twice, a type the
parser does not model (a function pointer, `__builtin_va_list`), an attribute
that may change a type (`aligned`, `packed`, `vector_size`, `mode`, or one it does not know), and
anything that needs one of those. It drops only what changes neither a type nor its layout: `restrict`,
`__extension__`, `_Noreturn`, `__inline`, `__asm__(...)` labels, and attributes such as `noreturn`,
`nonnull`, `format`, `deprecated` and `visibility`. Character and string literals are copied as they
are; their contents are never taken for delimiters. The kept text and each new declaration are parsed
together, as the reader parses the file, so a struct named first by a forward reference (`struct
stat *` in a member) is completed by its later definition. Before it writes, it reads its own output
back with `read_type_library`, so a file it writes always loads.

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
  the built-in names only, and its own declarations: a library parses on its own, so the table it is
  read into cannot change what its text means. Its types are then moved up to take their ids from
  `known.next_id()`, so they do not collide with that table.
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
tag) is `typelib.duplicate_name`. `typedef struct { ... } item;` declares the ordinary name `item`
(the untagged struct takes the typedef's name), so a function `item` collides with it. The parser
reports each name it declares with its name space (`CDeclaredName` in `cdecl.h`), and the check uses
that list. Scalar, pointer and array types are not declarations and are not checked.

The parser's final whole-set check (`cdecl.invalid_type`) is reported as `typelib.invalid_types`,
because the parser runs that check first on the same set.

Line endings must be LF. A CR byte anywhere is refused (`typelib.carriage_return`).

## Refusals

The reader refuses with a stable `typelib.` code. A header error's message begins `line L:`, with
the line in the library file. A refusal from the C text keeps the parser's `cdecl.` code, and its
`line L, column C:` is moved to the library file's line. The codes are listed in the header comment
of `typelib.h`.

## Applying a library (G22-T3)

`donkey-cli project type library add <db> <library.dtl>` merges a library's types into a project (a
name the project already has keeps the project's type and is counted as a collision) and records
the library. `project type library apply <db> <image-id>` matches each import stub of the image to
a library prototype by name (an ELF version suffix and one Mach-O underscore are removed first; an
`ordinal_N` import and a name seen with two versions are not matched) and stores it as a prototype
application with source `library`. A user, DWARF or PDB prototype at the same address is kept; a
later user edit replaces a library one. Every library of the project must be for the image's
architecture. `project type applications <db> <image-id>` lists the applications with their source,
and `decompile --project` notes the prototype on the stub.

## Where libraries live

The caller passes the path (`load_type_library`). Bundled libraries are installed from `typelibs/`
to `share/donkey/typelibs` on Linux, FreeBSD and a macOS install without the app, `typelibs` next to the executable on Windows, and
`Donkey.app/Contents/Resources/typelibs` in the macOS app. No per-user library directory is defined:
the project path is chosen by the caller too, so G22-T3 decides the user location.
