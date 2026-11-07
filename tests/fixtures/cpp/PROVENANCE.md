# Provenance: Itanium mangling corpus (G10-T1)

## Sources

- `names.cpp`, `templates.cpp`, `operators.cpp`, `stdlib.cpp`: written for this repository
  and released under the repository licence (MIT). They are not copies of any compiler
  test suite or demangler source.
- `stdlib.cpp` instantiates libstdc++ templates (`<functional>`, `<map>`, `<memory>`,
  `<stdexcept>`, `<string>`, `<vector>`), so its mangled names include standard library
  symbols. Those names come from the headers of the toolchain that built them, not from
  files in this repository.
- `itanium-pairs.txt`: each line is a defined `_Z` symbol from the four objects, followed
  by GNU c++filt's output for it. The expected text was produced by the tools below. It was
  not written by hand and not copied from a demangler's source code.

## Toolchain

Recorded with g++ 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1), GNU binutils 2.42 (`nm`,
`c++filt`), on x86-64 Linux.

## Recipe

Run from the repository root. `$OUT` is any empty scratch directory.

```bash
for f in names templates stdlib operators; do
  g++ -std=c++17 -O0 -c tests/fixtures/cpp/$f.cpp -o "$OUT/$f.o"
done
nm --defined-only "$OUT"/*.o | awk 'NF==3 && $3 ~ /^_Z/ {print $3}' | sort -u > "$OUT/mangled.txt"
c++filt < "$OUT/mangled.txt" > "$OUT/demangled.txt"
paste "$OUT/mangled.txt" "$OUT/demangled.txt"
```

The corpus file stores the pairs with a tab between them, below a `#` comment header.

## Verification

On the toolchain above, the recipe was rerun and its output compared with
`itanium-pairs.txt` (both sorted, comment lines removed). The two sets were identical: 512
pairs, no differences.

Other toolchains may spell some names differently. A different c++filt version is a reason
to regenerate and review the diff, not to edit the expected text by hand.

## Known residuals

Some names are not in the expected text because the demangler does not read them yet. The
test counts them as `demangle.unsupported` and does not compare them. The current ones are:

- Expression template arguments (`X...E`), which are not in the grammar this demangler
  reads: 9 names, all from `std::` library templates that use `enable_if` or `tuple`
  element expressions.
- A generic lambda whose parameter is its own template parameter (`T_` inside the lambda
  parameters): 1 name.
