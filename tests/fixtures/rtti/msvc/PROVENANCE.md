# MSVC RTTI fixture (G10-T3)

`hierarchy.cpp` was written for this repository (MIT, like the rest of the repository). It has a
polymorphic root `Shape` with a virtual destructor, `area` and `label`; `Square` derives from `Shape`;
`Tagged` derives from `Shape` and `Named`; `Named` has `name` and `rank`. It has no globals with
constructors and no runtime, so it links without the C runtime.

Built on Ubuntu 24.04 with clang 18.1.3, and linked with LLD:

    clang-18 --target=x86_64-pc-windows-msvc -fms-extensions -O0 -fno-exceptions -c hierarchy.cpp -o hierarchy.obj
    lld-link /nodefaultlib /entry:main /subsystem:console /force:unresolved /out:hierarchy.exe hierarchy.obj

`/force:unresolved` leaves `type_info`'s vftable and `_purecall` unresolved (the fixture is only read,
never run). The image has no COFF symbols, which is how LLD links by default: the reader does not need
them, because the class names are in the type descriptors.

The expected classes, bases and virtual function counts in `tests/unit/rtti_msvc_test.cpp` are read from
the source, not from the reader: `Shape` has three virtual entries (its destructor, `area`, `label`),
`Square` three (the destructor and the two overrides), `Tagged`'s `Shape` subobject three, its `Named`
subobject two (`name`, `rank`), and `Named` two.

- `hierarchy.exe`: SHA-256 is recorded by the test's commit. It is the file the reader is tested on.
