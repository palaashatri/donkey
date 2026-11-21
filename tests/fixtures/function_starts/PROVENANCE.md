# LC_FUNCTION_STARTS fixtures (G23-T3)

`starts.c` is written for this repository: two static functions reached only through a pointer
table in data, a function that calls through the table, and `main`. Stripped, the image names none of
them; only the linker's LC_FUNCTION_STARTS table lists their starts.

Built on Linux with LLVM 18 (Ubuntu clang 18.1.3, LLD 18.1.3), for each `ARCH` in `x86_64` and `arm64`:

    clang-18 --target=ARCH-apple-macos13 -O1 -c starts.c -o starts-ARCH.o
    ld64.lld-18 -arch ARCH -platform_version macos 13.0.0 13.0.0 -no_uuid -no_adhoc_codesign \
        -e _main -o starts-ARCH-full starts-ARCH.o
    llvm-strip-18 -o starts_ARCH starts-ARCH-full

(`-no_adhoc_codesign` only matters for arm64; with `-no_uuid` both builds are byte-for-byte
reproducible.) The images have no libSystem, so they do not run on macOS; they exist to be read.

| File | SHA-256 | `llvm-objdump --macho --function-starts` |
|---|---|---|
| `starts_x86_64` | `78d828e04ea6cae7c1fd630c94bd5317aab2d1e56ffab43fd367e2e9b28b4252` | 0x1000003b0, 0x1000003c0, 0x1000003d0, 0x1000003f0 |
| `starts_arm64` | `edf90c3a475a715042044b4c73897723fc15bdd8b49ee2beb6c7c9e5ef378355` | 0x100000360, 0x100000368, 0x100000370, 0x100000388 |
