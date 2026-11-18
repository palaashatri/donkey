# Load-scope fixtures (G24-T3)

Everything here is written for this repository (MIT). It tests where the dynamic loader binds an
import, so no-return marks are proven rather than assumed. No glibc code is included: `libc.so.6`
in each sysroot is a stand-in (`src/fakelibc.c`) that defines the names the fixtures import, with
glibc's version names, and is never run.

Built on Ubuntu 24.04 with GCC 13.3.0 and the matching AArch64 cross compiler, from `src/`:

    gcc -O1 -fPIC -shared -nostdlib -fno-builtin -s -Wl,-soname,libc.so.6 \
        -Wl,--version-script,libc-x86_64.map -Wl,--build-id=none \
        -o sysroot-x86_64/lib/x86_64-linux-gnu/libc.so.6 fakelibc.c
    aarch64-linux-gnu-gcc -O1 -fPIC -shared -nostdlib -fno-builtin -s -Wl,-soname,libc.so.6 \
        -Wl,--version-script,libc-aarch64.map -Wl,--build-id=none \
        -o sysroot-aarch64/lib/aarch64-linux-gnu/libc.so.6 fakelibc.c
    cp ../stubs/libmyexit.so.1 sysroot-x86_64/lib/x86_64-linux-gnu/
    gcc -O1 -fPIC -shared -s -Wl,-soname,libsteal.so.1 -Wl,--build-id=none -o clean/libsteal.so.1 steal.c
    gcc -O1 -fPIC -shared -s -fno-builtin-exit -Wl,-soname,libsteal.so.1 -Wl,--build-id=none \
        -o steal/libsteal.so.1 steal_exit.c
    gcc -O1 -fno-inline -s -Wl,--build-id=none -Wl,--no-as-needed -o steal_consumer \
        steal_consumer.c clean/libsteal.so.1
    gcc -O1 -fPIC -shared -nostdlib -s -Wl,-soname,libvers.so.1 -Wl,--version-script,vers.map \
        -Wl,--build-id=none -o libvers.so.1 vers.c

`steal_consumer` is linked against `clean/libsteal.so.1`, which has no `exit`, so its `exit` import
asks for `exit@GLIBC_2.2.5` from `libc.so.6`; DT_NEEDED lists `libsteal.so.1` first.
`steal/libsteal.so.1` is a later build of that library with an unversioned `exit` that returns.

Oracle, glibc's own loader on the build host (the program runs against the host's real libc):

    $ LD_LIBRARY_PATH=steal ./steal_consumer 1 2 3 4 5 6
    libsteal exit(1) returned
    Segmentation fault            (exit status 139: the call returned into code the compiler took as unreachable)
    $ LD_LIBRARY_PATH=clean ./steal_consumer 1 2 3 4 5 6
                                  (exit status 1: glibc's exit ran)

So a version need alone does not prove the provider: with `steal/` first, Donkey must not mark the
call; with `clean/`, it must.

| File | SHA-256 |
|---|---|
| `sysroot-x86_64/lib/x86_64-linux-gnu/libc.so.6` | `5c05f721501d40ef61e638da4c8fca1dcee644d686fde3dedc6a32848304010e` |
| `sysroot-x86_64/lib/x86_64-linux-gnu/libmyexit.so.1` | `76e666f442af3d61c8cc15d71bcf95e6cb8c1dfe3bda769ef0c7c8ac1e844ad6` (a copy of `../stubs/libmyexit.so.1`) |
| `sysroot-aarch64/lib/aarch64-linux-gnu/libc.so.6` | `30eb7faf79c149f87a19351a9d6cce50ab7039abd1340a3e4703115d95b11d69` |
| `clean/libsteal.so.1` | `81233b8b56fefd196370f957e7ef78ebc62a9c00d3608c0562fb66f330e41849` |
| `steal/libsteal.so.1` | `f9f740503b59e47bad5243636500b9bc7f4c191933dff1ca985211275a10316f` |
| `steal_consumer` | `95c2d42bdad2a76a503bfa53b7e97ea6f7d590b7bb4784994206ab7247a790d2` |
| `libvers.so.1` | `9efce0b3a3582636275194bc579fb3773dbaed09ead26923676d21c8e050d130` (`exit@V2` hidden at index 3, `exit@@V3` at index 4) |

`steal_consumer` and the `libsteal.so.1` builds link glibc's startup objects and libgcc pieces, as
any GCC-built program does (see `../stubs/PROVENANCE.md`).
