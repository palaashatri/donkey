# Load-scope fixtures (G24-T3)

Everything here is written for this repository (MIT). It tests where the dynamic loader binds an
import, so no-return marks are proven rather than assumed. No glibc code is included: `libc.so.6`
in each sysroot is a stand-in (`src/fakelibc.c`) that defines the names the fixtures import, with
glibc's version names, and is never run.

Built on Ubuntu 24.04 with GCC 13.3.0 and the matching AArch64 cross compiler. Run every command
from this directory (`tests/fixtures/loadscope`), so the outputs land where the tests read them:

    mkdir -p sysroot-x86_64/lib/x86_64-linux-gnu sysroot-aarch64/lib/aarch64-linux-gnu clean steal \
        hidden chain/inner
    gcc -O1 -fPIC -shared -nostdlib -fno-builtin -s -Wl,-soname,libc.so.6 \
        -Wl,--version-script,src/libc-x86_64.map -Wl,--build-id=none \
        -o sysroot-x86_64/lib/x86_64-linux-gnu/libc.so.6 src/fakelibc.c
    aarch64-linux-gnu-gcc -O1 -fPIC -shared -nostdlib -fno-builtin -s -Wl,-soname,libc.so.6 \
        -Wl,--version-script,src/libc-aarch64.map -Wl,--build-id=none \
        -o sysroot-aarch64/lib/aarch64-linux-gnu/libc.so.6 src/fakelibc.c
    cp ../stubs/libmyexit.so.1 sysroot-x86_64/lib/x86_64-linux-gnu/
    gcc -O1 -fPIC -shared -s -Wl,-soname,libsteal.so.1 -Wl,--build-id=none \
        -o clean/libsteal.so.1 src/steal.c
    gcc -O1 -fPIC -shared -s -fno-builtin-exit -Wl,-soname,libsteal.so.1 -Wl,--build-id=none \
        -o steal/libsteal.so.1 src/steal_exit.c
    gcc -O1 -fno-inline -s -Wl,--build-id=none -Wl,--no-as-needed -o steal_consumer \
        src/steal_consumer.c clean/libsteal.so.1
    gcc -O1 -fPIC -shared -nostdlib -s -Wl,-soname,libvers.so.1 -Wl,--version-script,src/vers.map \
        -Wl,--build-id=none -o libvers.so.1 src/vers.c
    gcc -O1 -fPIC -shared -nostdlib -s -Wl,-soname,libhidden.so.1 \
        -Wl,--version-script,src/hidden.map -Wl,--build-id=none -o hidden/libhidden.so.1 src/hidden.c
    gcc -O1 -fPIC -shared -nostdlib -s -Wl,-soname,libb.so.1 -Wl,--build-id=none -Wl,--no-as-needed \
        -o chain/inner/libb.so.1 src/chain_b.c clean/libsteal.so.1
    gcc -O1 -fPIC -shared -nostdlib -s -Wl,-soname,liba.so.1 -Wl,--build-id=none \
        -Wl,--disable-new-dtags,-rpath,'$ORIGIN/inner' -Wl,--no-as-needed \
        -o chain/liba.so.1 src/chain_a.c chain/inner/libb.so.1
    cp steal/libsteal.so.1 chain/inner/libsteal.so.1
    gcc -O1 -fno-inline -s -Wl,--build-id=none -Wl,--no-as-needed -Wl,-rpath-link,chain/inner:clean \
        -o chain/chain_consumer src/chain_consumer.c chain/liba.so.1
    gcc -O1 -fno-inline -s -Wl,--build-id=none -Wl,--no-as-needed \
        -Wl,--enable-new-dtags,-rpath,'$ORIGIN/../private' \
        -o origin_consumer src/steal_consumer.c clean/libsteal.so.1
    gcc -O1 -fno-inline -s -Wl,--build-id=none -Wl,--no-as-needed \
        -Wl,--disable-new-dtags,-rpath,'/opt/missing::/opt/base' \
        -o empty_entry_consumer src/steal_consumer.c clean/libsteal.so.1
    gcc -O1 -fPIC -shared -nostdlib -fno-builtin -s -Wl,-soname,libaborts.so.1 -Wl,--build-id=none \
        -Wl,--no-as-needed -o libaborts.so.1 src/aborts.c sysroot-x86_64/lib/x86_64-linux-gnu/libc.so.6

`libaborts.so.1` (built twice, the bytes are the same; SHA-256
`355a906d5a0f788ebfd67c921dfcfe07110fa18c8846bbdc652876512af9337d`) is a shared library that imports
`abort@GLIBC_2.2.5`. glibc looks a library's references up in the global scope of the program that
loaded it first (`_dl_lookup_symbol_x`: the program's search list, then the library's local scope),
so where its `abort` binds is known only with that program.

`plugin/` holds a program and three libraries it could dlopen, built from `src/plugin/` (each built twice,
the bytes are the same):

    F="-O1 -fPIC -nostdlib -s -Wl,--build-id=none -Wl,--no-as-needed"
    gcc $F -shared -Wl,-soname,libdep.so.1 -o plugin/a/libdep.so.1 src/plugin/dep_a.c
    gcc $F -shared -Wl,-soname,libhelper.so.1 -o plugin/a/libhelper.so.1 src/plugin/helper.c
    gcc $F -shared -Wl,-soname,libdep.so.1 -o plugin/b/libdep.so.1 src/plugin/dep_b.c
    gcc $F -shared -Wl,-soname,libdep.so.1 -Wl,--disable-new-dtags,-rpath,/opt/vendor \
        -o plugin/rpath/libdep.so.1 src/plugin/dep_a.c
    gcc $F -pie -Wl,-e,_start -Wl,--disable-new-dtags,-rpath,'$ORIGIN/a' -o plugin/program \
        src/plugin/program.c plugin/a/libdep.so.1
    gcc $F -shared -Wl,-soname,libplugin_runpath.so.1 -Wl,--enable-new-dtags,-rpath,'$ORIGIN/b' \
        -o plugin/libplugin_runpath.so.1 src/plugin/plugin_runpath.c plugin/b/libdep.so.1
    gcc $F -shared -Wl,-soname,libplugin_rpath.so.1 -o plugin/libplugin_rpath.so.1 \
        src/plugin/plugin_rpath.c plugin/a/libhelper.so.1
    gcc $F -shared -Wl,-soname,libplugin_symbolic.so.1 -Wl,-Bsymbolic -o plugin/libplugin_symbolic.so.1 \
        src/plugin/plugin_symbolic.c plugin/a/libdep.so.1

Oracle, glibc 2.39's loader on the build host, through a host program with the same DT_RPATH
`$ORIGIN/a` and need `libdep.so.1` that dlopens each library (`RTLD_NOW | RTLD_LOCAL`):

- `libplugin_runpath.so.1`: `LD_DEBUG=files` shows one link map for `libdep.so.1`, the program's
  (`a/`); `b/libdep.so.1` is never opened, and `marker` is undefined.
- `libplugin_rpath.so.1`: `LD_DEBUG=libs` finds `libhelper.so.1` in `a/`, "RPATH from file" the
  executable.
- `libplugin_symbolic.so.1`: its `dep_a` call returns 5 (its own definition); the program's `dep_a`
  returns 1, and `libplugin_runpath.so.1`'s call returns 1 (the program's).

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

The search cases have their own oracle, glibc's loader with `LD_DEBUG=libs` on the build host:

- `chain/chain_consumer` (run with `LD_LIBRARY_PATH=chain`): `libb.so.1` has no search path, and
  the loader finds its `libsteal.so.1` through the DT_RPATH of `liba.so.1`, which loaded it:
  `search path=.../chain/inner (RPATH from file chain/liba.so.1)`.
- `origin_consumer` copied to `<dir>/bin` with `libsteal.so.1` in `<dir>/private`: `search
  path=<dir>/bin/../private (RUNPATH from file <dir>/bin/origin_consumer)`, after its
  `glibc-hwcaps/x86-64-v4`, `-v3` and `-v2` subdirectories.
- `empty_entry_consumer`: DT_RPATH `/opt/missing::/opt/base` is searched as `/opt/missing`, the
  working directory (the empty entry), then `/opt/base`.

| File | SHA-256 |
|---|---|
| `sysroot-x86_64/lib/x86_64-linux-gnu/libc.so.6` | `5c05f721501d40ef61e638da4c8fca1dcee644d686fde3dedc6a32848304010e` |
| `sysroot-x86_64/lib/x86_64-linux-gnu/libmyexit.so.1` | `76e666f442af3d61c8cc15d71bcf95e6cb8c1dfe3bda769ef0c7c8ac1e844ad6` (a copy of `../stubs/libmyexit.so.1`) |
| `sysroot-aarch64/lib/aarch64-linux-gnu/libc.so.6` | `30eb7faf79c149f87a19351a9d6cce50ab7039abd1340a3e4703115d95b11d69` |
| `clean/libsteal.so.1` | `81233b8b56fefd196370f957e7ef78ebc62a9c00d3608c0562fb66f330e41849` |
| `steal/libsteal.so.1` | `f9f740503b59e47bad5243636500b9bc7f4c191933dff1ca985211275a10316f` |
| `steal_consumer` | `95c2d42bdad2a76a503bfa53b7e97ea6f7d590b7bb4784994206ab7247a790d2` |
| `libvers.so.1` | `9efce0b3a3582636275194bc579fb3773dbaed09ead26923676d21c8e050d130` (`exit@V2` hidden at index 3, `exit@@V3` at index 4) |
| `hidden/libhidden.so.1` | `1dd49b3c8b4d8e88e717abd1134eaf80249fa08a06a9eaa62cc19e0453b1ac8d` (only the hidden `exit@V2`) |
| `chain/liba.so.1` | `18fac116597485065b3577e18c17eb7ba41b5fd24a34404d821de5501687d455` |
| `chain/inner/libb.so.1` | `353701f41c966fe77318c386b421608bb0e3f9ac9f313c2ff356d75114badb97` |
| `chain/inner/libsteal.so.1` | `f9f740503b59e47bad5243636500b9bc7f4c191933dff1ca985211275a10316f` (a copy of `steal/libsteal.so.1`) |
| `chain/chain_consumer` | `4bfc2307f9be4fad6f4c67e314b7ab7de97e4e756728b3ecd4edacaccac3e761` |
| `origin_consumer` | `7f69e37a91b854945ba2a647c84c3167f010ffb17ab9cbe87ba456736d374b1f` |
| `empty_entry_consumer` | `73a98acdc9410d22c7acb9cfc2639546c90c196114beda4337dee0f5268119c3` |

`steal_consumer` and the `libsteal.so.1` builds link glibc's startup objects and libgcc pieces, as
any GCC-built program does (see `../stubs/PROVENANCE.md`).

## musl (G22-T3)

`musl/stubs_musl_x86_64` is `../stubs/stubs.c` linked against musl with the `musl-tools` 1.2.4-2
package of Ubuntu 24.04 (its `musl-gcc` wraps GCC 13.3.0): DT_NEEDED `libc.so`, interpreter
`/lib/ld-musl-x86_64.so.1`. It links musl's startup objects (`crt1.o`, `crti.o`, `crtn.o`, MIT). In
`musl/sysroot-x86_64`, `lib/ld-musl-x86_64.so.1` is not musl: it is `src/fakelibc.c` built without a
SONAME or symbol versions, as musl's loader has neither, and is never run. Run from this directory:

    mkdir -p musl/sysroot-x86_64/lib
    gcc -O1 -fPIC -shared -nostdlib -fno-builtin -s -Wl,--build-id=none \
        -o musl/sysroot-x86_64/lib/ld-musl-x86_64.so.1 src/fakelibc.c
    musl-gcc -O1 -fno-inline -s -Wl,--build-id=none -o musl/stubs_musl_x86_64 ../stubs/stubs.c

Built twice; the bytes are the same.

| File | SHA-256 |
|---|---|
| `musl/stubs_musl_x86_64` | `157e0a93172dedb76c522ebda4832b0db19427db9183fe2e59a9b370ec698ce5` |
| `musl/sysroot-x86_64/lib/ld-musl-x86_64.so.1` | `6011cd5ecaaf9449a9a4427bfc26bbebfebef0cf206f217777349603f7f3c6b9` |
