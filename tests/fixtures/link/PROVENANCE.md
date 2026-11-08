# Link fixtures

Shared objects for `tests/unit/link_test.cpp`. Each source was written for this repository.
They were built with Clang 18.1.3 on x86-64 Linux, with lld:

    clang-18 -shared -fPIC -O1 -fuse-ld=lld -Wl,-soname,libprovider.so.1 -o libprovider.so.1 provider.c
    clang-18 -shared -fPIC -O1 -fuse-ld=lld -Wl,-soname,libother.so.1 -o libother.so.1 other.c
    clang-18 -shared -fPIC -O1 -fuse-ld=lld -o libconsumer.so consumer.c ./libprovider.so.1

`libprovider.so.1` exports `provided_fn` and `provided_value`. `libother.so.1` exports a second
`provided_fn`, which the consumer does not need. `libconsumer.so` needs `libprovider.so.1` (and
`libc.so.6`, which Clang adds), imports `provided_fn`, and imports `missing_fn`, which no fixture
exports.

## AArch64 (`aarch64/`)

The same sources, built for AArch64 with Branch Target Identification, with no C library
(`-nostdlib`, so no `DT_NEEDED` on libc), so the PLT entries are the BTI form that lld 18 emits:

    clang-18 --target=aarch64-linux-gnu -O1 -fPIC -shared -nostdlib -mbranch-protection=bti \
      -fuse-ld=lld -Wl,-soname,libprovider.so.1 -o aarch64/libprovider.so.1 provider.c
    clang-18 --target=aarch64-linux-gnu -O1 -fPIC -shared -nostdlib -mbranch-protection=bti \
      -fuse-ld=lld -o aarch64/libconsumer.so consumer.c ./aarch64/libprovider.so.1

Under lld 18 the stubs in `.plt` are 24 bytes apart (each starts with an `adrp`), not 16, so the
two imports of `libconsumer.so` sit at offsets that a 16-byte scan misses.
