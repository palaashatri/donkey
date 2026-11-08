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
