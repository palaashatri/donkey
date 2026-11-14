pdata-pe-x86_64.dll was built from pdata_fixture.c and ext.c (both in this directory) with
  x86_64-w64-mingw32-gcc -O2 -shared -o pdata-pe-x86_64.dll pdata_fixture.c ext.c -Wl,--no-insert-timestamp
(MinGW-w64 GCC; own source, no third-party code). The tests expect hidden_fn at 0x2c8251390,
exported_fn at 0x2c82513b0 and ext_call at 0x2c82513d0 (image base 0x2c8250000).
