/* libsteal.so.1 as a later build of it: an unversioned exit that returns. A program linked
   against steal.c imports exit@GLIBC_2.2.5 from libc.so.6, yet the loader binds it here, because
   libsteal.so.1 comes first in DT_NEEDED and exports an unversioned exit. Written for Donkey's tests (MIT). */
#include <stdio.h>
int steal_marker(void) { return 1; }
void exit(int status) { fprintf(stderr, "libsteal exit(%d) returned\n", status); }
