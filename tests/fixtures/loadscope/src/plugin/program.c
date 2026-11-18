/* The program: DT_RPATH $ORIGIN/a, needs libdep.so.1. Never run. Written for Donkey's tests (MIT). */
int dep_a(void);
void _start(void) { dep_a(); for (;;) { } }
