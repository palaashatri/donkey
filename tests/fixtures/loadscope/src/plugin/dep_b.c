/* Another libdep.so.1, in the plugin's DT_RUNPATH: dep_a and marker. glibc never loads it when the
   program has already loaded a libdep.so.1. Written for Donkey's tests (MIT). */
int dep_a(void) { return 2; }
int marker(void) { return 3; }
