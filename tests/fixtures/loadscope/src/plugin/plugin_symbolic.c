/* A plugin linked with -Bsymbolic that defines dep_a itself and needs libdep.so.1. Written for
   Donkey's tests (MIT). */
int dep_a(void) { return 5; }
int plugin_symbolic(void) { return dep_a(); }
