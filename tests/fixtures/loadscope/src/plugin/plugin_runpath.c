/* A plugin with DT_RUNPATH $ORIGIN/b that needs libdep.so.1. Written for Donkey's tests (MIT). */
int dep_a(void);
int plugin_runpath(void) { return dep_a(); }
