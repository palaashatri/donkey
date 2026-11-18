/* libb.so.1: needs libsteal.so.1 and has no search path of its own. Written for Donkey's tests (MIT). */
int steal_marker(void);
int chain_b(void) { return steal_marker() + 1; }
