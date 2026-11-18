/* liba.so.1: needs libb.so.1 and has DT_RPATH $ORIGIN/inner, which libb.so.1 inherits when it
   looks for its own needs. Written for Donkey's tests (MIT). */
int chain_b(void);
int chain_a(void) { return chain_b() + 1; }
