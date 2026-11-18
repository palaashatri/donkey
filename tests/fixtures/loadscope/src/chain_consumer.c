/* Needs liba.so.1, which loads libb.so.1, which loads libsteal.so.1. Written for Donkey's tests (MIT). */
int chain_a(void);
int main(void) { return chain_a(); }
