/* Library functions for the signature generator tests (G09-T2). Written for this repository. */

extern int sig_external(int x);

static const int sig_table[4] = {2, 3, 5, 7};

/* Static (local) helper: not a global function, so the generator must not name it. */
__attribute__((noinline)) static int sig_local(int x) { return x * 3; }

int sig_add(int a, int b) { return a + b; }

int sig_mul(int a, int b) { return a * b; }

/* Reads a table in .rodata and calls a local helper, so it has relocations to both. */
int sig_lookup(int i) { return sig_table[i & 3] + sig_local(i); }

/* Calls a function the object does not define: a relocation to an external symbol. */
int sig_call_external(int x) { return sig_external(x) + 1; }
