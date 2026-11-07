/* Relocation fixture (G15-T1). Built with: cc -c -O0 -fno-pic -fno-stack-protector
 * -fcf-protection=none reloc.c -o reloc-x86_64.o. Written for this repository. */
int value = 42;
int *pointer = &value;

int global_helper(int x) { return x + 7; }
int call_global(int y) { return global_helper(y) * 2; }

extern int external_function(int);
int call_external(int z) { return external_function(z); }
