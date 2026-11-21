/* A Mach-O relocatable object for the analysis (G24): its __text section starts at address 0. */
int add(int a, int b) { return a + b; }
static int square(int x) { return x * x; }
int use(int x) { return square(x) + add(x, 1); }
