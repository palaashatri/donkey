/* G23-T3 fixture: a function reached only through a pointer in data. Stripped, its start is
   known only from LC_FUNCTION_STARTS. */
static int doubled(int x) { return x * 2; }
static int tripled(int x) { return x * 3; }
int (*const table[2])(int) = {doubled, tripled};
int run(int which, int x) { return table[which & 1](x); }
int main(void) { return run(0, 1); }
