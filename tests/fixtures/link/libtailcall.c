/* A function whose only transfer out is a tail call to an imported function. */
extern int imported_add(int);
int tail_fn(int x) { return imported_add(x + 1); }
int callee_fn(int x) { return x * 2; }
int use_callee(int x) { return callee_fn(x) + 1; }
