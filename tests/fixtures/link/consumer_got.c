// Calls two imports through the GOT, as -fno-plt code does, and takes the address of one import
// without calling it. It also calls a function it defines itself, through a PLT stub (with
// -fsemantic-interposition), and takes that function's address, which is a GOT slot.
extern int provided_fn(int);
extern int missing_fn(int);
int (*address_of_provided(void))(int) { return provided_fn; }
int own_fn(int x) { return x * 2; }
int (*address_of_own(void))(int) { return own_fn; }
int got_consumer_fn(int x) { return provided_fn(x) + missing_fn(x) + own_fn(x); }
