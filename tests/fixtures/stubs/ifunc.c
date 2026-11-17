// Written for Donkey's tests (G24-T4): an exported ifunc called through its own PLT stub, whose
// GOT slot an IRELATIVE relocation fills. See PROVENANCE.md.
static int pick_one(int x) { return x + 1; }
static int (*resolve_pick(void))(int) { return pick_one; }
int pick(int x) __attribute__((ifunc("resolve_pick"), visibility("protected")));
int use_pick(int x) { return pick(x) * 3; }
