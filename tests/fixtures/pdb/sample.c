/* A small freestanding program for the PDB reader (G06). Written for this repository. Built
   for x86-64 Windows with clang and linked with lld-link /debug: the PDB is the oracle input. */
struct point {
  int x;
  int y;
  long tag;
};

int shared_total = 5;

static int scale(struct point *p, int factor) {
  p->x *= factor;
  p->y *= factor;
  return p->x + p->y;
}

int sample_entry(int value) {
  struct point p = {value, value + 1, 3};
  shared_total += value;
  return scale(&p, 2) + (int)p.tag;
}
