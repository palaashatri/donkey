/* A small program with debug information for the compressed-section test (G07). Written for
   this repository. Built with -O0 -g and, for the test, with the debug sections compressed by
   objcopy --compress-debug-sections=zlib; the plain and compressed files must read the same. */
struct point {
  int x;
  int y;
  long tag;
};

enum shade { SHADE_LOW, SHADE_HIGH = 7 };

static int scale(struct point *p, int factor) {
  p->x *= factor;
  p->y *= factor;
  return p->x + p->y;
}

int sample_entry(int value) {
  struct point p = {value, value + 1, 3};
  enum shade s = value > 0 ? SHADE_HIGH : SHADE_LOW;
  return scale(&p, (int)s) + (int)p.tag;
}
