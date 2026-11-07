/* An enum used by a struct field, for the PDB enumerator reader (G06). Written for this
   repository. Built for x86-64 Windows with clang and linked with lld-link /debug: the PDB is the
   oracle input. */
enum color { red, green = 5, blue };

struct paint {
  enum color color;
  int weight;
};

struct paint paint_value = {green, 3};

int paint_weight(struct paint *p) {
  return p->weight;
}

int paint_entry(void) {
  return paint_weight(&paint_value);
}
