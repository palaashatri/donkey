/* A global-dynamic access to a thread-local variable this object does not define (G15-T1).
   Written for this repository. A static link cannot relax it, so it stays unresolved. */
extern __thread int ext_tls;

int read_ext(void) {
  return ext_tls;
}
