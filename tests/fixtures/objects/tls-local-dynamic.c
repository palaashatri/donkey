/* Thread-local variables for the local-dynamic model (G15-T1). Written for this repository.
   Compiled with -fPIC -ftls-model=local-dynamic: each access is a call to __tls_get_addr for
   the module block, then a DTPOFF32 offset. The linked executable from `ld -static` is the
   oracle. */
static __thread int ld_counter = 5;
static __thread long ld_pair[2];

int read_ld(void) {
  return ld_counter + (int)ld_pair[1];
}
