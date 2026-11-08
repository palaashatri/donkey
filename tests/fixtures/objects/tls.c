/* Thread-local variables for the TLS relocation forms (G15-T1). Written for this repository.
   Compiled to objects with -ftls-model=local-exec (TPOFF32) and -ftls-model=initial-exec
   (GOTTPOFF). The linked executables are the oracle: ld lays out the TLS block itself. */
__thread int tls_counter = 7;
__thread long tls_pair[2];
__thread char tls_byte = 3;

int read_tls(void) {
  return tls_counter + (int)tls_pair[1] + tls_byte;
}

void write_tls(int value) {
  tls_counter = value;
  tls_pair[1] = value;
}
