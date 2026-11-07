/* COMMON symbols (G15-T1). Tentative definitions with no initialiser, which -fcommon
   emits as SHN_COMMON symbols for the linker to place. Written for this repository. */
int shared_counter;
char shared_buffer[64];
long shared_wide;

int read_shared(void) { return shared_counter + shared_buffer[3]; }
void write_shared(long value) { shared_wide = value; }
