/* Data-access relocations for the AArch64 page and low-12-bit forms and the
   absolute data forms (G15-T1). Each function reads or writes one global of a
   different size, and one takes the address of a static table, so the object
   carries ADRP/ADD/LDR/STR relocations. The 16 KiB buffer between the globals puts
   the data at least four pages from the code, so the page term of ADRP is not zero. */
int counter;
short half = 3;
unsigned char spacer[16384] = {1};
unsigned char byte_value = 5;
long long wide = 7;
float ratio = 1.5f;
static int table[4] = {1, 2, 3, 4};
int *table_pointer = table;

int read_counter(void) { return counter; }
void write_counter(int value) { counter = value; }
short read_half(void) { return half; }
unsigned char read_byte(void) { return byte_value; }
long long read_wide(void) { return wide; }
int *address_of_table(void) { return table; }
int read_table(int index) { return table[index & 3]; }
