/* A static program that uses a spread of musl's C library (G09-T3). Written for this repository.
 * The signature test identifies the library functions it links, and compares the names with the
 * symbols of the unstripped build recorded in symbols.txt. */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int compare_ints(const void *a, const void *b) {
  int x = *(const int *)a;
  int y = *(const int *)b;
  return (x > y) - (x < y);
}

int main(int argc, char **argv) {
  int values[16];
  char buffer[64];
  int i;
  for (i = 0; i < 16; i++) {
    values[i] = (int)((i * 37) % 23);
  }
  qsort(values, 16, sizeof values[0], compare_ints);
  char *copy = malloc(64);
  if (copy == NULL) {
    return 2;
  }
  memset(buffer, 0, sizeof buffer);
  memcpy(buffer, argv[0] ? argv[0] : "x", 1);
  strcpy(copy, buffer);
  strcat(copy, "-");
  long parsed = strtol("1234", NULL, 10);
  int matched = strcmp(copy, "x-") == 0;
  char *where = strchr(copy, '-');
  char *found = strstr(copy, "-");
  size_t length = strlen(copy) + (where != NULL) + (found != NULL) + (size_t)parsed % 3;
  free(copy);
  if (argc > 5) {
    write(1, buffer, (size_t)(argc & 7));
  }
  return (int)(length + (size_t)matched + (size_t)values[0] + (size_t)abs(-1) * 0);
}
