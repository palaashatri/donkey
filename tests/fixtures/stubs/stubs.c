// Written for Donkey's tests (G24-T4): calls to two imports, one of them no-return. See PROVENANCE.md.
#include <stdio.h>
#include <stdlib.h>

int check(int value) {
  if (value < 0) {
    abort();
  }
  return value * 2;
}

int show(const char* text) { return puts(text); }

int main(int argc, char** argv) {
  (void)argv;
  show("stub fixture");
  return check(argc);
}
