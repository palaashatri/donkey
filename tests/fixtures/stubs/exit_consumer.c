// Written for Donkey's tests (G24-T3): calls `exit` and then goes on. Linked against libmyexit.so.1
// before the C library, so its `exit` is that library's (unversioned), which returns: the call
// must keep its fall-through. See PROVENANCE.md.
void exit(int status);

int after_exit(int value) {
  exit(value);
  return value + 7;
}

int main(int argc, char** argv) {
  (void)argv;
  return after_exit(argc);
}
