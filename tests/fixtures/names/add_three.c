volatile int sink;
int take(int *p) { return *p; }
int add_three(int a) {
  int total = a;
  int *p = &total;
  *p += 3;
  sink = take(p);
  return sink;
}
int main(int argc, char **argv) {
  (void)argv;
  return add_three(argc);
}
