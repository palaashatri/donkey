// A shared library with C++ exports, for the demangled-name output (G10-T4).
namespace shapes {
struct Box {
  int width;
};
int area(const Box& box, int scale) {
  return box.width * scale;
}
}  // namespace shapes
extern "C" int plain_export(int x) {
  return x + 1;
}
int shapes_total(int a, int b) {
  return a + b;
}
