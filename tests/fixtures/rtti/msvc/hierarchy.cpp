// MSVC-ABI RTTI fixture probe: a polymorphic root, a single-inheritance child, and a class with
// two bases. No globals with constructors and no CRT: linked with /entry:main /nodefaultlib.
void* operator new(unsigned long long size);
void operator delete(void* p) noexcept;
void operator delete(void* p, unsigned long long) noexcept;
struct Shape {
  virtual ~Shape() {}
  virtual int area() const = 0;
  virtual const char* label() const { return "shape"; }
  int id = 0;
};
struct Named {
  virtual const char* name() const { return "named"; }
  virtual int rank() const { return 0; }
};
struct Square : Shape {
  int side = 1;
  int area() const override { return side * side; }
  const char* label() const override { return "square"; }
};
struct Cube : Square {
  int area() const override { return 1; }
};
struct Tagged : Shape, Named {
  int area() const override { return 2; }
  const char* name() const override { return "tagged"; }
};
extern "C" int main() {
  Square s;
  Tagged t;
  Cube c;
  Shape* a = &s;
  Shape* b = &t;
  Shape* c_as_shape = &c;
  return a->area() + b->area() + c_as_shape->area() - 5;
}
void* operator new(unsigned long long size) {
  (void)size;
  return nullptr;
}
void operator delete(void*) noexcept {}
void operator delete(void*, unsigned long long) noexcept {}
