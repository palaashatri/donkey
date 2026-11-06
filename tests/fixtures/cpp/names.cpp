// Mangling fixture (G10-T1): namespaces, classes, operators, pointers and references.
// Written for this repository; compiled with g++ -std=c++17 -O0 -c by the corpus recipe.
namespace outer {
namespace inner {
int counter = 0;
struct Point {
  int x, y;
  Point() : x(0), y(0) {}
  Point(int a, int b) : x(a), y(b) {}
  ~Point() {}
  int sum() const { return x + y; }
  void move(int dx, int dy) { x += dx; y += dy; }
  Point operator+(const Point& o) const { return Point(x + o.x, y + o.y); }
  Point& operator+=(const Point& o) { x += o.x; y += o.y; return *this; }
  bool operator==(const Point& o) const { return x == o.x && y == o.y; }
  bool operator<(const Point& o) const { return x < o.x; }
  Point& operator[](int i) { return *this; }
  int operator()(int a, int b) const { return a * b; }
  explicit operator bool() const { return x != 0; }
  static Point origin() { return Point(); }
};
}  // namespace inner

int add(int a, int b) { return a + b; }
long mul(long a, long b) { return a * b; }
double scale(double v, float f) { return v * f; }
unsigned long long ull(unsigned long long a, unsigned short b, signed char c) { return a + b + c; }
bool flag(bool b, wchar_t w, char16_t c16, char32_t c32) { return b; }
void nothing() {}
void many(int a, char b, short c, long long d, unsigned e, unsigned long f, float g, double h,
          long double i, bool j, signed char k, unsigned char l) {}
int ptrs(const char* s, int* p, int& r, const int& cr, int** pp, char* const cp) { return 0; }
int arrays(int a[], int (*fp)(int), void (*vp)(char, double)) { return 0; }
void* voids(void* p, const void* cp, volatile int* vp, const volatile int* cvp) { return p; }
namespace {
int hidden(int x) { return x; }
}  // namespace
int call_hidden(int x) { return hidden(x); }
}  // namespace outer

struct Base {
  virtual ~Base() {}
  virtual int value() const { return 1; }
  virtual void set(int v) {}
  int plain() { return 2; }
};
struct Derived : Base {
  int value() const override { return 3; }
  void set(int v) override {}
  virtual int extra(double d) { return 4; }
};
int use_base(Base* b) { return b->value(); }
int use_derived(Derived& d) { return d.extra(1.5); }
