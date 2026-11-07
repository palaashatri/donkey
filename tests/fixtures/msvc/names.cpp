// MSVC name-mangling corpus (G10-T2). Compiled for x86-64 Windows with clang:
//   clang++ --target=x86_64-pc-windows-msvc -fno-exceptions -fno-rtti -c names.cpp
// and the mangled symbols are paired with llvm-undname output in msvc-pairs.txt.
// Written for this repository; it uses no standard library headers.

namespace ns {

struct Box {
  int value;
  Box();
  ~Box();
  Box& operator=(const Box& other);
  Box operator+(int delta) const;
  int get(int a) const;
  void set(int a);
  volatile int* ptr_volatile(volatile int* p) volatile;
  static int count(void);
  static void reset(double d);
  virtual void draw(char* target);

 protected:
  int protected_member(long n);

 private:
  void private_member(unsigned int u);
};

enum class Mode : int { Off, On };

union Variant {
  int i;
  float f;
};

struct Pair {
  int first;
  int second;
};

}  // namespace ns

ns::Box::Box() : value(0) {}
ns::Box::~Box() {}
ns::Box& ns::Box::operator=(const ns::Box& other) {
  value = other.value;
  return *this;
}
ns::Box ns::Box::operator+(int delta) const {
  Box b;
  b.value = value + delta;
  return b;
}
int ns::Box::get(int a) const {
  return value + a;
}
void ns::Box::set(int a) {
  value = a;
}
volatile int* ns::Box::ptr_volatile(volatile int* p) volatile {
  return p;
}
int ns::Box::count(void) {
  return 1;
}
void ns::Box::reset(double d) {
  (void)d;
}
void ns::Box::draw(char* target) {
  (void)target;
}
int ns::Box::protected_member(long n) {
  return (int)n;
}
void ns::Box::private_member(unsigned int u) {
  (void)u;
}

void free_fn(int, char*, const unsigned long long&);
void plain(void);
int add_longs(long a, unsigned long b, long long c, unsigned long long d);
float scale(float f, double g);
bool check(bool flag, wchar_t wide, signed char sc, unsigned char uc, short s, unsigned short us);
char* first_char(char* text, const char* end);
const char* name_of(const ns::Box& box, ns::Mode mode);
ns::Pair make_pair(int a, int b);
void take_pair(ns::Pair p);
void take_union(ns::Variant v);
void take_rvalue(int&& r);
int** double_pointer(int** pp);
void array_param(int values[4], const int matrix[2][3]);
void variadic(const char* fmt, ...);
int g_value = 3;
const char* g_text = "text";
ns::Box g_box;
ns::Mode g_mode = ns::Mode::On;
static int s_hidden = 5;
int* g_pointer;
const int g_const_array[3] = {1, 2, 3};

void use_all(ns::Box* box, double d) {
  box->get(1);
  box->set(2);
  free_fn(1, nullptr, 0);
  plain();
  (void)add_longs(1, 2, 3, 4);
  (void)scale(1.0f, d);
  (void)check(true, 'a', 1, 2, 3, 4);
  (void)first_char(nullptr, nullptr);
  (void)name_of(*box, ns::Mode::Off);
  (void)make_pair(1, 2);
  take_pair(ns::Pair{1, 2});
  ns::Variant v;
  take_union(v);
  int r = 1;
  take_rvalue(static_cast<int&&>(r));
  int* p = nullptr;
  double_pointer(&p);
  int values[4] = {0, 0, 0, 0};
  int matrix[2][3] = {{0}};
  array_param(values, matrix);
  variadic("x", 1);
}

// Operators, storage classes and qualifiers (G10-T2). Each operator is declared and defined
// so that its symbol is emitted for the corpus.
namespace ops {

struct Ops {
  Ops& operator=(const Ops&) = default;
  Ops operator+(const Ops&) const;
  Ops operator-(const Ops&) const;
  Ops operator*(const Ops&) const;
  Ops operator/(const Ops&) const;
  Ops operator%(const Ops&) const;
  Ops operator&(const Ops&) const;
  Ops operator|(const Ops&) const;
  Ops operator^(const Ops&) const;
  Ops operator<<(const Ops&) const;
  Ops operator>>(const Ops&) const;
  Ops& operator+=(const Ops&);
  Ops& operator-=(const Ops&);
  Ops& operator*=(const Ops&);
  Ops& operator/=(const Ops&);
  Ops& operator%=(const Ops&);
  Ops& operator&=(const Ops&);
  Ops& operator|=(const Ops&);
  Ops& operator^=(const Ops&);
  Ops& operator<<=(const Ops&);
  Ops& operator>>=(const Ops&);
  Ops& operator++();
  Ops operator++(int);
  Ops& operator--();
  Ops operator--(int);
  Ops operator-() const;
  Ops operator+() const;
  Ops operator~() const;
  bool operator!() const;
  bool operator==(const Ops&) const;
  bool operator!=(const Ops&) const;
  bool operator<(const Ops&) const;
  bool operator<=(const Ops&) const;
  bool operator>(const Ops&) const;
  bool operator>=(const Ops&) const;
  bool operator&&(const Ops&) const;
  bool operator||(const Ops&) const;
  Ops& operator,(const Ops&);
  int operator[](int) const;
  int operator()(int, int) const;
  Ops* operator->() const;
  int Ops::* operator->*(int Ops::*) const;
  static void* operator new(unsigned long long);
  static void operator delete(void*);
  static void* operator new[](unsigned long long);
  static void operator delete[](void*);
  ~Ops();
  Ops();
  int shared_value;
  static int shared;
  static const int kLimit = 4;
  void cv_method() const volatile;
  void volatile_method() volatile;
  static void protected_static();
  virtual void private_virtual_base();

 protected:
  static void protected_static_method();
  virtual void protected_virtual();

 private:
  virtual void private_virtual();
  static void private_static();
};

Ops Ops::operator+(const Ops&) const {
  return Ops();
}
Ops Ops::operator-(const Ops&) const {
  return Ops();
}
Ops Ops::operator*(const Ops&) const {
  return Ops();
}
Ops Ops::operator/(const Ops&) const {
  return Ops();
}
Ops Ops::operator%(const Ops&) const {
  return Ops();
}
Ops Ops::operator&(const Ops&) const {
  return Ops();
}
Ops Ops::operator|(const Ops&) const {
  return Ops();
}
Ops Ops::operator^(const Ops&) const {
  return Ops();
}
Ops Ops::operator<<(const Ops&) const {
  return Ops();
}
Ops Ops::operator>>(const Ops&) const {
  return Ops();
}
Ops& Ops::operator+=(const Ops&) {
  return *this;
}
Ops& Ops::operator-=(const Ops&) {
  return *this;
}
Ops& Ops::operator*=(const Ops&) {
  return *this;
}
Ops& Ops::operator/=(const Ops&) {
  return *this;
}
Ops& Ops::operator%=(const Ops&) {
  return *this;
}
Ops& Ops::operator&=(const Ops&) {
  return *this;
}
Ops& Ops::operator|=(const Ops&) {
  return *this;
}
Ops& Ops::operator^=(const Ops&) {
  return *this;
}
Ops& Ops::operator<<=(const Ops&) {
  return *this;
}
Ops& Ops::operator>>=(const Ops&) {
  return *this;
}
Ops& Ops::operator++() {
  return *this;
}
Ops Ops::operator++(int) {
  return Ops();
}
Ops& Ops::operator--() {
  return *this;
}
Ops Ops::operator--(int) {
  return Ops();
}
Ops Ops::operator-() const {
  return Ops();
}
Ops Ops::operator+() const {
  return Ops();
}
Ops Ops::operator~() const {
  return Ops();
}
bool Ops::operator!() const {
  return false;
}
bool Ops::operator==(const Ops&) const {
  return true;
}
bool Ops::operator!=(const Ops&) const {
  return false;
}
bool Ops::operator<(const Ops&) const {
  return false;
}
bool Ops::operator<=(const Ops&) const {
  return false;
}
bool Ops::operator>(const Ops&) const {
  return false;
}
bool Ops::operator>=(const Ops&) const {
  return false;
}
bool Ops::operator&&(const Ops&) const {
  return false;
}
bool Ops::operator||(const Ops&) const {
  return false;
}
Ops &Ops::operator,(const Ops&) {
  return *this;
}
int Ops::operator[](int i) const {
  return i;
}
int Ops::operator()(int a, int b) const {
  return a + b;
}
Ops* Ops::operator->() const {
  return nullptr;
}
int Ops::* Ops::operator->*(int Ops::* m) const {
  return m;
}
void* Ops::operator new(unsigned long long n) {
  return (void*)n;
}
void Ops::operator delete(void* p) {
  (void)p;
}
void* Ops::operator new[](unsigned long long n) {
  return (void*)n;
}
void Ops::operator delete[](void* p) {
  (void)p;
}
Ops::~Ops() {}
Ops::Ops() : shared_value(0) {}
int Ops::shared = 1;
void Ops::cv_method() const volatile {}
void Ops::volatile_method() volatile {}
void Ops::protected_static() {}
void Ops::private_virtual_base() {}
void Ops::protected_static_method() {}
void Ops::protected_virtual() {}
void Ops::private_virtual() {}
void Ops::private_static() {}

char* const g_const_pointer = nullptr;
const int g_const_int = 4;
int ops_use(Ops* o) {
  o->protected_static();
  return o->shared_value;
}

}  // namespace ops
