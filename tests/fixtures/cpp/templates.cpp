// Mangling fixture (G10-T1): class and function templates instantiated with many types.
template <typename T> struct Box {
  T value;
  Box() : value() {}
  explicit Box(T v) : value(v) {}
  T get() const { return value; }
  void set(T v) { value = v; }
  Box<T>* self() { return this; }
};
template <typename T, int N> struct Array {
  T data[N];
  T at(int i) const { return data[i]; }
};
template <typename T> T identity(T v) { return v; }
template <typename T, typename U> T convert(U u) { return static_cast<T>(u); }
template <typename... Ts> int count(Ts... args) { return sizeof...(Ts); }
template <typename T> void consume(const T& t) { (void)t; }
template <class T> struct Holder { template <typename U> static U pick(U u) { return u; } };

Box<int> b_int(3);
Box<char> b_char('c');
Box<long> b_long(5);
Box<unsigned> b_uint(7);
Box<short> b_short(1);
Box<bool> b_bool(true);
Box<float> b_float(1.0f);
Box<double> b_double(2.0);
Box<int*> b_intp(nullptr);
Box<const char*> b_cstr("x");
Box<Box<int>> b_nested;
Box<Box<Box<char>>> b_deep;
Array<int, 4> a_int;
Array<double, 2> a_double;
Array<Box<long>, 3> a_box;

int use_templates() {
  int r = b_int.get();
  r += b_char.get();
  r += (int)b_long.get();
  r += (int)b_uint.get();
  r += b_short.get();
  r += b_bool.get();
  r += (int)b_float.get();
  r += (int)b_double.get();
  r += b_intp.get() != nullptr;
  r += b_cstr.get()[0];
  r += b_nested.get().get();
  r += (int)b_deep.get().get().get();
  r += a_int.at(0);
  r += (int)a_double.at(1);
  r += (int)a_box.at(2).get();
  r += identity(1);
  r += identity('a');
  r += (int)identity(2L);
  r += (int)identity(3.0);
  r += (int)identity((unsigned char)4);
  r += (int)convert<long>(5.0);
  r += (int)convert<double>(6);
  r += count(1, 'a', 2.0);
  r += count();
  consume(r);
  consume(b_int);
  r += Holder<int>::pick(7);
  r += (int)Holder<char>::pick(8.0);
  return r;
}
