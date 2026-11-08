// Mangling fixture (G10-T1): every overloadable operator, conversions and literals.
// Written for this repository.
struct Num {
  int v;
  Num operator-() const { return Num{-v}; }
  Num operator+(Num o) const { return Num{v + o.v}; }
  Num operator-(Num o) const { return Num{v - o.v}; }
  Num& operator+=(Num o) {
    v += o.v;
    return *this;
  }
  Num operator!() const { return Num{!v}; }
  Num operator~() const { return Num{~v}; }
  Num& operator++() {
    ++v;
    return *this;
  }
  Num operator++(int) { return Num{v++}; }
  Num& operator--() {
    --v;
    return *this;
  }
  Num operator--(int) { return Num{v--}; }
  Num operator*(Num o) const { return Num{v * o.v}; }
  Num operator/(Num o) const { return Num{v / o.v}; }
  Num operator%(Num o) const { return Num{v % o.v}; }
  Num operator&(Num o) const { return Num{v & o.v}; }
  Num operator|(Num o) const { return Num{v | o.v}; }
  Num operator^(Num o) const { return Num{v ^ o.v}; }
  Num operator<<(int s) const { return Num{v << s}; }
  Num operator>>(int s) const { return Num{v >> s}; }
  Num& operator*=(Num o) {
    v *= o.v;
    return *this;
  }
  Num& operator/=(Num o) {
    v /= o.v;
    return *this;
  }
  Num& operator%=(Num o) {
    v %= o.v;
    return *this;
  }
  Num& operator&=(Num o) {
    v &= o.v;
    return *this;
  }
  Num& operator|=(Num o) {
    v |= o.v;
    return *this;
  }
  Num& operator^=(Num o) {
    v ^= o.v;
    return *this;
  }
  Num& operator<<=(int s) {
    v <<= s;
    return *this;
  }
  Num& operator>>=(int s) {
    v >>= s;
    return *this;
  }
  Num& operator-=(Num o) {
    v -= o.v;
    return *this;
  }
  bool operator!=(Num o) const { return v != o.v; }
  bool operator>(Num o) const { return v > o.v; }
  bool operator<=(Num o) const { return v <= o.v; }
  bool operator>=(Num o) const { return v >= o.v; }
  bool operator&&(Num o) const { return v && o.v; }
  bool operator||(Num o) const { return v || o.v; }
  Num* operator->() { return this; }
  int& operator->*(int Num::* m) { return this->*m; }
  void* operator new(unsigned long n) { return ::operator new(n); }
  void operator delete(void* p) { ::operator delete(p); }
  void* operator new[](unsigned long n) { return ::operator new[](n); }
  void operator delete[](void* p) { ::operator delete[](p); }
  operator int() const { return v; }

  Num operator,(Num o) const { return o; }
};
Num operator""_num(unsigned long long n) {
  return Num{(int)n};
}
int use_all(Num a, Num b) {
  Num c = -a;
  c = a * b + a / b - a % b + (a & b) + (a | b) + (a ^ b);
  c = (a << 1) >> 1;
  c += a;
  c -= b;
  c *= a;
  c /= b;
  c %= a;
  c &= a;
  c |= b;
  c ^= a;
  c <<= 1;
  c >>= 1;
  return (int)c + (a != b) + (a > b) + (a <= b) + (a >= b) + (a && b) + (a || b);
}
int main_like(int argc) {
  int Num::* member = &Num::v;
  Num n{argc};
  return n.*member + n.operator int();
}
