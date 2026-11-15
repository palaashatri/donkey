/* Decompiler differential corpus (M8). Built by the test suite at -O0, -O2
 * and -O3 with the host C compiler; each function is lifted from the built
 * library, run in the IR interpreter and compared with calling the compiled
 * function itself. Integer-only: floating point and SIMD are outside the
 * decompiler's supported subset. The calls section at the end calls helpers of
 * the same library (G21).
 *
 * Every function is exported, which also keeps compilers from cloning or
 * specialising it (an exported symbol can be interposed). */
#include <stdint.h>

#if defined(_WIN32)
#define CORPUS __declspec(dllexport) __declspec(noinline)
#else
#define CORPUS __attribute__((visibility("default"), noinline, used))
#endif

/* ---- integer arithmetic ---- */
CORPUS int c_add3(int a, int b, int c) {
  return a + b + c;
}
CORPUS long long c_add64(long long a, long long b) {
  return a + b;
}
CORPUS int c_sub_mul(int a, int b) {
  return (a - b) * 3;
}
CORPUS int c_mul_add(int a, int b, int c) {
  return a * b + c;
}
CORPUS unsigned c_mix(unsigned x) {
  return (x ^ (x >> 7)) * 0x9E3779B1u + 13u;
}
CORPUS uint64_t c_mix64(uint64_t x) {
  x ^= x >> 33;
  x *= 0xff51afd7ed558ccdULL;
  x ^= x >> 33;
  return x;
}
CORPUS int c_neg(int x) {
  return -x;
}
CORPUS unsigned c_not(unsigned x) {
  return ~x;
}
CORPUS int c_shifts(int x, int s) {
  return (x << 3) ^ (x >> (s & 7));
}
CORPUS unsigned c_ushift(unsigned x, unsigned s) {
  return x >> (s & 31u);
}
CORPUS unsigned c_rotl5(unsigned x) {
  return (x << 5) | (x >> 27);
}
CORPUS int c_trunc8(int x) {
  return (signed char)(x * 3);
}
CORPUS unsigned c_zext16(unsigned x) {
  return (unsigned short)(x + 1u);
}
CORPUS long long c_sext32(int x) {
  return (long long)x * 2;
}
CORPUS int c_lea_like(int a, int b) {
  return a * 5 + b * 8 + 7;
}

/* ---- branches ---- */
CORPUS int c_abs(int x) {
  return x < 0 ? -x : x;
}
CORPUS int c_max(int a, int b) {
  return a > b ? a : b;
}
CORPUS unsigned c_umin(unsigned a, unsigned b) {
  return a < b ? a : b;
}
CORPUS int c_clamp(int x, int lo, int hi) {
  if (x < lo) {
    return lo;
  }
  if (x > hi) {
    return hi;
  }
  return x;
}
CORPUS int c_sign(int x) {
  if (x > 0) {
    return 1;
  }
  if (x < 0) {
    return -1;
  }
  return 0;
}
CORPUS int c_classify(unsigned x) {
  if (x == 0) {
    return 10;
  }
  if (x < 16u) {
    return 20;
  }
  if (x >= 0x80000000u) {
    return 30;
  }
  return 40;
}
CORPUS int c_both(int a, int b) {
  return (a != 0 && b != 0) ? 7 : 3;
}

/* ---- loops ---- */
CORPUS unsigned c_popcount(unsigned x) {
  unsigned c = 0;
  while (x != 0) {
    c += x & 1u;
    x >>= 1;
  }
  return c;
}
CORPUS unsigned c_fib(unsigned n) {
  unsigned a = 0;
  unsigned b = 1;
  for (unsigned i = 0; i < (n & 63u); ++i) {
    const unsigned t = a + b;
    a = b;
    b = t;
  }
  return a;
}
CORPUS int c_sum_to(int n) {
  int s = 0;
  int i = 0;
  do {
    s += i;
    ++i;
  } while (i < (n & 1023));
  return s;
}
CORPUS unsigned c_collatz_steps(unsigned x) {
  unsigned steps = 0;
  x = (x & 0xffffu) | 1u;
  while (x != 1u && steps < 1000u) {
    x = (x & 1u) != 0 ? 3u * x + 1u : x >> 1;
    ++steps;
  }
  return steps;
}

/* ---- pointers and arrays (first argument points to 64 ints) ---- */
CORPUS unsigned c_sum_array(const unsigned* p, int n) {
  unsigned s = 0;
  for (int i = 0; i < n; ++i) {
    s += p[i];
  }
  return s;
}
CORPUS int c_dot(const int* a, const int* b, int n) {
  int s = 0;
  for (int i = 0; i < n; ++i) {
    s += a[i] * b[i];
  }
  return s;
}
CORPUS int c_count_eq(const int* p, int n, int v) {
  int c = 0;
  for (int i = 0; i < n; ++i) {
    if (p[i] == v) {
      ++c;
    }
  }
  return c;
}
CORPUS int c_index_of_max(const int* p, int n) {
  int best = 0;
  for (int i = 1; i < n; ++i) {
    if (p[i] > p[best]) {
      best = i;
    }
  }
  return best;
}
CORPUS unsigned c_bytes_sum(const unsigned char* p, int n) {
  unsigned s = 0;
  for (int i = 0; i < n; ++i) {
    s += p[i];
  }
  return s;
}
CORPUS void c_store_pair(int* out, int a, int b) {
  out[0] = a;
  out[1] = a + b;
}
CORPUS void c_fill(int* out, int n, int v) {
  for (int i = 0; i < n; ++i) {
    out[i] = v + i;
  }
}

/* ---- structs ---- */
struct corpus_point {
  int x;
  int y;
  long long z;
  unsigned char tag;
};
CORPUS long long c_point_sum(const struct corpus_point* p) {
  return p->x + 2LL * p->y + p->z + p->tag;
}
CORPUS void c_point_move(struct corpus_point* p, int dx) {
  p->x += dx;
  p->tag = (unsigned char)(p->tag + 1);
}

/* ---- switch ---- */
CORPUS int c_switch_dense(int x) {
  switch (x) {
    case 0:
      return 11;
    case 1:
      return 23;
    case 2:
      return 37;
    case 3:
      return 41;
    case 4:
      return 59;
    case 5:
      return 61;
    case 6:
      return 73;
    case 7:
      return 89;
    default:
      return -1;
  }
}
CORPUS int c_switch_sparse(int x) {
  switch (x) {
    case 1:
      return 5;
    case 10:
      return 6;
    case 100:
      return 7;
    case 1000:
      return 8;
    default:
      return 0;
  }
}

/* ---- ABI: more arguments than registers ---- */
CORPUS long long c_many_args(long long a, long long b, long long c, long long d, long long e,
                             long long f, long long g, long long h, long long i) {
  return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g + 8 * h + 9 * i;
}
CORPUS int c_narrow_args(signed char a, short b, unsigned char c, unsigned short d) {
  return a * 1000 + b + c + d;
}

/* ---- carry and borrow: 128-bit arithmetic from 64-bit halves (adc, sbb) ---- */
CORPUS unsigned long long c_add128_hi(unsigned long long alo, unsigned long long ahi,
                                      unsigned long long blo, unsigned long long bhi) {
  unsigned __int128 a = ((unsigned __int128)ahi << 64) | alo;
  unsigned __int128 b = ((unsigned __int128)bhi << 64) | blo;
  return (unsigned long long)((a + b) >> 64);
}
CORPUS unsigned long long c_sub128_hi(unsigned long long alo, unsigned long long ahi,
                                      unsigned long long blo, unsigned long long bhi) {
  unsigned __int128 a = ((unsigned __int128)ahi << 64) | alo;
  unsigned __int128 b = ((unsigned __int128)bhi << 64) | blo;
  return (unsigned long long)((a - b) >> 64);
}
CORPUS int c_add_wraps(unsigned long long x, unsigned long long y) {
  return x + y < x;
}

/* ---- double-width multiply and divide (mul, imul, div, idiv) ----
 * Division by zero and INT_MIN / -1 trap on x86, so the signed forms return 0
 * for them; the native code never traps. */
CORPUS unsigned long long c_mulhi_u64(unsigned long long a, unsigned long long b) {
  return (unsigned long long)(((unsigned __int128)a * b) >> 64);
}
CORPUS long long c_mulhi_s64(long long a, long long b) {
  return (long long)(((__int128)a * b) >> 64);
}
CORPUS unsigned int c_udiv32(unsigned int x, unsigned int y) {
  return y ? x / y : 0;
}
CORPUS unsigned int c_urem32(unsigned int x, unsigned int y) {
  return y ? x % y : 0;
}
CORPUS int c_sdiv32(int x, int y) {
  if (y == 0 || (y == -1 && x == (-2147483647 - 1))) {
    return 0;
  }
  return x / y;
}
CORPUS int c_srem32(int x, int y) {
  if (y == 0 || (y == -1 && x == (-2147483647 - 1))) {
    return 0;
  }
  return x % y;
}
CORPUS unsigned long long c_udiv64(unsigned long long x, unsigned long long y) {
  return y ? x / y : 0;
}
CORPUS unsigned long long c_urem64(unsigned long long x, unsigned long long y) {
  return y ? x % y : 0;
}
CORPUS long long c_sdiv64(long long x, long long y) {
  if (y == 0 || (y == -1 && x == (-9223372036854775807LL - 1))) {
    return 0;
  }
  return x / y;
}
CORPUS long long c_srem64(long long x, long long y) {
  if (y == 0 || (y == -1 && x == (-9223372036854775807LL - 1))) {
    return 0;
  }
  return x % y;
}
CORPUS unsigned long long c_div10(unsigned long long x) {
  return x / 10;
}

/* ---- bit operations: population count, bit scans, byte swap, bit test ----
 * The scans are guarded because the result of bsf and bsr is undefined for 0. */
CORPUS unsigned int c_popcount64(unsigned long long x) {
  return (unsigned int)__builtin_popcountll(x);
}
CORPUS unsigned int c_ctz64_guarded(unsigned long long x) {
  return x ? (unsigned int)__builtin_ctzll(x) : 64U;
}
CORPUS unsigned int c_clz64_guarded(unsigned long long x) {
  return x ? (unsigned int)__builtin_clzll(x) : 64U;
}
CORPUS unsigned int c_bswap32(unsigned int x) {
  return __builtin_bswap32(x);
}
CORPUS unsigned long long c_bswap64(unsigned long long x) {
  return __builtin_bswap64(x);
}
CORPUS int c_bit_test(unsigned long long x, unsigned int n) {
  return (int)((x >> (n & 63U)) & 1U);
}

/* ---- calls (G21) ----
 * The helpers are static and noinline: each call in a caller is direct (not through the PLT), and
 * the helper is a function of the same library, so the decompiler can take its signature. The
 * callers are exported like the rest of the corpus. */
#define CORPUS_HELPER static __attribute__((noinline, used))

CORPUS_HELPER int k_add2(int a, int b) {
  return a + b;
}

CORPUS_HELPER int k_six(int a, int b, int c, int d, int e, int f) {
  return a * 1 + b * 2 + c * 3 + d * 4 + e * 5 + f * 6;
}

CORPUS_HELPER int k_triple(int a) {
  return a * 3;
}

CORPUS_HELPER long k_wide(long a, long b) {
  return a * 7 - b;
}

/* The caller's result is the helper's result. */
CORPUS int c_call_add2(int a, int b) {
  return k_add2(a, b);
}

/* Six arguments, all in registers on System V. */
CORPUS int c_call_six(int a, int b, int c, int d, int e, int f) {
  return k_six(a, b, c, d, e, f) + 1;
}

/* The helper's result is not used: the caller's value comes from its own arithmetic. */
CORPUS int c_call_unused(int a) {
  (void)k_triple(a);
  return a + 2;
}

/* A call inside a loop, whose argument changes on each iteration. */
CORPUS int c_call_loop(int n) {
  int s = 0;
  for (int i = 0; i < n; ++i) {
    s = k_add2(s, i);
  }
  return s;
}

/* A 64-bit helper with two arguments and a 64-bit result. */
CORPUS long c_call_wide(long a, long b) {
  return k_wide(a, b) + k_wide(b, a);
}

/* A call whose result feeds a second call: the second call's argument is the first's result. */
CORPUS int c_call_chain(int a, int b) {
  return k_triple(k_add2(a, b));
}
