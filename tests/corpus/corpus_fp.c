/* Floating-point corpus (G01-T2): scalar SSE code on x86-64.

   Every function has the same prototype, double f(double, double, double, double),
   so one native signature calls all of them and the arguments travel in xmm0-xmm3.
   Compiled with -O0 -fno-stack-protector -fno-math-errno -ffp-contract=off: no libm
   call remains (sqrt is one instruction), and no fused multiply-add is formed.
   Unary minus is avoided on purpose: at -O0 it is an xorpd with a packed mask,
   which the lifter does not model. */

double fp_add(double a, double b, double c, double d) {
  (void)c;
  (void)d;
  return a + b;
}

double fp_sub(double a, double b, double c, double d) {
  (void)c;
  (void)d;
  return a - b;
}

double fp_mul(double a, double b, double c, double d) {
  (void)c;
  (void)d;
  return a * b;
}

double fp_div(double a, double b, double c, double d) {
  (void)c;
  (void)d;
  return a / b;
}

double fp_poly(double a, double b, double c, double d) {
  return a * b + c * d;
}

double fp_hypot_sqrt(double a, double b, double c, double d) {
  (void)c;
  (void)d;
  return __builtin_sqrt(a * a + b * b);
}

double fp_lt(double a, double b, double c, double d) {
  (void)c;
  (void)d;
  return a < b ? 1.0 : 0.0;
}

double fp_eq_select(double a, double b, double c, double d) {
  return a == b ? c : d;
}

double fp_ne_select(double a, double b, double c, double d) {
  return a != b ? c : d;
}

double fp_max(double a, double b, double c, double d) {
  (void)c;
  (void)d;
  return a > b ? a : b;
}

double fp_min(double a, double b, double c, double d) {
  (void)c;
  (void)d;
  return a < b ? a : b;
}

double fp_truncate_int(double a, double b, double c, double d) {
  (void)b;
  (void)c;
  (void)d;
  return (double)(int)a;
}

double fp_scale_by_int(double a, double b, double c, double d) {
  int i = (int)b;
  (void)c;
  (void)d;
  return a * i;
}

double fp_through_single(double a, double b, double c, double d) {
  float f = (float)a;
  (void)b;
  (void)c;
  (void)d;
  return (double)f * 2.0;
}

double fp_single_add(double a, double b, double c, double d) {
  float x = (float)a;
  float y = (float)b;
  (void)c;
  (void)d;
  return (double)(x + y);
}

double fp_sum_array(double a, double b, double c, double d) {
  double v[4] = {a, b, c, d};
  double s = 0.0;
  for (int i = 0; i < 4; i++) {
    s += v[i];
  }
  return s;
}

double fp_dot3(double a, double b, double c, double d) {
  double v[3] = {a, b, c};
  double w[3] = {b, c, d};
  double s = 0.0;
  for (int i = 0; i < 3; i++) {
    s += v[i] * w[i];
  }
  return s;
}

double fp_branchy(double a, double b, double c, double d) {
  if (a > 0.0) {
    return a * 2.0;
  }
  if (b > 0.0) {
    return b * 3.0;
  }
  return c + d;
}

double fp_loop_reduce(double a, double b, double c, double d) {
  double r = a;
  for (int i = 0; i < 3; i++) {
    if (r > b) {
      r = r - b;
    } else {
      r = r + c;
    }
  }
  return r + d;
}

double fp_mean4(double a, double b, double c, double d) {
  return (a + b + c + d) / 4.0;
}

double fp_lerp(double a, double b, double c, double d) {
  (void)d;
  return a + (b - a) * c;
}

double fp_clamp01(double a, double b, double c, double d) {
  (void)b;
  (void)c;
  (void)d;
  if (a < 0.0) {
    return 0.0;
  }
  if (a > 1.0) {
    return 1.0;
  }
  return a;
}

double fp_capped_root(double a, double b, double c, double d) {
  double s = a * a + b * b;
  (void)c;
  (void)d;
  return s < 1.0 ? s : __builtin_sqrt(s);
}

double fp_int_quotient(double a, double b, double c, double d) {
  int n = (int)c;
  (void)b;
  return n != 0 ? a / (double)n : d;
}

double fp_compare_chain(double a, double b, double c, double d) {
  double low = a < b ? a : b;
  double high = a < b ? b : a;
  (void)c;
  (void)d;
  return high - low;
}

double fp_single_mix(double a, double b, double c, double d) {
  float x = (float)c;
  (void)d;
  return (double)(x * (float)a) + b;
}
