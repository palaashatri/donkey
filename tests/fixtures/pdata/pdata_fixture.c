/* A PE x64 DLL for the .pdata reader. hidden_fn is never called and never exported, so only its
   RUNTIME_FUNCTION entry names it. ext_call forces a stack frame, so hidden_fn gets unwind data. */
extern int ext_call(int);
__attribute__((used)) static int hidden_fn(int x) {
  int a[4] = {x, x + 1, x + 2, x + 3};
  return ext_call(a[0]) + a[3];
}
__declspec(dllexport) int exported_fn(int x) { return x * 3 + ext_call(x); }
