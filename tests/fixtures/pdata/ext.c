/* The imported callee. Kept out of the fixture itself so hidden_fn really calls it. */
__declspec(dllexport) int ext_call(int x) { return x * 5 + 1; }
