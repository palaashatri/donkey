// Written for Donkey's tests (G24-T3): a library that exports its own `exit`, which returns.
// See PROVENANCE.md.
int exit_calls = 0;
void exit(int status) { exit_calls += status; }
