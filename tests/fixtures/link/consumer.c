// Imports one name that the needed library exports, and one that nothing exports.
extern int provided_fn(int);
extern int missing_fn(int);
int consumer_fn(int x) { return provided_fn(x) + missing_fn(x); }
