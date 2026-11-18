/* A plugin with no search path of its own that needs libhelper.so.1. Written for Donkey's tests (MIT). */
int helper(void);
int plugin_rpath(void) { return helper(); }
