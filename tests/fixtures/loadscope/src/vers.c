/* Two versions of exit: the hidden exit@V2 and the default exit@@V3, for the glibc lookup rules.
   Written for Donkey's tests (MIT). */
void exit_v2(int s) { (void)s; for (;;) { } }
void exit_v3(int s) { (void)s; for (;;) { } }
__asm__(".symver exit_v2, exit@V2");
__asm__(".symver exit_v3, exit@@V3");
