/* Only the hidden exit@V2, with no default version: an unversioned reference must pass it by.
   Written for Donkey's tests (MIT). */
void exit_v2(int s) { (void)s; for (;;) { } }
__asm__(".symver exit_v2, exit@V2");
