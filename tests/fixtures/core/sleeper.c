#include <signal.h>
#include <unistd.h>
volatile long marker = 0x5a5a1234;
__attribute__((noinline)) void park(long value) {
  marker = value;
  for (;;) pause();
}
int main(void) {
  park(0x1122334455667788L);
  return 0;
}
