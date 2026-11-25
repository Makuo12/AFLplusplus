/* Stand-in trap target as a shared library: the runtime attaches to the two
   maps in a constructor (env vars set by afl-fuzz before dlopen), traps
   report first hits in trace[0], and some inputs crash, hang or print. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>

static unsigned *trace, *virgin;

__attribute__((constructor)) static void runtime_init(void) {
  char *s = getenv("__AFL_SHM_ID"), *v = getenv("__AFL_TRAP_VIRGIN_SHM_ID");
  if (!s || !v) {
    fprintf(stderr, "runtime: no shm ids\n");
    abort();
  }
  trace = shmat(atoi(s), NULL, 0);
  virgin = shmat(atoi(v), NULL, 0);
}

static void trap(unsigned id) {
  id &= 0xffff;
  if (!virgin[id]) {
    virgin[id] = 1;
    trace[0]++;
  }
}

static int deep(int n) {
  volatile char pad[256];
  pad[0] = n;
  return n ? deep(n + 1) + pad[0] : 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *b, size_t n) {
  printf("target says hello\n"); /* must not reach the UI */
  trap(1);
  if (n >= 2) {
    trap(200 + b[0]);
    if (b[0] == 'S' && b[1] == 'V') {
      trap(2);
      *(volatile int *)0 = 1;
    } /* SIGSEGV */
    if (b[0] == 'R' && b[1] == 'C') {
      trap(3);
      return deep(1);
    } /* stack overflow */
    if (b[0] == 'H' && b[1] == 'G') {
      trap(4);
      for (;;) {}
    } /* hang */
  }
  const char *magic = "FUZZ!";
  for (size_t i = 0; i < n && i < 5; i++) {
    trap(1000 + i * 256 + b[i]);
    if (b[i] != (unsigned char)magic[i]) return 0;
    trap(10 + i);
  }
  if (n >= 5) abort(); /* SIGABRT */
  return 0;
}