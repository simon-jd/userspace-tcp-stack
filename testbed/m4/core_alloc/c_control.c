// Independent C translation unit. Volatile storage and -fno-builtin retain
// direct ELF references to the libc allocation functions in the executable.
#define _GNU_SOURCE
#include <malloc.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct counts { uint64_t entries[17], outer[17]; };
extern void utcp_heap_start(void);
extern void utcp_heap_stop(struct counts *);
extern void utcp_heap_sites(bool);
int main(void) {
  void *volatile p[9];
  void *aligned = NULL;
  struct counts observed;
  utcp_heap_sites(false);
  utcp_heap_start();
  p[0] = malloc(128);
  p[1] = calloc(1,128);
  p[2] = realloc(NULL,128);
  p[3] = aligned_alloc(64,128);
  if (posix_memalign(&aligned,64,128)) return 1;
  p[4] = aligned;
  p[5] = memalign(64,128);
  p[6] = valloc(128);
  p[7] = pvalloc(128);
  p[8] = reallocarray(NULL,1,128);
  utcp_heap_stop(&observed);
  for (unsigned i=0;i<17;++i) {
    printf("%u,%llu,%llu\n",i,(unsigned long long)observed.entries[i],
           (unsigned long long)observed.outer[i]);
    if (observed.outer[i] != (i>=8)) return 2;
  }
  for (unsigned i=0;i<9;++i) {
    if (!p[i]) return 3;
    free(p[i]);
  }
}
