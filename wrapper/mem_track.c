#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "global.h" /* also declares __real_malloc / __real_free */

/*
 * Tracks heap blocks allocated during one persistent iteration and frees
 * the survivors on reset.
 *
 * Link with:
 *   -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc -Wl,--wrap=free
 *   -Wl,--wrap=reallocarray -Wl,--wrap=memalign -Wl,--wrap=aligned_alloc
 *   -Wl,--wrap=posix_memalign -Wl,--wrap=valloc -Wl,--wrap=pvalloc
 *   -Wl,--wrap=strdup -Wl,--wrap=strndup
 *   -Wl,--wrap=getline -Wl,--wrap=getdelim
 *
 * Bookkeeping uses __real_malloc/__real_calloc/__real_free only, so it never
 * recurses into the wrappers and is never tracked itself. This file must NOT
 * go through CloneGlobalsPass.
 *
 * Table: open addressing instead of uthash.
 *   - The table is a plain array of the tracked pointers themselves
 *     (8 bytes per slot, 0 = empty), no per-block nodes.
 *   - Home slot by Fibonacci hashing: top bits of p * 2^64/phi, which spreads
 *     16-byte-aligned heap pointers evenly over the slots.
 *   - Collisions by linear probing; the table doubles when more than half
 *     full, so probe sequences stay short and usually stay in one cache line.
 *   - Deletion by backward shift (Knuth's algorithm for linear probing): the
 *     rest of the cluster moves up into the gap, so there are no tombstones
 *     to pile up under heavy malloc/free churn.
 *   - Reset scans the array, frees every entry and zeroes its slot.
 * Same semantics as the uthash version (verified with a differential test).
 */
#define KEEP __attribute__((section("untracer_state")))

void   *__real_calloc(size_t a, size_t b);
void   *__real_realloc(void *p, size_t n);
void   *__real_memalign(size_t al, size_t n);
void   *__real_aligned_alloc(size_t al, size_t n);
int     __real_posix_memalign(void **out, size_t al, size_t n);
void   *__real_valloc(size_t n);
void   *__real_pvalloc(size_t n);
char   *__real_strdup(const char *s);
char   *__real_strndup(const char *s, size_t n);
ssize_t __real_getline(char **lp, size_t *n, FILE *f);
ssize_t __real_getdelim(char **lp, size_t *n, int d, FILE *f);

static KEEP uintptr_t *tab = NULL;     /* 0 = empty slot */
static KEEP size_t     tab_cap = 0;    /* power of two */
static KEEP unsigned   tab_shift = 64; /* 64 - log2(cap) */
static KEEP size_t     tab_live = 0;
static KEEP int        heap_tracking = 0;

/* Fibonacci hashing: top bits of p * 2^64/phi; pointers are 16-aligned,
   the multiply spreads them over all slots. */
static inline size_t slot_of(uintptr_t p) {
  return (size_t)((p * 0x9E3779B97F4A7C15ULL) >> tab_shift);
}

static void tab_init(size_t cap) {
  tab = (uintptr_t *)__real_calloc(cap, sizeof(uintptr_t));
  tab_cap = cap;
  tab_shift = 64 - (unsigned)__builtin_ctzll(cap);
}

static void tab_insert_raw(uintptr_t p) {
  size_t mask = tab_cap - 1, i = slot_of(p);
  while (tab[i]) {
    if (tab[i] == p) return;
    i = (i + 1) & mask;
  }
  tab[i] = p;
  tab_live++;
}

static void tab_grow(void) {
  uintptr_t *old = tab;
  size_t     old_cap = tab_cap;
  tab_init(old_cap * 2);
  tab_live = 0;
  for (size_t i = 0; i < old_cap; i++)
    if (old[i]) tab_insert_raw(old[i]);
  __real_free(old);
}

static inline void track_heap(void *p) {
  if (!heap_tracking || p == NULL) return;
  if ((tab_live + 1) * 2 > tab_cap) tab_grow();
  tab_insert_raw((uintptr_t)p);
}

/* Returns 1 if p was tracked (and removes it). */
static inline int untrack_heap(void *p) {
  if (!tab_live) return 0;
  uintptr_t key = (uintptr_t)p;
  size_t    mask = tab_cap - 1, i = slot_of(key);
  while (tab[i] != key) {
    if (!tab[i]) return 0;
    i = (i + 1) & mask;
  }
  /* backward-shift deletion: move later entries of the cluster up */
  size_t j = i;
  for (;;) {
    j = (j + 1) & mask;
    if (!tab[j]) break;
    size_t home = slot_of(tab[j]);
    /* can tab[j] move to i?  yes if home is not cyclically in (i, j] */
    if ((j > i && (home <= i || home > j)) ||
        (j < i && (home <= i && home > j))) {
      tab[i] = tab[j];
      i = j;
    }
  }
  tab[i] = 0;
  tab_live--;
  return 1;
}

void *__wrap_malloc(size_t n) {
  void *p = __real_malloc(n);
  track_heap(p);
  return p;
}
void *__wrap_calloc(size_t a, size_t b) {
  void *p = __real_calloc(a, b);
  track_heap(p);
  return p;
}
void *__wrap_memalign(size_t al, size_t n) {
  void *p = __real_memalign(al, n);
  track_heap(p);
  return p;
}
void *__wrap_aligned_alloc(size_t al, size_t n) {
  void *p = __real_aligned_alloc(al, n);
  track_heap(p);
  return p;
}
int __wrap_posix_memalign(void **out, size_t al, size_t n) {
  int rc = __real_posix_memalign(out, al, n);
  if (rc == 0) track_heap(*out);
  return rc;
}
void *__wrap_valloc(size_t n) {
  void *p = __real_valloc(n);
  track_heap(p);
  return p;
}
void *__wrap_pvalloc(size_t n) {
  void *p = __real_pvalloc(n);
  track_heap(p);
  return p;
}
char *__wrap_strdup(const char *s) {
  char *p = __real_strdup(s);
  track_heap(p);
  return p;
}
char *__wrap_strndup(const char *s, size_t n) {
  char *p = __real_strndup(s, n);
  track_heap(p);
  return p;
}

/* libc-internal malloc calls are not wrapped; strdup/strndup are wrapped
 * explicitly above. Freeing an untracked (baseline) block costs one failed
 * lookup; with nothing tracked it costs nothing. */
void __wrap_free(void *p) {
  if (p == NULL) return;
  untrack_heap(p);
  __real_free(p);
}

void *__wrap_realloc(void *p, size_t n) {
  if (p == NULL) {
    void *r = __real_realloc(NULL, n);
    track_heap(r);
    return r;
  }
  void *r = __real_realloc(p, n);
  if (r == NULL) {
    if (n == 0) untrack_heap(p); /* glibc: realloc(p, 0) frees p */
    return NULL;
  }
  if (r != p && untrack_heap(p)) track_heap(r);
  return r;
}

void *__wrap_reallocarray(void *p, size_t a, size_t b) {
  size_t total;
  if (__builtin_mul_overflow(a, b, &total)) {
    errno = ENOMEM;
    return NULL;
  }
  return __wrap_realloc(p, total);
}

/* getline/getdelim realloc *lineptr inside libc, bypassing the wrappers. */
static ssize_t line_common(char **lp, ssize_t r, char *old) {
  if (lp && *lp != old) {
    if (old == NULL)
      track_heap(*lp);
    else if (untrack_heap(old))
      track_heap(*lp);
  }
  return r;
}
ssize_t __wrap_getdelim(char **lp, size_t *n, int d, FILE *f) {
  char *old = lp ? *lp : NULL;
  return line_common(lp, __real_getdelim(lp, n, d, f), old);
}
ssize_t __wrap_getline(char **lp, size_t *n, FILE *f) {
  char *old = lp ? *lp : NULL;
  return line_common(lp, __real_getline(lp, n, f), old);
}

/* Call once, right after __untracer_setup_global() / __untracer_snapshot_fds().
 * Everything allocated before this point is baseline and is never freed. */
void __untracer_heap_start(void) {
  if (!tab) tab_init(1024);
  heap_tracking = 1;
}

/* Call after close_open_file_handles() (streams may use tracked setvbuf
 * buffers) and before __untracer_restore_global(). Returns the number of
 * blocks freed. */
int free_open_heap(void) {
  int count = (int)tab_live;
  if (!tab_live) return 0;
  for (size_t i = 0; i < tab_cap; i++)
    if (tab[i]) {
      __real_free((void *)tab[i]);
      tab[i] = 0;
    }
  tab_live = 0;
  return count;
}