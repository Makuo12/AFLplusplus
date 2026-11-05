#define _GNU_SOURCE
#include <errno.h>
#include <malloc.h>
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
 * Bookkeeping uses __real_malloc/__real_free only, so it never recurses into
 * the wrappers and is never tracked itself. This file must NOT go through
 * CloneGlobalsPass. Requires uthash >= 2.0 (BYHASHVALUE macros).
 *
 * Speed changes versus the first version:
 *   1. A permanent sentinel node keeps the hash table alive across
 *      iterations, so uthash never frees/regrows/rehashes its buckets.
 *   2. Tracking nodes come from a slab-backed free list instead of one
 *      __real_malloc/__real_free per tracked block.
 *   3. Cheap multiply-xorshift hash for pointer keys instead of Jenkins.
 *   4. The hash is computed once per tracked allocation (find + add share it),
 *      and free() skips the lookup entirely when nothing is tracked.
 */
#define KEEP __attribute__((section("untracer_state")))

void *__real_calloc(size_t a, size_t b);
void *__real_realloc(void *p, size_t n);
void *__real_memalign(size_t al, size_t n);
void *__real_aligned_alloc(size_t al, size_t n);
int __real_posix_memalign(void **out, size_t al, size_t n);
void *__real_valloc(size_t n);
void *__real_pvalloc(size_t n);
char *__real_strdup(const char *s);
char *__real_strndup(const char *s, size_t n);
ssize_t __real_getline(char **lp, size_t *n, FILE *f);
ssize_t __real_getdelim(char **lp, size_t *n, int d, FILE *f);

/* Cheap hash for pointer keys (keyptr points at the pointer value). */
#define HASH_FUNCTION(keyptr, keylen, hashv)                         \
    do                                                               \
    {                                                                \
        uint64_t _k = (uint64_t)(uintptr_t)*(void *const *)(keyptr); \
        _k ^= _k >> 33;                                              \
        _k *= 0xff51afd7ed558ccdULL;                                 \
        _k ^= _k >> 33;                                              \
        (hashv) = (unsigned)_k;                                      \
    } while (0)

#define uthash_malloc(sz) __real_malloc(sz)
#define uthash_free(ptr, sz) __real_free(ptr)
#include "uthash.h"

typedef struct heap_obj
{
    void *p; /* hash key (reused as the free-list link while pooled) */
    UT_hash_handle hh;
} heap_obj;

static KEEP heap_obj *heap_map = NULL;
static KEEP int heap_tracking = 0;  /* only track after the baseline point */
static KEEP size_t heap_live = 0;   /* tracked nodes, excluding the sentinel */
static KEEP heap_obj heap_sentinel; /* never removed: keeps the table sized */
static KEEP heap_obj *free_nodes = NULL;

/* ---- node pool ----------------------------------------------------------- */

#define SLAB_NODES 4096

static heap_obj *node_alloc(void)
{
    if (!free_nodes)
    {
        heap_obj *slab = (heap_obj *)__real_malloc(SLAB_NODES * sizeof(heap_obj));
        if (!slab)
            return NULL;
        /* Slabs are never freed: they are bounded by the per-iteration peak. */
        for (size_t i = 0; i < SLAB_NODES; i++)
        {
            slab[i].p = free_nodes;
            free_nodes = &slab[i];
        }
    }
    heap_obj *n = free_nodes;
    free_nodes = (heap_obj *)n->p;
    return n;
}

static inline void node_release(heap_obj *n)
{
    n->p = free_nodes;
    free_nodes = n;
}

/* ---- tracking ------------------------------------------------------------ */

static inline heap_obj *find_heap(void *p)
{
    heap_obj *s = NULL;
    HASH_FIND_PTR(heap_map, &p, s);
    return s;
}

static inline void track_heap(void *p)
{
    if (!heap_tracking || p == NULL)
        return;

    unsigned hv;
    heap_obj *s = NULL;
    HASH_VALUE(&p, sizeof(void *), hv); /* hash once, reuse for find + add */
    HASH_FIND_BYHASHVALUE(hh, heap_map, &p, sizeof(void *), hv, s);
    if (s) /* stale entry for a reused address: already tracked */
        return;

    s = node_alloc();
    if (!s)
        return;
    s->p = p;
    HASH_ADD_KEYPTR_BYHASHVALUE(hh, heap_map, &s->p, sizeof(void *), hv, s);
    heap_live++;
}

static inline void drop_node(heap_obj *s)
{
    HASH_DEL(heap_map, s);
    node_release(s);
    heap_live--;
}

static inline int untrack_heap(void *p)
{
    if (!heap_live)
        return 0;
    heap_obj *s = find_heap(p);
    if (!s)
        return 0;
    drop_node(s);
    return 1;
}

/* ---- allocation wrappers ------------------------------------------------ */

void *__wrap_malloc(size_t n)
{
    void *p = __real_malloc(n);
    track_heap(p);
    return p;
}

void *__wrap_calloc(size_t a, size_t b)
{
    void *p = __real_calloc(a, b);
    track_heap(p);
    return p;
}

void *__wrap_memalign(size_t al, size_t n)
{
    void *p = __real_memalign(al, n);
    track_heap(p);
    return p;
}

void *__wrap_aligned_alloc(size_t al, size_t n)
{
    void *p = __real_aligned_alloc(al, n);
    track_heap(p);
    return p;
}

int __wrap_posix_memalign(void **out, size_t al, size_t n)
{
    int rc = __real_posix_memalign(out, al, n);
    if (rc == 0)
        track_heap(*out);
    return rc;
}

void *__wrap_valloc(size_t n)
{
    void *p = __real_valloc(n);
    track_heap(p);
    return p;
}

void *__wrap_pvalloc(size_t n)
{
    void *p = __real_pvalloc(n);
    track_heap(p);
    return p;
}

/* libc-internal malloc calls are not wrapped, so wrap these explicitly. */
char *__wrap_strdup(const char *s)
{
    char *p = __real_strdup(s);
    track_heap(p);
    return p;
}

char *__wrap_strndup(const char *s, size_t n)
{
    char *p = __real_strndup(s, n);
    track_heap(p);
    return p;
}

void __wrap_free(void *p)
{
    if (p == NULL)
        return;
    /* Nothing tracked (or tracking not started): skip the hash lookup. */
    if (heap_live)
    {
        heap_obj *s = find_heap(p);
        if (s)
            drop_node(s);
    }
    __real_free(p);
}

void *__wrap_realloc(void *p, size_t n)
{
    if (p == NULL)
    {
        void *r = __real_realloc(NULL, n);
        track_heap(r);
        return r;
    }

    heap_obj *old = heap_live ? find_heap(p) : NULL; /* NULL => predates baseline */
    void *r = __real_realloc(p, n);

    if (r == NULL)
    {
        if (n == 0 && old) /* glibc: realloc(p, 0) frees p */
            drop_node(old);
        return NULL; /* on real failure p is still valid and still tracked */
    }
    if (r != p && old)
    {
        drop_node(old);
        track_heap(r);
    }
    /* Baseline block that moved: deliberately NOT tracked (it must survive). */
    return r;
}

void *__wrap_reallocarray(void *p, size_t a, size_t b)
{
    size_t total;
    if (__builtin_mul_overflow(a, b, &total))
    {
        errno = ENOMEM;
        return NULL;
    }
    return __wrap_realloc(p, total);
}

/* getline/getdelim realloc *lineptr inside libc, bypassing the wrappers. */
static ssize_t line_common(char **lp, ssize_t r, char *old)
{
    if (lp && *lp != old)
    {
        if (old == NULL)
            track_heap(*lp);
        else if (untrack_heap(old))
            track_heap(*lp);
    }
    return r;
}

ssize_t __wrap_getdelim(char **lp, size_t *n, int d, FILE *f)
{
    char *old = lp ? *lp : NULL;
    return line_common(lp, __real_getdelim(lp, n, d, f), old);
}

ssize_t __wrap_getline(char **lp, size_t *n, FILE *f)
{
    char *old = lp ? *lp : NULL;
    return line_common(lp, __real_getline(lp, n, f), old);
}

/* ---- lifecycle ---------------------------------------------------------- */

/* Call once, right after __untracer_setup_global() / __untracer_snapshot_fds().
 * Everything allocated before this point is baseline and is never freed. */
void __untracer_heap_start(void)
{
    if (!heap_map)
    {
        /* Permanent entry so the table is never torn down by HASH_DEL. */
        heap_sentinel.p = (void *)1; /* never a real malloc result */
        HASH_ADD_PTR(heap_map, p, &heap_sentinel);
    }
    heap_tracking = 1;
}

/* Call after close_open_file_handles() (streams may use tracked setvbuf
 * buffers) and before __untracer_restore_global(). */
void free_open_heap(void)
{
    heap_obj *s, *tmp;
    HASH_ITER(hh, heap_map, s, tmp)
    {
        if (s == &heap_sentinel)
            continue;
        HASH_DEL(heap_map, s);
        __real_free(s->p);
        node_release(s);
    }
    heap_live = 0;
}