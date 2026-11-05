#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "global.h" /* also declares __real_malloc / __real_free */

/* The tracking nodes must come from the real allocator. With --wrap=malloc
 * active, plain malloc() would register them with the heap tracker, which
 * would then free them again on reset (double free). These macros must come
 * before the first #include of uthash.h. */
#define uthash_malloc(sz) __real_malloc(sz)
#define uthash_free(ptr, sz) __real_free(ptr)
#include "uthash.h"

/*
 * Tracks every FILE* the target opens (fopen, fopen64, freopen, fdopen,
 * tmpfile, popen) and closes the leftovers on reset. Raw file descriptors
 * (open, openat, pipe, socket, dup, ...) are not wrapped; instead the set of
 * open fds is snapshotted once and anything extra is closed on reset.
 *
 * Link with:
 *   -Wl,--wrap=fopen -Wl,--wrap=fopen64 -Wl,--wrap=freopen -Wl,--wrap=fdopen
 *   -Wl,--wrap=tmpfile -Wl,--wrap=popen -Wl,--wrap=fclose -Wl,--wrap=pclose
 *
 * Reset order per iteration (see harness):
 *   close_open_file_handles(); free_open_heap(); __untracer_restore_global();
 * Streams must be closed before the heap is freed, because a stream may be
 * using a heap buffer (setvbuf).
 *
 * This file must NOT go through CloneGlobalsPass: its state has to survive the
 * global restore, so it lives in its own section as well.
 */
#define KEEP __attribute__((section("untracer_state")))

FILE *__real_fopen(const char *path, const char *mode);
FILE *__real_fopen64(const char *path, const char *mode);
FILE *__real_freopen(const char *path, const char *mode, FILE *stream);
FILE *__real_fdopen(int fd, const char *mode);
FILE *__real_tmpfile(void);
FILE *__real_popen(const char *cmd, const char *type);
int __real_fclose(FILE *f);
int __real_pclose(FILE *f);

typedef struct
{
    FILE *f;     /* hash key */
    int is_pipe; /* 1 if opened by popen, closed with pclose */
    UT_hash_handle hh;
} file_ptr_obj;

static KEEP file_ptr_obj *file_ptr_map = NULL;

#define MAX_FDS 65536
static KEEP unsigned char baseline_fd[MAX_FDS];
static KEEP int baseline_taken = 0;

/* Scratch list used by for_each_open_fd (zero-initialized, lives in .bss). */
static int fd_list[MAX_FDS];

static int is_std_stream(FILE *f)
{
    return f == stdin || f == stdout || f == stderr;
}

static file_ptr_obj *find_file_ptr(FILE *f)
{
    file_ptr_obj *s = NULL;
    HASH_FIND_PTR(file_ptr_map, &f, s);
    return s;
}

static void track(FILE *f, int is_pipe)
{
    if (f == NULL || is_std_stream(f) || find_file_ptr(f) != NULL)
        return;

    /* __real_malloc (via the uthash macros too): never seen by the heap
     * tracker, so no pause/resume is needed. */
    file_ptr_obj *s = (file_ptr_obj *)__real_malloc(sizeof(*s));
    if (s)
    {
        s->f = f;
        s->is_pipe = is_pipe;
        HASH_ADD_PTR(file_ptr_map, f, s);
    }
}

static void untrack(FILE *f)
{
    file_ptr_obj *s = find_file_ptr(f);
    if (s)
    {
        HASH_DEL(file_ptr_map, s);
        __real_free(s);
    }
}

/* ---- wrappers ---------------------------------------------------------- */

FILE *__wrap_fopen(const char *path, const char *mode)
{
    FILE *f = __real_fopen(path, mode);
    track(f, 0);
    return f;
}

FILE *__wrap_fopen64(const char *path, const char *mode)
{
    FILE *f = __real_fopen64(path, mode);
    track(f, 0);
    return f;
}

FILE *__wrap_freopen(const char *path, const char *mode, FILE *stream)
{
    FILE *r = __real_freopen(path, mode, stream);
    if (r == NULL)
        untrack(stream); /* freopen closes the old stream even on failure */
    else if (r != stream)
    {
        untrack(stream);
        track(r, 0);
    }
    else
        track(r, 0); /* no-op if already tracked or a standard stream */
    return r;
}

FILE *__wrap_fdopen(int fd, const char *mode)
{
    FILE *f = __real_fdopen(fd, mode);
    track(f, 0);
    return f;
}

FILE *__wrap_tmpfile(void)
{
    FILE *f = __real_tmpfile();
    track(f, 0);
    return f;
}

FILE *__wrap_popen(const char *cmd, const char *type)
{
    FILE *f = __real_popen(cmd, type);
    track(f, 1);
    return f;
}

int __wrap_fclose(FILE *f)
{
    untrack(f);
    return __real_fclose(f);
}

int __wrap_pclose(FILE *f)
{
    untrack(f);
    return __real_pclose(f);
}

/* ---- raw fd handling --------------------------------------------------- */

/*
 * Calls cb(fd) for every open fd except the one used to read the directory.
 *
 * Two passes: first collect the fd numbers and close the directory, then call
 * the callback. That way cb may close descriptors without modifying
 * /proc/self/fd while it is still being read, which readdir does not
 * guarantee to handle correctly (entries can be skipped).
 */
static void for_each_open_fd(void (*cb)(int fd))
{
    DIR *d = opendir("/proc/self/fd");
    if (!d)
        return;

    int dfd = dirfd(d); /* the directory's own fd shows up in its listing */
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL)
    {
        if (e->d_name[0] < '0' || e->d_name[0] > '9')
            continue;
        int fd = atoi(e->d_name);
        if (fd == dfd)
            continue; /* closed below; must not be reported to cb */
        if (fd >= 0 && fd < MAX_FDS && n < MAX_FDS)
            fd_list[n++] = fd;
    }
    closedir(d);

    for (int i = 0; i < n; i++)
        cb(fd_list[i]);
}

static void mark_baseline(int fd)
{
    if (fd >= 0 && fd < MAX_FDS)
        baseline_fd[fd] = 1;
}

static void close_if_new(int fd)
{
    if (fd > 2 && fd < MAX_FDS && !baseline_fd[fd])
        close(fd);
}

/* Call once, right after __untracer_setup_global(). */
void __untracer_snapshot_fds(void)
{
    memset(baseline_fd, 0, sizeof(baseline_fd));
    for_each_open_fd(mark_baseline);
    baseline_taken = 1;
}

/* Call before free_open_heap() and __untracer_restore_global(). */
void close_open_file_handles(void)
{
    /* 1. Close tracked streams so stdio frees its buffers and the fds. */
    file_ptr_obj *s, *tmp;
    HASH_ITER(hh, file_ptr_map, s, tmp)
    {
        HASH_DEL(file_ptr_map, s);
        if (s->is_pipe)
            __real_pclose(s->f);
        else
            __real_fclose(s->f);
        __real_free(s);
    }

    /* 2. Close any other fd that was not open when the baseline was taken. */
    if (baseline_taken)
        for_each_open_fd(close_if_new);
}