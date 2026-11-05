#ifndef GLOBAL_H_
#define GLOBAL_H_

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* C linkage for everything, so these link whether the runtime files are
 * compiled as C or C++ and whether the caller is C or C++. */
#ifdef __cplusplus
extern "C"
{
#endif

    /* global.c: snapshot/restore of the target's globals */
    int __untracer_setup_global(void);
    int __untracer_restore_global(void);

    /* filer.c: FILE* tracking and raw-fd baseline */
    void __untracer_snapshot_fds(void);
    void close_open_file_handles(void);

    /* mem_track.c: heap tracking. Allocations before __untracer_heap_start()
     * are baseline and never freed. */
    void __untracer_heap_start(void);
    void free_open_heap(void);

    /* Real allocator entry points, resolved by -Wl,--wrap=malloc/free.
     * Runtime code that must NOT be tracked (tables that survive resets)
     * allocates through these. */
    void *__real_malloc(size_t n);
    void __real_free(void *p);

#ifdef __cplusplus
}
#endif

/* Per-iteration reset order:
 *   close_open_file_handles();
 *   free_open_heap();
 *   __untracer_restore_global();
 */

#endif /* GLOBAL_H_ */