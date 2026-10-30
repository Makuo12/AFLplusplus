#ifndef DATA_H_
#define DATA_H_
#include <sys/types.h> // Standard POSIX types
#include <inttypes.h>
#include "uthash.h" // Include uthash for hash table functionality
typedef struct
{
    char d_name[1025];
    off_t st_size; // off_t is the standard POSIX type for file sizes
    char file_path[1025];
    int has_issues;
    int single_pass;
    int full_pass;
    int path_found;
    int trace_count;
} Entry;

typedef struct
{
    uintptr_t addr;
    int32_t cmp_value;
    int32_t index;
    int32_t is_edge_count;
} Trace;

#define MAX_LOOP 256

typedef enum
{
    BLOCK,
    EDGE,
    EDGE_COUNT
} OracleType;

typedef struct
{
  int32_t meta_id; /* key */
  int32_t cmp_value;
  UT_hash_handle hh;
} LoopThresholdEntry;

#define LOOP_START_ADD 4
#define BUCKET_INC 32
#define MULTI_INC 4
#define BUCKET_SMALL_INC 2

#define HAVOC_BASE_CYCLES 500  /* havoc execs at perf_score == 100  */
#define SPLICE_BASE_CYCLES 250 /* splice execs at perf_score == 100 */
#define HAVOC_MAX_STAGE 4000   /* hard cap per stage */
#endif