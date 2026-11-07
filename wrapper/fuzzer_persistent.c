#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h> /* va_list, used by log_line() in startup.c */
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/shm.h>
#include <sys/ucontext.h>
#include <unistd.h>

#define uthash_malloc(sz) __real_malloc(sz)
#define uthash_free(ptr, sz) __real_free(ptr)

#include "uthash.h"
#include "data.h"
#include "global.h"
#include "config.h"
#ifdef __APPLE__
  #include <mach-o/getsect.h>
  #include <mach-o/dyld.h>
extern const struct mach_header_64 _mh_execute_header;
#endif

#define KEEP __attribute__((section("untracer_state")))

/* afl-fuzz scans the target binary for this string (check_binary) and only
   then runs in persistent mode, i.e. accepts a child that stops itself
   (SIGSTOP) after each input instead of exiting. __AFL_LOOP embeds the same
   marker in AFL++-instrumented targets. "used" keeps the optimizer from
   deleting the otherwise unreferenced variable. */
static volatile const char *persist_sig __attribute__((used)) = PERSIST_SIG;

#if defined(__linux__)
  #define UC_PC(uc) ((uc)->uc_mcontext.gregs[REG_RIP])
#elif defined(__APPLE__) && defined(__x86_64__)
  #define UC_PC(uc) ((uc)->uc_mcontext->__ss.__rip)
#elif defined(__APPLE__) && defined(__aarch64__)
  #define UC_PC(uc) ((uc)->uc_mcontext->__ss.__pc)
#else
  #error "unsupported platform"
#endif

/* ------------------------------------------------------------------ */
/* Prototypes for externally-defined symbols                          */
/* ------------------------------------------------------------------ */
sigjmp_buf env;

// extern void __reset_loop_counters(void);
extern int  target_main(int argc, char **argv);
extern void __reset_loop_counters(void);

static void sig_log(const char *msg, uintptr_t val);
extern void __real__exit(int) __attribute__((noreturn));

__attribute__((noreturn)) void __wrap_exit(int value) {
  siglongjmp(env, value ? value : 1);
}
__attribute__((noreturn)) void __wrap__exit(int value) {
  siglongjmp(env, value ? value : 1);
}
__attribute__((noreturn)) void __wrap__Exit(int value) {
  siglongjmp(env, value ? value : 1);
}

//     typedef struct
// {
//     uintptr_t page;
//     UT_hash_handle hh;
// } writable_page;

// KEEP writable_page *writable_pages = NULL;

typedef unsigned char u8;

uint32_t *virgin_bits;
uint32_t *trace_bits;

#define DEFAULT_LOG_PATH "./output/trap_handler.log"
static char log_path[4096] = DEFAULT_LOG_PATH;

static void init_log_path(void) {
  const char *p = getenv("LOG_FILE");
  if (p && *p && strlen(p) < sizeof(log_path)) { strcpy(log_path, p); }
}

// void make_writeable(uintptr_t start, uintptr_t end)
// {
//     static size_t page_size = 0;
//     if (!page_size)
//         page_size = (size_t)sysconf(_SC_PAGESIZE);

//     uintptr_t first_page = start & ~(uintptr_t)(page_size - 1);

//     uintptr_t last_page = end & ~(uintptr_t)(page_size - 1);

//     for (uintptr_t page = first_page; page <= last_page; page+=page_size) {
//         writable_page *found;
//         HASH_FIND(hh, writable_pages, &page, sizeof(uintptr_t), found);

//         if (found)
//             continue; /* already writable - skip the syscall */
//         if (mprotect((void *)page, page_size, PROT_READ | PROT_WRITE |
//         PROT_EXEC) != 0)
//         {
//             sig_log("mprotect failed, page=", page);
//             __real__exit(EXIT_FAILURE);
//         }

//         /* __real_malloc via the uthash macros above: untracked, persistent.
//         */ writable_page *entry = (writable_page
//         *)__real_malloc(sizeof(*entry)); if (entry)
//         {
//             entry->page = page;
//             HASH_ADD(hh, writable_pages, page, sizeof(uintptr_t), entry);
//         }
//     }
// }

/* ------------------------------------------------------------------ */
/* De-instrumentation output                                          */
/* ------------------------------------------------------------------ */

/* Retired trap ids (META_DATA_FILE) and raised loop thresholds
   (LOOP_THRESHOLD_FILE), read by remove_edge when afl-fuzz rebuilds the
   target. Opened once in main(), BEFORE __untracer_snapshot_fds(), so the
   closure's fd reset treats them as baseline and never closes them. */
static int meta_file_fd = -1;
static int loop_threshold_fd = -1;

void log_line(const char *fmt, ...);

static int open_append_env(const char *env_name) {
  const char *path = getenv(env_name);
  if (!path || strlen(path) < 2) {
    log_line("%s not set\n", env_name);
    __real__exit(EXIT_FAILURE);
  }

  /* O_APPEND: every write lands at the end, even after a harness restart. */
  int fd = open(path, O_CREAT | O_WRONLY | O_APPEND, 0644);
  if (fd < 0) {
    log_line("cannot open %s (%s): %s\n", env_name, path, strerror(errno));
    __real__exit(EXIT_FAILURE);
  }
  return fd;
}

/* async-signal-safe: format v as decimal into p, return length */
static size_t fmt_i32(char *p, int32_t v) {
  char     tmp[12];
  size_t   n = 0, len = 0;
  uint32_t u = v < 0 ? (uint32_t)0 - (uint32_t)v : (uint32_t)v;
  if (v < 0) p[len++] = '-';
  do {
    tmp[n++] = '0' + u % 10;
    u /= 10;
  } while (u);
  while (n)
    p[len++] = tmp[--n];
  return len;
}

static void meta_data_dump(int32_t meta_id) {
  char   buf[16];
  size_t n = fmt_i32(buf, meta_id);
  buf[n++] = '\n';
  if (write(meta_file_fd, buf, n) != (ssize_t)n)
    sig_log("meta write failed, id=", (uintptr_t)(uint32_t)meta_id);
}

static void loop_threshold_write(int32_t meta_id, int32_t cmp_value) {
  char   buf[32];
  size_t n = fmt_i32(buf, meta_id);
  buf[n++] = ',';
  n += fmt_i32(buf + n, cmp_value);
  buf[n++] = '\n';
  if (write(loop_threshold_fd, buf, n) != (ssize_t)n)
    sig_log("threshold write failed, id=", (uintptr_t)(uint32_t)meta_id);
}

static void setup_fd(void) {
  loop_threshold_fd = open_append_env("LOOP_THRESHOLD_FILE");
  meta_file_fd = open_append_env("META_DATA_FILE");
}

/* ------------------------------------------------------------------ */
/* Logging                                                            */
/* ------------------------------------------------------------------ */

/* NOT safe to call from signal handlers (stdio + malloc). */
void log_line(const char *fmt, ...) {
  FILE *log_file = fopen(log_path, "a");
  if (!log_file) log_file = stderr;  // fallback

  va_list ap;
  va_start(ap, fmt);
  vfprintf(log_file, fmt, ap);
  va_end(ap);

  if (log_file != stderr) fclose(log_file);
}

/* Async-signal-safe: only open/write/close, no stdio, no malloc. A crash
 * inside malloc or stdio would deadlock log_line() and show up as a hang
 * instead of a crash. Prints "<msg>0x<16 hex digits>\n". */
static void sig_log(const char *msg, uintptr_t val) {
  static const char hex[] = "0123456789abcdef";
  char              buf[96];
  size_t            n = 0;

  while (*msg && n < 64)
    buf[n++] = *msg++;
  buf[n++] = '0';
  buf[n++] = 'x';
  for (int s = (int)(sizeof(val) * 8) - 4; s >= 0; s -= 4)
    buf[n++] = hex[(val >> s) & 0xf];
  buf[n++] = '\n';

  int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
  if (fd >= 0) {
    (void)!write(fd, buf, n);
    close(fd);
  } else
    (void)!write(2, buf, n);
}

static inline void record_hit(int32_t idx, uint32_t val, int is_loop) {
  if (idx < 0 || (uint32_t)idx >= TRAP_VIRGIN_WORDS) {
    sig_log("trap index out of range: ", (uintptr_t)(uint32_t)idx);
    abort();
  }
  uint32_t old = virgin_bits[idx];
  if (val <= old) return; /* already known (also after a harness restart) */
  virgin_bits[idx] = val;
  if (old == 0 && !is_loop)
    trace_bits[0]++; /* new edge */
  else
    trace_bits[3]++; /* new or higher loop bucket */
  if (old == 0 && is_loop)
    trace_bits[1]++; /* loop header hit for the first time */
}

void trap_handler(int sig, siginfo_t *info, void *ctx) {
  ucontext_t *uc = (ucontext_t *)ctx;
  uintptr_t   rip = (uintptr_t)UC_PC(uc);
  uintptr_t   addr = rip - 1;

  if (addr < 0x400000) {
    sig_log("addr underflow, base address assumption wrong: ", addr);
    abort();
  }
  uintptr_t      resume_addr = 0;
  unsigned char *trap = (unsigned char *)addr;
  int32_t        value = 0, new_value = 0, index_block = 0;
  int32_t        bucket_value = 0;
  // Loop-counter layout:  0xcc 0x90 0x90 0x90 0x90 id0 id1 id2 id3   (9 bytes)
  // Edge-counter layout:  0xcc id0 id1 id2 id3                       (5 bytes)
  if (*trap == 0xcc && trap[1] == 0x90 && trap[2] == 0x90 && trap[3] == 0x90 &&
      trap[4] == 0x90) {
    uintptr_t cmp_addr = addr - 7;
    uintptr_t num_addr = cmp_addr + 1;
    memcpy(&value, (void *)num_addr, sizeof(value));
    if (value <= 1)
      new_value = 2;
    else if (value < LOOP_START_ADD)
      new_value = value + BUCKET_SMALL_INC;
    else
      new_value = value * MULTI_INC;

    memcpy(&index_block, (void *)(addr + 5), sizeof(index_block));
    if (new_value >= MAX_LOOP) {
      memset(trap, 0x90, 9);
      resume_addr = addr + 9;
      meta_data_dump(index_block);
    } else {
      memcpy((void *)num_addr, &new_value, sizeof(new_value));
      resume_addr = cmp_addr;
      loop_threshold_write(index_block, new_value);
    }

    if (new_value <= LOOP_START_ADD)
      bucket_value = (new_value / 2) - 1;
    else
      for (uint32_t v = (uint32_t)new_value; v >= 4; v >>= 2)
        bucket_value++; /* floor(log4(new_value)), no libm */

    record_hit(index_block, (uint32_t)bucket_value + 1, 1);
  } else if (*trap == 0xcc) {
    memcpy(&index_block, (void *)(addr + 1), sizeof(index_block));
    memset(trap, 0x90, 5);
    resume_addr = addr + 5;
    record_hit(index_block, 1, 0);
    meta_data_dump(index_block);
  } else {
    sig_log("failed at addr=", addr);
    sig_log("            offset=", addr - 0x400000);
    abort();
  }

  UC_PC(uc) = resume_addr;
}

void crash_handler(int sig, siginfo_t *info, void *context) {
  siglongjmp(env, sig);
}

void setup_signal(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sigemptyset(&sa.sa_mask);

  // SIGTRAP handler
  sa.sa_sigaction = trap_handler;
  sa.sa_flags = SA_SIGINFO | SA_NODEFER;
  sigaction(SIGTRAP, &sa, NULL);

  // // Crash handler
  // sa.sa_sigaction = crash_handler;
  // sa.sa_flags = SA_SIGINFO | SA_NODEFER;
  // sigaction(SIGILL, &sa, NULL);
  // sigaction(SIGABRT, &sa, NULL);
  // sigaction(SIGSEGV, &sa, NULL);
  // sigaction(SIGBUS, &sa, NULL);
}

/* ------------------------------------------------------------------ */
/* Shared memory setup                                                */
/* ------------------------------------------------------------------ */

static uint32_t *attach_shm(const char *env_name, size_t nwords) {
  const char *env = getenv(env_name);
  if (env == NULL) {
    /* standalone replay: zero-filled map shared with the forked child */
    void *p = mmap(NULL, nwords * sizeof(uint32_t), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
      log_line("anon mmap failed for %s: %s\n", env_name, strerror(errno));
      __real__exit(EXIT_FAILURE);
    }
    return (uint32_t *)p;
  }

  errno = 0;
  char *endptr = NULL;
  long  id = strtol(env, &endptr, 10);
  if (errno != 0 || endptr == env || *endptr != '\0' || id < 0) {
    log_line("invalid %s value: %s\n", env_name, env);
    __real__exit(EXIT_FAILURE);
  }

  struct shmid_ds ds;
  if (shmctl((int)id, IPC_STAT, &ds) == 0 &&
      ds.shm_segsz < nwords * sizeof(uint32_t)) {
    log_line(
        "%s segment too small (%zu < %zu): fuzzer/harness built with different "
        "config.h?\n",
        env_name, (size_t)ds.shm_segsz, nwords * sizeof(uint32_t));
    __real__exit(EXIT_FAILURE);
  }

  void *p = shmat((int)id, NULL, 0);
  if (p == (void *)-1) {
    log_line("shmat error for %s: %s\n", env_name, strerror(errno));
    __real__exit(EXIT_FAILURE);
  }
  return (uint32_t *)p;
}

void setup_shm(void) {
  virgin_bits = attach_shm(SHM_ID, TRAP_VIRGIN_WORDS);
  trace_bits = attach_shm(SHM_ENV_VAR, MAP_SIZE_TRACE);
}

static void run_persistent(char *argv0, char *input) {
  uint32_t msg = 1;
  int standalone = !getenv(SHM_ENV_VAR) || write(FORKSRV_FD + 1, &msg, 4) != 4;

  char  devnull[] = "/dev/null";
  char *args[] = {argv0, input, devnull, NULL};

  int child = -1; /* no persistent child yet */

  /* Inputs per child before it exits and a fresh one is forked (like the N
     in __AFL_LOOP(N)). 0 = unlimited: the closure reset (files, heap,
     globals) is what keeps iterations independent. */
  uint32_t    persist_cnt = 0;
  const char *pc = getenv("TRAP_PERSIST_CNT");
  if (pc && atoi(pc) > 0) persist_cnt = (uint32_t)atoi(pc);

  if (standalone) {
    /* No forkserver protocol: just run the target once and exit,
       same as your original standalone branch. */
    child = fork();
    if (child == 0) {
      __reset_loop_counters();
      int rc = 0;
      if (sigsetjmp(env, 1) == 0) rc = target_main(3, args);
      fflush(NULL);
      __real__exit(rc);
    }
    int wait_status = 0;
    while (waitpid(child, &wait_status, 0) < 0) {
      if (errno != EINTR) {
        log_line("waitpid: %s\n", strerror(errno));
        __real__exit(1);
      }
    }
    if (WIFSIGNALED(wait_status))
      log_line("child killed by signal %d\n", WTERMSIG(wait_status));
    log_line("new edges=%u new loop buckets=%u\n", trace_bits[0],
             trace_bits[3]);
    __real__exit(WIFEXITED(wait_status) ? WEXITSTATUS(wait_status)
                                        : 128 + WTERMSIG(wait_status));
  }

  /* Forkserver loop: the PARENT talks to afl-fuzz. The child is the
     persistent process that loops internally and stops itself. */
  for (;;) {
    uint32_t cmd;
    if (read(FORKSRV_FD, &cmd, 4) != 4) __real__exit(0); /* afl went away */

    uint32_t prev_timed_out = cmd; /* afl tells us if the last run timed out */

    if (child == -1 || prev_timed_out) {
      /* No usable child: spawn a fresh persistent process. */
      if (child != -1) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
      }
      child = fork();
      if (child == 0) {
        /* If the forkserver dies (afl-fuzz stops it to rebuild the
           target after de-instrumentation), take this child down too,
           even while it is stopped between inputs. Same as AFL++'s
           runtime. If the parent died before this line, exit now. */
        pid_t fsrv_pid = getppid();
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (getppid() != fsrv_pid) __real__exit(0);

        /* Persistent child: close afl's pipes, it doesn't need them. */
        close(FORKSRV_FD);
        close(FORKSRV_FD + 1);

        uint32_t iter = 0;
        for (;;) {
          int sig = sigsetjmp(env, 1);
          if (sig == 0) {
            optind = 0; /* glibc: also reinitializes getopt's internal state */
            __reset_loop_counters();
            int rc = target_main(3, args);
            (void)rc;
          }
          fflush(NULL);
          /* Stop myself; parent resumes me with SIGCONT for the
          next test case, or kills+replaces me on timeout. */
          close_open_file_handles();
          free_open_heap();
          if (__untracer_restore_global()) {
            log_line("__untracer_restore_global failed to clean\n");
            __real__exit(EXIT_FAILURE);
          }
          /* Iteration cap reached: exit normally; the forkserver
             reports the exit as this input's result and forks a
             fresh child for the next one. */
          if (persist_cnt && ++iter >= persist_cnt) __real__exit(0);
          raise(SIGSTOP);
        }
      }
    } else {
      /* Reuse the existing stopped child. */
      kill(child, SIGCONT);
    }

    /* Tell afl-fuzz the PID to watch/kill on timeout. */
    if (write(FORKSRV_FD + 1, &child, 4) != 4) __real__exit(0);

    /* Wait for the child to stop (iteration done) or die (crash/killed). */
    int   wait_status = 0;
    pid_t w;
    while ((w = waitpid(child, &wait_status, WUNTRACED)) < 0) {
      if (errno != EINTR) {
        log_line("waitpid: %s\n", strerror(errno));
        __real__exit(1);
      }
    }

    if (WIFSTOPPED(wait_status)) {
      /* Normal end of one loop iteration. */
      if (write(FORKSRV_FD + 1, &wait_status, 4) != 4) __real__exit(0);
    } else {
      /* Child exited or was killed (crash, timeout, loop-count exit). */
      if (write(FORKSRV_FD + 1, &wait_status, 4) != 4) __real__exit(0);
      child = -1; /* force a fresh fork next iteration */
    }
  }
}

extern void *__start___traps[];
extern void *__stop___traps[];

typedef struct {
  void    *addr;
  uint32_t id;
  int      is_loop;
} trap_entry;

static trap_entry *g_traps;
static size_t      g_trap_count;

static void make_pages_shared(void) {
  long      pg = sysconf(_SC_PAGESIZE);
  uintptr_t pgmask = ~(uintptr_t)(pg - 1);

  if (!g_trap_count) return;

  // Each trap's full span: 0xcc + 4 id bytes (edge), or for loop headers
  // the 7-byte cmp/jcc before the trap + 0xcc + 4 marker + 4 id bytes.
  // Any byte in that span may be rewritten, so every page it touches must
  // be shared between all forked children.
  //
  // All traps live in the target's .text, which is one contiguous mapping.
  // Remap the whole range [first trap page, last trap page] as ONE shared
  // mapping instead of one mapping per page: fork() copies every mapping
  // of the process, so thousands of per-page mappings made every fork slow.
  uintptr_t lo = UINTPTR_MAX, hi = 0;
  for (size_t i = 0; i < g_trap_count; i++) {
    uintptr_t addr = (uintptr_t)g_traps[i].addr;
    uintptr_t start = addr - (g_traps[i].is_loop ? 7 : 0);
    uintptr_t end = addr + (g_traps[i].is_loop ? 9 : 5) - 1;
    if (start < lo) lo = start;
    if (end > hi) hi = end;
  }

  uintptr_t base = lo & pgmask;
  size_t    len = ((hi & pgmask) + pg) - base;

  int fd = memfd_create("text_shared", 0);
  if (fd < 0) {
    log_line("memfd_create failed: %s\n", strerror(errno));
    __real__exit(EXIT_FAILURE);
  }

  if (ftruncate(fd, len) != 0) {
    log_line("ftruncate(%zu) failed: %s\n", len, strerror(errno));
    close(fd);
    __real__exit(EXIT_FAILURE);
  }

  size_t done = 0;
  while (done < len) {
    ssize_t w = write(fd, (void *)(base + done), len - done);
    if (w <= 0) {
      log_line("short write copying text %p (%zu/%zu): %s\n", (void *)base,
               done, len, strerror(errno));
      close(fd);
      __real__exit(EXIT_FAILURE);
    }
    done += (size_t)w;
  }

  void *r = mmap((void *)base, len, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_SHARED | MAP_FIXED, fd, 0);
  close(fd);  // mapping holds its own reference

  if (r == MAP_FAILED) {
    log_line("mmap MAP_FIXED failed for %p (+%zu): %s\n", (void *)base, len,
             strerror(errno));
    __real__exit(EXIT_FAILURE);
  }
}

static void collect_traps(void) {
  size_t n = (size_t)(__stop___traps - __start___traps);
  g_traps = malloc(n * sizeof(trap_entry));
  if (!g_traps) {
    log_line("collect_traps: oom\n");
    __real__exit(EXIT_FAILURE);
  }

  size_t   kept = 0;
  uint32_t max_id = 0;
  for (size_t i = 0; i < n; i++) {
    void          *addr = __start___traps[i];
    unsigned char *b = (unsigned char *)addr;

    int is_loop =
        (b[1] == 0x90 && b[2] == 0x90 && b[3] == 0x90 && b[4] == 0x90);
    uint32_t id =
        is_loop ? (b[5] | (b[6] << 8) | (b[7] << 16) | ((uint32_t)b[8] << 24))
                : (b[1] | (b[2] << 8) | (b[3] << 16) | ((uint32_t)b[4] << 24));

    if (id > max_id) max_id = id;

    g_traps[kept++] = (trap_entry){.addr = addr, .id = id, .is_loop = is_loop};
    // log_line("trap[%zu]: addr=%p id=%u loop=%d\n",
    //          i, g_traps[i].addr, g_traps[i].id, g_traps[i].is_loop);
  }
  g_trap_count = kept;

  if (g_trap_count && max_id >= TRAP_VIRGIN_WORDS) {
    log_line(
        "highest trap id %u does not fit TRAP_VIRGIN_WORDS (%u): "
        "raise TRAP_VIRGIN_WORDS in AFL++ config.h, then rebuild "
        "afl-fuzz and the harness\n",
        max_id, (unsigned)TRAP_VIRGIN_WORDS);
    __real__exit(EXIT_FAILURE);
  }
  // log_line("collected %zu trap sites\n", g_trap_count);
}

int main(int argc, char **argv) {
  init_log_path();
  setup_fd(); /* before __untracer_snapshot_fds(): these fds must survive resets
               */
  if (argc < 2) {
    log_line("usage: harness <input_file>\n");
    __real__exit(EXIT_FAILURE);
  }
  collect_traps();
  make_pages_shared();

  setup_shm();
  setup_signal();

  if (__untracer_setup_global()) {
    log_line("failed to setup globals \n");
    __real__exit(EXIT_FAILURE);
  }

  __untracer_snapshot_fds();  // missing
  __untracer_heap_start();    // missing

  run_persistent(argv[0], argv[1]);
  return 0;
}