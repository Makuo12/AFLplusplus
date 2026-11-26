/*
   american fuzzy lop++ - restart after de-instrumentation (Fuzzbiosis)
   --------------------------------------------------------------------

   The target is linked into afl-fuzz (src/afl-inproc.c), so new target code
   means a new afl-fuzz binary. After afl-fuzz-deinstr.c has rebuilt the
   target and relinked afl-fuzz over its own path, this file restarts the
   campaign on it:

     1. fuzzbiosis_request_restart() saves the trap virgin map, puts the
        restart state in the environment (it survives execv) and asks
        AFL++ to stop cleanly (stop_soon), so the final stats, the queue
        position and fastresume.bin are written as usual;
     2. stop_fuzzing() ends in exit(); the exit handler registered here runs
        after AFL++'s own, closes every fd above 2 (including the lock on
        the output directory) and re-executes the new binary with the
        original command line (AFL_AUTORESUME=1);
     3. the new process resumes the campaign; fuzzbiosis_restore_trap_state()
        (called by the executor when it prepares the target) copies the
        saved map back, so probes that already fired are not reported again.

   Nothing here depends on the executor, so this file is plain afl-fuzz
   code (picked up by the src/afl-fuzz*.c wildcard).
 */

#include "afl-fuzz.h"
#include "afl-inproc.h"

static char   rs_exe_path[PATH_MAX]; /* real path of this binary     */
static char **rs_argv;               /* original command line        */
static u8     rs_restart;            /* re-exec at exit              */

/* Re-execute the relinked binary. Registered once, early in main() (from
   afl_fsrv_init), so it runs after AFL++'s own exit handlers. */

static void rs_atexit(void) {
  if (!rs_restart) { return; }

  fflush(NULL);

  /* The old maps are gone after exec: do not let the new process see
     their IDs. afl-fuzz creates and exports fresh ones. */
  unsetenv(SHM_ENV_VAR);
  unsetenv(TRAP_SHM_ENV_VAR);

  /* execv() keeps open fds: close everything but stdin/out/err, above all
     the lock on the output directory, which the new process takes again. */
  long max_fd = sysconf(_SC_OPEN_MAX);
  if (max_fd < 0 || max_fd > 65536) { max_fd = 65536; }
  for (long fd = 3; fd < max_fd; fd++) {
    close((int)fd);
  }

  execv(rs_exe_path, rs_argv);
  fprintf(stderr, "[-] fuzzbiosis: re-exec of '%s' failed: %s\n", rs_exe_path,
          strerror(errno));
}

/* Remember how this process was started: the real path of the binary (so
   the relinked file is executed, not the old inode behind /proc/self/exe)
   and the original command line, from /proc/self/cmdline. Once only. */

void fuzzbiosis_restart_init(void) {
  static u8 once;
  if (once) { return; }
  once = 1;

  atexit(rs_atexit);

  ssize_t n = readlink("/proc/self/exe", rs_exe_path, sizeof(rs_exe_path) - 1);
  if (n <= 0) {
    rs_exe_path[0] = 0;
    return;
  }
  rs_exe_path[n] = 0;

  s32 fd = open("/proc/self/cmdline", O_RDONLY);
  if (fd < 0) { return; }
  u8      buf[65536];
  ssize_t len = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (len <= 0) { return; }
  buf[len] = 0;

  u32 argc = 0;
  for (ssize_t i = 0; i < len; i++) {
    if (!buf[i]) { argc++; }
  }

  rs_argv = ck_alloc((argc + 1) * sizeof(char *));
  u8 *p = buf;
  for (u32 i = 0; i < argc; i++) {
    rs_argv[i] = (char *)ck_strdup(p);
    p += strlen((char *)p) + 1;
  }
  rs_argv[argc] = NULL;
}

const char *fuzzbiosis_exe_path(void) {
  return rs_exe_path[0] ? rs_exe_path : NULL;
}

/* Save the trap virgin map, arrange for the next process to restore it and
   to resume the campaign, and stop the fuzzer cleanly. The re-exec itself
   happens in rs_atexit(). */

int fuzzbiosis_request_restart(afl_state_t *afl, u32 de_edge_max) {
  if (!rs_exe_path[0] || !rs_argv) {
    WARNF("fuzzbiosis: cannot restart (command line unknown)");
    return -1;
  }

  u8 *fn = alloc_printf("%s/.fuzzbiosis_trap_state", afl->out_dir);
  s32 fd = open((char *)fn, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);
  if (fd < 0) {
    WARNF("fuzzbiosis: cannot write '%s'", fn);
    ck_free(fn);
    return -1;
  }

  size_t bytes = TRAP_VIRGIN_WORDS * sizeof(u32);
  if (write(fd, afl->trap_virgin_bits, bytes) != (ssize_t)bytes) {
    close(fd);
    WARNF("fuzzbiosis: short write to '%s'", fn);
    ck_free(fn);
    return -1;
  }
  close(fd);

  /* The environment survives execv(): it carries the restart state. */
  setenv("FUZZBIOSIS_TRAP_STATE", (char *)fn, 1);
  setenv("AFL_AUTORESUME", "1", 1);
  setenv("AFL_FORCE_FASTRESUME", "1", 1);
  setenv("FUZZBIOSIS_DE_ON", "1", 1);
  u8 tmp[32];
  snprintf((char *)tmp, sizeof(tmp), "%u", de_edge_max);
  setenv("FUZZBIOSIS_DE_EDGE_MAX", (char *)tmp, 1);
  ck_free(fn);

  rs_restart = 1;
  afl->stop_soon = 2;
  OKF("fuzzbiosis: trap state saved, restarting on the rebuilt binary...");
  return 0;
}

/* After a restart: copy the saved trap virgin map into the new map, so the
   probes that already fired are not reported as new coverage again. */

void fuzzbiosis_restore_trap_state(afl_state_t *afl) {
  char *fn = getenv("FUZZBIOSIS_TRAP_STATE");
  if (!fn || !*fn) { return; }

  size_t bytes = TRAP_VIRGIN_WORDS * sizeof(u32);
  s32    fd = open(fn, O_RDONLY);
  if (fd < 0) {
    WARNF("fuzzbiosis: saved trap state '%s' missing, starting fresh", fn);
  } else {
    if (read(fd, afl->trap_virgin_bits, bytes) != (ssize_t)bytes) {
      memset(afl->trap_virgin_bits, 0, bytes);
      WARNF("fuzzbiosis: saved trap state '%s' is short, starting fresh", fn);
    } else {
      u64 count = 0;
      for (u32 i = 0; i < TRAP_VIRGIN_WORDS; i++) {
        count += afl->trap_virgin_bits[i];
      }
      afl->trap_virgin_count = count;
      OKF("fuzzbiosis: restored trap state (%llu probes already fired).",
          (unsigned long long)count);
    }
    close(fd);
    unlink(fn);
  }

  unsetenv("FUZZBIOSIS_TRAP_STATE");
}