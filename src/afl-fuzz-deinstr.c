/*
   american fuzzy lop++ - de-instrumentation for trap mode
   -------------------------------------------------------

   Port of the de-instrumentation from the trap-based AFL fork.

   The harness logs every fully retired trap id to META_DATA_FILE and every
   raised loop threshold to LOOP_THRESHOLD_FILE. Once more than DE_EDGE_MAX
   new edges + loop buckets have been reported since the last rebuild, we:

     1. stop the forkserver,
     2. run remove_edge on the IR (drops retired traps, bakes in thresholds),
     3. relink the target,
     4. promote the new IR, swap in the new binary,
     5. clear the two harness files and restart the forkserver.

   Environment:
     OUTPUT_HOME          dir with remove_edge, main.transformed.ll, fuzzer.bc
     META_DATA_FILE       written by the harness (retired trap ids)
     LOOP_THRESHOLD_FILE  written by the harness (id,threshold)
     DE_EDGE_MAX          rebuild threshold (default 4000)
     DE_EDGE_ARC          set: link with bfd + --image-base (cluster build)
     DE_CLANGXX           compiler for the relink (default clang++)
     BASE_ADDRESS         image base for DE_EDGE_ARC (default 0x400000)
     DE_LINK_EXTRA        extra arguments for the relink, space separated
                          (e.g. the persistent closure runtime objects and
                          its -Wl,--wrap=... flags); must match the build

   Only active in trap mode. If anything is missing, it is disabled with a
   warning and fuzzing continues normally.

 */

#include "afl-fuzz.h"
#include <sys/wait.h>

static u32 de_edge_count;      /* new edges since last de-instrumentation  */
static u32 de_edge_loop_count; /* new loop buckets since last rebuild      */
static u32 de_edge_max = 4000; /* DE_EDGE_MAX env                          */
static u8  de_arc;             /* DE_EDGE_ARC env: bfd + image-base link   */
static u8  de_enabled;         /* config validated at startup              */
static u8  de_on; /*this is set to true only when the first de-instrumentation
                     has been performed*/
static u8 *de_out_home, *de_meta, *de_thr, *de_clangxx, *de_base, *de_ir_file;
static time_t de_start_up;
static u8    *de_link_extra; /* DE_LINK_EXTRA: owned copy, tokenized once */
static char  *de_extra_argv[96];
static int    de_extra_argc;

static int de_run_time_to_start = 0;

/* Run a command and wait for it. 0 on success. */

static int de_run(char *const argv[]) {
  pid_t pid = fork();
  if (pid < 0) {
    WARNF("fork() failed: %s", strerror(errno));
    return -1;
  }

  if (pid == 0) {
    execvp(argv[0], argv);
    perror(argv[0]);
    _exit(127); /* never exit() in a child */
  }

  int status;
  if (waitpid(pid, &status, 0) < 0) {
    WARNF("waitpid() failed: %s", strerror(errno));
    return -1;
  }

  if (WIFSIGNALED(status)) {
    WARNF("%s terminated by signal %d", argv[0], WTERMSIG(status));
    return -1;
  }

  return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/* Read and validate the configuration once, at startup. */

/* Fuzzbiosis archive build (src/afl-inproc.c): the target is statically
   linked into afl-fuzz. A rebuild then produces a new libtarget.a, relinks
   afl-fuzz over its own path and restarts it with execv(). These symbols
   are defined only in that build, so they are NULL in a forkserver build. */
extern const int afl_inproc_executor __attribute__((weak));
const char *fuzzbiosis_exe_path(void) __attribute__((weak));
int fuzzbiosis_request_restart(afl_state_t *afl, u32 de_edge_max)    __attribute__((weak));

static u8   de_archive;                /* archive build: relink + restart  */
static char de_archive_tool[PATH_MAX]; /* fuzzbiosis-archive.sh            */
static char de_relink_tool[PATH_MAX];  /* afl-fuzz-relink.sh               */

/* FUZZBIOSIS_ARCHIVE / FUZZBIOSIS_RELINK, or the script next to afl-fuzz. */

static int de_find_tool(char *dst, const char *env, const char *name) {
  const char *v = getenv(env);
  if (v && *v) {
    snprintf(dst, PATH_MAX, "%s", v);
  } else {
    const char *exe = fuzzbiosis_exe_path ? fuzzbiosis_exe_path() : NULL;
    const char *slash = exe ? strrchr(exe, '/') : NULL;
    if (!slash) { return -1; }
    snprintf(dst, PATH_MAX, "%.*s/%s", (int)(slash - exe), exe, name);
  }
  return access(dst, X_OK);
}

void deinstr_setup(afl_state_t *afl) {
  u32 i;

  if (getenv("DE_EDGE_MAX")) { de_edge_max = atoi(getenv("DE_EDGE_MAX")); }
  if (getenv("DE_EDGE_ARC")) { de_arc = 1; }

  de_out_home = getenv("OUTPUT_HOME");
  de_meta = getenv("META_DATA_FILE");
  de_thr = getenv("LOOP_THRESHOLD_FILE");
  de_clangxx = getenv("DE_CLANGXX");
  de_base = getenv("BASE_ADDRESS");
  de_ir_file = getenv("DE_IR_FILE");

  de_run_time_to_start = 2 * 60 * 60; /* default: 2 hours */

  char *value = getenv("DE_RUN_TIME_TO_START");
  if (value) {
    int number = atoi(value);
    if (number >= 60) {
      de_run_time_to_start = number;
    } else {
      WARNF("DE_RUN_TIME_TO_START=%s is below 60 seconds - using the default.",
            value);
    }
  }

  if (!de_clangxx) { de_clangxx = "clang++"; }

  /* Split DE_LINK_EXTRA into separate arguments once, at startup. */
  if (getenv("DE_LINK_EXTRA")) {
    de_link_extra = (u8 *)ck_strdup((u8 *)getenv("DE_LINK_EXTRA"));
    char *save = NULL;
    for (char *tok = strtok_r((char *)de_link_extra, " \t\n", &save); tok;
         tok = strtok_r(NULL, " \t\n", &save)) {
      if (de_extra_argc >=
          (int)(sizeof(de_extra_argv) / sizeof(*de_extra_argv))) {
        WARNF(
            "DE_LINK_EXTRA has too many arguments - de-instrumentation "
            "DISABLED.");
        return;
      }

      de_extra_argv[de_extra_argc++] = tok;
    }
  }
  if (!de_base) { de_base = "0x400000"; }

  if (!de_out_home || !de_meta || !de_thr || !de_ir_file) {
    WARNF(
        "OUTPUT_HOME / META_DATA_FILE / LOOP_THRESHOLD_FILE / DE_IR_FILE not "
        "all set - de-instrumentation DISABLED.");
    return;
  }

  /* afl-fuzz links only the IR: the harness (shared.bc + forkserver.bc or
     persistent.bc) and the closure runtime must come from DE_LINK_EXTRA. */
  if (!de_extra_argc) {
    WARNF(
        "DE_LINK_EXTRA is empty (no harness or runtime to link) - "
        "de-instrumentation "
        "DISABLED.");
    return;
  }
  u8 *need[] = {"remove_edge", de_ir_file, NULL};
  for (i = 0; need[i]; i++) {
    u8 *p = alloc_printf("%s/%s", de_out_home, need[i]);
    if (access(p, R_OK)) {
      WARNF("'%s' not readable - de-instrumentation DISABLED.", p);
      ck_free(p);
      return;
    }

    ck_free(p);
  }

  if (&afl_inproc_executor) {
    if (de_find_tool(de_archive_tool, "FUZZBIOSIS_ARCHIVE",
                     "fuzzbiosis-archive.sh") ||
        de_find_tool(de_relink_tool, "FUZZBIOSIS_RELINK",
                     "afl-fuzz-relink.sh")) {
      WARNF(
          "fuzzbiosis-archive.sh / afl-fuzz-relink.sh not found next to "
          "afl-fuzz (or FUZZBIOSIS_ARCHIVE / FUZZBIOSIS_RELINK) - "
          "de-instrumentation DISABLED.");
      return;
    }
    de_archive = 1;
  }

  de_enabled = 1;
  de_start_up = time(NULL);

  /* Restarted after a de-instrumentation: the start delay has passed
     already, and the threshold may have been raised. */
  if (getenv("FUZZBIOSIS_DE_ON")) { de_on = 1; }
  if (getenv("FUZZBIOSIS_DE_EDGE_MAX")) {
    de_edge_max = atoi(getenv("FUZZBIOSIS_DE_EDGE_MAX"));
  }
  OKF("De-instrumentation enabled (threshold %u edges, %d extra link args).",
      de_edge_max, de_extra_argc);
}

/* Called from fuzz_run_target() after EVERY execution (fuzzing,
   calibration, crash / timeout re-runs), while the harness's counters for
   that run are still in trace_bits. Same tally as run_target() in the old
   fork. */

void deinstr_note_run(afl_state_t *afl) {
  u32 *t = (u32 *)afl->fsrv.trace_bits;
  de_edge_count += t[TRAP_NEW_EDGE_IDX];
  de_edge_loop_count += t[TRAP_NEW_LOOP_IDX];
}

/* Returns 0 on success. Order of commits is chosen so every partial failure
   is harmless:
     1. remove_edge  old IR -> new_ll          (nothing committed)
     2. relink       new_ll -> new_bin         (nothing committed)
     3. promote IR   new_ll -> main.transformed.ll
     4. swap binary  new_bin -> target_path
   The IR is the source of truth and the binary is derived from it. If step 4
   fails after step 3, the old binary keeps running, the next attempt rebuilds
   from the already-reduced IR, and stale ids in the meta file are harmless. */

/* Archive build. Same idea, more derived artifacts; still every partial
   failure is harmless:
     1. remove_edge  old IR -> new_ll                          (nothing
   committed)
     2. compile      new_ll -> new_target.o                    (nothing
   committed)
     3. archive      new_target.o + DE_LINK_EXTRA -> new_lib   (nothing
   committed)
     4. relink       afl-fuzz objects + new_lib -> new_exe     (nothing
   committed)
     5. promote IR   new_ll -> DE_IR_FILE
     6. swap binary  new_exe -> this afl-fuzz (rename() works while it runs)
   The running process keeps the old code until it re-executes itself.
   The archive is kept as OUTPUT_HOME/libtarget.a for reference. */

static int remove_instrumentation_archive(afl_state_t *afl) {
  int         ret = -1;
  const char *exe = fuzzbiosis_exe_path();
  (void)afl;

  u8 *remove_edge_bin = alloc_printf("%s/remove_edge", de_out_home);
  u8 *in_ll = alloc_printf("%s/%s", de_out_home, de_ir_file);
  u8 *new_ll = alloc_printf("%s/new.ll", de_out_home);
  u8 *new_obj = alloc_printf("%s/new_target.o", de_out_home);
  u8 *new_lib = alloc_printf("%s/libtarget.new.a", de_out_home);
  u8 *lib = alloc_printf("%s/libtarget.a", de_out_home);
  u8 *new_exe = alloc_printf("%s.new", exe);

  char *stage1[] = {(char *)remove_edge_bin, "-i", (char *)in_ll,  "-m",
                    (char *)de_meta,         "-o", (char *)new_ll, "-l",
                    (char *)de_thr,          NULL};

  /* Code generation only, as in the forkserver build's final link. */
  char *stage2[] = {(char *)de_clangxx,
                    "-O3",
                    "-funroll-loops",
                    "-DNDEBUG",
                    "-fno-stack-protector",
                    "-fomit-frame-pointer",
                    "-fno-semantic-interposition",
                    "-fvisibility=hidden",
                    "-Xclang",
                    "-disable-llvm-passes",
                    "-c",
                    (char *)new_ll,
                    "-o",
                    (char *)new_obj,
                    NULL};

  /* The archive tool bundles the target with its runtime (DE_LINK_EXTRA:
     objects, bitcode, -Wl,--wrap=... flags) and hides every symbol but the
     entry points, so nothing clashes with afl-fuzz's own. */
  char *stage3[160];
  int   n = 0;
  stage3[n++] = de_archive_tool;
  stage3[n++] = "-o";
  stage3[n++] = (char *)new_lib;
  stage3[n++] = (char *)new_obj;
  for (int k = 0; k < de_extra_argc; k++) {
    stage3[n++] = de_extra_argv[k];
  }
  stage3[n] = NULL;

  char *stage4[] = {de_relink_tool, (char *)new_lib, (char *)new_exe, NULL};

  if (de_run(stage1)) {
    WARNF("remove_edge failed");
    goto out;
  }
  if (de_run(stage2)) {
    WARNF("compiling the reduced IR failed");
    goto out;
  }
  if (de_run(stage3)) {
    WARNF("building the target archive failed");
    goto out;
  }
  if (de_run(stage4)) {
    WARNF("relinking afl-fuzz failed");
    goto out;
  }

  /* Step 5: promote IR. If this fails nothing has changed yet. */
  if (rename(new_ll, in_ll)) {
    WARNF("could not promote IR '%s'", new_ll);
    goto out;
  }

  /* Step 6: swap binary. */
  if (rename(new_exe, exe)) {
    WARNF(
        "could not install '%s' (IR already promoted; next try rebuilds "
        "from it)",
        new_exe);
    goto out;
  }

  if (rename(new_lib, lib)) { WARNF("could not keep '%s'", lib); }
  ret = 0;

out:
  if (ret) { /* ignore errors */
    unlink(new_exe);
    unlink(new_lib);
    unlink(new_ll);
  }
  unlink(new_obj);

  ck_free(remove_edge_bin);
  ck_free(in_ll);
  ck_free(new_ll);
  ck_free(new_obj);
  ck_free(new_lib);
  ck_free(lib);
  ck_free(new_exe);
  return ret;
}

static int remove_instrumentation(afl_state_t *afl) {
  int ret = -1;

  if (de_archive) { return remove_instrumentation_archive(afl); }

  u8 *target_path = afl->fsrv.target_path;
  u8 *remove_edge_bin = alloc_printf("%s/remove_edge", de_out_home);
  u8 *in_ll = alloc_printf("%s/%s", de_out_home, de_ir_file);
  u8 *new_ll = alloc_printf("%s/new.ll", de_out_home);
  u8 *new_bin = alloc_printf("%s.new", target_path);
  u8 *base_flag = alloc_printf("-Wl,--image-base=%s", de_base);

  char *stage1[] = {(char *)remove_edge_bin, "-i", (char *)in_ll,  "-m",
                    (char *)de_meta,         "-o", (char *)new_ll, "-l",
                    (char *)de_thr,          NULL};

  char *stage2[160];
  int   n = 0;
  stage2[n++] = (char *)de_clangxx;
  stage2[n++] = "-O3";
  stage2[n++] = "-funroll-loops";
  stage2[n++] = "-DNDEBUG";
  stage2[n++] = "-fno-stack-protector";
  stage2[n++] = "-fomit-frame-pointer";
  stage2[n++] = "-fno-semantic-interposition";
  stage2[n++] = "-fvisibility=hidden";
  /* Same as the build's final link: the IR is already optimized and
     instrumented, only generate code (no re-optimization, no duplicated
     traps). */

  stage2[n++] = "-Xclang";
  stage2[n++] = "-disable-llvm-passes";
  stage2[n++] = (char *)new_ll;
  for (int k = 0; k < de_extra_argc; k++) {
    stage2[n++] = de_extra_argv[k];
  }
  stage2[n++] = "-no-pie";
  if (de_arc) {
    stage2[n++] = "-fuse-ld=bfd";
    stage2[n++] = (char *)base_flag;
    stage2[n++] = "-Wl,-z,noseparate-code";
  }

  stage2[n++] = "-o";
  stage2[n++] = (char *)new_bin;
  stage2[n] = NULL;

  if (de_run(stage1)) {
    WARNF("remove_edge failed");
    goto out;
  }

  if (de_run(stage2)) {
    WARNF("relink failed");
    goto out;
  }

  /* Step 3: promote IR. If this fails nothing has changed yet. */
  if (rename(new_ll, in_ll)) {
    WARNF("could not promote IR '%s'", new_ll);
    goto out;
  }

  /* Step 4: swap binary. rename() works even if the old inode is executing. */
  if (rename(new_bin, target_path)) {
    WARNF(
        "could not install '%s' (IR already promoted; next try rebuilds "
        "from it)",
        new_bin);
    goto out;
  }

  ret = 0;

out:
  if (ret) { /* ignore errors */

    unlink(new_bin);
    unlink(new_ll);
  }

  ck_free(remove_edge_bin);
  ck_free(in_ll);
  ck_free(new_ll);
  ck_free(new_bin);
  ck_free(base_flag);
  return ret;
}

/* Stop the forkserver so the target binary can be rewritten. AFL++'s
   afl_fsrv_kill() kills the forkserver and its current child and closes the
   pipes, but only reaps without blocking; wait for it here so no stale
   process can still write to the harness files. */

static void deinstr_stop_forkserver(afl_state_t *afl) {
  s32 pid = afl->fsrv.fsrv_pid;

  afl_fsrv_kill(&afl->fsrv);
  if (pid > 0) { waitpid(pid, NULL, 0); } /* ECHILD is fine too */

  /* Don't let the last run's counters leak into the next one. */
  memset(afl->fsrv.trace_bits, 0, afl->fsrv.map_size);
}

/* Truncate a harness-written file, creating it if missing so the harness can
   always open it. Only call while no forkserver/child is alive. */

static void clear_file(const u8 *path) {
  s32 fd = open((char *)path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    /* Not fatal: with the IR chained, stale ids/thresholds are harmless
       (ids match nothing; thresholds equal what is already baked in). */
    WARNF("Unable to clear '%s'", path);
    return;
  }

  close(fd);
}

/* Called after every fuzzing execution, from common_fuzz_stuff(). */

void maybe_deinstrument(afl_state_t *afl) {
  if (likely(!de_enabled) ||
      likely(de_edge_count + de_edge_loop_count <= de_edge_max) ||
      likely(de_edge_count < 300)) {
    return;
  }

  if (!de_on) {
    time_t current_time = time(NULL);
    double difference = difftime(current_time, de_start_up);
    if (difference < de_run_time_to_start) {
      return;
    } else {
      de_on = 1;
    }
  }

  ACTF("De-instrumenting (%u new edges, %u loop buckets)...", de_edge_count,
       de_edge_loop_count);

  deinstr_stop_forkserver(afl); /* no writers from here on */

  if (remove_instrumentation(afl) == 0) {
    OKF("De-instrumentation done, restarting.");

    /* Success only: the batch is now baked into the new binary and the
       promoted IR. */
    clear_file(de_meta);
    clear_file(de_thr);

    de_edge_count = 0;
    de_edge_loop_count = 0;

    /* Archive build: the new code is in the relinked afl-fuzz on disk.
       Save the trap state, stop cleanly and re-execute it. */
    if (de_archive && fuzzbiosis_request_restart(afl, de_edge_max) == 0) {
      return;
    }

  } else {
    /* Old binary kept. Meta/threshold files are NOT cleared, so the same
       batch plus anything new is retried next time. */
    WARNF("De-instrumentation failed, continuing with old binary.");
    de_edge_max *= 2; /* don't retry on every exec */
  }

  /* Restart: with the old binary on failure, the new one on success. The
     virgin map lives in shared memory and survives, so traps the new binary
     still contains are not reported again. */
  afl_fsrv_start(&afl->fsrv, afl->argv, &afl->stop_soon,
                 afl->afl_env.afl_debug_child);
}