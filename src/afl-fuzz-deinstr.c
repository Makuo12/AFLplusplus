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

static u32   de_edge_count;      /* new edges since last de-instrumentation  */
static u32   de_edge_loop_count; /* new loop buckets since last rebuild      */
static u32   de_edge_max = 4000; /* DE_EDGE_MAX env                          */
static u8    de_arc;             /* DE_EDGE_ARC env: bfd + image-base link   */
static u8    de_enabled;         /* config validated at startup              */
static u8   *de_out_home, *de_meta, *de_thr, *de_clangxx, *de_base, *de_ir_file;
static u8   *de_link_extra; /* DE_LINK_EXTRA: owned copy, tokenized once */
static char *de_extra_argv[96];
static int   de_extra_argc;

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

void deinstr_setup(afl_state_t *afl) {
  u32 i;

  if (!afl->trap_mode) { return; }
  

  if (getenv("DE_EDGE_MAX")) { de_edge_max = atoi(getenv("DE_EDGE_MAX")); }
  if (getenv("DE_EDGE_ARC")) { de_arc = 1; }

  de_out_home = getenv("OUTPUT_HOME");
  de_meta = getenv("META_DATA_FILE");
  de_thr = getenv("LOOP_THRESHOLD_FILE");
  de_clangxx = getenv("DE_CLANGXX");
  de_base = getenv("BASE_ADDRESS");
  de_ir_file = getenv("DE_IR_FILE");

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
        "DE_LINK_EXTRA is empty (no harness to link) - de-instrumentation "
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

  de_enabled = 1;
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

static int remove_instrumentation(afl_state_t *afl) {
  int ret = -1;

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
      likely(de_edge_count + de_edge_loop_count <= de_edge_max)) {
    return;
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