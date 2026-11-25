/*
   american fuzzy lop++ - in-process executor (Fuzzbiosis)
   -------------------------------------------------------

   The target is an archive library (libtarget.a) statically linked into
   afl-fuzz and called directly for every input: no forkserver, no fork, no
   pipes, no dlopen().

     make afl-fuzz TARGET_LIB=/path/to/libtarget.a
     afl-fuzz -i in -o out [options] -- /proc/self/exe [args...]

   The target "program" is afl-fuzz itself (/proc/self/exe), since the target
   lives inside it; the arguments after it go to LLVMFuzzerInitialize.

   Two layers:
     fuzzbiosis_load / fuzzbiosis_set_input / fuzzbiosis_run_target
         the executor itself (declared in include/afl-inproc.h);
     afl_fsrv_*
         thin forwards with the forkserver API's names, so AFL++ reaches the
         executor without changes:
           fuzz_run_target() -> afl_fsrv_run_target() -> fuzzbiosis_run_target()
             -> LLVMFuzzerTestOneInput() in the linked target.

   Restarting after de-instrumentation (save trap state, stop cleanly,
   re-exec the relinked binary) lives in src/afl-fuzz-restart.c.

   This file replaces afl-forkserver.c in the afl-fuzz link only
   (afl-showmap, afl-tmin, ... keep the real forkserver).

   Target contract (libtarget.a):
     int  LLVMFuzzerTestOneInput(const uint8_t *data, size_t size); required
     void fuzzbiosis_runtime_init(void);                            optional
     int  LLVMFuzzerInitialize(int *argc, char ***argv);            optional
   fuzzbiosis_runtime_init() is where the trap runtime attaches to the
   coverage maps (__AFL_SHM_ID, __AFL_TRAP_VIRGIN_SHM_ID). It is called once
   the maps exist, before LLVMFuzzerInitialize. It cannot be a constructor:
   statically linked, those run before afl-fuzz's main(), before the maps
   are created.

   Environment:
     AFL_DEBUG_CHILD          let the target write to stdout/stderr

   Crashes and timeouts: a fatal signal raised while the target runs, or the
   SIGALRM of the per-run timer, jumps back with siglongjmp() and the run is
   reported as FSRV_RUN_CRASH / FSRV_RUN_TMOUT. A signal raised while the
   fuzzer itself runs is not caught; it gets the default action. After a
   crash the process keeps going: if the target damaged memory or died
   holding a libc lock, the fuzzer can misbehave later.

 */

#include "afl-fuzz.h"
#include "afl-inproc.h"

#include <setjmp.h>
#include <signal.h>
#include <sys/time.h>

/* Lets other files ask "is this the in-process build?" through a weak
   reference, without depending on this file (see afl-fuzz-deinstr.c). */
const int afl_inproc_executor = 1;

/* The target, linked in from libtarget.a. Weak so afl-fuzz still links
   without a target (plain "make"); running it then stops with a message. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
    __attribute__((weak));
int  LLVMFuzzerInitialize(int *argc, char ***argv) __attribute__((weak));
void fuzzbiosis_runtime_init(void) __attribute__((weak));

static afl_state_t *ip_afl;
static u8           ip_loaded;

static u8    *ip_input; /* exact-size copy of the input */
static size_t ip_input_len;

static sigjmp_buf            ip_jmp;
static volatile sig_atomic_t ip_in_target; /* 1 only while the target runs */
static volatile sig_atomic_t ip_fault;     /* signal that ended the run    */
static sigset_t              ip_base_mask; /* mask to restore after faults */

static u8  ip_quiet; /* silence target output        */
static s32 ip_saved_out = -1, ip_saved_err = -1, ip_devnull = -1;

static const int ip_fault_sigs[] = {SIGSEGV, SIGBUS,  SIGILL,
                                    SIGFPE,  SIGABRT, SIGALRM};

/* ---------------------------------------------------------------------- */
/* Signals                                                                 */
/* ---------------------------------------------------------------------- */

static void ip_on_signal(int sig) {
  if (!ip_in_target) {
    /* The timer fired just after the target returned: nothing to do. */
    if (sig == SIGALRM) { return; }

    /* The fuzzer itself faulted. Restore the default action and let the
       fault happen again (returning re-executes the instruction; abort()
       is re-raised), so it dies normally instead of being hidden. */
    signal(sig, SIG_DFL);
    if (sig == SIGABRT) { raise(sig); }
    return;
  }

  ip_in_target = 0;
  ip_fault = sig;
  siglongjmp(ip_jmp, 1);
}

static void ip_install_handlers(void) {
  /* The handler runs on its own stack so a stack overflow in the target
     is caught too. */
  size_t  sz = 1 << 16;
  stack_t ss = {.ss_sp = ck_alloc(sz), .ss_size = sz, .ss_flags = 0};
  if (sigaltstack(&ss, NULL)) { PFATAL("inproc: sigaltstack() failed"); }

  /* SA_NODEFER keeps the signal unblocked after siglongjmp(), so the jump
     buffer does not have to save the signal mask: sigsetjmp(..., 1) would
     cost a syscall on every run. The fault path restores ip_base_mask
     instead, in case the target (or abort()) blocked other signals. */
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = ip_on_signal;
  sa.sa_flags = SA_ONSTACK | SA_NODEFER;
  sigemptyset(&sa.sa_mask);

  for (u32 i = 0; i < sizeof(ip_fault_sigs) / sizeof(*ip_fault_sigs); i++) {
    if (sigaction(ip_fault_sigs[i], &sa, NULL)) {
      PFATAL("inproc: sigaction(%d) failed", ip_fault_sigs[i]);
    }
  }

  sigprocmask(SIG_BLOCK, NULL, &ip_base_mask);
}

/* ---------------------------------------------------------------------- */
/* Target output                                                           */
/* ---------------------------------------------------------------------- */

/* The target shares stdout/stderr, and libc's FILE buffers, with the
   fuzzer. Point fds 1 and 2 at /dev/null while it runs, and drop whatever
   it left in the stdio buffers before the fds are given back. */

static inline void ip_silence(void) {
  fflush(stdout);
  fflush(stderr);
  dup2(ip_devnull, 1);
  dup2(ip_devnull, 2);
}

static inline void ip_unsilence(void) {
  fflush(stdout);
  fflush(stderr);
  dup2(ip_saved_out, 1);
  dup2(ip_saved_err, 2);
}

/* ---------------------------------------------------------------------- */
/* The target called exit()                                                */
/* ---------------------------------------------------------------------- */

/* The harness turns the target's exit() into a jump back to itself, so this
   only fires for an exit the harness cannot intercept (e.g. _exit from a
   library built without the redirect pass): the fuzzer goes down with the
   target. Record which input did it, since nothing else will. */

static void ip_on_exit(void) {
  if (!ip_in_target || !ip_afl) { return; }
  ip_in_target = 0;

  u8 *fn = alloc_printf("%s/inproc_exit_input", ip_afl->out_dir);
  s32 fd = open((char *)fn, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);
  if (fd >= 0) {
    if (write(fd, ip_input, ip_input_len) != (ssize_t)ip_input_len) {}
    close(fd);
  }

  if (ip_saved_err >= 0) { dup2(ip_saved_err, 2); }
  fprintf(stderr,
          "\n[-] inproc: the target called exit() while running an input; "
          "afl-fuzz stops with it. The input was saved to %s\n",
          fn);
  ck_free(fn);
}

/* ---------------------------------------------------------------------- */
/* Executor: load, input, run                                              */
/* ---------------------------------------------------------------------- */

/* Prepare the linked target: once only. */

void fuzzbiosis_load(afl_forkserver_t *fsrv, char **argv, u8 debug_output) {
  if (ip_loaded) { return; }
  ip_loaded = 1;

  afl_state_t *afl = (afl_state_t *)fsrv->afl_ptr;
  ip_afl = afl;

  if (!LLVMFuzzerTestOneInput) {
    FATAL(
        "inproc: no target linked into afl-fuzz. Build it with "
        "'make afl-fuzz TARGET_LIB=/path/to/libtarget.a'");
  }

  if (afl->custom_mutators_count) {
    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {
      if (el->afl_custom_fuzz_send) {
        FATAL(
            "inproc: custom mutator '%s' delivers inputs itself (fuzz_send), "
            "which needs a separate target process",
            el->name);
      }
    });
  }

  for (u32 i = 1; argv && argv[i]; i++) {
    if (strstr(argv[i], "@@")) {
      WARNF(
          "inproc: '@@' is ignored; the input is passed to the entry point "
          "in memory");
      break;
    }
  }

  ip_quiet = !debug_output;

  if (ip_quiet) {
    ip_devnull = open("/dev/null", O_RDWR);
    ip_saved_out = dup(1);
    ip_saved_err = dup(2);
    if (ip_devnull < 0 || ip_saved_out < 0 || ip_saved_err < 0) {
      PFATAL("inproc: cannot set up output redirection");
    }
  }

  /* Coming back from a de-instrumentation restart? */
  fuzzbiosis_restore_trap_state(afl);

  /* The maps and their environment variables exist now: let the target's
     runtime attach to them. */
  if (fuzzbiosis_runtime_init) { fuzzbiosis_runtime_init(); }

  if (LLVMFuzzerInitialize && argv) {
    /* argv[0] is the target "program", the rest are its arguments. */
    int    argc = 0;
    char **args = argv;
    while (args[argc]) {
      argc++;
    }
    ACTF("inproc: calling LLVMFuzzerInitialize()...");
    LLVMFuzzerInitialize(&argc, &args);
  }

  /* Installed after LLVMFuzzerInitialize has run, so ours are the handlers
     in place while fuzzing. */
  ip_install_handlers();
  atexit(ip_on_exit);

  OKF("inproc: target linked in%s.",
      ip_quiet ? ", output silenced (AFL_DEBUG_CHILD shows it)" : "");
}

/* Keep the input in memory, in a buffer of exactly its size so ASan can see
   reads past its end. */

void __attribute__((hot)) fuzzbiosis_set_input(u8 *buf, size_t len) {
  if (unlikely(len > MAX_FILE)) { len = MAX_FILE; }

  free(ip_input);
  ip_input = malloc(len ? len : 1);
  if (unlikely(!ip_input)) { PFATAL("inproc: malloc() failed"); }
  if (len) { memcpy(ip_input, buf, len); }
  ip_input_len = len;
}

/* Run one input. Same bookkeeping as the forkserver version: clear the map,
   count the execution, set last_run_timed_out / last_kill_signal /
   child_status, return OK / TMOUT / CRASH. */

fsrv_run_result_t __attribute__((hot)) fuzzbiosis_run_target(
    afl_forkserver_t *fsrv, u32 timeout) {
  static const struct itimerval disarm = {{0, 0}, {0, 0}};
  struct itimerval arm = {{0, 0}, {timeout / 1000, (timeout % 1000) * 1000}};

  if (unlikely(!ip_loaded)) {
    FATAL("inproc: target run before it was loaded");
  }

  memset(fsrv->trace_bits, 0, fsrv->map_size);
  fsrv->last_run_timed_out = 0;
  fsrv->last_kill_signal = 0;
  fsrv->child_status = 0;
  ip_fault = 0;

  if (ip_quiet) { ip_silence(); }

  if (!sigsetjmp(ip_jmp, 0)) {
    setitimer(ITIMER_REAL, &arm, NULL);
    ip_in_target = 1;
    LLVMFuzzerTestOneInput(ip_input, ip_input_len);
    ip_in_target = 0;
  }

  setitimer(ITIMER_REAL, &disarm, NULL);

  if (unlikely(ip_fault)) { sigprocmask(SIG_SETMASK, &ip_base_mask, NULL); }

  if (ip_quiet) { ip_unsilence(); }

  fsrv->total_execs++;
  MEM_BARRIER();

  if (unlikely(ip_fault)) {
    if (ip_fault == SIGALRM) {
      fsrv->last_run_timed_out = 1;
      fsrv->last_kill_signal = fsrv->child_kill_signal;
      fsrv->child_status = fsrv->child_kill_signal; /* WIFSIGNALED form */
      return FSRV_RUN_TMOUT;
    }

    fsrv->last_kill_signal = ip_fault;
    fsrv->child_status = ip_fault; /* WIFSIGNALED form */
    return FSRV_RUN_CRASH;
  }

  return FSRV_RUN_OK;
}

/* ---------------------------------------------------------------------- */
/* AFL++'s setup entry points                                              */
/* ---------------------------------------------------------------------- */

/* Same defaults as the real afl_fsrv_init(), minus what only a forkserver
   process uses. Called once, early in main(): also records the command
   line for a later restart and registers the exit handler first, so it
   runs after AFL++'s own. */

void afl_fsrv_init(afl_forkserver_t *fsrv) {
#ifdef __linux__
  fsrv->nyx_handlers = NULL;
  fsrv->out_dir_path = NULL;
  fsrv->nyx_mode = 0;
  fsrv->nyx_runner = NULL;
  fsrv->nyx_log_fd = -1;
  fsrv->gui_mode = 0;
  fsrv->gui_python_pid = -1;
#endif

  fsrv->out_fd = -1;
  fsrv->out_dir_fd = -1;
  fsrv->dev_null_fd = -1;
  fsrv->crash_trace_fd = -1;
  fsrv->dev_urandom_fd = -1;
  fsrv->fsrv_ctl_fd = -1;
  fsrv->fsrv_st_fd = -1;

  fsrv->use_stdin = true;
  fsrv->no_unlink = false;
  fsrv->exec_tmout = EXEC_TIMEOUT;
  fsrv->init_tmout = EXEC_TIMEOUT * FORK_WAIT_MULT;
  fsrv->mem_limit = MEM_LIMIT;
  fsrv->out_file = NULL;
  fsrv->child_kill_signal = SIGKILL;
  fsrv->max_length = MAX_FILE;

  fsrv->child_pid = -1;
  fsrv->last_child_pid = -1;
  fsrv->map_size = get_map_size();
  fsrv->real_map_size = fsrv->map_size;
  fsrv->use_fauxsrv = false;
  fsrv->use_value_profile = false;
  fsrv->last_run_timed_out = false;
  fsrv->debug = false;
  fsrv->uses_crash_exitcode = false;
  fsrv->uses_asan = 0;
  fsrv->uid_set = 0;
  fsrv->gid_set = 0;
  fsrv->perm = DEFAULT_PERMISSION;
  fsrv->child_sync = NULL;
  fsrv->child_sync_offset = 0;

  /* Record the command line and register the re-exec handler now, early
     in main(), so it runs after AFL++'s own exit handlers. */
  fuzzbiosis_restart_init();
}

/* Only cmplog (-c) and sanitizer binaries (-w) clone the forkserver; both
   need a second target process. */

void afl_fsrv_init_dup(afl_forkserver_t *fsrv_to, afl_forkserver_t *from) {
  (void)fsrv_to;
  (void)from;
  FATAL("inproc: -c (cmplog) and -w (sanitizer binaries) are not supported");
}

/* Prepare the target once. fsrv_pid stays 0 (there is no forkserver), so
   callers such as calibrate_case_trap() call this again later: those calls
   return at once. */

void afl_fsrv_start(afl_forkserver_t *fsrv, char **argv,
                    volatile u8 *stop_soon_p, u8 debug_child_output) {
  (void)stop_soon_p;
  fuzzbiosis_load(fsrv, argv, debug_child_output);
}

/* The startup map-size probe. Prepare the target now (the coverage maps and
   their environment variables already exist) and report that no larger
   map is needed: a resize would re-create the coverage SHM. */

u32 afl_fsrv_get_mapsize(afl_forkserver_t *fsrv, char **argv,
                         volatile u8 *stop_soon_p, u8 debug_child_output) {
  afl_fsrv_start(fsrv, argv, stop_soon_p, debug_child_output);
  return 0;
}

/* ---------------------------------------------------------------------- */
/* AFL++'s entry points, forwarded to the executor                         */
/* ---------------------------------------------------------------------- */

void __attribute__((hot)) afl_fsrv_write_to_testcase(afl_forkserver_t *fsrv,
                                                     u8 *buf, size_t len) {
  (void)fsrv;
  fuzzbiosis_set_input(buf, len);
}

fsrv_run_result_t __attribute__((hot)) afl_fsrv_run_target(
    afl_forkserver_t *fsrv, u32 timeout, volatile u8 *stop_soon_p) {
  (void)stop_soon_p;
  return fuzzbiosis_run_target(fsrv, timeout);
}

/* No process to stop. */

void afl_fsrv_kill(afl_forkserver_t *fsrv) {
  (void)fsrv;
}

void afl_fsrv_deinit(afl_forkserver_t *fsrv) {
  (void)fsrv;
}

#ifdef __linux__
nyx_plugin_handler_t *afl_load_libnyx_plugin(u8 *libnyx_binary) {
  (void)libnyx_binary;
  FATAL("inproc: Nyx mode (-X/-Y) is not supported");
  return NULL;
}

void nyx_load_target_hash(afl_forkserver_t *fsrv) {
  (void)fsrv;
  FATAL("inproc: Nyx mode (-X/-Y) is not supported");
}

#endif