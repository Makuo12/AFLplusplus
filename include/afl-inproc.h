/*
   Fuzzbiosis in-process executor (src/afl-inproc.c).

   The target is an archive library statically linked into afl-fuzz and
   called directly. AFL++ reaches the executor through the forkserver API's
   names (afl_fsrv_start / afl_fsrv_write_to_testcase / afl_fsrv_run_target),
   which afl-inproc.c forwards here.
 */

#ifndef AFL_INPROC_H
#define AFL_INPROC_H

#include "forkserver.h"

struct afl_state;

/* Prepare the linked target once: restore trap state after a restart, call
   fuzzbiosis_runtime_init() and LLVMFuzzerInitialize(argc, argv) if the
   target has them, install the crash and timeout handlers. */
void fuzzbiosis_load(afl_forkserver_t *fsrv, char **argv, u8 debug_output);

/* Hand the next input to the executor (copied to an exact-size buffer). */
void fuzzbiosis_set_input(u8 *buf, size_t len);

/* Run the current input through the target: FSRV_RUN_OK, FSRV_RUN_TMOUT
   or FSRV_RUN_CRASH, with the same bookkeeping as the forkserver. */
fsrv_run_result_t fuzzbiosis_run_target(afl_forkserver_t *fsrv, u32 timeout);

/* ---- src/afl-fuzz-restart.c -------------------------------------------- */

/* Record the command line and register the re-exec handler. Once, early. */
void fuzzbiosis_restart_init(void);

/* Real path of the running afl-fuzz binary (the one to relink over). */
const char *fuzzbiosis_exe_path(void);

/* After a successful rebuild: save the trap state, stop the fuzzer cleanly
   and re-execute the relinked binary, which resumes the campaign. */
int fuzzbiosis_request_restart(struct afl_state *afl, u32 de_edge_max);

/* After a restart: put the saved trap virgin map back. */
void fuzzbiosis_restore_trap_state(struct afl_state *afl);

#endif