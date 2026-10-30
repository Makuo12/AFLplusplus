#include "afl-fuzz.h"
#include <sys/ipc.h>
#include <sys/shm.h>

/* Called once after option parsing. Turns off every feature that needs
   repeatable traces: a trap fires once per session, so later runs of the
   same input see nothing. */

void trap_mode_setup(afl_state_t *afl) {
  if (!afl->trap_mode) { return; }

  OKF("Trap-based instrumentation mode enabled (AFL_TRAP_MODE).");

#ifndef __linux__
  FATAL("AFL_TRAP_MODE is only supported on Linux");
#endif
#ifdef USEMMAP
  FATAL("AFL_TRAP_MODE needs SysV shared memory; rebuild without USEMMAP");
#endif

  if (afl->non_instrumented_mode) {
    FATAL("AFL_TRAP_MODE and -n are mutually exclusive");
  }

  if (afl->shm.cmplog_mode) {
    FATAL("AFL_TRAP_MODE does not support CmpLog (-c): traps fire only once");
  }

  /* FAST & co. count hits per path hash; with traps almost every run has
     an empty trace, so those counts are meaningless. */
  if (afl->schedule != EXPLORE) {
    WARNF("AFL_TRAP_MODE: power schedule forced to 'explore'");
    afl->schedule = EXPLORE;
  }
  afl->saved_schedule = afl->schedule;

  /* -D uses an effector map built by comparing traces. */
  if (!afl->skip_deterministic) {
    WARNF("AFL_TRAP_MODE: deterministic stages (-D) disabled");
    afl->skip_deterministic = 1;
  }

  afl->disable_trim = 1;                    /* trim compares checksums  */
  afl->afl_env.afl_frameshift_disabled = 1; /* compares traces          */
}

/* The harness-owned virgin map: the SHM_ID half of your old setup_shm(). */

void trap_setup_shm(afl_state_t *afl) {
  if (!afl->trap_mode) { return; }

  size_t bytes = (size_t)TRAP_VIRGIN_WORDS * sizeof(u32);

  afl->trap_virgin_shm_id =
      shmget(IPC_PRIVATE, bytes, IPC_CREAT | IPC_EXCL | afl->perm);
  if (afl->trap_virgin_shm_id < 0) { PFATAL("trap: shmget() failed"); }

  afl->trap_virgin_bits = shmat(afl->trap_virgin_shm_id, NULL, 0);
  if (afl->trap_virgin_bits == (void *)-1) {
    shmctl(afl->trap_virgin_shm_id, IPC_RMID, NULL);
    PFATAL("trap: shmat() failed");
  }

  /* Linux keeps an IPC_RMID-marked segment alive and attachable while we
     hold it, so mark it now: nothing leaks even if we are SIGKILLed.
     (AFL++ does the same for its own maps.) */
  shmctl(afl->trap_virgin_shm_id, IPC_RMID, NULL);

  memset(afl->trap_virgin_bits, 0, bytes);

  u8 *id_str = alloc_printf("%d", afl->trap_virgin_shm_id);
  setenv(TRAP_SHM_ENV_VAR, id_str, 1);
  ck_free(id_str);
}

void trap_remove_shm(afl_state_t *afl) {
  if (afl->trap_virgin_bits && afl->trap_virgin_bits != (void *)-1) {
    shmdt(afl->trap_virgin_bits);
    afl->trap_virgin_bits = NULL;
  }
}

/* The harness writes its two counters as u32 into the first words of
   AFL++'s coverage map (AFL++ zeroes the whole map before every run). */

static inline u32 *trap_counters(afl_state_t *afl) {
  return (u32 *)afl->fsrv.trace_bits;
}

/* 2 if this run hit anything the harness had not seen before, else 0.
   Same as your has_new_traps(); 2 means "new coverage" to AFL++ too. */

u8 has_new_traps(afl_state_t *afl) {
  u32 *t = trap_counters(afl);
  return (t[TRAP_NEW_EDGE_IDX] || t[TRAP_NEW_LOOP_IDX]) ? 2 : 0;
}

/* How much new coverage the last run reported (edges + loop buckets). */

u32 trap_count_bytes(afl_state_t *afl) {
  u32 *t = trap_counters(afl);
  return t[TRAP_NEW_EDGE_IDX] + t[TRAP_NEW_LOOP_IDX];
}

/* Number of trap ids ever reported, read from the harness's virgin map.
   This is what the UI and fuzzer_stats show as "edges found". */

u32 trap_count_virgin_entries(afl_state_t *afl) {
  u32 i, ret = 0;
  if (!afl->trap_virgin_bits) { return 0; }

  for (i = 0; i < TRAP_VIRGIN_WORDS; i++) {
    if (afl->trap_virgin_bits[i]) { ++ret; }
  }

  return ret;
}

/* prior_hnb / prior_cnt carry the novelty of the run that discovered the
   entry: by the time we calibrate, its traps are gone, so the re-runs below
   cannot see it any more. Seeds pass 0/0 and use the first run instead.
   The first run is not timed (it may still fire leftover traps). */

u8 calibrate_case_trap(afl_state_t *afl, struct queue_entry *q, u8 *use_mem,
                       u32 handicap, u8 from_queue, u8 prior_hnb,
                       u32 prior_cnt) {
  /* AFL++ has no re_run_cal; fuzz_one only recalibrates entries whose
     calibration failed, which are never was_fuzzed, so this matches. */
  u8  fault = 0, new_bits = prior_hnb, hnb = 0, first_run = !q->was_fuzzed;
  u64 start_us = 0, stop_us, diff_us;
  s32 old_sc = afl->stage_cur, old_sm = afl->stage_max;
  u32 use_tmout = afl->fsrv.exec_tmout;
  u8 *old_sn = afl->stage_name;
  u32 cov_cnt = prior_cnt;

  u64 calibration_start_us = get_cur_time_us();

  if (!from_queue || afl->resuming_fuzz) {
    use_tmout = MAX(afl->fsrv.exec_tmout + CAL_TMOUT_ADD,
                    afl->fsrv.exec_tmout * CAL_TMOUT_PERC / 100);
  }

  ++q->cal_failed;

  afl->stage_name = "calibration";
  afl->stage_max = afl->afl_env.afl_cal_fast ? CAL_CYCLES_FAST : CAL_CYCLES;
  if (afl->stage_max < 2) { afl->stage_max = 2; } /* run 0 is untimed */

  /* Start the forkserver if needed: copied from the stock calibrate_case. */

  if (!afl->fsrv.fsrv_pid) {
    u8 vp_env_armed = vp_env_arm(afl);
    afl_fsrv_start(&afl->fsrv, afl->argv, &afl->stop_soon,
                   afl->afl_env.afl_debug_child);
    if (vp_env_armed) { vp_env_disarm(); }

    if (afl->fsrv.support_shmem_fuzz && !afl->fsrv.use_shmem_fuzz) {
      afl_shm_deinit(afl->shm_fuzz);
      ck_free(afl->shm_fuzz);
      afl->shm_fuzz = NULL;
      afl->fsrv.support_shmem_fuzz = 0;
      afl->fsrv.shmem_fuzz = NULL;
    }
  }

  /* Stock does this too: run the input exactly as stored, not re-mangled by
     a post-processing custom mutator. */
  u8 saved_keep_original = afl->afl_env.afl_post_process_keep_original;
  afl->afl_env.afl_post_process_keep_original = 1;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {
    if (afl->stage_cur == 1) { start_us = get_cur_time_us(); }

    if (!first_run && !(afl->stage_cur % afl->stats_update_freq)) {
      show_stats(afl);
    }

    (void)write_to_testcase(afl, (void **)&use_mem, q->len, 1);

    fault = fuzz_run_target(afl, &afl->fsrv, use_tmout);

    update_calibration_time(afl, &calibration_start_us);

    if (afl->stop_soon || fault != afl->crash_mode) { goto abort_calibration; }

    if (!afl->stage_cur) {
      u32 c = trap_count_bytes(afl);
      if (!cov_cnt) { cov_cnt = c; } /* seeds: stage 0 is the real run */

      if (cov_cnt) {
        afl->trap_seen_cov = 1;

      } else if (!afl->trap_seen_cov) {
        fault = FSRV_RUN_NOINST; /* nothing has EVER been hit: broken */
        goto abort_calibration;
      }
    }

    hnb = has_new_traps(afl);
    if (hnb > new_bits) { new_bits = hnb; }
  }

  stop_us = get_cur_time_us();
  diff_us = stop_us - start_us;
  if (unlikely(!diff_us)) { diff_us = 1; }

  afl->total_cal_us += diff_us;
  afl->total_cal_cycles += afl->stage_max - 1;
  afl->trap_total_len += q->len;

  q->exec_us = diff_us / (afl->stage_max - 1);
  if (unlikely(!q->exec_us)) { q->exec_us = 1; }

  /* AFL++ tracks the slowest input here; it uses it for auto timeouts. */
  u32 exec_ms = (u32)((q->exec_us + 500) / 1000);
  if (unlikely(exec_ms > afl->slowest_exec_ms)) {
    afl->slowest_exec_ms = exec_ms;
  }

  if (cov_cnt) { q->bitmap_size = cov_cnt; }
  q->handicap = handicap;
  q->cal_failed = 0;

  afl->total_bitmap_size += q->bitmap_size;
  ++afl->total_bitmap_entries;

  /* Replaces update_bitmap_score(): the trap cull looks at the whole queue,
     so it only needs to know something changed. */
  afl->score_changed = 1;

  if (first_run && from_queue && !fault && !new_bits) {
    fault = FSRV_RUN_NOBITS;
  }

abort_calibration:

  afl->afl_env.afl_post_process_keep_original = saved_keep_original;

  if (new_bits == 2 && !q->has_new_cov) {
    q->has_new_cov = 1;
    ++afl->queued_with_cov;
  }

  afl->stage_name = old_sn;
  afl->stage_cur = old_sc;
  afl->stage_max = old_sm;

  if (!first_run) { show_stats(afl); }

  update_calibration_time(afl, &calibration_start_us);
  return fault;
}