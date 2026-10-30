#include "afl-fuzz.h"
#include <sys/ipc.h>
#include <sys/shm.h>

/* Called once after option parsing. Turns off every feature that needs
   repeatable traces: a trap fires once per session, so later runs of the
   same input see nothing. */
#include <math.h>

void mark_as_redundant(afl_state_t *, struct queue_entry *, u8);

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

/* Write a queue / crash / hang file. permissive_create() is AFL++'s helper:
   it applies -o permissions and chown like the stock code does. */

static void trap_write_file(afl_state_t *afl, u8 *fn, void *mem, u32 len) {
  s32 fd = permissive_create(afl, fn);
  if (likely(fd >= 0)) {
    ck_write(fd, mem, len, fn);
    close(fd);
  }
}

u8 save_if_interesting_trap(afl_state_t *afl, void *mem, u32 len, u8 fault) {
  if (unlikely(len == 0)) { return 0; }

  u8  fn[PATH_MAX];
  u8  keeping = 0, res, hnb = 0;
  u8 *ext_dot = afl->file_extension ? "." : "";
  u8 *ext = afl->file_extension ? afl->file_extension : (u8 *)"";

  /* Capture novelty BEFORE calibration re-runs the target and consumes it. */
  u32 found_cnt = trap_count_bytes(afl);

  if (likely(fault == afl->crash_mode)) {
    /* Queue admission: keep only if this run hit previously unseen traps. */
    if (likely(!(hnb = has_new_traps(afl)))) {
      if (unlikely(afl->crash_mode)) { ++afl->total_crashes; }
      return 0;
    }

    afl->bitmap_changed = 1;
    afl->last_edge_time = get_cur_time(); /* for the UI / stats */
    afl->last_edge_execs = afl->fsrv.total_execs;

    /* Queue file name, same format as stock AFL++ (describe_op adds
       src:, op:, +cov, etc.). */
    u8 *queue_fn;
#ifndef SIMPLE_FILES
    if (!afl->afl_env.afl_sha1_filenames) {
      queue_fn = alloc_printf(
          "%s/queue/id:%06u,%s%s%s", afl->out_dir, afl->queued_items,
          describe_op(afl, hnb, NAME_MAX - strlen("id:000000,")), ext_dot, ext);

    } else {
      const char *hex = sha1_hex(mem, len);
      queue_fn =
          alloc_printf("%s/queue/%s%s%s", afl->out_dir, hex, ext_dot, ext);
      ck_free((char *)hex);
    }

#else
    queue_fn = alloc_printf("%s/queue/id_%06u%s%s", afl->out_dir,
                            afl->queued_items, ext_dot, ext);
#endif

    /* AFL++ writes the file before add_to_queue (your AFL did it after). */
    trap_write_file(afl, queue_fn, mem, len);

    u8 file_modified = add_to_queue(afl, queue_fn, len, 0);

    if (hnb == 2) {
      afl->queue_top->has_new_cov = 1;
      ++afl->queued_with_cov;
    }

    /* add_to_queue() may have rewritten the file (custom mutator post-
       processing); then calibrate what is actually on disk. */
    u8 *use_mem = mem, *reloaded = NULL;
    if (unlikely(file_modified)) {
      s32 rfd = open((char *)afl->queue_top->fname, O_RDONLY);
      if (unlikely(rfd < 0)) {
        PFATAL("Unable to open '%s'", (char *)afl->queue_top->fname);
      }

      reloaded = ck_alloc(afl->queue_top->len);
      ck_read(rfd, reloaded, afl->queue_top->len, afl->queue_top->fname);
      close(rfd);
      use_mem = reloaded;
    }

    /* Direct call (not via calibrate_case) so the discovery novelty is
       passed in: the re-runs inside can no longer see those traps. */
    res = calibrate_case_trap(afl, afl->queue_top, use_mem,
                              afl->queue_cycle - 1, 0, hnb, found_cnt);

    if (unlikely(res == FSRV_RUN_ERROR)) {
      FATAL("Unable to execute target application");
    }

    /* AFL++ keeps recent testcases in memory (testcase cache). */
    if (likely(afl->q_testcase_max_cache_size)) {
      queue_testcase_store_mem(afl, afl->queue_top, use_mem);
    }

    if (unlikely(reloaded)) { ck_free(reloaded); }

    keeping = 1;
  }

  switch (fault) {
    case FSRV_RUN_TMOUT:

      ++afl->total_tmouts;

      if (afl->saved_hangs >= KEEP_UNIQUE_HANG) { return keeping; }

      /* Unique = the hanging run hit traps nobody hit before. */
      if (!has_new_traps(afl)) { return keeping; }

      ++afl->saved_tmouts;

      /* Re-run with a more generous timeout to confirm it's a real hang. */

      if (afl->fsrv.exec_tmout < afl->hang_tmout) {
        u8 new_fault;
        (void)write_to_testcase(afl, (void **)&mem, len, 0);
        new_fault = fuzz_run_target(afl, &afl->fsrv, afl->hang_tmout);

        /* A longer timeout may uncover a crash; don't discard it. */
        if (!afl->stop_soon && new_fault == FSRV_RUN_CRASH) {
          goto keep_as_crash;
        }

        if (afl->stop_soon || new_fault != FSRV_RUN_TMOUT) { return keeping; }
      }

#ifndef SIMPLE_FILES
      snprintf(fn, PATH_MAX, "%s/hangs/id:%06llu,%s%s%s", afl->out_dir,
               afl->saved_hangs,
               describe_op(afl, 0, NAME_MAX - strlen("id:000000,")), ext_dot,
               ext);
#else
      snprintf(fn, PATH_MAX, "%s/hangs/id_%06llu%s%s", afl->out_dir,
               afl->saved_hangs, ext_dot, ext);
#endif

      ++afl->saved_hangs;
      afl->last_hang_time = get_cur_time();
      break;

    case FSRV_RUN_CRASH:

    keep_as_crash:

      /* No crash dedup: a crashing run usually re-walks known code, so its
         trace is empty. Save every crash, capped by KEEP_UNIQUE_CRASH. */

      ++afl->total_crashes;

      if (afl->saved_crashes >= KEEP_UNIQUE_CRASH) { return keeping; }

      if (unlikely(!afl->saved_crashes) &&
          (afl->afl_env.afl_no_crash_readme != 1)) {
        write_crash_readme(afl);
      }

#ifndef SIMPLE_FILES
      snprintf(fn, PATH_MAX, "%s/crashes/id:%06llu,sig:%02u,%s%s%s",
               afl->out_dir, afl->saved_crashes, afl->fsrv.last_kill_signal,
               describe_op(afl, 0, NAME_MAX - strlen("id:000000,sig:00,")),
               ext_dot, ext);
#else
      snprintf(fn, PATH_MAX, "%s/crashes/id_%06llu_%02u%s%s", afl->out_dir,
               afl->saved_crashes, afl->fsrv.last_kill_signal, ext_dot, ext);
#endif

      ++afl->saved_crashes;
      afl->last_crash_time = get_cur_time();
      afl->last_crash_execs = afl->fsrv.total_execs;
      break;

    case FSRV_RUN_ERROR:
      FATAL("Unable to execute target application");

    default:
      return keeping;
  }

  /* Save the crash or hang test case. */
  trap_write_file(afl, fn, mem, len);

  return keeping;
}

static inline double trap_cost_of(struct queue_entry *q) {
  double c = TRAP_CULL_W_TIME * log((double)q->exec_us + 1.0) +
             TRAP_CULL_W_LEN * log((double)q->len + 1.0);
  if (q->has_new_cov) { c += log(TRAP_CULL_NEWCOV_BONUS); }
  return c;
}

void cull_queue_trap(afl_state_t *afl) {
  struct queue_entry *q, *best = NULL;
  double              mean = 0.0, m2 = 0.0, best_c = 0.0, sd, thr;
  u32                 i, n = 0;

  if (likely(!afl->score_changed)) { return; }
  afl->score_changed = 0;

  afl->queued_favored = 0;
  afl->pending_favored = 0;
  afl->smallest_favored = -1; /* AFL++: lowest-id pending favored entry */

  /* Pass 1: running mean / variance (Welford) over active entries, and the
     single cheapest entry. AFL++ keeps the queue as an array, and entries
     can be disabled (e.g. crashing seeds), so those are skipped. */

  for (i = 0; i < afl->queued_items; i++) {
    q = afl->queue_buf[i];
    if (q->disabled) { continue; }

    double x = trap_cost_of(q);
    double delta = x - mean;
    ++n;
    mean += delta / n;
    m2 += delta * (x - mean);
    if (!best || x < best_c) {
      best = q;
      best_c = x;
    }
  }

  sd = n > 1 ? sqrt(m2 / n) : 0.0;
  thr = mean + TRAP_CULL_K * sd;

  /* Pass 2: mark favored. */

  for (i = 0; i < afl->queued_items; i++) {
    q = afl->queue_buf[i];

    if (q->disabled) {
      q->favored = 0;
      continue;
    }

    /* always keep the cheapest entry so the favored set is never empty */
    u8 fav = (n < 2) || q == best || trap_cost_of(q) <= thr;

    q->favored = fav;

    if (fav) {
      ++afl->queued_favored;

      if (!q->was_fuzzed) {
        ++afl->pending_favored;
        if (afl->smallest_favored < 0 || afl->smallest_favored > (s64)q->id) {
          afl->smallest_favored = (s64)q->id;
        }
      }
    }

    mark_as_redundant(afl, q, !fav);
  }

  /* AFL++ picks entries through a weighted alias table that depends on
     'favored'; tell it to rebuild. */
  afl->reinit_table = 1;
}

u32 calculate_score_trap(afl_state_t *afl, struct queue_entry *q) {
  u32 avg_exec_us = afl->total_cal_cycles
                        ? (u32)(afl->total_cal_us / afl->total_cal_cycles)
                        : 0;
  u32 perf_score = 100;

  /* Speed vs. average. No calibration data yet: nothing to compare. */
  if (avg_exec_us) {
    if (q->exec_us * 0.1 > avg_exec_us) {
      perf_score = 10;

    } else if (q->exec_us * 0.25 > avg_exec_us) {
      perf_score = 25;

    } else if (q->exec_us * 0.5 > avg_exec_us) {
      perf_score = 50;

    } else if (q->exec_us * 0.75 > avg_exec_us) {
      perf_score = 75;

    } else if (q->exec_us * 4 < avg_exec_us) {
      perf_score = 300;

    } else if (q->exec_us * 3 < avg_exec_us) {
      perf_score = 200;

    } else if (q->exec_us * 2 < avg_exec_us) {
      perf_score = 150;
    }
  }

  /* bitmap_size means "new traps found", not path size, so length is used
     instead. */

  double avg_len = afl->total_bitmap_entries
                       ? (double)afl->trap_total_len / afl->total_bitmap_entries
                       : 0.0;
  double len_ratio = avg_len > 0 ? (double)q->len / avg_len : 1.0;

  if (q->has_new_cov) {
    /* new coverage: short inputs get the biggest boost */
    if (len_ratio < 0.33) {
      perf_score *= 4;

    } else if (len_ratio < 0.5) {
      perf_score *= 3;

    } else if (len_ratio < 0.75) {
      perf_score *= 2;

    } else if (len_ratio < 1.0) {
      perf_score *= 1.5;

    } else if (len_ratio > 3.0) {
      perf_score *= 0.75; /* big and new: mild penalty only */
    }

  } else {
    /* no new coverage: favor short, penalize long */
    if (len_ratio < 0.5) {
      perf_score *= 1.5;

    } else if (len_ratio < 0.75) {
      perf_score *= 1.25;

    } else if (len_ratio > 3.0) {
      perf_score *= 0.25;

    } else if (len_ratio > 2.0) {
      perf_score *= 0.5;

    } else if (len_ratio > 1.5) {
      perf_score *= 0.75;
    }
  }

  /* Handicap: latecomers run a bit longer until they catch up. */

  /* Handicap: latecomers run a bit longer until they catch up. Only read
      here; fuzz_one() decrements it (AFL++ calls calculate_score for every
      entry whenever it rebuilds the selection table). */

  if (q->handicap >= 4) {
    perf_score *= 4;

  } else if (q->handicap) {
    perf_score *= 2;
  }

  /* Deeper inputs get more time. */

  switch (q->depth) {
    case 0 ... 3:
      break;
    case 4 ... 7:
      perf_score *= 2;
      break;
    case 8 ... 13:
      perf_score *= 3;
      break;
    case 14 ... 25:
      perf_score *= 4;
      break;
    default:
      perf_score *= 5;
  }

  /* Cap. AFL++ makes the multiplier configurable (default HAVOC_MAX_MULT
     = 64); it was a fixed constant in your AFL. */
  if (perf_score > afl->havoc_max_mult * 100) {
    perf_score = afl->havoc_max_mult * 100;
  }

  return perf_score;
}

/* Slow or large compared to the average calibrated entry. */

u8 trap_is_heavy_entry(afl_state_t *afl, struct queue_entry *q) {
  u64 avg_us =
      afl->total_cal_cycles ? afl->total_cal_us / afl->total_cal_cycles : 0;
  double avg_len = afl->total_bitmap_entries
                       ? (double)afl->trap_total_len / afl->total_bitmap_entries
                       : 0.0;

  if (avg_us && (double)q->exec_us > (double)avg_us * TRAP_SLOW_MULT) {
    return 1;
  }

  if (avg_len > 0 && (double)q->len > avg_len * TRAP_LARGE_MULT) { return 1; }

  return 0;
}