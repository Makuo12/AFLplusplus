#!/bin/bash
#SBATCH --job-name=single_run
#SBATCH --partition=normal_q
#SBATCH --account=fuzzing
#SBATCH --time=25:30:00
#SBATCH --constraint=amd
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem-per-cpu=4G
#SBATCH --output=./logs/fuzz-%j.log
#SBATCH --error=./logs/fuzz-%j.log
#SBATCH --array=1-5

# Trap-mode AFL++ WITHOUT de-instrumentation.

set -euo pipefail

echo "node=$(hostname -s) cpu=$(lscpu | grep 'Model name' | sed 's/.*: *//')"

# --- AFL++ trap mode -------------------------------------------------------
export AFL_TRAP_MODE=1                  # REQUIRED: use the trap-based port

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
export AFL_NO_UI=1
export AFL_NO_AFFINITY=1

export AFL_FAST_CAL=1                   # 3 calibration runs (1 warm-up + 2 timed) instead of 7
export AFL_NO_SYNC=1                    # don't import other instances' inputs
# Trimming, frameshift, deterministic stages and CmpLog are turned off by
# AFL_TRAP_MODE automatically; no need to set AFL_DISABLE_TRIM.

# No de-instrumentation in this variant. SLURM passes the submitting shell's
# environment to the job, so make sure nothing switches it on by accident.
unset OUTPUT_HOME META_DATA_FILE LOOP_THRESHOLD_FILE DE_EDGE_MAX DE_EDGE_ARC DE_CLANGXX

FUZZ_SECONDS=$((24*60*60))
ORACLE="main.oracle"
PROGRAM="single_aflpp_nodeinstr"    # distinct from the de-instrumentation runs


if [[ "${1:-}" = "arc" ]]; then
    module load LLVM/20.1.8-GCCcore-14.3.0
    module load GCCcore/14.3.0
    ID="${SLURM_ARRAY_JOB_ID:-${SLURM_JOB_ID:-0}}_${SLURM_ARRAY_TASK_ID:-0}"
    FULL_ID="${PROGRAM}_${ID}"

    wrap="$HOME/single/AFLplusplus"   # same as build
    AFLPP="$wrap"                         # patched AFL++ directory
    runner="$wrap/single_runner"
    mkdir -p "$runner"

    output="$runner/output_${FULL_ID}"    # per-task copy
    rm -rf "$output"
    mkdir -p "$output"
    cp -r "$wrap/output/." "$output/"     # everything: binaries, .bc, .ll, ...

    tmp_base="${TMPDIR:-/tmp}"
else
    # run on my local linux machine
    unset AFL_NO_AFFINITY                 # let afl-fuzz bind itself to a free core
    wrap=$(pwd)
    AFLPP="$wrap"                         # patched AFL++ directory

    ID="local_$(date +%s)_$$"
    FULL_ID="${PROGRAM}_${ID}"

    output="$wrap/output_${FULL_ID}"
    mkdir -p "$output"
    cp -r "$wrap/output/." "$output/"

    tmp_base="/tmp"
fi

tmp_input="$tmp_base/single_${FULL_ID}"
OUTROOT="$tmp_base/$FULL_ID"            # node-local fuzzer output
RESULTS_DIR="$output/results"           # persistent results
SUT_ORACLE="$output/$ORACLE"
SUT_ARGS=(@@)                           # harness reads the input from argv[1]

# Harness log (trap_handler output). Kept outside the AFL++ output dir so
# AFL++'s own directory handling never touches it.
export LOG_FILE="$tmp_base/${FULL_ID}_harness.log"

mkdir -p "$tmp_input" "$RESULTS_DIR"
cp -rf "$wrap/testcases/pdf/." "$tmp_input/"
SEED_DIR="$tmp_input"

AFL_FUZZ="$AFLPP/afl-fuzz"
[ -d "$SEED_DIR" ]   || { echo "Missing seed dir: $SEED_DIR" >&2; exit 1; }
[ -x "$SUT_ORACLE" ] || { echo "Missing oracle: $SUT_ORACLE" >&2; exit 1; }
[ -x "$AFL_FUZZ" ]   || { echo "Missing afl-fuzz: $AFL_FUZZ" >&2; exit 1; }

# -z : no deterministic stages (in this AFL++ -d is deprecated and ignored)
rc=0
timeout -s INT "$FUZZ_SECONDS" "$AFL_FUZZ" -z -i "$SEED_DIR" -o "$OUTROOT" \
    -t 5000 -m 2048 -- "$SUT_ORACLE" "${SUT_ARGS[@]}" || rc=$?
echo "afl-fuzz exited with code $rc"

# AFL++ writes into a per-instance subfolder: $OUTROOT/default/
if [ -f "$OUTROOT/default/fuzzer_stats" ]; then
    cp "$OUTROOT/default/fuzzer_stats" "$RESULTS_DIR/fuzzer_stats_$FULL_ID"
fi
if [ -f "$OUTROOT/default/plot_data" ]; then
    cp "$OUTROOT/default/plot_data" "$RESULTS_DIR/plot_data_$FULL_ID"
fi
if [ -f "$LOG_FILE" ]; then
    cp "$LOG_FILE" "$RESULTS_DIR/harness_log_$FULL_ID"
fi

# Tar from the parent so the archive contains only "$FULL_ID/..."
tar -C "$(dirname "$OUTROOT")" -czf "$RESULTS_DIR/$FULL_ID.out.tar.gz" "$FULL_ID"