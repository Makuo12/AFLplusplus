#!/bin/bash
#SBATCH --job-name=forkserver_run
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

set -euo pipefail

echo "node=$(hostname -s) cpu=$(lscpu | grep 'Model name' | sed 's/.*: *//')"

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
export AFL_NO_UI=1
# export AFL_NO_FORKSRV=1  
export AFL_NO_AFFINITY=1

export AFL_DISABLE_TRIM=1
export AFL_FAST_CAL=1                   # fewer calibration runs (3 instead of 4 on stable inputs)
export AFL_NO_SYNC=1                    # don't import other instances' inputs

FUZZ_SECONDS=$((24*60*60))
TRACE="main.trace"
ORACLE="main.oracle"
PROGRAM="forkserver_afl"


if [[ "${1:-}" = "arc" ]]; then
module load LLVM/20.1.8-GCCcore-14.3.0
    module load GCCcore/14.3.0
    ID="${SLURM_ARRAY_JOB_ID:-${SLURM_JOB_ID:-0}}_${SLURM_ARRAY_TASK_ID:-0}"
    FULL_ID="${PROGRAM}_${ID}"

    wrap="$HOME/forkserver/AFL"      # same as build
    runner="$wrap/forkserver_runner"
    mkdir -p "$runner"

    output="$runner/output_${ID}"                # per-task copy
    rm -rf "$output"
    mkdir -p "$output"
    cp -r "$wrap/output/." "$output/"      # everything: binaries, .bc, .ll, edge, remove_edge, ...

    tmp_base="${TMPDIR:-/tmp}"
    tmp_input="$tmp_base/forkserver_${FULL_ID}"
    OUTROOT="$tmp_base/$FULL_ID"            # node-local fuzzer output (wiped at job end)
    RESULTS_DIR="$output/results"             # persistent results
    export LOOP_THRESHOLD_FILE="$OUTROOT/loop_threshold.txt"
    SUT_ORACLE="$output/$ORACLE"
    SUT_TRACE="$output/$TRACE"
    SUT_ARGS=(@@ /dev/null)
    export LOG_FILE="$OUTROOT/fuzzer_log_file"
    mkdir -p "$tmp_input" "$OUTROOT" "$RESULTS_DIR"
    cp -rf "$wrap/testcases/pdf/." "$tmp_input/"
    SEED_DIR="$tmp_input"

    [ -d "$SEED_DIR" ] || { echo "Missing seed dir: $SEED_DIR" >&2; exit 1; }
    [ -x "$SUT_ORACLE" ] || { echo "Missing oracle: $SUT_ORACLE" >&2; exit 1; }
    [ -x "$SUT_TRACE" ] || { echo "Missing trace: $SUT_TRACE" >&2; exit 1; }

else
    # run on my local linux machine
    wrap=$(pwd)

    ID="local_$(date +%s)_$$"
    FULL_ID="${PROGRAM:-forkserver}_${ID}"

    output="$wrap/output_$ID"
    mkdir -p "$output"
    cp -r "$wrap/output/." "$output/"

    tmp_base="/tmp"
    tmp_input="$tmp_base/forkserver_${FULL_ID}"
    OUTROOT="$tmp_base/$FULL_ID"
    RESULTS_DIR="$output/results"

    SUT_ORACLE="$output/$ORACLE"
    SUT_TRACE="$output/$TRACE"
    SUT_ARGS=(@@ /dev/null)

    mkdir -p "$tmp_input" "$OUTROOT" "$RESULTS_DIR"
    cp -rf "$wrap/testcases/pdf/." "$tmp_input/"
    SEED_DIR="$tmp_input"
    export LOOP_THRESHOLD_FILE="./output/loop_threshold.txt"

    [ -d "$SEED_DIR" ] || { echo "Missing seed dir: $SEED_DIR" >&2; exit 1; }
    [ -x "$SUT_ORACLE" ] || { echo "Missing oracle: $SUT_ORACLE" >&2; exit 1; }
    [ -x "$SUT_TRACE" ] || { echo "Missing trace: $SUT_TRACE" >&2; exit 1; }
fi

rc=0
if [[ "${1:-}" = "arc" ]]; then
    timeout -s INT "$FUZZ_SECONDS" ./fuzzer/afl-fuzz -d -i "$SEED_DIR" -o "$OUTROOT" \
    -t 5000 -m 2048 -- "$SUT_ORACLE" "${SUT_ARGS[@]}" || rc=$?
else
    timeout -s INT "$FUZZ_SECONDS" ./fuzzer/afl-fuzz -d -i "$SEED_DIR" -o "$OUTROOT" \
    -t 5000 -m 2048 -- "$SUT_ORACLE" "${SUT_ARGS[@]}" || rc=$?
fi
echo "afl-fuzz exited with code $rc"

if [ -f "$OUTROOT/fuzzer_stats" ]; then
  cp "$OUTROOT/fuzzer_stats" "$RESULTS_DIR/fuzzer_stats_$FULL_ID"
fi

# Tar from the parent so the archive contains only "$FULL_ID/..."
tar -C "$(dirname "$OUTROOT")" -czf "$RESULTS_DIR/$FULL_ID.out.tar.gz" "$FULL_ID"