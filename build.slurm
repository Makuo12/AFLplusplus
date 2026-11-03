#!/bin/bash
#SBATCH --job-name=forkserver_build
#SBATCH --partition=normal_q
#SBATCH --account=fuzzing
#SBATCH --constraint=amd
#SBATCH --time=01:00:00
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=4
#SBATCH --mem-per-cpu=4G
#SBATCH --output=./logs/build-%j.log
#SBATCH --error=./logs/build-%j.log

# Trap-mode AFL++ WITHOUT de-instrumentation.
# $wrap is the patched AFL++ checkout; it must be the same directory the run
# script uses (it copies $wrap/output from there).

set -e

if [ "${1:-}" = "arc" ]; then
    module load LLVM/20.1.8-GCCcore-14.3.0
    module load CMake/3.31.8-GCCcore-14.3.0
    module load GCCcore/14.3.0
    pip install --user wllvm
    export PATH="$HOME/.local/bin:$PATH"
    wrap="$HOME/forkserver/AFLplusplus"
else
    export LLVM_CC_NAME=clang-20        # ← pin to version 20
    export LLVM_CXX_NAME=clang++-20     # ← pin to version 20
    wrap=$(pwd)
fi

echo "Building afl-fuzz (AFL++ with trap mode)"
# Remove objects from earlier builds: -flto object files only link with the
# same GCC version that created them (GCC 11 objects + GCC 14 link = error).
rm -f "$wrap"/src/*.o "$wrap"/afl-fuzz
make -C "$wrap" afl-fuzz NO_PYTHON=1 NO_NYX=1

export BASE_ADDRESS=0x400000

PERF_FLAGS="-O3 -funroll-loops -DNDEBUG -fno-stack-protector -fomit-frame-pointer -fno-semantic-interposition -fvisibility=hidden"

LIB_PATH="$(llvm-config --libdir)"
BIN_PATH="$(llvm-config --bindir)"
export LLVM_COMPILER=clang

rm -rf "$wrap/output"
mkdir -p "$wrap/output"

echo "Building llvm passes"
rm -rf "$wrap/build"

cmake -B "$wrap/build" \
      -DLLVM_DIR="$LIB_PATH/cmake/llvm" \
      -DCMAKE_BUILD_TYPE=Release 2>&1 | cat
make -C "$wrap/build" -j"$(nproc)"

echo "Building xpdf with custom coverage tracer..."
SRC="$wrap/targets/xpdf-4.06_2"
BUILD="$SRC/build"

rm -rf "$BUILD"

COVERAGE_FLAGS="-I $wrap/include -fno-pie"
EXTRA_ARGS=()

case "$(uname -s)" in
  Darwin) ;;
  Linux)  EXTRA_ARGS=(-DCMAKE_EXE_LINKER_FLAGS="-no-pie"
                      -DCMAKE_SHARED_LINKER_FLAGS="-no-pie") ;;
  *) echo "Unknown OS: $(uname -s)"; exit 1 ;;
esac

cmake -S "$SRC" -B "$BUILD" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=wllvm \
  -DCMAKE_CXX_COMPILER=wllvm++ \
  -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" \
  -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
  "${EXTRA_ARGS[@]}"

cmake --build "$BUILD" -j"$(nproc)"

echo "Extract whole-program bitcode from the final binary"
extract-bc "$BUILD/xpdf/pdftotext" -o "$wrap/output/whole_program.bc"

$BIN_PATH/opt \
    -load-pass-plugin="$wrap/build/Untracer.so" \
    -passes="rename" \
    "$wrap/output/whole_program.bc" -o "$wrap/output/out.bc"

echo "Disassembling bitcode to LLVM IR"
llvm-dis "$wrap/output/out.bc" -o "$wrap/output/out.ll"

# Harness. $wrap/include is AFL++'s include dir, so fuzzer_persistent.c gets the same
# config.h (TRAP_VIRGIN_WORDS, SHM_ID, MAP_SIZE_TRACE) as afl-fuzz.
echo "Make target init"
$BIN_PATH/clang -O2 -funroll-loops -I "$wrap/include" \
    -c -emit-llvm "$wrap/wrapper/fuzzer_persistent.c" -o "$wrap/output/fuzzer_persistent.bc"

echo "Building edge-only binary"
$BIN_PATH/clang++ "$wrap/trap_instrumentation/EdgeCount.cc" "$wrap/trap_instrumentation/EdgeHandler.cc" \
    "$wrap/trap_instrumentation/PCTable.cc" "$wrap/trap_instrumentation/Instrumentation.cc" \
    -I "$wrap/include" -o "$wrap/output/edge" \
    $(llvm-config --cxxflags --ldflags --libs core irreader analysis) \
    $(llvm-config --system-libs) $PERF_FLAGS

"$wrap/output/edge" "$wrap/output/out.ll" "$wrap/output/main.transformed.ll"

# Final link. -Xclang -disable-llvm-passes: the IR is already -O3 code with
# the traps placed exactly where the passes put them; only generate code,
# don't re-optimize (inlining / unrolling could duplicate traps). Same as the
# de-instrumentation build, so both variants are compiled identically.
echo "Building final binary"
if [[ "$(uname -s)" == "Darwin" ]]; then
    INCLUDE="-isysroot $(xcrun --show-sdk-path)"
    $BIN_PATH/clang++ $INCLUDE \
        "$wrap/output/main.transformed.ll" "$wrap/output/fuzzer_persistent.bc" \
        -L/opt/homebrew/opt/fontconfig/lib -lfontconfig \
        -o "$wrap/output/main.oracle"
elif [[ "$(uname -s)" == "Linux" ]]; then
    if [[ "${1:-}" = arc ]]; then
        $BIN_PATH/clang++ $PERF_FLAGS -Xclang -disable-llvm-passes -I "$wrap/include" \
            "$wrap/output/main.transformed.ll" $RUNTIME "$wrap/output/fuzzer_persistent.bc" \
            -no-pie -fuse-ld=bfd \
            -Wl,--image-base=$BASE_ADDRESS -Wl,-z,noseparate-code \
            -o "$wrap/output/main.oracle"
    else
        $BIN_PATH/clang++ $PERF_FLAGS -Xclang -disable-llvm-passes -I "$wrap/include" \
            "$wrap/output/main.transformed.ll" $RUNTIME "$wrap/output/fuzzer_persistent.bc" \
            -no-pie \
            -o "$wrap/output/main.oracle"
    fi
else
    echo "Unknown OS: $(uname -s)"
    exit 1
fi

echo "Done with build"