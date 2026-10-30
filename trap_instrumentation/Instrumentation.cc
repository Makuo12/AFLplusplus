#include "PCTablePass.h"
#include "Edge.h"
#include <fstream>
#include "llvm/ADT/StringSet.h"
#include <map>

using namespace llvm;
using namespace std;

using namespace llvm;

std::vector<std::string> skipFunctions = {
    // runtime / pctable
    "__runtime",
    "pctable",
    "PCTableEntry",
    "__untracer", // covers __untracer_heap_start, _setup_global, _restore_global(_sections),
                  // _make_writable, _snapshot_fds, etc.

    // libc / system
    "sysconf",
    "sscanf",
    "mprotect",
    "printf",
    "fopen",
    "fclose",
    "fgets",
    "sigemptyset",
    "sigaction",
    "sizeof",

    // all linker-wrapped symbols (covers __wrap_* and __real_* for every function)
    "__wrap_",
    "__real_",

    // C allocation family
    "malloc", // also malloc_usable_size, __libc_malloc
    "calloc",
    "realloc", // also reallocarray
    "free",
    "cfree",
    "memalign",
    "aligned_alloc",
    "posix_memalign",
    "valloc",
    "pvalloc",
    "mallopt",
    "strdup",
    "strndup",
    "wcsdup",
    "getline",
    "getdelim",
    "asprintf", // also vasprintf
    "realpath",
    "open_memstream",
    "fmemopen",
    "setvbuf",
    "mmap",
    "munmap",
    "mremap",
    "brk",
    "sbrk",
    "alloca",

    // C++ allocation (mangled names, substring match covers all overloads)
    "_Znwm",        // operator new(size_t) + nothrow + align_val_t variants
    "_Znam",        // operator new[]
    "_ZdlPv",       // operator delete (+ sized, nothrow, aligned)
    "_ZdaPv",       // operator delete[] (+ sized, nothrow, aligned)
    "operator new", // demangled form, in case names are demangled
    "operator delete",
    "__cxa_allocate_exception",
    "__cxa_free_exception",
    "__cxa_allocate_dependent_exception",
    "__cxa_free_dependent_exception",
    "new_allocator", // libstdc++ std::allocator internals

    // uthash
    "HASH_FIND",
    "HASH_ADD",
    "HASH_DEL",
    "HASH_ITER",

    // file-pointer tracking
    "file_ptr_obj",
    "add_file_ptr",
    "find_file_ptr",
    "delete_file_ptr",
    "fopen_hook",
    "fclose_hook",
    "close_open_file_handles",

    // heap tracking: old implementation
    "ptr_obj",
    "add_ptr",
    "find_ptr",
    "delete_ptr",
    "myMalloc",
    "myCalloc",
    "myRealloc",
    "myFree",
    "free_ptrs",

    // heap tracking: new open-addressing table
    "hash_ptr",
    "tab_find",
    "tab_erase",
    "tab_grow",
    "track_heap",
    "untrack_heap",
    "line_common",
    "free_open_heap",
    "__untracer_heap_start",

    "__cxa_",            // covers __cxa_throw, __cxa_rethrow, __cxa_begin_catch,
                         // __cxa_end_catch, __cxa_allocate_exception,
                         // __cxa_free_exception, __cxa_get_exception_ptr,
                         // __cxa_call_unexpected, __cxa_bad_cast, __cxa_bad_typeid,
                         // __cxa_atexit, __cxa_guard_*, __cxa_pure_virtual, ...
    "_Unwind_",          // _Unwind_Resume, _Unwind_RaiseException, _Unwind_DeleteException, ...
    "__gxx_personality", // __gxx_personality_v0, __gxx_personality_sj0
    "__gcc_personality",
    "__clang_call_terminate",   // emitted by clang for noexcept / cleanup-failure paths
    "_ZSt9terminatev",          // std::terminate (mangled)
    "_ZSt10unexpectedv",        // std::unexpected
    "_ZSt13set_terminatePFvvE", // std::set_terminate
    "std::terminate",           // demangled forms, in case names are demangled
    "std::unexpected",
    "__cxa_throw", // explicit, in case you later narrow "__cxa_" down
    "__cxa_begin_catch",
    "__cxa_end_catch",
    "__cxa_rethrow",
    "llvm.eh", // llvm.eh.typeid.for, llvm.eh.sjlj.*, etc.
    "_ZTI",    // typeinfo objects (std::type_info for catch matching)
    "_ZTS",    // typeinfo name strings

    // C-style non-local jumps (the C equivalent of try/catch)
    "setjmp",  // also _setjmp, __sigsetjmp, sigsetjmp
    "longjmp", // also _longjmp, siglongjmp
    "__builtin_setjmp",
    "__builtin_longjmp",

    // global-section restore
    "__untracer_make_writable",
    "__untracer_restore_global_sections",
    "__untracer_restore_global",
    "__untracer_setup_global",

    "main"
};

static const StringSet<> exactSkip = {"main", "free", "malloc", "calloc", "realloc", "brk", "sbrk",
                                      "mmap", "munmap", "mremap", "alloca", "strdup", "strndup",
                                      "getline", "getdelim", "realpath", "setvbuf"};

bool foundInSkipFunctions(StringRef fName)
{
    if (exactSkip.contains(fName))
        return true;
    for (const auto &func : skipFunctions)
        if (fName.contains(func))
            return true;
    return false;
}

void processBlocks(Module &M, SmallPtrSet<BasicBlock *, 16> &seen)
{
    int wholeCount = 0;
    // Create up front so a harness declaring
    // `extern "C" void __reset_loop_counters()` links even with 0 loops.
    getOrCreateResetFn(M);

    // ---- Phase 1: edge handlers, all functions ----
    // These split blocks / edges, so they run BEFORE we count loop headers.
    for (Function &F : M)
    {
        if (!shouldProcessFunction(F))
            continue;
        instrumentBlocks(F, seen, wholeCount);
        for (BasicBlock &BB : llvm::make_early_inc_range(F))
            handleSwitchFallthroughEdge(*BB.getTerminator(), wholeCount, seen);
        for (BasicBlock &BB : llvm::make_early_inc_range(F))
            handleIfEdges(*BB.getTerminator(), wholeCount, seen);
        for (BasicBlock &BB : llvm::make_early_inc_range(F))
            handleInvokeEdges(*BB.getTerminator(), wholeCount, seen);
    }
    // ---- Phase 2: count loop headers, create the array + reset body ----
    unsigned N = countLoopHeaders(M);
    GlobalVariable *CounterArr = nullptr;
    if (N > 0)
    {
        CounterArr = createCounterArray(M, N);
        buildResetFn(M, CounterArr, N);
    }

    // ---- Phase 3: loop guards, then block instrumentation, per function ----
    // Same per-function order as before (loops, then instrumentBlocks).
    unsigned slot = 0;
    for (Function &F : M)
    {
        if (!shouldProcessFunction(F))
            continue;
        if (CounterArr)
            processLoop(&F, CounterArr, slot, wholeCount);
        // Handle PCTable
    }
    assert(slot == N && "loop count and loop instrumentation disagree");

}


int writeToFile(Module &M, const char *outputFile)
{
    if (verifyModule(M, &errs()))
    {
        errs() << "ERROR: Module is invalid after transform!\n";
        return 1;
    }

    // Write the transformed IR to a new file
    std::error_code EC;
    raw_fd_ostream Out(outputFile, EC);
    if (EC)
    {
        errs() << "Could not open output file: " << EC.message() << "\n";
        return 1;
    }
    M.print(Out, nullptr);
    errs() << "Wrote transformed IR to main.transformed.ll\n";
    return 0;
}

std::unique_ptr<Module> parseFile(const char *filename, SMDiagnostic &Err, LLVMContext &Context)
{
    std::unique_ptr<Module> M = parseIRFile(filename, Err, Context);
    if (!M)
    {
        Err.print(filename, errs());
        return nullptr;
    }
    return M;
}

int main(int argc, char **argv)
{
    map<string, BlockInfo> blocks;
    SmallPtrSet<BasicBlock *, 16> seen;
    if (argc < 2)
    {
        errs() << "Usage: " << argv[0] << " <file.ll>\n";
        return 1;
    }
    const char *inputFile = argv[1];
    const char *outputFile = argv[2];
    LLVMContext Context;
    SMDiagnostic Err;
    auto M = parseFile(inputFile, Err, Context);
    if (M == nullptr)
        return 1;
    // Sanity check the IR is still well-formed after the transform
    // mainCountBlock(*M, blocks);
    // errs() << "Done counting blocks and critical edges.\n";
    processBlocks(*M, seen);
    return writeToFile(*M, outputFile);
}