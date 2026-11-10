#include "PCTablePass.h"
#include "Edge.h"
#include <fstream>
#include "llvm/ADT/StringSet.h"
#include <map>

using namespace llvm;
using namespace std;

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
    errs() << "meta_id count" << " " << wholeCount;
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

void countBranches(Module &M) {
    map<string, BlockInfo> blocks;
    for (Function &F: M) {
        int globalCount = 0;
        if (F.isDeclaration()) return;
        for (BasicBlock &BB : llvm::make_early_inc_range(F)) {
            Instruction *TI = BB.getTerminator();
            switch (TI->getOpcode()) {
                case Instruction::Ret:
                    ++blocks["Ret"].blockCount;
                    countCriticalEdge(*TI, globalCount, blocks["Ret"].criticalEdgeCount);
                    break;
                case Instruction::Br:
                    ++blocks["Br"].blockCount;
                    countCriticalEdge(*TI, globalCount, blocks["Br"].criticalEdgeCount);
                    break;
                case Instruction::Switch:
                    ++blocks["Switch"].blockCount;
                    countCriticalEdge(*TI, globalCount, blocks["Switch"].criticalEdgeCount);
                    break;
                case Instruction::IndirectBr:
                    ++blocks["IndirectBr"].blockCount;
                    countCriticalEdge(*TI, globalCount, blocks["IndirectBr"].criticalEdgeCount);
                    break;
                case Instruction::Invoke:
                    ++blocks["Invoke"].blockCount;
                    countCriticalEdge(*TI, globalCount, blocks["Invoke"].criticalEdgeCount);
                    break;
                    case Instruction::CallBr:
                    ++blocks["CallBr"].blockCount;
                    countCriticalEdge(*TI, globalCount, blocks["CallBr"].criticalEdgeCount);
                    break;
                case Instruction::Resume:
                    ++blocks["Resume"].blockCount;
                    countCriticalEdge(*TI, globalCount, blocks["Resume"].criticalEdgeCount);
                break;
                case Instruction::CatchSwitch:
                    ++blocks["CatchSwitch"].blockCount;
                    countCriticalEdge(*TI, globalCount,
                                        blocks["CatchSwitch"].criticalEdgeCount);
                    break;
                case Instruction::CatchRet:
                    ++blocks["CatchRet"].blockCount;
                    countCriticalEdge(*TI, globalCount,
                                        blocks["CatchRet"].criticalEdgeCount);
                    break;
                case Instruction::CleanupRet:
                    ++blocks["CleanupRet"].blockCount;
                    countCriticalEdge(*TI, globalCount,
                                        blocks["CleanupRet"].criticalEdgeCount);
                    break;
                case Instruction::Unreachable:
                    ++blocks["Unreachable"].blockCount;
                    countCriticalEdge(*TI, globalCount,
                                        blocks["Unreachable"].criticalEdgeCount);
                    break;
            }
        }
    }
    if (!blocks.empty()) {
        errs() << "Instruction,BlockCount,CriticalEdgeCount \n";
        for (auto item: blocks) {
            errs() << item.first << "," << item.second.blockCount << "," << item.second.criticalEdgeCount << "\n";
        }
    }
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
    
    countBranches(*M);
    // Sanity check the IR is still well-formed after the transform
    // mainCountBlock(*M, blocks);
    // errs() << "Done counting blocks and critical edges.\n";
    processBlocks(*M, seen);
    errs() << "After instrumentation and spliting \n";
    countBranches(*M);
    return writeToFile(*M, outputFile);
}