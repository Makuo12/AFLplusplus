#pragma once
#include "trap_common.h"
#include <map>
#include <string>
using namespace llvm;
struct BlockInfo
{
    int blockCount = 0;
    int criticalEdgeCount = 0;
};

void handleSwitchFallthroughEdge(Instruction &TI, int &count, SmallPtrSet<BasicBlock *, 16> &seen);
void handleInvokeEdges(Instruction &TI, int &invokeAddedCount, SmallPtrSet<BasicBlock *, 16> &seen);
void handleIfEdges(Instruction &TI, int &count, SmallPtrSet<BasicBlock *, 16> &seen);
void countCriticalEdge(Instruction &TI, int &globalCount, int &criticalEdgeCount);
void insertCounterGuard(BasicBlock *HeaderBB, GlobalVariable *CounterArr, unsigned slot, int &count);
Function *getOrCreateResetFn(Module &M);
bool processLoop(Function *F, GlobalVariable *CounterArr, unsigned &slot, int &count);
bool shouldProcessFunction(Function &F);
unsigned countLoopHeaders(Module &M);
GlobalVariable *createCounterArray(Module &M, unsigned N);
void buildResetFn(Module &M, GlobalVariable *Arr, unsigned N);
InlineAsm *makeTrapAsm(LLVMContext &Ctx, int id, int category);