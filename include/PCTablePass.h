#pragma once
#include "trap_common.h"

using namespace llvm;

void instrumentBlocks(Function &F, SmallPtrSet<BasicBlock *, 16> &seen, int &pctableCount);
GlobalVariable *buildPCTable(Function &F);
void emitRegistrationCtor(llvm::Module &M, llvm::GlobalVariable *PCTable, llvm::Function &F);
