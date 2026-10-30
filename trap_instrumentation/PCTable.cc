#include "Edge.h"

using namespace llvm;

void instrumentBlocks(Function &F, SmallPtrSet<BasicBlock *, 16> &seen, int &pctableCount)
{
    if (F.isDeclaration())
        return;
    LLVMContext &Ctx = F.getContext();
    Type *IdTy = Type::getInt32Ty(Ctx);

    for (BasicBlock &BB : F)
    {
        if (seen.count(&BB))
            continue;
        seen.insert(&BB);
        if (&BB == &F.getEntryBlock())
            continue;

        Instruction *InsertPt = &*BB.getFirstInsertionPt();
        IRBuilder<> IRB(InsertPt);

        int id = pctableCount++;

        CallInst *TrapCall = IRB.CreateCall(makeTrapAsm(Ctx, id, /*category=*/0));
        MDNode *MD = MDNode::get(Ctx, ConstantAsMetadata::get(ConstantInt::get(IdTy, id)));
        TrapCall->setMetadata("block_id", MD);
    }
}