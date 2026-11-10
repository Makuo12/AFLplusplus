#include "PCTablePass.h"
#include <string>
#include <map>
#include "Edge.h"

using namespace std;
using namespace llvm;

#include "llvm/Transforms/Utils/BasicBlockUtils.h"  // SplitCriticalEdge

void handleSwitchFallthroughEdge(Instruction &TI, int &count,
                                 SmallPtrSet<BasicBlock *, 16> &seen) {
  auto *SI = dyn_cast<SwitchInst>(&TI);
  if (!SI) return;
  LLVMContext &Ctx = SI->getContext();
  Type        *Int32Ty = Type::getInt32Ty(Ctx);

  for (unsigned i = 0, e = SI->getNumSuccessors(); i != e; ++i) {
    BasicBlock *NewBB = SplitCriticalEdge(SI, i);
    if (!NewBB) continue;  // not critical, nothing to do

    int id = count++;
    NewBB->setName("sw.edge" + std::to_string(id));

    IRBuilder<> Builder(
        NewBB->getTerminator());  // insert before the br SplitCriticalEdge
                                  // already added
    CallInst *TrapCall =
        Builder.CreateCall(makeTrapAsm(Ctx, id, /*category=*/0));
    MDNode *MD = MDNode::get(
        Ctx, ConstantAsMetadata::get(ConstantInt::get(Int32Ty, id)));
    TrapCall->setMetadata("switch_fallthrough_id", MD);
    seen.insert(NewBB);
  }
}

void handleInvokeEdges(Instruction &TI, int &count,
                       SmallPtrSet<BasicBlock *, 16> &seen) {
  auto *II = dyn_cast<InvokeInst>(&TI);
  if (!II) return;
  LLVMContext &Ctx = II->getContext();
  Type        *Int32Ty = Type::getInt32Ty(Ctx);

  // Successor 0 is the normal destination, successor 1 the unwind
  // destination. Only the normal edge is split: the unwind edge leads to a
  // landing pad, which must stay the direct successor of the invoke
  // (SplitCriticalEdge refuses EH pads anyway).
  BasicBlock *NewBB = SplitCriticalEdge(II, /*SuccNum=*/0);
  if (!NewBB)
    return;  // not critical: the normal destination's own block trap covers it

  int id = count++;
  NewBB->setName("invoke.cont" + std::to_string(id));

  IRBuilder<> Builder(
      NewBB->getTerminator());  // before the br SplitCriticalEdge added
  CallInst *TrapCall = Builder.CreateCall(makeTrapAsm(Ctx, id, /*category=*/0));
  MDNode   *MD =
      MDNode::get(Ctx, ConstantAsMetadata::get(ConstantInt::get(Int32Ty, id)));
  TrapCall->setMetadata("invoke_block_id", MD);
  seen.insert(NewBB);
}

void countCriticalEdge(Instruction &TI, int &globalCount,
                       int &criticalEdgeCount) {
  for (unsigned i = 0, e = TI.getNumSuccessors(); i != e; ++i) {
    if (isCriticalEdge(&TI, i)) {
      ++globalCount;
      ++criticalEdgeCount;
    }
  }
}

void handleIfEdges(Instruction &TI, int &count,
                   SmallPtrSet<BasicBlock *, 16> &seen) {
  auto *BI = dyn_cast<BranchInst>(&TI);
  if (!BI) { return; }
  LLVMContext &Ctx = TI.getContext();
  Function    *F = TI.getFunction();
  Module      *M = F->getParent();
  BasicBlock  *BB = TI.getParent();
  Type        *Int32Ty = Type::getInt32Ty(M->getContext());
  for (unsigned i = 0, e = TI.getNumSuccessors(); i != e; ++i) {
    if (isCriticalEdge(&TI, i)) {
      BasicBlock *FalseBB = BI->getSuccessor(i);
      if (pred_size(FalseBB) > 1) {
        int    id = count++;
        string name = "if.else.new";
        name += std::to_string(id);
        BasicBlock *NewElseBB = BasicBlock::Create(Ctx, name, F, FalseBB);
        BI->setSuccessor(i, NewElseBB);
        for (PHINode &PN : FalseBB->phis()) {
          int idx = PN.getBasicBlockIndex(BB);
          if (idx >= 0) PN.setIncomingBlock(idx, NewElseBB);
        }
        IRBuilder<> Builder(NewElseBB);

        InlineAsm *IA = makeTrapAsm(Ctx, id, /*category=*/0);
        CallInst  *TrapCall = Builder.CreateCall(IA);
        MDNode    *MD = MDNode::get(
            Ctx, ConstantAsMetadata::get(ConstantInt::get(Int32Ty, id)));
        TrapCall->setMetadata("else_block_id", MD);

        Builder.CreateBr(FalseBB);
        seen.insert(NewElseBB);
      }
    }
  }
}

// category: 0=edge (id at rip+1), 1=loop (0x90 marker at rip+1, id at rip+5)
InlineAsm *makeTrapAsm(LLVMContext &Ctx, int id, int category) {
  uint32_t uid = static_cast<uint32_t>(id);
  unsigned b0 = uid & 0xFF, b1 = (uid >> 8) & 0xFF, b2 = (uid >> 16) & 0xFF,
           b3 = (uid >> 24) & 0xFF;

  std::string idBytes = std::to_string(b0) + ", " + std::to_string(b1) + ", " +
                        std::to_string(b2) + ", " + std::to_string(b3);

  std::string body = "1:\n\t.byte 0xcc\n\t";
  if (category == 1) body += ".byte 0x90, 0x90, 0x90, 0x90\n\t";
  body += ".byte " + idBytes + "\n\t";

  body +=
      ".pushsection __traps,\"aw\",@progbits\n\t"
      ".balign 8\n\t"
      ".quad 1b\n\t"
      ".popsection\n\t";

  FunctionType *AsmFTy =
      FunctionType::get(Type::getVoidTy(Ctx), /*isVarArg=*/false);
  return InlineAsm::get(AsmFTy, body, "~{memory}", /*hasSideEffects=*/true);
}