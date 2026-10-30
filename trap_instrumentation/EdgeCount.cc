#include "Edge.h"

using namespace llvm;
#include "llvm/IR/InlineAsm.h"

using namespace llvm;
using namespace std;

// Splits HeaderBB at its first insertion point and inserts:
//   %cval = load counter
//   if (%cval < 5) { asm "nop"; }
//   counter = %cval + 1
#include "llvm/Transforms/Utils/LoopUtils.h" // InsertPreheaderForLoop

#include <cassert>
#include <cstdint>
#include <string>

using namespace llvm;

static constexpr const char *kResetFnName = "__reset_loop_counters";
static constexpr const char *kCounterArrName = "loop_counters";

// ---------------------------------------------------------------------
// Reset function: `void __reset_loop_counters()`
// Created once per module. Body is filled in by buildResetFn().
// ---------------------------------------------------------------------
Function *getOrCreateResetFn(Module &M)
{
    if (Function *F = M.getFunction(kResetFnName))
        return F;

    LLVMContext &Ctx = M.getContext();
    FunctionType *FTy = FunctionType::get(Type::getVoidTy(Ctx), /*isVarArg=*/false);
    Function *F = Function::Create(FTy, GlobalValue::ExternalLinkage, kResetFnName, &M);

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", F);
    ReturnInst::Create(Ctx, Entry);
    // Deliberately NOT added to global ctors: in a single-process fuzzer
    // it must run at the start of every iteration, not once at startup.
    return F;
}

// One filter used by EVERY phase below (edge handlers, loop counting, loop
// instrumentation, block instrumentation). The loop count and the loop
// instrumentation must agree on which functions are visited, so this can't
// be duplicated inline.
bool shouldProcessFunction(Function &F)
{
    if (F.isDeclaration())
        return false;
    StringRef Name = F.getName();
    if (Name == "main" || Name == kResetFnName || foundInSkipFunctions(Name))
        return false;
    if (Name.find("llvm.") != StringRef::npos)
        return false; // skip LLVM intrinsics
    return true;
}

// Body: one memset over the whole counter array.
void buildResetFn(Module &M, GlobalVariable *Arr, unsigned N)
{
    Function *F = getOrCreateResetFn(M);
    IRBuilder<> B(F->getEntryBlock().getTerminator());
    B.CreateMemSet(Arr, B.getInt8(0), static_cast<uint64_t>(N) * 4, MaybeAlign(4));
}

// Insert `call void @__reset_loop_counters()` at the top of the per-input
// entry point. Skip this if you call the reset manually from your harness.
void insertResetCall(Module &M, StringRef EntryName = "LLVMFuzzerTestOneInput")
{
    Function *Entry = M.getFunction(EntryName);
    if (!Entry || Entry->isDeclaration())
        return;
    Function *ResetFn = getOrCreateResetFn(M);
    IRBuilder<> B(&*Entry->getEntryBlock().getFirstInsertionPt());
    B.CreateCall(ResetFn);
}

// ---------------------------------------------------------------------
// Header selection: single source of truth shared by both passes, so the
// count in pass 1 always matches what pass 2 instruments.
// ---------------------------------------------------------------------
bool isInstrumentable(BasicBlock *HeaderBB)
{
    return HeaderBB->getFirstInsertionPt() != HeaderBB->end() &&
           !HeaderBB->isEHPad();
}

bool shouldSkipFunction(const Function &F)
{
    return F.isDeclaration() || F.getName() == kResetFnName;
}

void collectHeaders(Function &F, SmallVectorImpl<BasicBlock *> &Out)
{
    if (shouldSkipFunction(F))
        return;

    DominatorTree DT(F);
    LoopInfo LI;
    LI.analyze(DT);

    for (BasicBlock &BB : F)
    {
        Loop *L = LI.getLoopFor(&BB);
        if (L && L->getHeader() == &BB)
        {
            if (isInstrumentable(&BB))
                Out.push_back(&BB);
            else
                errs() << "  Skipping header " << BB.getName() << " in "
                       << F.getName()
                       << ": not safe to instrument (EH pad / no valid "
                          "insertion point)\n";
        }
    }
}

// Replaces the earlier countLoopHeaders(Module &): same as before, but only
// counts functions processBlocks would actually instrument.
unsigned countLoopHeaders(Module &M)
{
    unsigned N = 0;
    for (Function &F : M)
    {
        if (!shouldProcessFunction(F))
            continue;
        SmallVector<BasicBlock *, 8> H;
        collectHeaders(F, H);
        N += H.size();
    }
    return N;
}

// ---- Counter array ----
GlobalVariable *createCounterArray(Module &M, unsigned N)
{
    auto *ArrTy = ArrayType::get(Type::getInt32Ty(M.getContext()), N);
    return new GlobalVariable(M, ArrTy, /*isConstant=*/false,
                              GlobalValue::InternalLinkage,
                              ConstantAggregateZero::get(ArrTy),
                              kCounterArrName);
}

// ---------------------------------------------------------------------
// Insert the guard for one loop header. `slot` selects the array element;
// `count` is the running id embedded in the asm bytes and metadata.
// ---------------------------------------------------------------------
void insertCounterGuard(BasicBlock *HeaderBB, GlobalVariable *CounterArr,
                        unsigned slot, int &count)
{
    LLVMContext &Ctx = HeaderBB->getContext();

    // Defensive re-check (collectHeaders already filtered these).
    if (!isInstrumentable(HeaderBB))
        return;

    Instruction *InsertPt = &*HeaderBB->getFirstInsertionPt();
    IRBuilder<> Builder(InsertPt);

    Type *I32Ty = Type::getInt32Ty(Ctx);
    PointerType *PtrTy = PointerType::getUnqual(Ctx);
    FunctionType *AsmFTy =
        FunctionType::get(Type::getVoidTy(Ctx), {PtrTy}, /*isVarArg=*/false);

    int id = count++;

    // Encode id as 4 little-endian bytes so the runtime can memcpy an
    // int32_t straight back out (x86 native byte order).
    uint32_t uid = static_cast<uint32_t>(id);
    unsigned b0 = uid & 0xFF;
    unsigned b1 = (uid >> 8) & 0xFF;
    unsigned b2 = (uid >> 16) & 0xFF;
    unsigned b3 = (uid >> 24) & 0xFF;

    // $0 = address of this loop's counter slot, passed in a GPR.
    // ".byte 0x3d,0x01,0x00,0x00,0x00" == "cmp eax, 1" forced to imm32
    // (5 bytes) rather than the compact form the assembler would pick.
    //
    // Label "1" is already used by this template for the jle target
    // (post-trap landing point), so the trap's own bookmark uses a
    // distinct local label "2" to avoid colliding with it. "2b" below
    // resolves to the address of the 0xcc byte, same mechanism as every
    // other trap site, just under a different label number since "1"
    // was taken here.
    std::string AsmStr =
        "movl ($0), %eax\n\t"
        ".byte 0x3d, 0x01, 0x00, 0x00, 0x00\n\t"
        "jle 1f\n\t"
        "2:\n\t"
        ".byte 0xcc\n\t"                   // trap byte
        ".byte 0x90, 0x90, 0x90, 0x90\n\t" // marker: loop vs edge
        ".byte " +
        std::to_string(b0) + ", " + std::to_string(b1) + ", " +
        std::to_string(b2) + ", " + std::to_string(b3) + "\n\t" +
        ".pushsection __traps,\"aw\",@progbits\n\t"
        ".balign 8\n\t"
        ".quad 2b\n\t"
        ".popsection\n\t"
        "1:\n\t"
        "addl $$1, %eax\n\t"
        "movl %eax, ($0)\n\t";

    InlineAsm *IA = InlineAsm::get(
        AsmFTy, AsmStr,
        /*Constraints=*/"r,~{eax},~{cc},~{memory}",
        /*hasSideEffects=*/true);

    // &loop_counters[slot]
    Value *SlotPtr = Builder.CreateInBoundsGEP(
        CounterArr->getValueType(), CounterArr,
        {ConstantInt::get(I32Ty, 0), ConstantInt::get(I32Ty, slot)},
        "loop.ctr");

    CallInst *TrapCall = Builder.CreateCall(IA, {SlotPtr});
    MDNode *MD = MDNode::get(
        Ctx, ConstantAsMetadata::get(ConstantInt::get(I32Ty, id)));
    TrapCall->setMetadata("loop_header_id", MD);
}
// ---------------------------------------------------------------------
// Pass 2: instrument every loop header in F (all nesting levels).
// ---------------------------------------------------------------------
bool processLoop(Function *F, GlobalVariable *CounterArr, unsigned &slot, int &count)
{
    if (!F || shouldSkipFunction(*F))
        return false;

    // Collect first; insertion doesn't split blocks, but this keeps us
    // from iterating F's live block list while modifying it.
    SmallVector<BasicBlock *, 8> Headers;
    collectHeaders(*F, Headers);

    for (BasicBlock *HeaderBB : Headers)
        insertCounterGuard(HeaderBB, CounterArr, slot++, count);

    return !Headers.empty();
}