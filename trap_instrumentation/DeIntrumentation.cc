#include "DeEdge.h"
#include <getopt.h>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace std;
using namespace llvm;

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

static int32_t getMetaId(MDNode *MD)
{
    return (int32_t)mdconst::extract<ConstantInt>(MD->getOperand(0))->getSExtValue();
}

/* ---------------- TRAP DISCOVERY ----------------
 * Metadata kinds written by the instrumentation:
 *   else_block_id            handleIfEdges            (if.else.new<id> block)
 *   switch_fallthrough_id    handleSwitchFallthroughEdge (sw.edge<id> block)
 *   invoke_block_id          handleInvokeEdges        (in place, or invoke.cont<id>)
 *   block_id                 instrumentBlocks         (in place)
 *   loop_header_id           insertCounterGuard       (in place, takes slot ptr)
 */
void findTrapInstructions(
    Module &M, unordered_set<int32_t> &metaIds,
    unordered_map<int32_t, int32_t> &thresholds,
    std::vector<CallInst *> &elseArmTraps,
    std::vector<CallInst *> &switchEdgeTraps,
    std::vector<CallInst *> &invokeTraps,
    std::vector<CallInst *> &loopCountTraps,
    std::vector<CallInst *> &blockTraps,
    std::vector<CallInst *> &allLoopCountTraps)
{
    for (Function &F : M)
    {
        for (Instruction &I : instructions(F))
        {
            auto *CI = dyn_cast<CallInst>(&I);
            if (!CI)
                continue;

            if (MDNode *MD = CI->getMetadata("else_block_id"))
            {
                if (metaIds.count(getMetaId(MD)))
                    elseArmTraps.push_back(CI);
            }
            else if (MDNode *MD = CI->getMetadata("switch_fallthrough_id"))
            {
                if (metaIds.count(getMetaId(MD)))
                    switchEdgeTraps.push_back(CI);
            }
            else if (MDNode *MD = CI->getMetadata("invoke_block_id"))
            {
                if (metaIds.count(getMetaId(MD)))
                    invokeTraps.push_back(CI);
            }
            else if (MDNode *MD = CI->getMetadata("loop_header_id"))
            {
                int32_t id = getMetaId(MD);
                // Live loops with a saved threshold: candidates for
                // applyLoopThresholds().
                if (thresholds.count(id))
                    allLoopCountTraps.push_back(CI);
                // Retired loops: removed by removeLoopInstrumentation().
                if (metaIds.count(id))
                    loopCountTraps.push_back(CI);
            }
            else if (MDNode *MD = CI->getMetadata("block_id"))
            {
                if (metaIds.count(getMetaId(MD)))
                    blockTraps.push_back(CI);
            }
        }
    }
}

/* ---------------- EDGE-BLOCK REMOVAL ----------------
 * if.else.new<id>, sw.edge<id> and invoke.cont<id> are all blocks the
 * instrumentation created to host exactly one trap:
 *     Pred --> [ call trap ; br Succ ] --> Succ
 * Removing the trap means bypassing the block: point Pred's terminator at
 * Succ, repoint Succ's PHI entries from the block to Pred, delete the block.
 */

// Returns true if Trap's block was a private [trap; br] block and has been
// bypassed and erased. Returns false (touching nothing) if the block isn't
// of that shape, so the caller can fall back to erasing just the trap.
static bool tryBypassTrapBlock(CallInst *Trap)
{
    BasicBlock *BB = Trap->getParent();
    if (!BB || BB->size() != 2 || &BB->front() != Trap || !Trap->use_empty())
        return false;

    auto *Br = dyn_cast<BranchInst>(BB->getTerminator());
    if (!Br || !Br->isUnconditional())
        return false;

    BasicBlock *Pred = BB->getUniquePredecessor();
    BasicBlock *Succ = BB->getUniqueSuccessor();
    if (!Pred || !Succ || Pred == BB || Succ == BB)
        return false;

    // Works for br, switch and invoke (normal dest) terminators alike.
    Instruction *PredTI = Pred->getTerminator();
    for (unsigned i = 0, e = PredTI->getNumSuccessors(); i != e; ++i)
        if (PredTI->getSuccessor(i) == BB)
            PredTI->setSuccessor(i, Succ);

    for (PHINode &PN : Succ->phis())
    {
        int idx = PN.getBasicBlockIndex(BB);
        if (idx >= 0)
            PN.setIncomingBlock(idx, Pred);
    }

    BB->eraseFromParent(); // takes the trap with it
    return true;
}

static void removeEdgeBlockTraps(std::vector<CallInst *> &traps, const char *kind)
{
    for (CallInst *Trap : traps)
    {
        if (tryBypassTrapBlock(Trap))
            continue;

        // Unexpected shape (another pass touched the block?). Don't leave a
        // retired trap armed: drop just the trap and keep the CFG as is.
        errs() << "[deinstr] WARNING: " << kind << " trap in block '"
               << Trap->getParent()->getName()
               << "' is not a private [trap; br] block -- erasing only the trap\n";
        Trap->eraseFromParent();
    }
}

void removeIfEdgeInstrumentation(unordered_set<int32_t> &, std::vector<CallInst *> &traps)
{
    removeEdgeBlockTraps(traps, "if-else edge");
}

void removeSwitchFallthroughInstrumentation(unordered_set<int32_t> &, std::vector<CallInst *> &traps)
{
    removeEdgeBlockTraps(traps, "switch edge");
}

// Two shapes (see handleInvokeEdges):
//   - spliced:  invoke.cont<id> = [trap; br NormalDest]   -> bypass the block
//   - in place: trap sits at the top of NormalDest (before its first
//               non-PHI instruction, possibly ahead of a block_id trap),
//               so just erase the call.
void removeInvokeInstrumentation(unordered_set<int32_t> &, std::vector<CallInst *> &traps)
{
    for (CallInst *Trap : traps)
    {
        if (tryBypassTrapBlock(Trap))
            continue;
        if (!Trap->use_empty())
        {
            errs() << "[deinstr] ERROR: invoke trap in '" << Trap->getParent()->getName()
                   << "' has unexpected uses -- skipping\n";
            continue;
        }
        Trap->eraseFromParent();
    }
}

/* ---------------- BLOCK TRAPS ----------------
 * block_id traps are ordinary instructions at the top of a block; erasing
 * them leaves the CFG and PHIs untouched. Must run AFTER the edge-block
 * removals above only in the sense that nothing here depends on them; the
 * two sets never share a call.
 */
void removeBlockInstrumentation(unordered_set<int32_t> &, std::vector<CallInst *> &traps)
{
    for (CallInst *Trap : traps)
    {
        if (!Trap->use_empty())
        {
            errs() << "[deinstr] ERROR: block trap call result in '"
                   << Trap->getParent()->getName() << "' has unexpected uses -- skipping\n";
            continue;
        }
        Trap->eraseFromParent();
    }
}

/* ---------------- LOOP GUARDS ----------------
 * Counters are slots in the global @loop_counters array. The guard call's
 * single argument is either a `getelementptr inbounds` instruction or, if
 * IRBuilder constant-folded it, a constant expression. Only the instruction
 * form needs erasing. The array slot itself stays; it's harmless (zeroed by
 * __reset_loop_counters).
 */
void removeLoopInstrumentation(unordered_set<int32_t> &, std::vector<CallInst *> &traps)
{
    for (CallInst *Trap : traps)
    {
        StringRef FName = Trap->getFunction()->getName();

        GetElementPtrInst *SlotGEP = nullptr;
        if (Trap->arg_size() != 1)
        {
            errs() << "[deinstr] ERROR: loop guard call in function '" << FName
                   << "' has " << Trap->arg_size()
                   << " args, expected 1 -- skipping slot cleanup for this call\n";
        }
        else
        {
            SlotGEP = dyn_cast<GetElementPtrInst>(Trap->getArgOperand(0));
        }

        // The id bytes, trap and __traps entry all live in one asm blob, so
        // erasing the call removes all of them.
        Trap->eraseFromParent();

        if (SlotGEP && SlotGEP->use_empty())
            SlotGEP->eraseFromParent();
    }
}

/* ---------------- LOOP THRESHOLD RESTORATION ----------------
 * For loops that are NOT retired this round, rewrite the guard's inline asm
 * so the initial cmp immediate (1 as emitted by insertCounterGuard) becomes
 * the threshold the fuzzer had already advanced the loop to. Without this,
 * every recompile resets every live loop counter's threshold.
 */

// Threshold file: "id,cmp_value" lines. Thresholds only grow, so keep the max
// per id. Ids present in the meta file are retired loops and get none.
void loadThresholds(unordered_set<int32_t> &metaIds,
                    unordered_map<int32_t, int32_t> &thresholds,
                    string &thresholdFile)
{
    if (thresholdFile.empty())
        return;

    ifstream file(thresholdFile);
    if (!file)
    {
        errs() << "[deinstr] WARNING: could not open threshold file '"
               << thresholdFile << "' -- proceeding with no threshold restoration\n";
        return;
    }

    string line;
    int lineNo = 0;
    while (getline(file, line))
    {
        ++lineNo;
        // A last line without '\n' may be truncated ("12,6" from "12,64"),
        // which would parse fine but give a too-low value.
        if (file.eof())
            break;
        if (line.empty())
            continue;

        int32_t id = 0, cmp_value = 0;
        if (sscanf(line.c_str(), "%d,%d", &id, &cmp_value) != 2)
        {
            errs() << "[deinstr] [thresholds] WARNING: malformed line " << lineNo
                   << " ('" << line << "') -- skipping\n";
            continue;
        }

        if (metaIds.count(id) != 0)
            continue;

        auto it = thresholds.find(id);
        if (it == thresholds.end() || it->second < cmp_value) {
            thresholds[id] = cmp_value;
        }
    }
}

// Rewrites only the imm32 of the forced-imm32 "cmp eax, imm32" in the guard:
//     ".byte 0x3d, 0x01, 0x00, 0x00, 0x00\n\t"
//                  ^^^^^^^^^^^^^^^^^^^^^^ these four bytes
// The trap byte, marker, id bytes, labels and __traps section entry are
// left untouched.
static bool patchCmpImmediate(std::string &Asm, int32_t newThreshold)
{
    static const std::string Prefix = ".byte 0x3d, ";
    size_t pos = Asm.find(Prefix);
    if (pos == std::string::npos)
        return false;

    size_t start = pos + Prefix.size();
    size_t end = Asm.find('\n', start);
    if (end == std::string::npos)
        return false;

    uint32_t u = static_cast<uint32_t>(newThreshold);
    std::string imm =
        std::to_string(u & 0xFF) + ", " +
        std::to_string((u >> 8) & 0xFF) + ", " +
        std::to_string((u >> 16) & 0xFF) + ", " +
        std::to_string((u >> 24) & 0xFF);

    Asm.replace(start, end - start, imm);
    return true;
}

// InlineAsm is uniqued and immutable: build a new one from the old string and
// swap the call. Returns the new call (old one erased), or nullptr on failure
// with Trap left untouched.
CallInst *updateLoopCounterThreshold(CallInst *Trap, int32_t id, int32_t newThreshold)
{
    if (Trap->arg_size() != 1)
    {
        errs() << "[deinstr] ERROR: loop guard call for id " << id << " has "
               << Trap->arg_size() << " args, expected 1 -- skipping threshold restore\n";
        return nullptr;
    }

    auto *OldIA = dyn_cast<InlineAsm>(Trap->getCalledOperand());
    if (!OldIA)
    {
        errs() << "[deinstr] ERROR: loop guard call for id " << id
               << " is not an inline asm call -- skipping threshold restore\n";
        return nullptr;
    }

    std::string AsmStr = OldIA->getAsmString();
    if (!patchCmpImmediate(AsmStr, newThreshold))
    {
        errs() << "[deinstr] ERROR: could not find cmp immediate in guard asm for id "
               << id << " -- skipping threshold restore\n";
        return nullptr;
    }

    // Same function type, constraints and flags; only the string changes.
    InlineAsm *NewIA = InlineAsm::get(
        OldIA->getFunctionType(), AsmStr, OldIA->getConstraintString(),
        OldIA->hasSideEffects(), OldIA->isAlignStack(),
        OldIA->getDialect(), OldIA->canThrow());

    IRBuilder<> Builder(Trap);
    CallInst *NewCall = Builder.CreateCall(NewIA, {Trap->getArgOperand(0)});
    NewCall->copyMetadata(*Trap); // loop_header_id, debug loc, ...

    Trap->eraseFromParent(); // void call, no uses to replace
    return NewCall;
}

void applyLoopThresholds(unordered_map<int32_t, int32_t> &thresholds,
                         unordered_set<int32_t> &metaIds,
                         std::vector<CallInst *> &allLoopCountTraps)
{
    for (CallInst *&CI : allLoopCountTraps)
    {
        MDNode *MD = CI->getMetadata("loop_header_id");
        if (!MD)
            continue;
        int32_t id = getMetaId(MD);

        if (metaIds.count(id))
            continue; // retiring this round

        auto it = thresholds.find(id);
        if (it == thresholds.end())
            continue;

        if (CallInst *NewCall = updateLoopCounterThreshold(CI, id, it->second))
            CI = NewCall;
    }
}
/* -------------- END LOOP THRESHOLD RESTORATION -------------- */

void loadData(unordered_set<int32_t> &metaIds, string &metaFile)
{
    ifstream file(metaFile);
    if (!file)
    {
        errs() << "[deinstr] ERROR: could not open meta file '" << metaFile << "'\n";
        return;
    }
    string line;
    while (getline(file, line))
    {
        // eofbit after getline means the last line had no trailing '\n';
        // the harness always writes '\n', so it's truncated.
        if (file.eof())
            break;
        if (line.empty())
            continue;
        char *end = nullptr;
        long v = strtol(line.c_str(), &end, 10);
        if (end == line.c_str() || *end != '\0')
            continue;
        metaIds.insert(static_cast<int32_t>(v));
    }
}

int writeToFile(Module &M, const char *outputFile)
{
    if (verifyModule(M, &errs()))
    {
        errs() << "ERROR: Module is invalid after transform!\n";
        return 1;
    }

    std::error_code EC;
    raw_fd_ostream Out(outputFile, EC);
    if (EC)
    {
        errs() << "Could not open output file: " << EC.message() << "\n";
        return 1;
    }
    M.print(Out, nullptr);
    return 0;
}

int main(int argc, char **argv)
{
    int c;
    string metaFile;
    string inputFile;
    string outputFile;
    string thresholdFile; // optional -l <loop_thresholds.txt>
    while ((c = getopt(argc, argv, "m:i:o:l:")) > 0)
    {
        switch (c)
        {
        case 'i':
            inputFile = optarg;
            break;
        case 'm':
            metaFile = optarg;
            break;
        case 'o':
            outputFile = optarg;
            break;
        case 'l':
            thresholdFile = optarg;
            break;
        default:
            exit(EXIT_FAILURE);
        }
    }
    if (metaFile.empty() || inputFile.empty() || outputFile.empty())
    {
        errs() << "Usage: " << argv[0]
               << " -i <file.ll> -m <meta_data.txt> -o <output_file> [-l <loop_thresholds.txt>]\n";
        return 1;
    }
    LLVMContext Context;
    SMDiagnostic Err;
    auto M = parseFile(inputFile.data(), Err, Context);
    if (M == nullptr)
        return 1;

    unordered_set<int32_t> metaIds;
    loadData(metaIds, metaFile);
    unordered_map<int32_t, int32_t> thresholds;
    loadThresholds(metaIds, thresholds, thresholdFile);

    std::vector<CallInst *> elseArmTraps;
    std::vector<CallInst *> switchEdgeTraps;
    std::vector<CallInst *> invokeTraps;
    std::vector<CallInst *> loopCountTraps;
    std::vector<CallInst *> blockTraps;
    std::vector<CallInst *> allLoopCountTraps;
    findTrapInstructions(*M, metaIds, thresholds, elseArmTraps, switchEdgeTraps,
                         invokeTraps, loopCountTraps, blockTraps, allLoopCountTraps);

    // Threshold restoration touches only live loops (disjoint from
    // loopCountTraps, which holds the retiring ones), so order vs. the
    // removals below doesn't matter for correctness.
    if (!thresholds.empty())
        applyLoopThresholds(thresholds, metaIds, allLoopCountTraps);

    removeIfEdgeInstrumentation(metaIds, elseArmTraps);
    removeSwitchFallthroughInstrumentation(metaIds, switchEdgeTraps);
    removeInvokeInstrumentation(metaIds, invokeTraps);
    removeBlockInstrumentation(metaIds, blockTraps);
    removeLoopInstrumentation(metaIds, loopCountTraps);

    return writeToFile(*M, outputFile.data());
}