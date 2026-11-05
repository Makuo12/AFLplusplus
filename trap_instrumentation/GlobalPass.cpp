#include "GlobalPass.h"

// Linux only: every tracked global is placed in this section. Because the name
// is a valid C identifier, GNU ld defines __start___cls_glob / __stop___cls_glob
// around it, which the runtime (global.c) uses to snapshot and restore it.
static constexpr const char *ClosureGlobalSection = "__cls_glob";

/**
 * @brief Moves every mutable, module-defined global variable into the
 * __cls_glob section so the runtime can snapshot and restore them as one block.
 *
 * @param M
 * @return true if at least one global was moved
 */
bool CloneGlobalsPass::cloneGlobals(Module &M)
{
    bool Changed = false;

    for (GlobalVariable &G : M.globals())
    {
        // Defined in another module, nothing for us to place.
        if (G.isDeclaration())
            continue;

        // Read-only data never changes, so there is nothing to reset.
        if (G.isConstant())
            continue;

        // Respect an explicit section; this also keeps the runtime's own
        // state (section "untracer_state") out of the snapshot.
        if (G.hasSection())
            continue;

        // TLS lives in the thread-local segment, not in a normal section.
        if (G.isThreadLocal())
            continue;

        // Compiler-internal globals: llvm.used, llvm.global_ctors, etc.
        if (G.getName().starts_with("llvm."))
            continue;

        // Common-linkage globals (C with -fcommon) cannot carry a section.
        if (G.hasCommonLinkage())
            continue;

        G.setSection(ClosureGlobalSection);
        Changed = true;
    }

    return Changed;
}

/**
 * @brief runOnModule method for Module Pass
 *
 * @param M
 * @return true if the module was modified
 */
bool CloneGlobalsPass::runOnModule(Module &M)
{
    return cloneGlobals(M);
}

PreservedAnalyses CloneGlobalsPass::run(Module &M, ModuleAnalysisManager &AM)
{
    // Only the section attribute changes; no instructions or CFG are touched.
    return runOnModule(M) ? PreservedAnalyses::none() : PreservedAnalyses::all();
}