#pragma once

#include "trap_common.h"

#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"

using namespace llvm;

/**
 * @brief Linux-only pass that moves every mutable, module-defined global
 * variable into the "__cls_glob" section. The runtime (global.c) snapshots
 * that section once after startup and memcpy's it back to reset all of those
 * globals at once. The pass does not copy variables or insert any code.
 */
class CloneGlobalsPass : public PassInfoMixin<CloneGlobalsPass>
{
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);

  /// Returns true if at least one global was moved into the section.
  bool cloneGlobals(Module &M);

  /// Returns true if the module was modified.
  bool runOnModule(Module &M);

  /// Needed so the pass still runs when optimization is disabled (-O0).
  static bool isRequired() { return true; }
};