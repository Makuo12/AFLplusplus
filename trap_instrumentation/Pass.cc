#include "RenameMain.h"
#include "GlobalPass.h"
using namespace llvm;

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "UntracerPass", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            // Register by name so opt can find it
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "rename") {
                    MPM.addPass(RenameMainPass());
                    MPM.addPass(CloneGlobalsPass());
                    return true;
                  }
                  return false;
                });
          }};
}