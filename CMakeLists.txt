cmake_minimum_required(VERSION 3.20)
project(Untracer)

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)

include_directories(${LLVM_INCLUDE_DIRS} include/)
add_definitions(${LLVM_DEFINITIONS})

# GOOD: Use LLVM's dedicated macro for pass plugins instead of add_library(MODULE)
add_llvm_pass_plugin(Untracer
    ./src/Pass.cc
    ./src/RenameMainPass.cpp
)

set_target_properties(Untracer PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# NOTE: add_llvm_pass_plugin handles -fno-rtti and proper linking automatically,
# so llvm_map_components_to_libnames and target_link_libraries are no longer needed!