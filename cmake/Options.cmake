if (NOT CMAKE_GENERATOR STREQUAL "Ninja")
	message(WARNING "Consider using Ninja for optimal build system performance: -G Ninja")
endif()

if (NOT CMAKE_C_COMPILER_ID STREQUAL Clang)
  message(WARNING "Clang is the preferred compiler for this project, use: CC=clang")
endif()

if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "No build type selected, default to Debug")
  set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type (default Debug)" FORCE)
endif()

set(OE_PREFIX "" CACHE PATH "Installation prefix of Open Enclave, otherwise built from source")

set(LKL_DEBUG FALSE CACHE BOOL "Enable extra debugging for LKL")

set(LIBC musl CACHE STRING "Libc implementation to build.  Currently only musl is supported")
# Add "glibc" here once glibc is supported
set(LIBC_NAMES "musl")
set_property(CACHE LIBC PROPERTY STRINGS ${LIBC_NAMES})
if(NOT LIBC IN_LIST LIBC_NAMES)
    message(FATAL_ERROR "LIBC must be one of: ${LIBC_NAMES}")
endif()

set(USE_LLD CACHE BOOL "Use LLVM's lld linker")

set(COPY_INDIVIDUAL_FILES FALSE CACHE BOOL
    "Copy source files one at a time. This makes the initial build slower, but incremental builds faster.")
    