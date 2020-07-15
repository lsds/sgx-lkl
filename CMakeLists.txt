# We follow Open Enclave's minimum CMake version requirement.
# See openenclave/scripts/ansible/roles/linux/openenclave/tasks/environment-setup.yml.
cmake_minimum_required(VERSION 3.13.1 FATAL_ERROR)

# CXX is added here to avoid default compiler selection issues
# when including Open Enclave via add_subdirectory.
# SGX-LKL does not use C++ currently.
project(SGX-LKL C CXX ASM)

# Conventions:
# - All filenames/paths, and variables containing them, must be quoted.

get_filename_component(real_binary_dir "${CMAKE_BINARY_DIR}" REALPATH)
if (NOT CMAKE_BINARY_DIR STREQUAL real_binary_dir)
	message(FATAL_ERROR "${CMAKE_BINARY_DIR} must not be a symlink as LKL will not build otherwise")
endif()

include(cmake/Constants.cmake)
include(cmake/Helpers.cmake)
include(cmake/Options.cmake)
include(cmake/BuildMetadata.cmake)

if (USE_LLD)
	find_program(LINKER NAMES ld.lld-10 ld.lld-9 ld.lld-8 ld.lld-7 ld.lld REQUIRED)
	if (CMAKE_C_COMPILER_ID STREQUAL Clang)
		set(LINKER_CFLAG "-fuse-ld=${LINKER}")
	else()
		# GCC does not support absolute paths yet.
		# If an unversioned 'lld' executable is not found, gcc will fail.
		set(LINKER_CFLAG "-fuse-ld=lld")
	endif()
	add_link_options("${LINKER_CFLAG}")
else()
	set(LINKER "ld")
endif()

# TODO clean up flags, add -Wall etc., make sure they are consistently used everywhere

set(LIBC_CFLAGS_EXTRA "${LIBC_CFLAGS_EXTRA} -fPIC -D__USE_GNU")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(LKL_CFLAGS_EXTRA "${LKL_CFLAGS_EXTRA} -g3 -ggdb3 -O0 -DDEBUG")
	set(LIBC_CFLAGS_EXTRA "${LIBC_CFLAGS_EXTRA} -g3 -ggdb3 -O0 -DDEBUG")
endif()
if(${LKL_DEBUG})
	set(LKL_CFLAGS_EXTRA "${LKL_CFLAGS_EXTRA} -DLKL_DEBUG")
endif()

# Include all SGX-LKL components.
file(GLOB COMPONENT_CMAKE_FILES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/cmake/components/*.cmake")
foreach (cmake_file IN LISTS COMPONENT_CMAKE_FILES)
	include("${cmake_file}")
endforeach()

# TODO Install build outputs to the right folders.

# TODO remove tools after relayering
add_executable(lkl_bits tools/lkl_bits.c)
target_include_directories(lkl_bits PRIVATE "${CMAKE_BINARY_DIR}/lkl-headers/include")
add_dependencies(lkl_bits build-lkl)

add_executable(lkl_syscalls tools/lkl_syscalls.c)
target_include_directories(lkl_syscalls PRIVATE "${CMAKE_BINARY_DIR}/lkl-headers/include")
add_dependencies(lkl_syscalls build-lkl)

add_custom_command(
	OUTPUT "${CMAKE_BINARY_DIR}/lkl-headers/include/lkl/bits.h"
		   "${CMAKE_BINARY_DIR}/lkl-headers/include/lkl/syscalls.h"
	COMMAND lkl_bits > "${CMAKE_BINARY_DIR}/lkl-headers/include/lkl/bits.h"
	COMMAND lkl_syscalls > "${CMAKE_BINARY_DIR}/lkl-headers/include/lkl/syscalls.h"
	DEPENDS lkl_bits lkl_syscalls
)
add_custom_target(gen-extra-lkl-headers DEPENDS 
	"${CMAKE_BINARY_DIR}/lkl-headers/include/lkl/bits.h"
	"${CMAKE_BINARY_DIR}/lkl-headers/include/lkl/syscalls.h")
