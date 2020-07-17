# We follow Open Enclave's minimum CMake version requirement.
# See openenclave/scripts/ansible/roles/linux/openenclave/tasks/environment-setup.yml.
cmake_minimum_required(VERSION 3.13.1 FATAL_ERROR)
message(STATUS "CMake version: ${CMAKE_VERSION}")

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

# Global compile options for both enclave and host code.
# See cmake/components/common.cmake for enclave/host-specific options.
foreach(LANG C CXX)
	set(CMAKE_${LANG}_FLAGS "-Wall -Werror")
	set(CMAKE_${LANG}_FLAGS_DEBUG "-O0 -g3 -ggdb3")
	set(CMAKE_${LANG}_FLAGS_RELWITHDEBINFO "-O3 -g3 -ggdb3 -DNDEBUG")
	set(CMAKE_${LANG}_FLAGS_RELEASE "-O3 -DNDEBUG")
endforeach()
string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE_UPPER)
set(CMAKE_C_FLAGS_BUILD_TYPE "${CMAKE_C_FLAGS_${BUILD_TYPE_UPPER}}")

# The linker is used for partially linking the kernel and user space object files
# and for fully linking the enclave image and host launcher.
# The code below does two things:
# - If lld is requested, set -fuse-ld=... as global linker option for all targets.
# - A LINKER variable is made available for manually invoking the linker executable.
# Note that invoking the linker executable manually is only required
# because CMake does not have a library type for partially linked objects.
# See https://gitlab.kitware.com/cmake/cmake/-/issues/16977.
# For more details on partial linking see cmake/components/enclave.cmake.
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
	unset(LINKER_CFLAG)
else()
	find_program(LINKER NAMES ld REQUIRED)
endif()

# Include all top-level SGX-LKL components.
include(cmake/components/host.cmake)
include(cmake/components/enclave.cmake)

# TODO Install build outputs to the right folders.
