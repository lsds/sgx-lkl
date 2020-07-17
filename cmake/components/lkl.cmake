include_guard(GLOBAL)

include(ExternalProject)
include(cmake/Helpers.cmake)
include(cmake/RecursiveCopy.cmake)

# Note that most compile flags can be set via defconfig options. See below.
# Important: Don't try to set optimization flags like -O0 here.
# The Linux kernel makes assumptions about optimizations used and overriding them will fail.
set(LKL_EXTRA_CFLAGS "-fPIE")
if (LKL_DEBUG)
	string(APPEND LKL_EXTRA_CFLAGS " -DLKL_DEBUG")
endif()

# See src/lkl/override/defconfig for all other options.
# Here we only add additional defconfig and Make options that depend on CMake options.
set(LKL_EXTRA_OPTIONS)
if (NOT LKL_USE_GCC AND CMAKE_C_COMPILER_ID STREQUAL "Clang")
	list(APPEND LKL_EXTRA_OPTIONS "CONFIG_CC_IS_CLANG=y" "CC=${CMAKE_C_COMPILER}")
	message(STATUS "Building LKL with Clang")
endif()

# Copy the LKL sources to the build directory.  This copies everything except
# the files that we will modify and creates rules so that any modification of
# the source files will trigger a re-copy and rebuild.
# Note: We probably could exclude a load of directories for architectures and
# drivers that we don't care about if we want to reduce the binary code size.
# Note 2: It might be better to simply symlink the files that we're not
# modifying into the build directory at configure time (though driving this
# from CMake will be a lot slower than from Ninja and avoiding re-doing the
# copy on subsequent builds is harder).
set(LKL_EXCLUDE
	# Files we modify or generate.
	arch/lkl/configs/defconfig
	net/Makefile
	net/Kconfig
	# Folders we don't need.
	arch/alpha
	arch/arc
	arch/arm
	arch/arm64
	arch/c6x
	arch/csky
	arch/h8300
	arch/hexagon
	arch/ia64
	arch/m68k
	arch/microblaze
	arch/mips
	arch/nds32
	arch/nios2
	arch/openrisc
	arch/parisc
	arch/powerpc
	arch/riscv
	arch/s390
	arch/sh
	arch/sparc
	arch/um
	arch/unicore32
	arch/xtensa
)
list(TRANSFORM LKL_EXCLUDE PREPEND "${LKL_SUBDIRECTORY}/" OUTPUT_VARIABLE LKL_EXCLUDE)
copy_source_directory_to_output("${LKL_SUBDIRECTORY}" "${LKL_EXCLUDE}")
# NEW_FILES is populated by copy_source_directory_to_output().
add_custom_target(copy-lkl DEPENDS ${NEW_FILES})

# Replace the default kernel configuration file with our own.
set(DEFCONFIG_OVERRIDE_PATH "${LKL_SUBDIRECTORY}/arch/lkl/configs/defconfig")
add_custom_command(OUTPUT ${DEFCONFIG_OVERRIDE_PATH}
	COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_SOURCE_DIR}/src/lkl/override/defconfig" "${DEFCONFIG_OVERRIDE_PATH}"
	MAIN_DEPENDENCY "${CMAKE_SOURCE_DIR}/src/lkl/override/defconfig"
	COMMENT "Overriding LKL default configuration")

ExternalProject_Add(wireguard-ep
	URL ${WIREGUARD_URL}
	URL_HASH ${WIREGUARD_HASH}
	CONFIGURE_COMMAND ""
	BUILD_COMMAND ""
	INSTALL_COMMAND ""
	${COMMON_EP_OPTIONS}
)
get_external_project_property(wireguard-ep SOURCE_DIR WIREGUARD_SOURCE_DIR)

# Apply the wireguard patch into our copy of the kernel tree.  
# Note, this can go away once our upstream LKL has the wireguard patches
# already applied
add_custom_command(
	OUTPUT "lkl/net/wireguard" "lkl/net/Kconfig" "lkl/net/Makefile" "wireguard-patches-applied.stamp"
	DEPENDS "${LKL_SUBDIRECTORY}/net/Makefile" "${LKL_SUBDIRECTORY}/net/Kconfig" wireguard-ep
	COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_SOURCE_DIR}/${LKL_SUBDIRECTORY}/net/Makefile" "${CMAKE_SOURCE_DIR}/${LKL_SUBDIRECTORY}/net/Kconfig" "${CMAKE_BINARY_DIR}/lkl/net"
	COMMAND ${CMAKE_COMMAND} -E remove_directory "${CMAKE_BINARY_DIR}/lkl/net/wireguard"
	COMMAND "${WIREGUARD_SOURCE_DIR}/contrib/kernel-tree/create-patch.sh" | patch --forward -p1
	COMMAND ${CMAKE_COMMAND} -E touch "${CMAKE_BINARY_DIR}/wireguard-patches-applied.stamp"
	WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/lkl" 
	)

add_custom_target(apply-wireguard-patches DEPENDS "wireguard-patches-applied.stamp")
add_custom_target(lkl-source-setup
	DEPENDS copy-lkl "${DEFCONFIG_OVERRIDE_PATH}" apply-wireguard-patches
	)

# We need to add the headers that we're going to generate as part of the
# headers_install steps of the LKL build, but we don't know what those files
# are until after the build.  To fix that, we use `find` after the header
# install build to update a list in this file.
set(LKL_HEADERS_FILE "${CMAKE_BINARY_DIR}/lkl-headers.list")
touch("${LKL_HEADERS_FILE}")
set(LKL_HEADERS "")
include("${LKL_HEADERS_FILE}")

# LKL's build system generates as main output liblkl.a.
# liblkl.a contains lkl.o and liblkl-in.o.
# lkl.o is the actual LKL and has two undefined symbols lkl_bug and lkl_printf.
# Those two symbols are satisfied by liblkl-in.o by relying on an available libc.
# In kernel space we do not have a libc available.
# Therefore, we will only depend on lkl.o and re-implement lkl_bug and lkl_printf.
# Open Enclave's oecore provides everything necessary for an implementation.
# See lkl/tools/lkl/lib/utils.c for the original implementations.
set(LKL_LIB_PATH "lkl/tools/lkl/lib/lkl.o")
set(LKL_HEADER_PATH "${CMAKE_BINARY_DIR}/lkl-headers")
add_custom_command(OUTPUT "${LKL_LIB_PATH}"
	DEPENDS lkl-source-setup
	COMMAND make -C "${CMAKE_BINARY_DIR}/${LKL_SUBDIRECTORY}/tools/lkl" -j ${NUMBER_OF_CORES} V=1 "EXTRA_CFLAGS=${LKL_EXTRA_CFLAGS}" ${LKL_EXTRA_OPTIONS} "${CMAKE_BINARY_DIR}/${LKL_LIB_PATH}"
	COMMAND ${CMAKE_COMMAND} -E env "DESTDIR=${LKL_HEADER_PATH}" make -C "${CMAKE_BINARY_DIR}/${LKL_SUBDIRECTORY}/tools/lkl/" -j ${NUMBER_OF_CORES} V=1 "PREFIX=\"\"" headers_install
	COMMAND make -C "${CMAKE_BINARY_DIR}/${LKL_SUBDIRECTORY}" ARCH=lkl "INSTALL_HDR_PATH=${LKL_HEADER_PATH}" -j ${NUMBER_OF_CORES} V=1 "PREFIX=\"\"" headers_install
	COMMAND echo "set(LKL_HEADERS" > "${LKL_HEADERS_FILE}.tmp"
	COMMAND find "${LKL_HEADER_PATH}" >> "${LKL_HEADERS_FILE}.tmp"
	COMMAND echo ")" >> "${LKL_HEADERS_FILE}.tmp"
	COMMAND ${CMAKE_COMMAND} -E copy_if_different "${LKL_HEADERS_FILE}.tmp" "${LKL_HEADERS_FILE}"
	COMMAND ${CMAKE_COMMAND} -E remove "${LKL_HEADERS_FILE}.tmp" 
	WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/lkl"
	BYPRODUCTS ${LKL_HEADERS} "${LKL_HEADERS_FILE}" 
	VERBATIM
	COMMENT "Compiling LKL"
)
add_custom_target(build-lkl DEPENDS "${LKL_LIB_PATH}")

set(LKL_INCLUDE_DIR "${LKL_HEADER_PATH}/include")

# TODO remove tools after relayering
add_executable(lkl_bits tools/lkl_bits.c)
target_include_directories(lkl_bits PRIVATE "${LKL_INCLUDE_DIR}")
add_dependencies(lkl_bits sgx-lkl::lkl)

add_executable(lkl_syscalls tools/lkl_syscalls.c)
target_include_directories(lkl_syscalls PRIVATE "${LKL_INCLUDE_DIR}")
add_dependencies(lkl_syscalls sgx-lkl::lkl)

set(LKL_BITS_H "${LKL_INCLUDE_DIR}/lkl/bits.h")
set(LKL_SYSCALLS_H "${LKL_INCLUDE_DIR}/lkl/syscalls.h")
add_custom_command(
	OUTPUT "${LKL_BITS_H}" "${LKL_SYSCALLS_H}"
	COMMAND lkl_bits > "${LKL_BITS_H}"
	COMMAND lkl_syscalls > "${LKL_SYSCALLS_H}"
	DEPENDS lkl_bits lkl_syscalls
)

add_library(lkl-headers INTERFACE)
target_include_directories(lkl-headers SYSTEM INTERFACE "${LKL_INCLUDE_DIR}")
add_dependencies(lkl-headers
	build-lkl
	"${LKL_BITS_H}"
	"${LKL_SYSCALLS_H}"
	)
add_library(sgx-lkl::lkl-headers ALIAS lkl-headers)

add_library(lkl STATIC 
	"${LKL_LIB_PATH}"
	src/lkl/lkl_oe.c
	)
target_link_libraries(lkl 
	PRIVATE sgx-lkl::common-enclave
	INTERFACE sgx-lkl::lkl-headers
	)
add_library(sgx-lkl::lkl ALIAS lkl)
