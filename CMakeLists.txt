include(cmake/Constants.cmake)

cmake_minimum_required(VERSION ${MIN_CMAKE_VERSION})

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

include(ExternalProject)
include(ProcessorCount)
include(cmake/Helpers.cmake)
include(cmake/RecursiveCopy.cmake)
include(cmake/Constants.cmake)
include(cmake/Options.cmake)
include(cmake/BuildMetadata.cmake)

set_directory_properties(PROPERTIES EP_BASE "${EXTERNAL_PROJECT_BASE_DIR}")
ProcessorCount(NUMBER_OF_CORES)
read_build_metadata()

if (USE_LLD)
	find_program(LINKER NAMES ld.lld-10 ld.lld-9 ld.lld-8 ld.lld-7 ld.lld REQUIRED)
	if (CMAKE_C_COMPILER_ID STREQUAL Clang)
		set(LINKER_CFLAG "-fuse-ld=${LINKER}")
	elseif()
		# GCC does not support absolute paths.
		set(LINKER_CFLAG "-fuse-ld=lld")
	endif()
	add_link_options("${LINKER_CFLAG}")
else()
	set(LINKER "ld")
endif()

find_package(Python COMPONENTS Interpreter REQUIRED)

if (OE_PREFIX)
	set(openenclave_DIR "${OE_PREFIX}/lib/openenclave/cmake")
	find_package(openenclave REQUIRED)
else()
	# OE should prefix public options.
	set(WITH_EEID ON CACHE BOOL "" FORCE)
	set(COMPILE_SYSTEM_EDL OFF CACHE BOOL "" FORCE)
	set(ENABLE_REFMAN OFF CACHE BOOL "" FORCE)
	set(BUILD_TESTS OFF CACHE BOOL "" FORCE)

	set(OPENENCLAVE_DIR "${CMAKE_SOURCE_DIR}/openenclave")
	add_subdirectory("${OPENENCLAVE_DIR}" EXCLUDE_FROM_ALL)
	
	# OE should provide aliased targets.
	add_library(openenclave::oe_includes ALIAS oe_includes)
	add_library(openenclave::oecore ALIAS oecore)
	add_library(openenclave::oeenclave ALIAS oeenclave)
	add_library(openenclave::oehost ALIAS oehost)
	add_library(openenclave::oesyscall ALIAS oesyscall)
	add_library(openenclave::oelibc ALIAS oelibc)
	add_library(openenclave::oecryptombed ALIAS oecryptombed)
	add_library(openenclave::mbedtls ALIAS mbedtls)
	add_library(openenclave::mbedcrypto_static ALIAS mbedcrypto_static)
	add_library(openenclave::mbedx509 ALIAS mbedx509)
	add_executable(openenclave::oeedger8r ALIAS edger8r)
	
	set(oeedger8r_search_path_args 
		--search-path "${OPENENCLAVE_DIR}/include"
		--search-path "${OPENENCLAVE_DIR}/include/openenclave/edl/sgx")
endif()

include(cmake/oeenclave.cmake)

set(LIBC_CFLAGS_EXTRA "${LIBC_CFLAGS_EXTRA} -fPIC -D__USE_GNU")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(LKL_CFLAGS_EXTRA "${LKL_CFLAGS_EXTRA} -g3 -ggdb3 -O0 -DDEBUG")
	set(LIBC_CFLAGS_EXTRA "${LIBC_CFLAGS_EXTRA} -g3 -ggdb3 -O0 -DDEBUG")
endif()
if(${LKL_DEBUG})
	set(LKL_CFLAGS_EXTRA "${LKL_CFLAGS_EXTRA} -DLKL_DEBUG")
endif()

# Common properties for code that is part of the enclave image.
add_library(sgxlkl_enclave INTERFACE)
target_compile_definitions(sgxlkl_enclave INTERFACE -DSGXLKL_ENCLAVE -DOE_WITH_EXPERIMENTAL_EEID)
target_include_directories(sgxlkl_enclave INTERFACE "src/include" "${CMAKE_BINARY_DIR}/generated")
target_link_libraries(sgxlkl_enclave INTERFACE sgx-lkl::oeenclave)
add_library(sgx-lkl::enclave ALIAS sgxlkl_enclave)

# Common properties for code that is part of the host tool.
add_library(sgxlkl_host INTERFACE)
target_compile_definitions(sgxlkl_host INTERFACE -DOE_WITH_EXPERIMENTAL_EEID)
target_include_directories(sgxlkl_host INTERFACE "src/include" "${CMAKE_BINARY_DIR}/generated")
target_link_libraries(sgxlkl_host INTERFACE openenclave::oehost)
add_library(sgx-lkl::host ALIAS sgxlkl_host)

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
	COMMAND make -C "${CMAKE_BINARY_DIR}/${LKL_SUBDIRECTORY}/tools/lkl" -j ${NUMBER_OF_CORES} V=1 "${CMAKE_BINARY_DIR}/${LKL_LIB_PATH}"
	COMMAND ${CMAKE_COMMAND} -E env "DESTDIR=${LKL_HEADER_PATH}" make -C "${CMAKE_BINARY_DIR}/${LKL_SUBDIRECTORY}/tools/lkl/" -j ${NUMBER_OF_CORES} V=1 "PREFIX=\"\"" headers_install
	COMMAND make -C "${CMAKE_BINARY_DIR}/${LKL_SUBDIRECTORY}" ARCH=lkl "INSTALL_HDR_PATH=${LKL_HEADER_PATH}" -j ${NUMBER_OF_CORES} V=1 "PREFIX=\"\"" headers_install
	COMMAND echo "'set(LKL_HEADERS'" > "${LKL_HEADERS_FILE}.tmp"
	COMMAND find "${LKL_HEADER_PATH}" >> "${LKL_HEADERS_FILE}.tmp"
	COMMAND echo "')'" >> "${LKL_HEADERS_FILE}.tmp"
	COMMAND ${CMAKE_COMMAND} -E copy_if_different "${LKL_HEADERS_FILE}.tmp" "${LKL_HEADERS_FILE}"
	COMMAND ${CMAKE_COMMAND} -E remove "${LKL_HEADERS_FILE}.tmp" 
	WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/lkl"
	BYPRODUCTS ${LKL_HEADERS} "${LKL_HEADERS_FILE}" 
	COMMENT "Compiling LKL"
)
add_library(lkl STATIC 
	"${LKL_LIB_PATH}"
	src/lkl/lkl_oe.c
	#src/lkl/oe_errno.c
	)
target_link_libraries(lkl PRIVATE sgx-lkl::enclave)
add_library(sgx-lkl::lkl ALIAS lkl)

add_custom_target(build-lkl DEPENDS "${LKL_LIB_PATH}")
add_custom_target(copy-lkl DEPENDS ${NEW_FILES})

file(GLOB MAIN_C_SRCS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/main-oe/*.c")
file(GLOB HOSTINTERFACE_C_SRCS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/host_interface/*.c")
file(GLOB SHARED_C_SRCS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/shared/*.c")
file(GLOB ENCLAVE_C_SRCS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/enclave/*.c")
file(GLOB KERNEL_C_SRCS CONFIGURE_DEPENDS
	"${CMAKE_SOURCE_DIR}/src/lkl/*.c"
	"${CMAKE_SOURCE_DIR}/src/sched/*.c"
	"${CMAKE_SOURCE_DIR}/src/wireguard/*.c")

set(GENERATED_HOST_EDGE_FILES 
	"generated/host/sgxlkl_args.h"
	"generated/host/sgxlkl_u.c"
	"generated/host/sgxlkl_u.h"
	)
set(GENERATED_ENCLAVE_EDGE_FILES 
	"generated/enclave/sgxlkl_args.h"
	"generated/enclave/sgxlkl_t.c"
	"generated/enclave/sgxlkl_t.h"
	)
set(GENERATED_HOST_CONFIG_FILES
	"generated/host/sgxlkl_host_config_gen.h"
	"generated/host/sgxlkl_host_config_gen.c"
)
set(GENERATED_ENCLAVE_CONFIG_FILES
	"generated/enclave/sgxlkl_enclave_config_gen.h"
	"generated/enclave/sgxlkl_enclave_config_gen.c"
)

set(HOST_CONFIG_SCHEMA "${CMAKE_SOURCE_DIR}/tools/schemas/host-config.schema.json")
set(ENCLAVE_CONFIG_SCHEMA "${CMAKE_SOURCE_DIR}/tools/schemas/enclave-config.schema.json")

mkdir("generated/host")
mkdir("generated/enclave")
add_custom_command(OUTPUT ${GENERATED_HOST_CONFIG_FILES}
	COMMAND Python::Interpreter	"${CMAKE_SOURCE_DIR}/tools/generate_config.py"
		--header "host/sgxlkl_host_config_gen.h"
		--source "host/sgxlkl_host_config_gen.c"
		"${HOST_CONFIG_SCHEMA}"
	WORKING_DIRECTORY "generated"
	DEPENDS "${CMAKE_SOURCE_DIR}/tools/generate_config.py" "${HOST_CONFIG_SCHEMA}"
)
add_custom_command(OUTPUT ${GENERATED_ENCLAVE_CONFIG_FILES}
	COMMAND ${CMAKE_COMMAND} -E make_directory "generated/enclave"
	COMMAND Python::Interpreter	"${CMAKE_SOURCE_DIR}/tools/generate_config.py"
		--header "enclave/sgxlkl_enclave_config_gen.h"
		--source "enclave/sgxlkl_enclave_config_gen.c"
		"${ENCLAVE_CONFIG_SCHEMA}"
	WORKING_DIRECTORY "generated"
	DEPENDS "${CMAKE_SOURCE_DIR}/tools/generate_config.py" "${ENCLAVE_CONFIG_SCHEMA}"
)

add_library(sgxlkl_host_config STATIC ${GENERATED_HOST_CONFIG_FILES})
target_link_libraries(sgxlkl_host_config PRIVATE sgx-lkl::host)
add_library(sgx-lkl::host-config ALIAS sgxlkl_host_config)

add_library(sgxlkl_enclave_config_enclave STATIC ${GENERATED_ENCLAVE_CONFIG_FILES})
target_link_libraries(sgxlkl_enclave_config_enclave PRIVATE sgx-lkl::enclave)
add_library(sgx-lkl::enclave-config-enclave ALIAS sgxlkl_enclave_config_enclave)

add_library(sgxlkl_enclave_config_host STATIC ${GENERATED_ENCLAVE_CONFIG_FILES})
target_link_libraries(sgxlkl_enclave_config_host PRIVATE sgx-lkl::host)
add_library(sgx-lkl::enclave-config-host ALIAS sgxlkl_enclave_config_host)

add_custom_command(OUTPUT ${GENERATED_HOST_EDGE_FILES}
	COMMAND openenclave::oeedger8r
		${oeedger8r_search_path_args}
		--untrusted "${CMAKE_SOURCE_DIR}/src/sgxlkl.edl"
		--untrusted-dir "${CMAKE_BINARY_DIR}/generated/host"
	DEPENDS "${CMAKE_SOURCE_DIR}/src/sgxlkl.edl"
	)
add_custom_command(OUTPUT ${GENERATED_ENCLAVE_EDGE_FILES}
	COMMAND openenclave::oeedger8r
		${oeedger8r_search_path_args}
		--trusted "${CMAKE_SOURCE_DIR}/src/sgxlkl.edl"
		--trusted-dir "${CMAKE_BINARY_DIR}/generated/enclave"
	DEPENDS "${CMAKE_SOURCE_DIR}/src/sgxlkl.edl"
	)

add_library(sgxlkl_edl_enclave STATIC ${GENERATED_ENCLAVE_EDGE_FILES})
target_link_libraries(sgxlkl_edl_enclave PRIVATE sgx-lkl::enclave)
add_library(sgx-lkl::edl-enclave ALIAS sgxlkl_edl_enclave)

add_library(sgxlkl_edl_host STATIC ${GENERATED_HOST_EDGE_FILES})
target_link_libraries(sgxlkl_edl_host PRIVATE sgx-lkl::host)
add_library(sgx-lkl::edl-host ALIAS sgxlkl_edl_host)

# The enclave image of SGX-LKL is separated into two parts:
# 1. Kernel space
#   - Open Enclave
#   - LKL
#   - Enclave entrypoint
# 2. User space
#   - libc (musl, or later glibc)
#   - vicsetup
#   - libcurl
#   - mbedtls
#   - libdevicemapper
#   - libext2fs
#   - Linux init "process"
# Note on libc:
#   In the future we will have dynamically linked variants
#   of libc for user processes, while the init "process" and
#   its required libraries (libcurl etc.) rely on a statically linked musl.
# Note on Open Enclave:
#   Due to architectural issues we will have to include oeenclave
#   and hence oelibc as well. To avoid duplicate libc symbols we
#   will hide them and leave only oe_*.
# The only dependency from user space to kernel space is via the lkl_syscall function.
# The only dependency from kernel space to user space is via the libc entrypoint function (TODO name?).
# To enforce this separation and to allow having two copies of mbedtls we need to:
# - Partially link all kernel space objects into a single object file.
# - Partially link all user space objects into a single object file.
# - Verify no unresolved symbols exist:
#     ! nm -g libsgxlkl_kernel.o | grep ' U '
#     ! nm -g libsgxlkl_user.o | grep ' U '
# - Hide all kernel space symbols except lkl_syscall and the enclave entrypoint.
# - Hide all user space symbols except the libc entrypoint and libc itself (apps need libc).
# - Fully link both object files into an enclave image.
# `ld -r` can be used for partial linking, `objcopy --keep-global-symbol=..` for hiding symbols.

# Enclave entrypoint.
touch(${CMAKE_BINARY_DIR}/dummy.c)
add_library(sgxlkl_enclave_init STATIC
	# TODO
	#${ENCLAVE_C_SRCS}
	${CMAKE_BINARY_DIR}/dummy.c
)
target_link_libraries(sgxlkl_enclave_init PRIVATE
	sgx-lkl::enclave
	sgx-lkl::lkl
	sgx-lkl::enclave-config-enclave
	)
add_library(sgx-lkl::enclave-init ALIAS sgxlkl_enclave_init)

add_library(sgxlkl_kernel_init_fini_stubs STATIC src/lkl/init_fini_stubs.s)
add_library(sgx-lkl::kernel-init-fini-stubs ALIAS sgxlkl_kernel_init_fini_stubs)

# Kernel space object.
set(SGXLKL_KERNEL_OBJ "libsgxlkl_kernel.o")
add_custom_command(
	OUTPUT "${SGXLKL_KERNEL_OBJ}"
	COMMENT "Building kernel space object"
	COMMAND "${CMAKE_COMMAND}" -E rm -f "${SGXLKL_KERNEL_OBJ}"
	COMMAND "${LINKER}" -r -o "${SGXLKL_KERNEL_OBJ}"
		-m elf_x86_64

		# Only those objects reachable from the enclave entrypoint will be included
		# in the relocatable object file. This is because we use static archives.
		# Object files would always be included in full.
		--entry=_start

		# It would be nice if we could use --gc-sections during partial linking to avoid
		# pulling in unused undefined symbols and also keep the object size small
		# at this stage already. However, this is not possible for the following reasons:
		# gold and lld don't support -r together with --gc-sections.
		# ld supports it but crashes.
		#   gold: "error: cannot mix -r with --gc-sections or --icf"
		#   lld: "error: -r and --gc-sections may not be used together"
		#   ld: "BFD (GNU Binutils for Ubuntu) 2.30 assertion fail ../../bfd/elflink.c:8723"
		# Note that ld also required --gc-keep-exported if --gc-sections is used:
		#   "startfiles:.debug_info: error: relocation references symbol 
		#     mbedtls_cipher_supported which was removed by garbage collection.
		#    startfiles:.debug_info: error: try relinking with --gc-keep-exported enabled."
		# Solution: We will use --gc-sections only during the final link.
		# For this to work we need to work around two OE issues:
		# https://github.com/openenclave/openenclave/issues/3254
		# https://github.com/openenclave/openenclave/issues/3255
		# While the OE issues are not resolved yet we can either
		# - provide empty definitions ourselves for the two ocall symbols, or
		# - allow those two symbols to be undefined and rely on --gc-sections
		#   to remove them during the final link.
		# We use the second option for now.

		# Subset of oecore flags compatible with -r.
		-nostdlib
		# FIXME why doesn't it work with it?
		#-nodefaultlibs
		#-nostartfiles
		-Bstatic
		-Bsymbolic
		--export-dynamic

		# TODO use proper order
		--start-group
		$<TARGET_FILE:sgx-lkl::edl-enclave>
		$<TARGET_FILE:sgx-lkl::enclave-config-enclave>
		$<TARGET_FILE:sgx-lkl::enclave-init>
		$<TARGET_FILE:sgx-lkl::lkl>
		# Linking against the partially linked oeenclave.o (see cmake/oeenclave.cmake)
		# has the disadvantage that all its symbols are included.
		# This would lead to a lot more undefined symbols since we can't
		# use --gc-sections during partial linking (see note above).
		#$<TARGET_FILE:sgx-lkl::oeenclave>
		$<TARGET_FILE:openenclave::oeenclave>
		$<TARGET_FILE:openenclave::oecryptombed>
		$<TARGET_FILE:openenclave::mbedtls>
		$<TARGET_FILE:openenclave::mbedx509>
		$<TARGET_FILE:openenclave::mbedcrypto_static>
		$<TARGET_FILE:openenclave::oelibc>
		$<TARGET_FILE:openenclave::oesyscall>
		$<TARGET_FILE:openenclave::oecore>
		$<TARGET_FILE:sgx-lkl::kernel-init-fini-stubs>
		--end-group
	COMMAND echo "Checking for unresolved symbols"
	COMMAND ! "${CMAKE_NM}" -g "${SGXLKL_KERNEL_OBJ}" 
		| grep ' U ' # filter to undefined symbols
		# TODO remove once OE issues resolved (see comments above)
		| grep -v -e "oe_realloc_ocall" -e "oe_sgx_thread_wake_wait_ocall"
	COMMAND echo "Checking for initializer/teardown sections"
	COMMAND ! "${CMAKE_NM}" -g "${SGXLKL_KERNEL_OBJ}" 
		| grep -e '.ctors' -e '.preinit_array' -e '.init_array'
		       -e '.dtors' -e '.fini_array'
	COMMAND echo "Hiding symbols"
	COMMAND "${CMAKE_OBJCOPY}"
		--keep-global-symbol=_start
	    --keep-global-symbol=lkl_syscall
	   "${SGXLKL_KERNEL_OBJ}"
	DEPENDS
		sgx-lkl::edl-enclave
		sgx-lkl::enclave-config-enclave
		sgx-lkl::enclave-init
		sgx-lkl::lkl
		sgx-lkl::oeenclave
		sgx-lkl::kernel-init-fini-stubs
	)

add_library(sgxlkl_kernel STATIC "${SGXLKL_KERNEL_OBJ}")
set_target_properties(sgxlkl_kernel PROPERTIES LINKER_LANGUAGE C)
add_library(sgx-lkl::kernel ALIAS sgxlkl_kernel)

touch("dummy.c")
add_library(sgxlkl_user_init STATIC "dummy.c")
target_link_libraries(sgxlkl_user_init PRIVATE
	sgx-lkl::libc-init
	curl::curl
	devicemapper::devicemapper
	e2fsprogs::ext2fs
)
add_library(sgx-lkl::user-init ALIAS sgxlkl_user_init)

set(SGXLKL_USER_OBJ "libsgxlkl_user.o")
add_custom_command(
	OUTPUT "${SGXLKL_USER_OBJ}"
	COMMENT "Building user space object"
	COMMAND "${LINKER}" -r -o "${SGXLKL_USER_OBJ}" --whole-archive
		$<TARGET_FILE:sgx-lkl::user-init>
	# TODO enable again, see notes above
	#COMMAND echo "Checking for unresolved symbols"
	#COMMAND ! "${CMAKE_NM}" -g "${SGXLKL_USER_OBJ}" | grep ' U '
	#| grep -v -E -e "'__(fini|init)_array_(start|end)'" # available at final link only
	#COMMAND echo "Hiding symbols"
	#COMMAND "${CMAKE_OBJCOPY}" --keep-global-symbol=lkl_syscall "${SGXLKL_USER_OBJ}"
	COMMAND_EXPAND_LISTS
	DEPENDS
		sgx-lkl::user-init
	)

add_library(sgxlkl_user STATIC "${SGXLKL_USER_OBJ}")
set_target_properties(sgxlkl_user PROPERTIES LINKER_LANGUAGE C)
add_library(sgx-lkl::user ALIAS sgxlkl_user)

# Enclave image.
touch("dummy.c")
add_library(sgxlkl_enclave_image SHARED "dummy.c")
target_link_libraries(sgxlkl_enclave_image PRIVATE sgx-lkl::kernel sgx-lkl::user)
set_target_properties(sgxlkl_enclave_image PROPERTIES LINKER_LANGUAGE C)
add_library(sgx-lkl::enclave-image ALIAS sgxlkl_enclave_image)

ExternalProject_Add(json-c-ep
	URL ${JSON_C_URL}
	URL_HASH ${JSON_C_HASH}
	CONFIGURE_COMMAND "<SOURCE_DIR>/configure" "CC=${CMAKE_C_COMPILER}" "--prefix=<INSTALL_DIR>"
	BUILD_COMMAND make -j ${NUMBER_OF_CORES}
	INSTALL_COMMAND make install
	BUILD_BYPRODUCTS "<INSTALL_DIR>/lib/libjson-c.so"
)
ExternalProject_Get_property(json-c-ep INSTALL_DIR)
add_library(json-c INTERFACE)
target_link_libraries(json-c INTERFACE "${INSTALL_DIR}/lib/libjson-c.so")
target_include_directories(json-c INTERFACE "${INSTALL_DIR}/include")
add_dependencies(json-c json-c-ep)
add_library(json-c::json-c ALIAS json-c)

add_library(sgxlkl_json_host STATIC "src/libjson/json.c")
target_include_directories(sgxlkl_json_host PUBLIC "src/libjson/include")
target_link_libraries(sgxlkl_json_host PRIVATE sgx-lkl::host)
add_library(sgx-lkl::json-host ALIAS sgxlkl_json_host)

find_package(Threads REQUIRED)

add_executable(${HOST_TOOL_NAME}
	${MAIN_C_SRCS}
	${HOSTINTERFACE_C_SRCS}
	${SHARED_C_SRCS}
	${GENERATED_HOST_EDGE_FILES}
	)
target_include_directories(${HOST_TOOL_NAME} PRIVATE
	"src/include"
	"${CMAKE_BINARY_DIR}/lkl-headers/include"
	)
target_link_libraries(${HOST_TOOL_NAME} PRIVATE
	Threads::Threads
	rt
	sgx-lkl::host
	sgx-lkl::edl-host
	sgx-lkl::json-host
	sgx-lkl::host-config
	sgx-lkl::enclave-config-host
	sgx-lkl::build-metadata
	)
target_link_options(${HOST_TOOL_NAME} PRIVATE "LINKER:--gc-sections")
# If we are configuring for the first build, add a fake dependency of this tool
# on the LKL build.  For subsequent builds this will be picked up by the real
# LKL header dependencies.
if(NOT LKL_HEADERS)
	add_dependencies(${HOST_TOOL_NAME} build-lkl)
endif()

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

# sgx-lkl-musl is used as libc in userspace.
set(MUSL_LIBNAMES
	libc.a
	libcrypt.a
	libdl.a
	libm.a
	libpthread.a
	libresolv.a
	librt.a
	libutil.a
	libxnet.a
)
list(TRANSFORM MUSL_LIBNAMES PREPEND "<INSTALL_DIR>/lib/" OUTPUT_VARIABLE MUSL_BYPRODUCTS)
set(LINUX_HEADERS_INC "/usr/include")
ExternalProject_Add(sgx-lkl-musl-ep
	# For now, this builds host-musl, while the relayering is in progress.
	# Current sgx-lkl-musl has dependencies to SGX-LKL headers, OE, etc.
	# TODO change to /sgx-lkl-musl
	SOURCE_DIR "${CMAKE_SOURCE_DIR}/host-musl" # /sgx-lkl-musl
	CONFIGURE_COMMAND "<SOURCE_DIR>/configure" 
		"CC=${CMAKE_C_COMPILER}"
		"CFLAGS=${LIBC_CFLAGS_EXTRA}"
		"--prefix=<INSTALL_DIR>"
		"--syslibdir=<INSTALL_DIR>/lib"
	BUILD_COMMAND make -j ${NUMBER_OF_CORES}
	INSTALL_COMMAND make install
	COMMAND ln -sf "${LINUX_HEADERS_INC}/linux" "<INSTALL_DIR>/include/linux"
	COMMAND ln -sf "${LINUX_HEADERS_INC}/x86_64-linux-gnu/asm" "<INSTALL_DIR>/include/asm"
	COMMAND ln -sf "${LINUX_HEADERS_INC}/asm-generic" "<INSTALL_DIR>/include/asm-generic"
	# TODO Fix musl-gcc for gcc versions that have been built with --enable-default-pie
	#gcc -v 2>&1 | grep "\-\-enable-default-pie" > /dev/null && sed -i 's/"$$@"/-fpie -pie "\$$@"/g' ${HOST_LIBC_BLD_DIR}/bin/musl-gcc || true
	BUILD_BYPRODUCTS "${MUSL_BYPRODUCTS}"
	BUILD_ALWAYS TRUE
)
set_target_properties(sgx-lkl-musl-ep PROPERTIES EXCLUDE_FROM_ALL TRUE)
ExternalProject_Get_property(sgx-lkl-musl-ep INSTALL_DIR)
list(TRANSFORM MUSL_LIBNAMES PREPEND "${INSTALL_DIR}/lib/" OUTPUT_VARIABLE MUSL_LIBRARIES)
set(MUSL_INCLUDE_DIRS "${INSTALL_DIR}/include")
if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
	set(MUSL_C_COMPILER "${INSTALL_DIR}/bin/musl-gcc")
elseif (CMAKE_C_COMPILER_ID STREQUAL "Clang")
	# The clang wrapper adds unneeded flags only needed for executables
	# and shared libraries. Any warnings related to that can be ignored.
	set(MUSL_C_COMPILER "${INSTALL_DIR}/bin/musl-clang")
elseif ()
	message(FATAL_ERROR "Unsupported compiler: ${CMAKE_C_COMPILER_ID}")
endif()
# The following will be refined depending on how we build enclave images.
add_library(sgx-lkl-musl INTERFACE)
target_link_libraries(sgx-lkl-musl INTERFACE "${MUSL_LIBRARIES}")
target_include_directories(sgx-lkl-musl INTERFACE "${MUSL_INCLUDE_DIRS}")
add_dependencies(sgx-lkl-musl sgx-lkl-musl-ep)

if (LIBC STREQUAL "musl")
	# Eventually init components will always use a statically linked musl,
	# while apps can use a dynamically linked musl/glibc.
	# For now, both the init components and apps are required to use the same libc.
	add_library(sgx-lkl::libc-init ALIAS sgx-lkl-musl)
	set(SGXLKL_LIBC_INIT_COMPILER "${MUSL_C_COMPILER}")
endif()

# libext2fs (part of e2fsprogs) is used in userspace to dynamically create disks with ext4 filesystems.
ExternalProject_Add(e2fsprogs-ep
	URL ${E2FSPROGS_URL}
	URL_HASH ${E2FSPROGS_HASH}
	CONFIGURE_COMMAND "<SOURCE_DIR>/configure" "CC=${CMAKE_C_COMPILER}"
	COMMAND make -C "<BINARY_DIR>/util" # build-time tools that must not be built against musl
	COMMAND "<SOURCE_DIR>/configure" "CC=${SGXLKL_LIBC_INIT_COMPILER}" "CFLAGS=-DOMIT_COM_ERR" "--prefix=<INSTALL_DIR>"
	BUILD_COMMAND make -j ${NUMBER_OF_CORES} libs
	INSTALL_COMMAND make -C "<BINARY_DIR>/lib/ext2fs" install
	COMMAND ${CMAKE_COMMAND} -E make_directory "<INSTALL_DIR>/include/et"
	COMMAND ${CMAKE_COMMAND} -E touch "<INSTALL_DIR>/include/et/com_err.h"
	BUILD_BYPRODUCTS "<INSTALL_DIR>/lib/libext2fs.a"
	DEPENDS sgx-lkl::libc-init
)
ExternalProject_Get_property(e2fsprogs-ep INSTALL_DIR)
add_library(ext2fs INTERFACE)
target_link_libraries(ext2fs INTERFACE "${INSTALL_DIR}/lib/libext2fs.a")
target_include_directories(ext2fs INTERFACE "${INSTALL_DIR}/include")
add_dependencies(ext2fs e2fsprogs-ep)
add_library(e2fsprogs::ext2fs ALIAS ext2fs)

# libcurl is used in userspace for fetching disk encryption keys.
ExternalProject_Add(curl-ep
	URL ${CURL_URL}
	URL_HASH ${CURL_HASH}
	CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env curl_disallow_alarm=yes "<SOURCE_DIR>/configure" 
		"CC=${SGXLKL_LIBC_INIT_COMPILER}"
		"CFLAGS=-DUSE_BLOCKING_SOCKETS"
		"--prefix=<INSTALL_DIR>"
		--disable-shared --with-pic
		# TODO make conditional
		--enable-debug
		# FIXME A userspace variant of mbedtls needs to be used here.
		--with-mbedtls=${OE_SDK_LIBS}/openenclave/enclave
		--without-zlib --without-ssl --without-ca-bundle --without-ca-path --without-libdl
		--without-libssh2 --without-libidn2
		--disable-unix-sockets --disable-threaded-resolver --disable-cookies --disable-rtsp
		--disable-dict --disable-file --disable-rt --disable-ftp --disable-gopher
		--disable-imap --disable-pop3 --disable-smtp --disable-telnet --disable-tftp
		--disable-smb --disable-smbs --disable-netrc
	BUILD_COMMAND make -j ${NUMBER_OF_CORES}
	INSTALL_COMMAND make install
	BUILD_BYPRODUCTS "<INSTALL_DIR>/lib/libcurl.a"
	DEPENDS sgx-lkl::libc-init
)
ExternalProject_Get_property(curl-ep INSTALL_DIR)
add_library(curl INTERFACE)
target_link_libraries(curl INTERFACE "${INSTALL_DIR}/lib/libcurl.a")
target_include_directories(curl INTERFACE "${INSTALL_DIR}/include")
add_dependencies(curl curl-ep)
add_library(curl::curl ALIAS curl)

# libdevmapper is used in userspace as dependency of libvicsetup.
ExternalProject_Add(devicemapper-ep
	URL ${DEVICEMAPPER_URL}
	URL_HASH ${DEVICEMAPPER_HASH}
	CONFIGURE_COMMAND "<SOURCE_DIR>/configure" 
		"CC=${SGXLKL_LIBC_INIT_COMPILER}"
		"CFLAGS=-Dptrdiff_t=intptr_t"
		"--enable-static_link"
		"--prefix=<INSTALL_DIR>"
	BUILD_COMMAND make -j ${NUMBER_OF_CORES}
	INSTALL_COMMAND make install
	BUILD_BYPRODUCTS "<INSTALL_DIR>/lib/libdevmapper.a"
	DEPENDS sgx-lkl::libc-init
)
ExternalProject_Get_property(devicemapper-ep INSTALL_DIR)
add_library(devicemapper INTERFACE)
target_link_libraries(devicemapper INTERFACE "${INSTALL_DIR}/lib/libdevmapper.a")
target_include_directories(devicemapper INTERFACE "${INSTALL_DIR}/include")
add_dependencies(devicemapper devicemapper-ep)
add_library(devicemapper::devicemapper ALIAS devicemapper)
