cmake_minimum_required(VERSION 3.17)

# CXX is added here to avoid default compiler selection issues
# when including Open Enclave via add_subdirectory.
# SGX-LKL does not use C++ currently.
project(SGX-LKL C CXX)

# Conventions:
# - All filenames/paths, and variables containing them, must be quoted.

if (CMAKE_C_COMPILER_ID STREQUAL "Clang" AND DEFINED ENV{LD})
    add_link_options("-fuse-ld=$ENV{LD}")
endif()

if (NOT CMAKE_GENERATOR STREQUAL "Ninja")
	message(WARNING "Consider using Ninja for optimal build system performance: -G Ninja")
endif()

if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "No build type selected, default to Debug")
  set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type (default Debug)" FORCE)
endif()

get_filename_component(real_binary_dir "${CMAKE_BINARY_DIR}" REALPATH)
if (NOT CMAKE_BINARY_DIR STREQUAL real_binary_dir)
	message(FATAL_ERROR "${CMAKE_BINARY_DIR} must not be a symlink as LKL will not build otherwise")
endif()

include(ExternalProject)
set_directory_properties(PROPERTIES EP_BASE "external")

include(ProcessorCount)
ProcessorCount(NUMBER_OF_CORES)

include(cmake/Helpers.cmake)
include(cmake/RecursiveCopy.cmake)

set(OE_PREFIX "" CACHE PATH "Installation prefix of Open Enclave, otherwise built from source")
if (OE_PREFIX)
	set(openenclave_DIR "${OE_PREFIX}/lib/openenclave/cmake")
	find_package(openenclave REQUIRED)
else()
	# OE should prefix public options.
	set(WITH_EEID OFF CACHE BOOL "" FORCE) # TODO enable once compile errors fixed
	set(COMPILE_SYSTEM_EDL OFF CACHE BOOL "" FORCE)
	set(ENABLE_REFMAN OFF CACHE BOOL "" FORCE)
	set(BUILD_TESTS OFF CACHE BOOL "" FORCE)

	set(OPENENCLAVE_DIR "${CMAKE_SOURCE_DIR}/openenclave")
	add_subdirectory("${OPENENCLAVE_DIR}" EXCLUDE_FROM_ALL)
	
	# OE should provide aliased targets.
	add_library(openenclave::oecore ALIAS oecore)
	add_library(openenclave::oeenclave ALIAS oeenclave)
	add_library(openenclave::oehost ALIAS oehost)
	add_executable(openenclave::oeedger8r ALIAS edger8r)
	
	set(oeedger8r_search_path_args 
		--search-path "${OPENENCLAVE_DIR}/include"
		--search-path "${OPENENCLAVE_DIR}/include/openenclave/edl/sgx")
endif()

set(LKL_SUBDIRECTORY "lkl")
set(THIRD_PARTY_DOWNLOADS_DIRECTORY "${CMAKE_BINARY_DIR}/third_party")

execute_process(
	COMMAND git rev-parse --short HEAD
	OUTPUT_VARIABLE SGXLKL_GIT_COMMIT
	WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}")
string(STRIP "${SGXLKL_GIT_COMMIT}" SGXLKL_GIT_COMMIT)

file(READ "VERSION" SGXLKL_VERSION)
string(STRIP "${SGXLKL_VERSION}" SGXLKL_VERSION)

execute_process(
	COMMAND make --quiet -C "${CMAKE_SOURCE_DIR}/${LKL_SUBDIRECTORY}" kernelversion
	OUTPUT_VARIABLE LKL_VERSION)
string(STRIP "${LKL_VERSION}" LKL_VERSION)

message(STATUS "SGX-LKL git commit: ${SGXLKL_GIT_COMMIT}")
message(STATUS "SGX-LKL version: ${SGXLKL_VERSION}")
message(STATUS "LKL version: ${LKL_VERSION}")

set(LKL_DEBUG FALSE CACHE BOOL "Enable extra debugging for LKL")
set(LIBC musl CACHE STRING "Libc implementation to build.  Currently only musl is supported")
# Add "glibc" here once glibc is supported
set_property(CACHE LIBC PROPERTY STRINGS "musl")
set(SGXLKL_COPY_INDIVIDUAL_FILES FALSE CACHE BOOL
	"Copy source files one at a time. This makes the initial build slower, but incremental builds faster.")

if(LIBC STREQUAL "musl")
	set(LIBC_IS_MUSL TRUE)
else()
	message(FATAL_ERROR "${LIBC} is not a supported libc")
endif()

set(LIBC_CFLAGS_EXTRA "${LIBC_CFLAGS_EXTRA} -fPIC -D__USE_GNU")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(LKL_CFLAGS_EXTRA "${LKL_CFLAGS_EXTRA} -g3 -ggdb3 -O0 -DDEBUG")
	set(LIBC_CFLAGS_EXTRA "${LIBC_CFLAGS_EXTRA} -g3 -ggdb3 -O0 -DDEBUG")
endif()
if(${LKL_DEBUG})
	set(LKL_CFLAGS_EXTRA "${LKL_CFLAGS_EXTRA} -DLKL_DEBUG")
endif()

# Copy the LKL sources to the build directory.  This copies everything except
# the files that we will modify and creates rules so that any modification of
# the source files will trigger a re-copy and rebuild.
# Note: We probably could exclude a load of directories for architectures and
# drivers that we don't care about if we want to reduce the binary code size.
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
	URL https://download.wireguard.com/monolithic-historical/WireGuard-0.0.20191219.tar.xz
	URL_HASH SHA256=5aba6f0c38e97faa0b155623ba594bb0e4bd5e29deacd8d5ed8bda8d8283b0e7
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

set(LKL_LIB_PATH "lkl/tools/lkl/liblkl.a")
set(LKL_HEADER_PATH "${CMAKE_BINARY_DIR}/lkl-headers")
add_custom_command(OUTPUT "${LKL_LIB_PATH}"
	DEPENDS lkl-source-setup
	COMMAND "DESTDIR=${LKL_HEADER_PATH}" make -C "${CMAKE_BINARY_DIR}/${LKL_SUBDIRECTORY}/tools/lkl/" -j ${NUMBER_OF_CORES} V=1 "${CMAKE_BINARY_DIR}/${LKL_LIB_PATH}"
	COMMAND "DESTDIR=${LKL_HEADER_PATH}" make -C "${CMAKE_BINARY_DIR}/${LKL_SUBDIRECTORY}/tools/lkl/" -j ${NUMBER_OF_CORES} V=1 "PREFIX=\"\"" headers_install
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

add_custom_target(build-lkl DEPENDS "${LKL_LIB_PATH}")

add_custom_target(copy-lkl DEPENDS ${NEW_FILES})
add_custom_target(sgx-lkl ALL DEPENDS build-lkl)

add_definitions(
	-DSGXLKL_GIT_COMMIT="${SGXLKL_GIT_COMMIT}"
	-DSGXLKL_VERSION="${SGXLKL_VERSION}"
	-DLKL_VERSION="${LKL_VERSION}"
	)


set(HOST_TOOL_NAME sgx-lkl-run)

file(GLOB MAIN_C_SRCS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/main-oe/*.c")
file(GLOB HOSTINTERFACE_C_SRCS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/host_interface/*.c")
file(GLOB SHARED_C_SRCS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/shared/*.c")
file(GLOB ENCLAVE_C_SRCS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/enclave/*.c")
file(GLOB KERNEL_C_SRCS CONFIGURE_DEPENDS
	"${CMAKE_SOURCE_DIR}/src/lkl/*.c"
	"${CMAKE_SOURCE_DIR}/src/sched/*.c"
	"${CMAKE_SOURCE_DIR}/src/wireguard/*.c")

set(GENERATED_HOST_EDGE_FILES 
	"geninclude/host/sgxlkl_args.h"
	"geninclude/host/sgxlkl_u.c"
	"geninclude/host/sgxlkl_u.h"
	)
set(GENERATED_ENCLAVE_EDGE_FILES 
	"geninclude/enclave/sgxlkl_args.h"
	"geninclude/enclave/sgxlkl_t.c"
	"geninclude/enclave/sgxlkl_t.h"
	)

add_custom_command(OUTPUT ${GENERATED_HOST_EDGE_FILES}
	COMMAND openenclave::oeedger8r
		${oeedger8r_search_path_args}
		--untrusted "${CMAKE_SOURCE_DIR}/src/sgxlkl.edl"
		--untrusted-dir "${CMAKE_BINARY_DIR}/geninclude/host"
	DEPENDS "${CMAKE_SOURCE_DIR}/src/sgxlkl.edl"
	)
add_custom_command(OUTPUT ${GENERATED_ENCLAVE_EDGE_FILES}
	COMMAND openenclave::oeedger8r
		${oeedger8r_search_path_args}
		--trusted "${CMAKE_SOURCE_DIR}/src/sgxlkl.edl"
		--trusted-dir "${CMAKE_BINARY_DIR}/geninclude/enclave"
	DEPENDS "${CMAKE_SOURCE_DIR}/src/sgxlkl.edl"
	)

ExternalProject_Add(json-c-ep
	URL https://github.com/json-c/json-c/archive/json-c-0.13.1-20180305.tar.gz
	URL_HASH SHA256=5d867baeb7f540abe8f3265ac18ed7a24f91fe3c5f4fd99ac3caba0708511b90
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

add_executable(${HOST_TOOL_NAME}
	${MAIN_C_SRCS}
	${HOSTINTERFACE_C_SRCS}
	${SHARED_C_SRCS}
	${GENERATED_HOST_EDGE_FILES}
	)
target_include_directories(${HOST_TOOL_NAME} PRIVATE
	"src/include"
	"${CMAKE_BINARY_DIR}/geninclude"
	"${CMAKE_BINARY_DIR}/lkl-headers/include"
	)
target_link_libraries(${HOST_TOOL_NAME} pthread json-c::json-c openenclave::oehost rt)
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
add_library(sgx-lkl::musl ALIAS sgx-lkl-musl)

# libext2fs (part of e2fsprogs) is used in userspace to dynamically create disks with ext4 filesystems.
ExternalProject_Add(e2fsprogs-ep
	URL https://git.kernel.org/pub/scm/fs/ext2/e2fsprogs.git/snapshot/e2fsprogs-1.45.5.tar.gz
	URL_HASH SHA256=0fd76e55c1196c1d97a2c01f2e84f463b8e99484541b43ff4197f5a695159fd3
	CONFIGURE_COMMAND "<SOURCE_DIR>/configure" "CC=${CMAKE_C_COMPILER}"
	COMMAND make -C "<BINARY_DIR>/util" # build-time tools that must not be built against musl
	COMMAND "<SOURCE_DIR>/configure" "CC=${MUSL_C_COMPILER}" "CFLAGS=-DOMIT_COM_ERR" "--prefix=<INSTALL_DIR>"
	BUILD_COMMAND make -j ${NUMBER_OF_CORES} libs
	INSTALL_COMMAND make -C "<BINARY_DIR>/lib/ext2fs" install
	COMMAND ${CMAKE_COMMAND} -E make_directory "<INSTALL_DIR>/include/et"
	COMMAND ${CMAKE_COMMAND} -E touch "<INSTALL_DIR>/include/et/com_err.h"
	BUILD_BYPRODUCTS "<INSTALL_DIR>/lib/libext2fs.a"
	DEPENDS sgx-lkl::musl
)
ExternalProject_Get_property(e2fsprogs-ep INSTALL_DIR)
add_library(ext2fs INTERFACE)
target_link_libraries(ext2fs INTERFACE "${INSTALL_DIR}/lib/libext2fs.a")
target_include_directories(ext2fs INTERFACE "${INSTALL_DIR}/include")
add_dependencies(ext2fs e2fsprogs-ep)
add_library(e2fsprogs::ext2fs ALIAS ext2fs)

# libcurl is used in userspace for fetching disk encryption keys.
ExternalProject_Add(curl-ep
	URL https://curl.haxx.se/download/curl-7.66.0.tar.bz2
	URL_HASH SHA256=6618234e0235c420a21f4cb4c2dd0badde76e6139668739085a70c4e2fe7a141
	CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env curl_disallow_alarm=yes "<SOURCE_DIR>/configure" 
		"CC=${MUSL_C_COMPILER}"
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
	DEPENDS sgx-lkl::musl
)
ExternalProject_Get_property(curl-ep INSTALL_DIR)
add_library(curl INTERFACE)
target_link_libraries(curl INTERFACE "${INSTALL_DIR}/lib/libcurl.a")
target_include_directories(curl INTERFACE "${INSTALL_DIR}/include")
add_dependencies(curl curl-ep)
add_library(curl::curl ALIAS curl)

# libdevicemapper is used in userspace as dependency of libvicsetup.
ExternalProject_Add(devicemapper-ep
	URL https://github.com/lvmteam/lvm2/archive/v2_02_98.tar.gz
	URL_HASH SHA256=56db106cba31e3a143f758ae1b569f2df91fd3403ae7076374700ebadcfa6583
	CONFIGURE_COMMAND "<SOURCE_DIR>/configure" 
		"CC=${MUSL_C_COMPILER}"
		"CFLAGS=-Dptrdiff_t=intptr_t"
		"--enable-static_link"
		"--prefix=<INSTALL_DIR>"
	BUILD_COMMAND make -j ${NUMBER_OF_CORES}
	INSTALL_COMMAND make install
	BUILD_BYPRODUCTS "<INSTALL_DIR>/lib/libdevicemapper.a"
	DEPENDS sgx-lkl::musl
)
ExternalProject_Get_property(devicemapper-ep INSTALL_DIR)
add_library(devicemapper INTERFACE)
target_link_libraries(devicemapper INTERFACE "${INSTALL_DIR}/lib/libdevicemapper.a")
target_include_directories(devicemapper INTERFACE "${INSTALL_DIR}/include")
add_dependencies(devicemapper devicemapper-ep)
add_library(devicemapper::devicemapper ALIAS devicemapper)
