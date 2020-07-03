cmake_minimum_required(VERSION 3.17)
project(SGX-LKL)

include(ProcessorCount)
ProcessorCount(NUMBER_OF_CORES)

set(OE_PREFIX "" CACHE PATH "Installation prefix of Open Enclave, otherwise built from source")
if (OE_PREFIX)
	set(openenclave_DIR ${OE_PREFIX}/lib/openenclave/cmake)
	find_package(openenclave REQUIRED)
else()
	# OE should prefix public options.
	set(WITH_EEID OFF CACHE BOOL "" FORCE) # TODO enable once compile errors fixed
	set(COMPILE_SYSTEM_EDL OFF CACHE BOOL "" FORCE)
	set(ENABLE_REFMAN OFF CACHE BOOL "" FORCE)
	set(BUILD_TESTS OFF CACHE BOOL "" FORCE)

	set(OPENENCLAVE_DIR ${CMAKE_SOURCE_DIR}/openenclave)
	add_subdirectory(${OPENENCLAVE_DIR} EXCLUDE_FROM_ALL)
	
	# OE should provide aliased targets.
	add_library(openenclave::oecore ALIAS oecore)
	add_library(openenclave::oeenclave ALIAS oeenclave)
	add_library(openenclave::oehost ALIAS oehost)
	add_executable(openenclave::oeedger8r ALIAS edger8r)
	
	set(oeedger8r_search_path_args 
		--search-path ${OPENENCLAVE_DIR}/include
		--search-path ${OPENENCLAVE_DIR}/include/openenclave/edl/sgx)
endif()

get_cmake_property(_variableNames VARIABLES)
#foreach (_variableName ${_variableNames})
#message(STATUS "${_variableName}=${${_variableName}}")
#endforeach()
# OE_BASH=/bin/bash
# OE_BINDIR=/opt/openenclave/bin
# OE_BRANCH=refs/heads/feature.sgx-lkl
# OE_BUILD_NUMBER=0
# OE_COMMIT=2765e96a0a7159b2721653f2bbe997a01b4101d3
# OE_DATADIR=/opt/openenclave/share
# OE_INCLUDEDIR=/opt/openenclave/include
# OE_LIBDIR=/opt/openenclave/lib
# OE_SCRIPTSDIR=/opt/opene
# OpenEnclave_VERSION_MAJOR=0
# OpenEnclave_VERSION_MINOR=7
# OpenEnclave_VERSION_PATCH=0
# OpenEnclave_VERSION_TWEAK=0
# PACKAGE_PREFIX_DIR=/opt/openenclave

function(mkdir DIRECTORY)
	execute_process(COMMAND ${CMAKE_COMMAND} "-E" "make_directory" ${DIRECTORY})
endfunction()

set(LKL_SUBDIRECTORY "lkl")
set(THIRD_PARTY_DOWNLOADS_DIRECTORY "${CMAKE_BINARY_DIR}/third_party")

execute_process(COMMAND "git" "rev-parse" "--short" "HEAD"
	OUTPUT_VARIABLE SGXLKL_GIT_COMMIT
	WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}")
string(STRIP "${SGXLKL_GIT_COMMIT}" SGXLKL_GIT_COMMIT)
file(READ "VERSION" SGXLKL_VERSION)
string(STRIP "${SGXLKL_VERSION}" SGXLKL_VERSION)
execute_process(COMMAND "make" "--quiet" "-C" "${CMAKE_SOURCE_DIR}/${LKL_SUBDIRECTORY}" "kernelversion" OUTPUT_VARIABLE LKL_VERSION)
string(STRIP "${LKL_VERSION}" LKL_VERSION)

message(STATUS "SGX-LKL git commit: ${SGXLKL_GIT_COMMIT}")
message(STATUS "SGX-LKL version: ${SGXLKL_VERSION}")
message(STATUS "LKL version: ${LKL_VERSION}")

set(LKL_DEBUG FALSE CACHE BOOL "Enable extra debugging for LKL")
set(LIBC musl CACHE STRING "Libc implementation to build.  Currently only musl is supported")
# Add "glibc" here once glibc is supported
set_property(CACHE LIBC PROPERTY STRINGS "musl")
set(SGXLKL_COPY_INDIVIDUAL_FILES FALSE CACHE BOOL
	"Copy source files one at a time.  This makes the initial build slower, but incremental builds faster.")

if(LIBC STREQUAL "musl")
	set(LIBC_IS_MUSL TRUE)
else()
	message(FATAL_ERROR "${LIBC} is not a supported libc")
endif()


if(NOT CMAKE_BUILD_TYPE STREQUAL "Release")
endif()
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(LKL_CFLAGS_EXTRA "${LKL_CFLAGS_EXTRA} -g3 -ggdb3 -O0 -DDEBUG")
endif()
if(${LKL_DEBUG})
	set(LKL_CFLAGS_EXTRA "${LKL_CFLAGS_EXTRA} -DLKL_DEBUG")
endif()

function(touch FILE_NAME)
	execute_process(COMMAND ${CMAKE_COMMAND} "-E" "touch" "${FILE_NAME}")
endfunction()

include(cmake/RecursiveCopy.cmake)
include(cmake/DownloadAndExtract.cmake)


# Generate rules to download and extract the tarballs that we need.
# These are all downloaded into a downloads directory in the build directory
# and extracted into a third_party directory in the build directory.
download_and_extract_tarball("cryptsetup" "https://gitlab.com/cryptsetup/cryptsetup/repository/archive.tar.gz?ref=v2.0.2")
download_and_extract_tarball("devicemapper" "https://github.com/lvmteam/lvm2/archive/v2_02_98.tar.gz")
download_and_extract_tarball("e2fsprogs" "https://git.kernel.org/pub/scm/fs/ext2/e2fsprogs.git/snapshot/e2fsprogs-1.45.5.tar.gz")
download_and_extract_tarball("util-linux" "https://git.kernel.org/pub/scm/utils/util-linux/util-linux.git/snapshot/util-linux-2.29.2.tar.gz")
download_and_extract_tarball("popt" "https://deb.debian.org/debian/pool/main/p/popt/popt_1.16.orig.tar.gz")
download_and_extract_tarball("json-c" "https://github.com/json-c/json-c/archive/json-c-0.13.1-20180305.tar.gz")
download_and_extract_tarball("wireguard" "https://download.wireguard.com/monolithic-historical/WireGuard-0.0.20191219.tar.xz")
download_and_extract_tarball("curl" "https://curl.haxx.se/download/curl-7.66.0.tar.bz2")

# Copy the LKL sources to the build directory.  This copies everything except
# the files that we will modify and creates rules so that any modification of
# the source files will trigger a re-copy and rebuild.
# Note: We probably could exclude a load of directories for architectures and
# drivers that we don't care about if we want to reduce the binary code size.
# Note 2: It might be better to simply symlink the files that we're not
# modifying into the build directory at configure time (though driving this
# from CMake will be a lot slower than from Ninja and avoiding re-doing the
# copy on subsequent builds is harder).
copy_source_directory_to_output("${LKL_SUBDIRECTORY}" "${LKL_SUBDIRECTORY}/arch/lkl/configs/defconfig;${LKL_SUBDIRECTORY}/net/Makefile;${LKL_SUBDIRECTORY}/net/Kconfig")

# Replace the default kernel configuration file with our own.
set(DEFCONFIG_OVERRIDE_PATH "${LKL_SUBDIRECTORY}/arch/lkl/configs/defconfig")
add_custom_command(OUTPUT ${DEFCONFIG_OVERRIDE_PATH}
	COMMAND ${CMAKE_COMMAND} ARGS "-E" "copy_if_different" "${CMAKE_SOURCE_DIR}/src/lkl/override/defconfig" ${DEFCONFIG_OVERRIDE_PATH}
	MAIN_DEPENDENCY "${LKL_SUBDIRECTORY}/arch/lkl/configs/defconfig"
	COMMENT "Overriding LKL default configuration")

# Apply the wireguard patch into our copy of the kernel tree.  
# Note, this can go away once our upstream LKL has the wireguard patches
# already applied
add_custom_command(
	OUTPUT "lkl/net/wireguard" "lkl/net/Kconfig" "lkl/net/Makefile" "wireguard-patches-applied.stamp"
	DEPENDS "${LKL_SUBDIRECTORY}/net/Makefile" "${LKL_SUBDIRECTORY}/net/Kconfig" fetch-and-extract-wireguard
	COMMAND ${CMAKE_COMMAND} "-E" "copy" "${CMAKE_SOURCE_DIR}/${LKL_SUBDIRECTORY}/net/Makefile" "${CMAKE_SOURCE_DIR}/${LKL_SUBDIRECTORY}/net/Kconfig" "${CMAKE_BINARY_DIR}/lkl/net"
	COMMAND ${CMAKE_COMMAND} "-E" "remove_directory" "${CMAKE_BINARY_DIR}/lkl/net/wireguard"
	COMMAND "${wireguard_LOCATION}/contrib/kernel-tree/create-patch.sh" "|" "patch" "--forward" "-p1"
	COMMAND ${CMAKE_COMMAND} "-E" "touch" "${CMAKE_BINARY_DIR}/wireguard-patches-applied.stamp"
	WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/lkl" 
	)

add_custom_target(apply-wireguard-patches DEPENDS "wireguard-patches-applied.stamp")
add_custom_target(lkl-source-setup
	DEPENDS copy-lkl ${DEFCONFIG_OVERRIDE_PATH} apply-wireguard-patches
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
add_custom_command(OUTPUT ${LKL_LIB_PATH}
	DEPENDS lkl-source-setup
	COMMAND "DESTDIR=${LKL_HEADER_PATH}" "make" "-C" "${CMAKE_BINARY_DIR}/${LKL_SUBDIRECTORY}/tools/lkl/" "-j" "${NUMBER_OF_CORES}" "V=1" "${CMAKE_BINARY_DIR}/${LKL_LIB_PATH}"
	COMMAND "DESTDIR=${LKL_HEADER_PATH}" "make" "-C" "${CMAKE_BINARY_DIR}/${LKL_SUBDIRECTORY}/tools/lkl/" "-j" "${NUMBER_OF_CORES}" "V=1" "PREFIX=\"\"" headers_install
	COMMAND "make" "-C" "${CMAKE_BINARY_DIR}/${LKL_SUBDIRECTORY}" "ARCH=lkl" "INSTALL_HDR_PATH=${LKL_HEADER_PATH}" "-j" "${NUMBER_OF_CORES}" "V=1" "PREFIX=\"\"" headers_install
	COMMAND "echo" ARGS "'set(LKL_HEADERS'" ">" "${LKL_HEADERS_FILE}.tmp"
	COMMAND "find" ARGS "${LKL_HEADER_PATH}" ">>" "${LKL_HEADERS_FILE}.tmp"
	COMMAND "echo" ARGS "')'" ">>" "${LKL_HEADERS_FILE}.tmp"
	COMMAND ${CMAKE_COMMAND} ARGS "-E" "copy_if_different" "${LKL_HEADERS_FILE}.tmp" "${LKL_HEADERS_FILE}"
	COMMAND ${CMAKE_COMMAND} ARGS "-E" "remove" "${LKL_HEADERS_FILE}.tmp" 
	WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/lkl"
	BYPRODUCTS ${LKL_HEADERS} "${LKL_HEADERS_FILE}" 
	COMMENT "Compiling LKL"
)

add_custom_target(build-lkl DEPENDS "${LKL_LIB_PATH}")

add_custom_target(copy-lkl DEPENDS ${NEW_FILES})
add_custom_target(sgx-lkl ALL DEPENDS build-lkl)

add_definitions(
	"-DSGXLKL_GIT_COMMIT=\"${SGXLKL_GIT_COMMIT}\""
	"-DSGXLKL_VERSION=\"${SGXLKL_VERSION}\""
	"-DLKL_VERSION=\"${LKL_VERSION}\""
	)


set(HOST_TOOL_NAME "sgx-lkl-run")

file(GLOB MAIN_C_SRCS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/main-oe/*.c")
file(GLOB HOSTINTERFACE_C_SRCS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/host_interface/*.c")
file(GLOB SHARED_C_SRCS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/shared/*.c")
file(GLOB ENCLAVE_C_SRCS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/shared/*.c")
file(GLOB KERNEL_C_SRCS CONFIGURE_DEPENDS
	"${CMAKE_SOURCE_DIR}/src/lkl/*.c"
	"${CMAKE_SOURCE_DIR}/src/sched/*.c"
	"${CMAKE_SOURCE_DIR}/src/wireguard/*.c")

set(GENERATED_EDGE_FILES 
	"geninclude/enclave/sgxlkl_args.h"
	"geninclude/enclave/sgxlkl_t.c"
	"geninclude/enclave/sgxlkl_t.h"
	"geninclude/host/sgxlkl_args.h"
	"geninclude/host/sgxlkl_u.c"
	"geninclude/host/sgxlkl_u.h"
	)


add_custom_command(OUTPUT "oeedger8r-run.stamp"
	DEPENDS "${CMAKE_SOURCE_DIR}/src/sgxlkl.edl"
	COMMAND openenclave::oeedger8r ${oeedger8r_search_path_args} "--trusted" "${CMAKE_SOURCE_DIR}/src/sgxlkl.edl" "--trusted-dir" "${CMAKE_BINARY_DIR}/geninclude/enclave" "--untrusted" "${CMAKE_SOURCE_DIR}/src/sgxlkl.edl" "--untrusted-dir" "${CMAKE_BINARY_DIR}/geninclude/host"
	COMMAND ${CMAKE_COMMAND} "-E" "touch" "${CMAKE_BINARY_DIR}/oeedger8r-run.stamp"
	DEPENDS "${CMAKE_SOURCE_DIR}/src/sgxlkl.edl"
	BYPRODUCTS ${GENERATED_EDGE_FILES} 
	)

add_custom_target(build-interface-definitions
	DEPENDS "oeedger8r-run.stamp"
	)

set(HOST_LIBS_BUILD_DIRECTORY "${CMAKE_BINARY_DIR}/host-libs-build")
set(HOST_LIBS_INSTALL_DIRECTORY "${CMAKE_BINARY_DIR}/host-libs/")
mkdir("${HOST_LIBS_BUILD_DIRECTORY}")
mkdir("${HOST_LIBS_INSTALL_DIRECTORY}")

set(JSON_C_INSTALL_FILES
	include/json-c
	lib/libjson-c.a
	lib/libjson-c.la
	lib/libjson-c.so
	lib/libjson-c.so.4
	lib/libjson-c.so.4.0.0
	lib/pkgconfig
	include/json-c/arraylist.h
	include/json-c/bits.h
	include/json-c/debug.h
	include/json-c/json.h
	include/json-c/json_c_version.h
	include/json-c/json_config.h
	include/json-c/json_inttypes.h
	include/json-c/json_object.h
	include/json-c/json_object_iterator.h
	include/json-c/json_pointer.h
	include/json-c/json_tokener.h
	include/json-c/json_util.h
	include/json-c/json_visit.h
	include/json-c/linkhash.h
	include/json-c/printbuf.h
	lib/pkgconfig/json-c.pc)

list(TRANSFORM JSON_C_INSTALL_FILES PREPEND "${HOST_LIBS_INSTALL_DIRECTORY}/" OUTPUT_VARIABLE HOST_JSON_C_INSTALL_FILES)

set(HOST_JSON_C_BUILD_DIRECTORY "${HOST_LIBS_BUILD_DIRECTORY}/json-c")
mkdir("${HOST_JSON_C_BUILD_DIRECTORY}")
add_custom_command(OUTPUT "${HOST_JSON_C_BUILD_DIRECTORY}/Makefile"
	DEPENDS fetch-and-extract-json-c
	COMMAND "${THIRD_PARTY_DOWNLOADS_DIRECTORY}/json-c/configure" "--enable-static" "--prefix=${HOST_LIBS_INSTALL_DIRECTORY}"
	WORKING_DIRECTORY "${HOST_JSON_C_BUILD_DIRECTORY}"
	)
add_custom_target(build-host-json-c
	DEPENDS "${HOST_JSON_C_BUILD_DIRECTORY}/Makefile" fetch-and-extract-json-c
	COMMAND "make" "-j${NUMBER_OF_CORES}" install
	WORKING_DIRECTORY "${HOST_JSON_C_BUILD_DIRECTORY}"
	BYPRODUCTS ${JSON_C_INSTALL_FILES}
	)

add_executable("${HOST_TOOL_NAME}" ${MAIN_C_SRCS} ${HOSTINTERFACE_C_SRCS} ${SHARED_C_SRCS} "geninclude/host/sgxlkl_u.c")
target_include_directories("${HOST_TOOL_NAME}" PRIVATE
	"src/include"
	"${CMAKE_BINARY_DIR}/geninclude"
	"${CMAKE_BINARY_DIR}/lkl-headers/include"
	"${HOST_LIBS_INSTALL_DIRECTORY}/include"
	"${OE_INCLUDEDIR}")
target_link_directories("${HOST_TOOL_NAME}" PRIVATE
	"${HOST_LIBS_INSTALL_DIRECTORY}/lib"
	"${OE_LIBDIR}/openenclave/host"
	)

target_link_libraries("${HOST_TOOL_NAME}" "pthread" "json-c" "oehost" openenclave::oehost "rt")
target_link_options("${HOST_TOOL_NAME}" PRIVATE "LINKER:--gc-sections")
add_dependencies("${HOST_TOOL_NAME}" build-interface-definitions)
# If we are configuring for the first build, add a fake dependency of this tool
# on the LKL build.  For subsequent builds this will be picked up by the real
# LKL header dependencies.
if(NOT LKL_HEADERS)
	add_dependencies("${HOST_TOOL_NAME}" build-lkl build-host-json-c)
endif()


