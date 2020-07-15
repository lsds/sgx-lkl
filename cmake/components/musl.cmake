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
	${COMMON_EP_OPTIONS}
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

# The following will be refined depending on how we build user space libraries.
add_library(sgx-lkl-musl INTERFACE)
target_link_libraries(sgx-lkl-musl INTERFACE "${MUSL_LIBRARIES}")
target_include_directories(sgx-lkl-musl INTERFACE "${MUSL_INCLUDE_DIRS}")
# Note that custom properties in INTERFACE libraries need to be prefixed with INTERFACE_.
set_target_properties(sgx-lkl-musl PROPERTIES INTERFACE_COMPILER_WRAPPER "${MUSL_C_COMPILER}")
add_dependencies(sgx-lkl-musl sgx-lkl-musl-ep)
add_library(sgx-lkl::musl ALIAS sgx-lkl-musl)

if (LIBC STREQUAL "musl")
	# Eventually init components will always use a statically linked musl,
	# while apps can use a dynamically linked musl/glibc.
	# For now, both the init components and apps are required to use the same libc.
	add_library(sgx-lkl::libc-init ALIAS sgx-lkl-musl)
endif()
