include_guard(GLOBAL)
include(cmake/Helpers.cmake)
include(cmake/components/common.cmake)
include(cmake/components/openenclave.cmake)
include(cmake/components/lkl.cmake)
include(cmake/components/edl.cmake)
include(cmake/components/config.cmake)

#file(GLOB SHARED_C_SRCS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/shared/*.c")
file(GLOB ENCLAVE_C_SRCS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/enclave/*.c")
#file(GLOB KERNEL_C_SRCS CONFIGURE_DEPENDS
#	"${CMAKE_SOURCE_DIR}/src/lkl/*.c"
#	"${CMAKE_SOURCE_DIR}/src/sched/*.c"
#	"${CMAKE_SOURCE_DIR}/src/wireguard/*.c")

add_library(sgxlkl-kernel-enclave-init STATIC
	# TODO add other sources
	${ENCLAVE_C_SRCS}
)
target_link_libraries(sgxlkl-kernel-enclave-init PRIVATE
	sgx-lkl::common-enclave
	sgx-lkl::lkl
	sgx-lkl::enclave-config-enclave
	# TODO remove this after relayering
	#sgx-lkl::libc-init
	)
add_library(sgx-lkl::kernel-enclave-init ALIAS sgxlkl-kernel-enclave-init)

add_library(sgxlkl-kernel-init-fini-stubs STATIC src/lkl/init_fini_stubs.s)
add_library(sgx-lkl::kernel-init-fini-stubs ALIAS sgxlkl-kernel-init-fini-stubs)

set(SGXLKL_KERNEL_OBJ "${CMAKE_BINARY_DIR}/libsgxlkl_kernel.o")
add_custom_command(
	OUTPUT "${SGXLKL_KERNEL_OBJ}"
	COMMENT "Building kernel space object"
	COMMAND "${CMAKE_COMMAND}" -E remove -f "${SGXLKL_KERNEL_OBJ}"
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

		--start-group
		$<TARGET_FILE:sgx-lkl::edl-enclave>
		$<TARGET_FILE:sgx-lkl::enclave-config-enclave>
		$<TARGET_FILE:sgx-lkl::kernel-enclave-init>
		$<TARGET_FILE:sgx-lkl::lkl>
		$<TARGET_FILE:sgx-lkl::kernel-init-fini-stubs>
		$<TARGET_FILE:openenclave::oeenclave>
		$<TARGET_FILE:openenclave::oecryptombed>
		$<TARGET_FILE:openenclave::mbedtls>
		$<TARGET_FILE:openenclave::mbedx509>
		$<TARGET_FILE:openenclave::mbedcrypto_static>
		$<TARGET_FILE:openenclave::oelibc>
		$<TARGET_FILE:openenclave::oesyscall>
		$<TARGET_FILE:openenclave::oecore>
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
		sgx-lkl::kernel-enclave-init
		sgx-lkl::lkl
		sgx-lkl::kernel-init-fini-stubs
		openenclave::oeenclave
	)

add_library(sgxlkl_kernel STATIC "${SGXLKL_KERNEL_OBJ}")
set_target_properties(sgxlkl_kernel PROPERTIES LINKER_LANGUAGE C)
add_library(sgx-lkl::kernel ALIAS sgxlkl_kernel)
