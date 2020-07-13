
# NOTE:
# THIS FILE IS *NOT USED* CURRENTLY, SEE NOTES IN CMakeLists.txt.

# This file creates oeenclave.o, which contains all objects from the
# entire OE enclave-side stack. It only exports select symbols. It omits
# symbols from oelibc and mbedtls.

# The following symbols are also defined in oeenclave.
# To avoid multiple global definitions we need to hide them.
# All other global symbols stay global.
set(LOCAL_OECORE
    rand
    srand
    memcpy
    __memcpy_fwd
    memset
    memcmp
    memmove
    oe_free_sgx_endorsements
    oe_get_sgx_endorsements
    oe_parse_sgx_endorsements
    #__stack_chk_fail
)
list(TRANSFORM LOCAL_OECORE PREPEND "--localize-symbol=" OUTPUT_VARIABLE LOCAL_OECORE)

set(OECORE_OBJ "oecore.o")
add_custom_command(
	OUTPUT "${OECORE_OBJ}"
	COMMENT "Building oecore object"
    COMMAND "${LINKER}" -r -o "${OECORE_OBJ}" 
        --whole-archive
        $<TARGET_FILE:openenclave::oecore>
	COMMAND echo "Hiding symbols"
    COMMAND "${CMAKE_OBJCOPY}" ${LOCAL_OECORE} "${OECORE_OBJ}"
	DEPENDS
		openenclave::oecore
    )

add_library(sgxlkl_oe_syscall_ocall_stubs STATIC src/lkl/oe_syscall_ocall_stubs.c)

set(OEENCLAVE_OBJ "oeenclave.o")
add_custom_command(
	OUTPUT "${OEENCLAVE_OBJ}"
	COMMENT "Building oeenclave object"
    COMMAND "${LINKER}" -r -o "${OEENCLAVE_OBJ}"
        --whole-archive
		$<TARGET_FILE:openenclave::oeenclave>
		$<TARGET_FILE:openenclave::oecryptombed>
		$<TARGET_FILE:openenclave::mbedtls>
		$<TARGET_FILE:openenclave::mbedx509>
		$<TARGET_FILE:openenclave::mbedcrypto_static>
		$<TARGET_FILE:openenclave::oelibc>
        $<TARGET_FILE:openenclave::oesyscall>
        $<TARGET_FILE:sgxlkl_oe_syscall_ocall_stubs>
        "${OECORE_OBJ}"
    # At this stage, various symbols are still (correctly) undefined:
    # - Platform OCALLs (oe_*_ocall)
    # - ECALL table (__oe_ecalls_table[_size])
    # - Initializers/finalizers (__(init|fini)_array_(start|end))
    # - Other symbols that would be removed via --gc-sections in later links:
    #  - pthread_setcancelstate, _pthread_cleanup_pop, _pthread_cleanup_push
    #  - lstat
    #  - __h_errno_location
    #  - __res_send 
	#COMMAND echo "Checking for unresolved symbols"
	#COMMAND ! "${CMAKE_NM}" -g "${OEENCLAVE_OBJ}" | grep ' U '
	COMMAND echo "Hiding symbols"
    COMMAND "${CMAKE_OBJCOPY}" -w 
        --keep-global-symbol='*oe_*'
        --keep-global-symbol='__stack_chk_fail'
        "${OEENCLAVE_OBJ}"
    DEPENDS
        openenclave::oeenclave
        openenclave::oecryptombed
        openenclave::mbedtls
        openenclave::mbedx509
        openenclave::mbedcrypto_static
        openenclave::oelibc
        openenclave::oesyscall
        sgxlkl_oe_syscall_ocall_stubs
        "${OECORE_OBJ}"
    )

add_library(sgxlkl_oeenclave STATIC "${OEENCLAVE_OBJ}")
set_target_properties(sgxlkl_oeenclave PROPERTIES LINKER_LANGUAGE C)
target_include_directories(sgxlkl_oeenclave INTERFACE
    $<TARGET_PROPERTY:openenclave::oe_includes,INTERFACE_INCLUDE_DIRECTORIES>
)
target_compile_definitions(sgxlkl_oeenclave INTERFACE
    $<TARGET_PROPERTY:openenclave::oecore,INTERFACE_COMPILE_DEFINITIONS>
)
target_compile_options(sgxlkl_oeenclave INTERFACE
    $<TARGET_PROPERTY:openenclave::oecore,INTERFACE_COMPILE_OPTIONS>
    # TODO Should we inherit from OE or manually define them here?
    #-m64
    #-fPIE
    #-nostdinc
    #-fstack-protector-strong
    #-fvisibility=hidden
    #-fno-omit-frame-pointer
    #-ffunction-sections
    #-fdata-sections
    #-ftls-model=local-exec
)
target_link_options(sgxlkl_oeenclave INTERFACE
    # TODO Should we inherit from OE or manually define them here?
    LINKER:-nostdlib
    LINKER:-nodefaultlibs
    LINKER:-nostartfiles
    LINKER:--no-undefined
    LINKER:-Bstatic
    LINKER:-Bsymbolic
    LINKER:--export-dynamic
    LINKER:-pie
    LINKER:--build-id
    LINKER:-z,noexecstack
    LINKER:-z,now
    LINKER:-gc-sections
)
add_library(sgx-lkl::oeenclave ALIAS sgxlkl_oeenclave)
