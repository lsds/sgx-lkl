include_guard(GLOBAL)

if (OE_PREFIX)
	set(openenclave_DIR "${OE_PREFIX}/lib/openenclave/cmake")
    find_package(openenclave REQUIRED CONFIG)
    set(OEEDGER8R_EXTRA_FLAGS)
else()
	# OE should prefix public options.
	set(WITH_EEID ON CACHE BOOL "" FORCE)
	set(COMPILE_SYSTEM_EDL OFF CACHE BOOL "" FORCE)
	# See https://github.com/lsds/sgx-lkl/issues/617.
	set(USE_DEBUG_MALLOC OFF CACHE BOOL "" FORCE)
	set(ENABLE_REFMAN OFF CACHE BOOL "" FORCE)
	set(BUILD_TESTS OFF CACHE BOOL "" FORCE)

	set(OPENENCLAVE_DIR "${PROJECT_SOURCE_DIR}/openenclave")
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
	add_executable(openenclave::oesign ALIAS oesign)
	add_executable(openenclave::oeedger8r ALIAS edger8r)

	# Enable build of liboe_ptrace.so so that we can install it.
	add_custom_target(build-oe-ptrace ALL DEPENDS oe_ptrace)
    
    # oeedger8r won't locate default includes when run from a build.
	set(OEEDGER8R_EXTRA_FLAGS
		--search-path "${OPENENCLAVE_DIR}/include"
		--search-path "${OPENENCLAVE_DIR}/include/openenclave/edl/sgx")
endif()
