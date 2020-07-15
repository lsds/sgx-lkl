find_package(Python COMPONENTS Interpreter REQUIRED)

if (OE_PREFIX)
	set(openenclave_DIR "${OE_PREFIX}/lib/openenclave/cmake")
    find_package(openenclave REQUIRED CONFIG)
    set(oeedger8r_extra_search_path_args)
else()
	# OE should prefix public options.
	set(WITH_EEID ON CACHE BOOL "" FORCE)
	set(COMPILE_SYSTEM_EDL OFF CACHE BOOL "" FORCE)
	# See https://github.com/lsds/sgx-lkl/issues/617.
	set(USE_DEBUG_MALLOC OFF CACHE BOOL "" FORCE)
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
    
    # oeedger8r won't locate default includes when run from a build.
	set(oeedger8r_extra_search_path_args 
		--search-path "${OPENENCLAVE_DIR}/include"
		--search-path "${OPENENCLAVE_DIR}/include/openenclave/edl/sgx")
endif()

# Note that custom targets cannot be namespaced.
add_custom_target(sgxlkl_oeedger8r_props)
set_target_properties(sgxlkl_oeedger8r_props PROPERTIES 
    EXTRA_OEEDGER8R_FLAGS "${oeedger8r_extra_search_path_args}")
