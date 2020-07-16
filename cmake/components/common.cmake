# Common compile flags for SGX-LKL code, represented as INTERFACE libraries.
# Note that LKL does not use the flags below. See lkl.cmake.

include_guard(GLOBAL)
include(cmake/components/openenclave.cmake)

set(COMMON_DEFINITIONS
    -DOE_API_VERSION=2
    -DOE_WITH_EXPERIMENTAL_EEID
)
if (CMAKE_BUILD_TYPE STREQUAL "Release")
    list(APPEND COMMON_DEFINITIONS
        -DSGXLKL_RELEASE
    )
endif()

# Host code.
add_library(sgxlkl_common_host INTERFACE)
target_compile_definitions(sgxlkl_common_host INTERFACE 
    ${COMMON_DEFINITIONS}
    )
target_include_directories(sgxlkl_common_host INTERFACE 
    "src/include"
    "${CMAKE_BINARY_DIR}/generated"
    )
# Note that openenclave::oehost also pulls in OE's public include folders,
# compile definitions, compile options, and linker options, apart from the
# oehost static library.
target_link_libraries(sgxlkl_common_host INTERFACE openenclave::oehost)
add_library(sgx-lkl::common-host ALIAS sgxlkl_common_host)


# Enclave code.
add_library(sgxlkl_common_enclave INTERFACE)
target_compile_definitions(sgxlkl_common_enclave INTERFACE
    # Definitions used in OE headers.
    ${COMMON_DEFINITIONS}
    -DOE_BUILD_ENCLAVE
    # Definitions used in SGX-LKL code.
    -DSGXLKL_ENCLAVE
    )
# Different from the host code above, we do not rely on pulling in
# compile flags automatically via OE targets.
# This is because we need more control over them and also forward them
# to external non-CMake project build systems.
# Note that linker flags for the enclave image are defined in enclave.cmake.
# See openenclave/enclave/core/CMakeLists.txt for further explanations.
set(COMMON_ENCLAVE_CFLAGS
    -fPIE
    -nostdinc
    -fstack-protector-strong
    -fno-omit-frame-pointer
    -ffunction-sections
    -fdata-sections
    -ftls-model=local-exec
)
target_compile_options(sgxlkl_common_enclave INTERFACE ${COMMON_ENCLAVE_CFLAGS})
target_include_directories(sgxlkl_common_enclave INTERFACE
    "src/include"
    "${CMAKE_BINARY_DIR}/generated"
    "$<TARGET_PROPERTY:openenclave::oe_includes,INTERFACE_INCLUDE_DIRECTORIES>"
    )
# TARGET_PROPERTY does not introduce a target dependency.
# We add a target dependency as OE generates some headers from EDL files.
# Adding a dependency is only needed when building OE as part of this build (default).
add_dependencies(sgxlkl_common_enclave openenclave::oe_includes)
add_library(sgx-lkl::common-enclave ALIAS sgxlkl_common_enclave)

# Not used here, but for convenience in other components.
# Keep this down here, as it needs COMMON_ENCLAVE_CFLAGS.
include(cmake/components/libc.cmake)