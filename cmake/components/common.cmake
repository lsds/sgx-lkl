# Common compile flags for SGX-LKL code, represented as INTERFACE libraries.
# Note that LKL does not use the flags below. See lkl.cmake.

include_guard(GLOBAL)
include(cmake/Helpers.cmake)
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
add_library(sgxlkl-common-host INTERFACE)
target_compile_definitions(sgxlkl-common-host INTERFACE 
    ${COMMON_DEFINITIONS}
    )
target_include_directories(sgxlkl-common-host INTERFACE 
    "src/include"
    "${CMAKE_BINARY_DIR}/generated"
    )
# Note that openenclave::oehost also pulls in OE's public include folders,
# compile definitions, compile options, and linker options, apart from the
# oehost static library.
target_link_libraries(sgxlkl-common-host INTERFACE openenclave::oehost)
add_library(sgx-lkl::common-host ALIAS sgxlkl-common-host)


# Enclave code.
add_library(sgxlkl-common-enclave INTERFACE)
target_compile_definitions(sgxlkl-common-enclave INTERFACE
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
target_compile_options(sgxlkl-common-enclave INTERFACE ${COMMON_ENCLAVE_CFLAGS})

# Since we use -nostdinc we need to re-add the compiler include folder to gain
# access to headers like stdatomic.h or intrinsics.
get_c_compiler_include_dir(C_COMPILER_INCLUDE_DIR)
message(STATUS "C compiler include dir: ${C_COMPILER_INCLUDE_DIR}")
# CMake filters out the compiler include folder if it finds -nostdinc.
# We need to trick it by making a copy of that folder. Note that a symlink wouldn't work.
# See https://gitlab.kitware.com/cmake/cmake/-/issues/19227.
set(C_COMPILER_INCLUDE_DIR_COPY "${CMAKE_BINARY_DIR}/c_compiler_include")
file(GLOB C_COMPILER_HEADERS CONFIGURE_DEPENDS "${C_COMPILER_INCLUDE_DIR}/*.h")
set(C_COMPILER_INC_STAMP "${CMAKE_BINARY_DIR}/c_compiler_dir.stamp")
add_custom_command(OUTPUT "${C_COMPILER_INC_STAMP}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${C_COMPILER_INCLUDE_DIR_COPY}"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${C_COMPILER_HEADERS} "${C_COMPILER_INCLUDE_DIR_COPY}"
    COMMAND ${CMAKE_COMMAND} -E touch "${C_COMPILER_INC_STAMP}"
    DEPENDS ${C_COMPILER_HEADERS}
)
add_custom_target(copy-c-compiler-include-dir DEPENDS "${C_COMPILER_INC_STAMP}")
add_dependencies(sgxlkl-common-enclave copy-c-compiler-include-dir)

target_include_directories(sgxlkl-common-enclave INTERFACE
    "src/include"
    "${CMAKE_BINARY_DIR}/generated"
)
target_include_directories(sgxlkl-common-enclave SYSTEM INTERFACE
    "$<TARGET_PROPERTY:openenclave::oe_includes,INTERFACE_INCLUDE_DIRECTORIES>"
    "${C_COMPILER_INCLUDE_DIR_COPY}"
    )
# TARGET_PROPERTY does not introduce a target dependency.
# We add a target dependency as OE generates some headers from EDL files.
# Adding a dependency is only needed when building OE as part of this build (default).
add_dependencies(sgxlkl-common-enclave openenclave::oe_includes)
add_library(sgx-lkl::common-enclave ALIAS sgxlkl-common-enclave)

# Not used here, but for convenience in other components.
# Keep this down here, as it needs COMMON_ENCLAVE_CFLAGS.
include(cmake/components/libc.cmake)