# Common properties for code that is part of the enclave image.
add_library(sgxlkl_common_enclave INTERFACE)
target_compile_definitions(sgxlkl_common_enclave INTERFACE -DSGXLKL_ENCLAVE -DOE_WITH_EXPERIMENTAL_EEID)
target_include_directories(sgxlkl_common_enclave INTERFACE "src/include" "${CMAKE_BINARY_DIR}/generated")
target_link_libraries(sgxlkl_common_enclave INTERFACE openenclave::oeenclave)
add_library(sgx-lkl::common-enclave ALIAS sgxlkl_common_enclave)

# Common properties for code that is part of the host tool.
add_library(sgxlkl_common_host INTERFACE)
target_compile_definitions(sgxlkl_common_host INTERFACE -DOE_WITH_EXPERIMENTAL_EEID)
target_include_directories(sgxlkl_common_host INTERFACE "src/include" "${CMAKE_BINARY_DIR}/generated")
target_link_libraries(sgxlkl_common_host INTERFACE openenclave::oehost)
add_library(sgx-lkl::common-host ALIAS sgxlkl_common_host)