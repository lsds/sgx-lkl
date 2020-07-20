include_guard(GLOBAL)
include(cmake/components/openenclave.cmake)

set(GENERATED_HOST_EDGE_FILES 
  "generated/host/sgxlkl_args.h"
  "generated/host/sgxlkl_u.c"
  "generated/host/sgxlkl_u.h"
  )
set(GENERATED_ENCLAVE_EDGE_FILES 
  "generated/enclave/sgxlkl_args.h"
  "generated/enclave/sgxlkl_t.c"
  "generated/enclave/sgxlkl_t.h"
  )

add_custom_command(OUTPUT ${GENERATED_HOST_EDGE_FILES}
  COMMAND openenclave::oeedger8r
    ${OEEDGER8R_EXTRA_FLAGS}
    --untrusted "${PROJECT_SOURCE_DIR}/src/sgxlkl.edl"
    --untrusted-dir "${CMAKE_CURRENT_BINARY_DIR}/generated/host"
  COMMAND_EXPAND_LISTS
  # TODO add imported files in EDL as dependencies
  DEPENDS openenclave::oeedger8r "${PROJECT_SOURCE_DIR}/src/sgxlkl.edl"    
  )
add_custom_command(OUTPUT ${GENERATED_ENCLAVE_EDGE_FILES}
  COMMAND openenclave::oeedger8r
    ${OEEDGER8R_EXTRA_FLAGS}
    --trusted "${PROJECT_SOURCE_DIR}/src/sgxlkl.edl"
    --trusted-dir "${CMAKE_CURRENT_BINARY_DIR}/generated/enclave"
  COMMAND_EXPAND_LISTS
  # TODO add imported files in EDL as dependencies
  DEPENDS openenclave::oeedger8r "${PROJECT_SOURCE_DIR}/src/sgxlkl.edl"
  )

add_library(sgxlkl-edl-enclave STATIC ${GENERATED_ENCLAVE_EDGE_FILES})
target_link_libraries(sgxlkl-edl-enclave PRIVATE sgx-lkl::common-enclave)
add_library(sgx-lkl::edl-enclave ALIAS sgxlkl-edl-enclave)

add_library(sgxlkl-edl-host STATIC ${GENERATED_HOST_EDGE_FILES})
target_link_libraries(sgxlkl-edl-host PRIVATE sgx-lkl::common-host)
add_library(sgx-lkl::edl-host ALIAS sgxlkl-edl-host)
