include_guard(GLOBAL)
include(cmake/components/common.cmake)
include(cmake/components/musl.cmake)
include(cmake/components/lkl.cmake)

if (LIBC STREQUAL "musl")
  # Eventually init components will always use a statically linked musl,
  # while apps can use a dynamically linked musl/glibc.
  # For now, both the init components and apps are required to use the same libc.
  add_library(sgx-lkl::libc-init ALIAS sgxlkl-musl)
  set(LIBC_CFLAGS "${MUSL_CFLAGS}")
endif()

# For external projects running in user space in the enclave.
set(THIRD_PARTY_USERSPACE_CFLAGS
  ${CMAKE_C_FLAGS_BUILD_TYPE}
  ${COMMON_ENCLAVE_CFLAGS}
  ${LIBC_CFLAGS}
  -isystem "${LKL_INCLUDE_DIR}"
  -isystem "${C_COMPILER_INCLUDE_DIR}"
  )
list(JOIN THIRD_PARTY_USERSPACE_CFLAGS " " THIRD_PARTY_USERSPACE_CFLAGS)

set(THIRD_PARTY_USERSPACE_DEPENDS
  sgx-lkl::libc-init
  sgx-lkl::common-enclave
  sgx-lkl::lkl-headers
)