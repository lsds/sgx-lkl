include_guard(GLOBAL)

set(JSON_C_SRCS "src/libjson/json.c")
set(JSON_INCLUDE_DIRS "src/libjson/include")

add_library(sgxlkl-json-host STATIC "${JSON_C_SRCS}")
target_include_directories(sgxlkl-json-host PUBLIC "${JSON_INCLUDE_DIRS}")
target_link_libraries(sgxlkl-json-host PRIVATE sgx-lkl::common-host)
add_library(sgx-lkl::json-host ALIAS sgxlkl-json-host)

# TODO add enclave variants
