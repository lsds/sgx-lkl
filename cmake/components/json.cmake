set(JSON_C_SRCS "src/libjson/json.c")
set(JSON_INCLUDE_DIRS "src/libjson/include")

add_library(sgxlkl_json_host STATIC "${JSON_C_SRCS}")
target_include_directories(sgxlkl_json_host PUBLIC "${JSON_INCLUDE_DIRS}")
target_link_libraries(sgxlkl_json_host PRIVATE sgx-lkl::common-host)
add_library(sgx-lkl::json-host ALIAS sgxlkl_json_host)

# TODO add enclave variants
