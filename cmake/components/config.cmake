include_guard(GLOBAL)

include(cmake/Helpers.cmake)
include(cmake/components/common.cmake)

find_package(Python COMPONENTS Interpreter REQUIRED)

set(GENERATED_HOST_CONFIG_FILES
	"generated/host/sgxlkl_host_config_gen.h"
	"generated/host/sgxlkl_host_config_gen.c"
)
set(GENERATED_ENCLAVE_CONFIG_FILES
	"generated/enclave/sgxlkl_enclave_config_gen.h"
	"generated/enclave/sgxlkl_enclave_config_gen.c"
)

set(HOST_CONFIG_SCHEMA "${PROJECT_SOURCE_DIR}/tools/schemas/host-config.schema.json")
set(ENCLAVE_CONFIG_SCHEMA "${PROJECT_SOURCE_DIR}/tools/schemas/enclave-config.schema.json")

mkdir("generated/host")
mkdir("generated/enclave")
add_custom_command(OUTPUT ${GENERATED_HOST_CONFIG_FILES}
	COMMAND Python::Interpreter	"${PROJECT_SOURCE_DIR}/tools/generate_config.py"
		--header "host/sgxlkl_host_config_gen.h"
		--source "host/sgxlkl_host_config_gen.c"
		"${HOST_CONFIG_SCHEMA}"
	WORKING_DIRECTORY "generated"
	DEPENDS "${PROJECT_SOURCE_DIR}/tools/generate_config.py" "${HOST_CONFIG_SCHEMA}"
)
add_custom_command(OUTPUT ${GENERATED_ENCLAVE_CONFIG_FILES}
	COMMAND ${CMAKE_COMMAND} -E make_directory "generated/enclave"
	COMMAND Python::Interpreter	"${PROJECT_SOURCE_DIR}/tools/generate_config.py"
		--header "enclave/sgxlkl_enclave_config_gen.h"
		--source "enclave/sgxlkl_enclave_config_gen.c"
		"${ENCLAVE_CONFIG_SCHEMA}"
	WORKING_DIRECTORY "generated"
	DEPENDS "${PROJECT_SOURCE_DIR}/tools/generate_config.py" "${ENCLAVE_CONFIG_SCHEMA}"
)

add_library(sgxlkl-host-config STATIC ${GENERATED_HOST_CONFIG_FILES})
target_link_libraries(sgxlkl-host-config PRIVATE sgx-lkl::common-host)
add_library(sgx-lkl::host-config ALIAS sgxlkl-host-config)

add_library(sgxlkl-enclave-config-enclave STATIC ${GENERATED_ENCLAVE_CONFIG_FILES})
target_link_libraries(sgxlkl-enclave-config-enclave PRIVATE sgx-lkl::common-enclave)
add_library(sgx-lkl::enclave-config-enclave ALIAS sgxlkl-enclave-config-enclave)

add_library(sgxlkl-enclave-config-host STATIC ${GENERATED_ENCLAVE_CONFIG_FILES})
target_link_libraries(sgxlkl-enclave-config-host PRIVATE sgx-lkl::common-host)
add_library(sgx-lkl::enclave-config-host ALIAS sgxlkl-enclave-config-host)