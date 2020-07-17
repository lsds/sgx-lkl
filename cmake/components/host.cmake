include_guard(GLOBAL)
include(cmake/components/common.cmake)
include(cmake/components/edl.cmake)
include(cmake/components/json.cmake)
include(cmake/components/config.cmake)
include(cmake/components/lkl.cmake)

find_package(Threads REQUIRED)

file(GLOB MAIN_C_SRCS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/main-oe/*.c")
file(GLOB HOSTINTERFACE_C_SRCS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/host_interface/*.c")
file(GLOB SHARED_C_SRCS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/shared/*.c")

add_executable(${HOST_TOOL_NAME}
	${MAIN_C_SRCS}
	${HOSTINTERFACE_C_SRCS}
	${SHARED_C_SRCS}
	)
target_link_libraries(${HOST_TOOL_NAME} PRIVATE
	Threads::Threads
	rt
	sgx-lkl::common-host
	sgx-lkl::edl-host
	sgx-lkl::json-host
	sgx-lkl::host-config
	sgx-lkl::enclave-config-host
	sgx-lkl::build-metadata
	sgx-lkl::lkl-headers
	)
