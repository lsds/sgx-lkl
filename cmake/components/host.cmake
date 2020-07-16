include_guard(GLOBAL)

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
	)
# If we are configuring for the first build, add a fake dependency of this tool
# on the LKL build.  For subsequent builds this will be picked up by the real
# LKL header dependencies.
if(NOT LKL_HEADERS)
	add_dependencies(${HOST_TOOL_NAME} build-lkl)
endif()