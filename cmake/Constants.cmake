include_guard(GLOBAL)

# Paths
set(LKL_SUBDIRECTORY "lkl")
set(EXTERNAL_PROJECT_BASE_DIR "external")

# Target names
set(HOST_TOOL_NAME sgx-lkl-run)
set(ENCLAVE_IMAGE_NAME sgxlkl)
set(ENCLAVE_IMAGE_PATH_SIGNED "${CMAKE_CURRENT_BINARY_DIR}/lib${ENCLAVE_IMAGE_NAME}.so.signed")

# External projects
set(WIREGUARD_URL "https://download.wireguard.com/monolithic-historical/WireGuard-0.0.20191219.tar.xz")
set(WIREGUARD_HASH "SHA256=5aba6f0c38e97faa0b155623ba594bb0e4bd5e29deacd8d5ed8bda8d8283b0e7")
set(E2FSPROGS_URL "https://git.kernel.org/pub/scm/fs/ext2/e2fsprogs.git/snapshot/e2fsprogs-1.45.5.tar.gz")
set(E2FSPROGS_HASH "SHA256=0fd76e55c1196c1d97a2c01f2e84f463b8e99484541b43ff4197f5a695159fd3")
set(CURL_URL "https://curl.haxx.se/download/curl-7.66.0.tar.bz2")
set(CURL_HASH "SHA256=6618234e0235c420a21f4cb4c2dd0badde76e6139668739085a70c4e2fe7a141")
set(DEVICEMAPPER_URL "https://github.com/lvmteam/lvm2/archive/v2_02_98.tar.gz")
set(DEVICEMAPPER_HASH "SHA256=56db106cba31e3a143f758ae1b569f2df91fd3403ae7076374700ebadcfa6583")

# Dynamic "constants" / settings
include(ProcessorCount)
ProcessorCount(NUMBER_OF_CORES)

set_directory_properties(PROPERTIES EP_BASE "${EXTERNAL_PROJECT_BASE_DIR}")
set(COMMON_EP_OPTIONS
	EXCLUDE_FROM_ALL ON
	)
if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.14")
	# LOG_OUTPUT_ON_FAILURE is available in 3.14 onwards only.
	list(APPEND COMMON_EP_OPTIONS
		# Log all output to files instead of printing.
		# Note that this still prints a single line even on success.
		# See also https://gitlab.kitware.com/cmake/cmake/-/issues/20958.
		LOG_DOWNLOAD ON
		LOG_UPDATE ON
		LOG_PATCH ON
		LOG_CONFIGURE ON
		LOG_BUILD ON
		LOG_INSTALL ON
		LOG_TEST ON
		LOG_MERGED_STDOUTERR ON
		# Print log in case of errors.
		LOG_OUTPUT_ON_FAILURE ON
		)
endif()
