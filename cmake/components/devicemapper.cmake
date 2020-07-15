include(ExternalProject)
include(cmake/Constants.cmake)

# libdevmapper is used in userspace as dependency of libvicsetup.
ExternalProject_Add(devicemapper-ep
	URL ${DEVICEMAPPER_URL}
	URL_HASH ${DEVICEMAPPER_HASH}
	CONFIGURE_COMMAND "<SOURCE_DIR>/configure" 
		"CC=${SGXLKL_LIBC_INIT_COMPILER}"
		"CFLAGS=-Dptrdiff_t=intptr_t"
		"--enable-static_link"
		"--prefix=<INSTALL_DIR>"
	BUILD_COMMAND make -j ${NUMBER_OF_CORES}
	INSTALL_COMMAND make install
	BUILD_BYPRODUCTS "<INSTALL_DIR>/lib/libdevmapper.a"
	DEPENDS sgx-lkl::libc-init
	${COMMON_EP_OPTIONS}
)
ExternalProject_Get_property(devicemapper-ep INSTALL_DIR)
add_library(devicemapper INTERFACE)
target_link_libraries(devicemapper INTERFACE "${INSTALL_DIR}/lib/libdevmapper.a")
target_include_directories(devicemapper INTERFACE "${INSTALL_DIR}/include")
add_dependencies(devicemapper devicemapper-ep)
add_library(devicemapper::devicemapper ALIAS devicemapper)
