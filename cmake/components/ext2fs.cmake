include(ExternalProject)
include(cmake/Constants.cmake)

# libext2fs (part of e2fsprogs) is used in userspace to dynamically create disks with ext4 filesystems.
ExternalProject_Add(e2fsprogs-ep
	URL ${E2FSPROGS_URL}
	URL_HASH ${E2FSPROGS_HASH}
	CONFIGURE_COMMAND "<SOURCE_DIR>/configure" "CC=${CMAKE_C_COMPILER}"
	COMMAND make -C "<BINARY_DIR>/util" # build-time tools that must not be built against musl
	COMMAND "<SOURCE_DIR>/configure" "CC=${SGXLKL_LIBC_INIT_COMPILER}" "CFLAGS=-DOMIT_COM_ERR" "--prefix=<INSTALL_DIR>"
	BUILD_COMMAND make -j ${NUMBER_OF_CORES} libs
	INSTALL_COMMAND make -C "<BINARY_DIR>/lib/ext2fs" install
	COMMAND ${CMAKE_COMMAND} -E make_directory "<INSTALL_DIR>/include/et"
	COMMAND ${CMAKE_COMMAND} -E touch "<INSTALL_DIR>/include/et/com_err.h"
	BUILD_BYPRODUCTS "<INSTALL_DIR>/lib/libext2fs.a"
	DEPENDS sgx-lkl::libc-init
	${COMMON_EP_OPTIONS}
)
ExternalProject_Get_property(e2fsprogs-ep INSTALL_DIR)
add_library(ext2fs INTERFACE)
target_link_libraries(ext2fs INTERFACE "${INSTALL_DIR}/lib/libext2fs.a")
target_include_directories(ext2fs INTERFACE "${INSTALL_DIR}/include")
add_dependencies(ext2fs e2fsprogs-ep)
add_library(e2fsprogs::ext2fs ALIAS ext2fs)
