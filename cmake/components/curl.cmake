include(ExternalProject)
include(cmake/Constants.cmake)

# libcurl is used in userspace for fetching disk encryption keys.
ExternalProject_Add(curl-ep
	URL ${CURL_URL}
	URL_HASH ${CURL_HASH}
	CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env curl_disallow_alarm=yes "<SOURCE_DIR>/configure" 
		"CC=${SGXLKL_LIBC_INIT_COMPILER}"
		"CFLAGS=-DUSE_BLOCKING_SOCKETS"
		"--prefix=<INSTALL_DIR>"
		--disable-shared --with-pic
		# TODO make conditional
		--enable-debug
		# FIXME A userspace variant of mbedtls needs to be used here.
		--with-mbedtls=${OE_SDK_LIBS}/openenclave/enclave
		--without-zlib --without-ssl --without-ca-bundle --without-ca-path --without-libdl
		--without-libssh2 --without-libidn2
		--disable-unix-sockets --disable-threaded-resolver --disable-cookies --disable-rtsp
		--disable-dict --disable-file --disable-rt --disable-ftp --disable-gopher
		--disable-imap --disable-pop3 --disable-smtp --disable-telnet --disable-tftp
		--disable-smb --disable-smbs --disable-netrc
	BUILD_COMMAND make -j ${NUMBER_OF_CORES}
	INSTALL_COMMAND make install
	BUILD_BYPRODUCTS "<INSTALL_DIR>/lib/libcurl.a"
	DEPENDS sgx-lkl::libc-init
	${COMMON_EP_OPTIONS}
)
ExternalProject_Get_property(curl-ep INSTALL_DIR)
add_library(curl INTERFACE)
target_link_libraries(curl INTERFACE "${INSTALL_DIR}/lib/libcurl.a")
target_include_directories(curl INTERFACE "${INSTALL_DIR}/include")
add_dependencies(curl curl-ep)
add_library(curl::curl ALIAS curl)
