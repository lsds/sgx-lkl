include ../config.mak

ARCH ?= x86_64

.PHONY: clean distclean
.INTERMEDIATE: ${MAKE_ROOT}/devicemapper.tar.gz ${MAKE_ROOT}/e2fsprogs.tar.gz ${MAKE_ROOT}/json-c.tar.gz ${MAKE_ROOT}/wireguard.tar.gz\
               ${JSONC} ${WIREGUARD}

default: all

all: ${THIRD_PARTY_LIB_DEVICE_MAPPER} ${THIRD_PARTY_LIB_EXT2FS} ${THIRD_PARTY_LIB_JSON} ${THIRD_PARTY_LIB_CURL} ${OE_STUBS}

MAKE_ROOT=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))

${LIB_CURL_BUILD} ${DEVICEMAPPER_BUILD}:
	@mkdir -p $@

${DEVICEMAPPER}:
	wget --retry-connrefused -O "${MAKE_ROOT}/devicemapper.tar.gz" 'https://github.com/lvmteam/lvm2/archive/v2_02_98.tar.gz'
	mkdir -p $@ && tar -C $@ --strip 1 -xf ${MAKE_ROOT}/devicemapper.tar.gz
	rm ${MAKE_ROOT}/devicemapper.tar.gz

${E2FSPROGS}:
	wget --retry-connrefused -O "${MAKE_ROOT}/e2fsprogs.tar.gz" 'https://git.kernel.org/pub/scm/fs/ext2/e2fsprogs.git/snapshot/e2fsprogs-1.45.5.tar.gz'
	mkdir -p $@ && tar -C $@ --strip 1 -xf ${MAKE_ROOT}/e2fsprogs.tar.gz
	rm ${MAKE_ROOT}/e2fsprogs.tar.gz

${JSONC}:
	wget --retry-connrefused -O "${MAKE_ROOT}/json-c.tar.gz" 'https://github.com/json-c/json-c/archive/json-c-0.13.1-20180305.tar.gz'
	mkdir -p $@ && tar -C $@ --strip 1 -xf ${MAKE_ROOT}/json-c.tar.gz
	rm ${MAKE_ROOT}/json-c.tar.gz

${WIREGUARD}:
	wget --retry-connrefused -O "${MAKE_ROOT}/wireguard.tar.gz" 'https://download.wireguard.com/monolithic-historical/WireGuard-0.0.20191219.tar.xz'
	mkdir -p $@ && tar -C $@ --strip 1 -xf ${MAKE_ROOT}/wireguard.tar.gz
	rm ${MAKE_ROOT}/wireguard.tar.gz

${CURL}:
	wget --retry-connrefused -O "${MAKE_ROOT}/curl.tar.bz2" 'https://curl.haxx.se/download/curl-7.66.0.tar.bz2'
	mkdir -p $@ && tar -C $@ --strip 1  -xf "${MAKE_ROOT}/curl.tar.bz2"
	rm "${MAKE_ROOT}/curl.tar.bz2"

${THIRD_PARTY_LIB_DEVICE_MAPPER}: ${DEVICEMAPPER}
	cd ${DEVICEMAPPER}; [ -f Makefile ] || CC=${HOST_CC} CFLAGS="${THIRD_PARTY_CFLAGS} -Dptrdiff_t=intptr_t" ./configure \
		--prefix=${DEVICEMAPPER_BUILD}/ --enable-static_link >/dev/null
	+CC=${HOST_CC} ${MAKE} -C ${DEVICEMAPPER} -j`${TOOLS}/ncore.sh` device-mapper
	+CC=${HOST_CC} ${MAKE} -C ${DEVICEMAPPER}/libdm -j`${TOOLS}/ncore.sh` install

${THIRD_PARTY_LIB_EXT2FS}: ${E2FSPROGS}
	# util/ contains build-time tools that must not be built against musl
	cd ${E2FSPROGS}; ./configure >/dev/null; ${MAKE} -C ${E2FSPROGS}/util
	cd ${E2FSPROGS}; CC=${HOST_CC} CFLAGS="${THIRD_PARTY_CFLAGS} -DOMIT_COM_ERR" ./configure \
		--prefix=${E2FSPROGS_BUILD}/ >/dev/null
	+CC=${HOST_CC} ${MAKE} -C ${E2FSPROGS} -j`${TOOLS}/ncore.sh` libs
	+CC=${HOST_CC} ${MAKE} -C ${E2FSPROGS}/lib/ext2fs -j`${TOOLS}/ncore.sh` install
	# ext2fs.h lacks OMIT_COM_ERR include guard.
	mkdir ${E2FSPROGS_BUILD}/include/et
	touch ${E2FSPROGS_BUILD}/include/et/com_err.h

${THIRD_PARTY_LIB_JSON}: ${JSONC}
	cd ${JSONC}; [ -f Makefile ] || CC=${HOST_CC} CFLAGS="${THIRD_PARTY_CFLAGS}" ./autogen.sh >/dev/null && autoreconf -i >/dev/null
	cd ${JSONC}; [ -f Makefile ] || CC=${HOST_CC} CFLAGS="${THIRD_PARTY_CFLAGS}" ./configure \
		--prefix=${JSONC_BUILD}/ --enable-static >/dev/null
	+CC=${HOST_CC} CFLAGS=-fPIC ${MAKE} -C ${JSONC} all install

${OE_STUBS}: ${LIB_CURL_BUILD} oe_stubs/oe_stubs.c ${OPENENCLAVE}
	${HOST_CC} ${THIRD_PARTY_CFLAGS} -I${OE_SDK_INCLUDES}/openenclave/3rdparty/ -c oe_stubs/oe_stubs.c -o ${LIB_CURL_BUILD}/oe_stubs.o
	ar rc $@ ${LIB_CURL_BUILD}/oe_stubs.o

${THIRD_PARTY_LIB_CURL}: ${LIB_CURL_BUILD} ${CURL} ${OE_STUBS} ${OPENENCLAVE}
	cd ${CURL} && \
		CC=${HOST_CC} CFLAGS="${THIRD_PARTY_CFLAGS} -include ${SGXLKL_ROOT}/third_party/oe_stubs/oe_stubs.h" \
		CPPFLAGS="-I${OE_SDK_INCLUDES}/openenclave/3rdparty/ -DUSE_BLOCKING_SOCKETS" \
		LDFLAGS="-L${OE_SDK_LIBS}/openenclave/enclave -L${LIB_CURL_BUILD}" LIBS="" \
		curl_disallow_alarm=yes ./configure --prefix=${LIB_CURL_BUILD} --disable-shared --with-pic  --with-mbedtls=${OE_SDK_LIBS}/openenclave/enclave \
		--without-zlib --without-ssl --without-ca-bundle --without-ca-path --enable-debug --without-libdl --without-libssh2 --without-libidn2 \
		--disable-unix-sockets --disable-threaded-resolver --disable-cookies --disable-rtsp --disable-dict --disable-file --disable-rt \
		--disable-ftp --disable-gopher --disable-imap --disable-pop3 --disable-smtp --disable-telnet --disable-tftp \
		--disable-smb --disable-smbs --disable-netrc >/dev/null
	${MAKE} -C ${CURL}/lib -j`${TOOLS}/ncore.sh` libcurl.la
	cp ${CURL}/lib/.libs/libcurl.a ${LIB_CURL_BUILD}

clean:
	+[ -f ${DEVICEMAPPER}/Makefile ] && ${MAKE} -C ${DEVICEMAPPER} distclean || true
	+[ -f ${E2FSPROGS}/Makefile ] && ${MAKE} -C ${E2FSPROGS} distclean || true
	+[ -f ${JSONC}/Makefile ] && ${MAKE} -C ${JSONC} distclean || true
	+[ -f ${CURL}/Makefile ] && ${MAKE} -C ${CURL} distclean || true
	+rm -rf $(MAKE_ROOT)/devicemapper.tar.gz
	+rm -rf $(MAKE_ROOT)/e2fsprogs.tar.gz
	+rm -rf $(MAKE_ROOT)/json-c.tar.gz
	+rm -rf $(MAKE_ROOT)/wireguard.tar.gz
	+rm -rf ${MAKE_ROOT}/curl.tar.bz2
	+rm -rf ${OE_STUBS} ${LIB_CURL_BUILD}/oe_stubs.o

distclean: clean
	+rm -rf $(DEVICEMAPPER)
	+rm -rf $(E2FSPROGS)
	+rm -rf $(JSONC)
	+rm -rf $(WIREGUARD)
	+rm -rf $(CURL)
