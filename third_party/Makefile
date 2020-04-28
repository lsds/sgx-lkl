include ../config.mak

ARCH ?= x86_64

.PHONY: clean distclean
.INTERMEDIATE: ${MAKE_ROOT}/cryptsetup.tar.gz ${MAKE_ROOT}/devicemapper.tar.gz ${MAKE_ROOT}/e2fsprogs.tar.gz ${MAKE_ROOT}/util-linux.tar.gz ${MAKE_ROOT}/popt.tar.gz ${MAKE_ROOT}/json-c.tar.gz ${MAKE_ROOT}/wireguard.tar.gz\
               ${CRYPTSETUP} ${DEVICEMAPPER} ${UTILLINUX} ${POPT} ${JSONC} ${WIREGUARD}

default: all

all: ${THIRD_PARTY_LIB_CRYPTSETUP} ${THIRD_PARTY_LIB_EXT2FS} ${LIB_CURL_BUILD}

MAKE_ROOT=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))

${CRYPTSETUP_BUILD} ${LIB_CURL_BUILD}:
	@mkdir -p $@

${CRYPTSETUP}:
	wget -O "${MAKE_ROOT}/cryptsetup.tar.gz" 'https://gitlab.com/cryptsetup/cryptsetup/repository/archive.tar.gz?ref=v2.0.2'
	mkdir -p $@ && tar -C $@ --strip 1 -xf ${MAKE_ROOT}/cryptsetup.tar.gz
	# The following patch changes the memory allocations in cryptsetup from
	# regular malloc() to lkl_sys_mmap(). This ensures that the allocated
	# memory is visible to LKL.
	cd $@ && patch -p4 < ../cryptsetup-sgx_lkl-mmap.patch
	rm ${MAKE_ROOT}/cryptsetup.tar.gz

${DEVICEMAPPER}:
	wget -O "${MAKE_ROOT}/devicemapper.tar.gz" 'https://github.com/lvmteam/lvm2/archive/v2_02_98.tar.gz'
	mkdir -p $@ && tar -C $@ --strip 1 -xf ${MAKE_ROOT}/devicemapper.tar.gz
	rm ${MAKE_ROOT}/devicemapper.tar.gz

${E2FSPROGS}:
	wget -O "${MAKE_ROOT}/e2fsprogs.tar.gz" 'https://git.kernel.org/pub/scm/fs/ext2/e2fsprogs.git/snapshot/e2fsprogs-1.45.5.tar.gz'
	mkdir -p $@ && tar -C $@ --strip 1 -xf ${MAKE_ROOT}/e2fsprogs.tar.gz
	rm ${MAKE_ROOT}/e2fsprogs.tar.gz

${UTILLINUX}:
	wget -O "${MAKE_ROOT}/util-linux.tar.gz" 'https://git.kernel.org/pub/scm/utils/util-linux/util-linux.git/snapshot/util-linux-2.29.2.tar.gz'
	mkdir -p $@ && tar -C $@ --strip 1 -xf ${MAKE_ROOT}/util-linux.tar.gz
	rm ${MAKE_ROOT}/util-linux.tar.gz

${POPT}:
	wget -O "${MAKE_ROOT}/popt.tar.gz" 'https://deb.debian.org/debian/pool/main/p/popt/popt_1.16.orig.tar.gz'
	mkdir -p $@ && tar -C $@ --strip 1 -xf ${MAKE_ROOT}/popt.tar.gz
	rm ${MAKE_ROOT}/popt.tar.gz

${JSONC}:
	wget -O "${MAKE_ROOT}/json-c.tar.gz" 'https://github.com/json-c/json-c/archive/json-c-0.13.1-20180305.tar.gz'
	mkdir -p $@ && tar -C $@ --strip 1 -xf ${MAKE_ROOT}/json-c.tar.gz
	rm ${MAKE_ROOT}/json-c.tar.gz

${WIREGUARD}:
	wget -O "${MAKE_ROOT}/wireguard.tar.gz" 'https://download.wireguard.com/monolithic-historical/WireGuard-0.0.20191219.tar.xz'
	mkdir -p $@ && tar -C $@ --strip 1 -xf ${MAKE_ROOT}/wireguard.tar.gz
	rm ${MAKE_ROOT}/wireguard.tar.gz

${CURL}:
	wget -O "${MAKE_ROOT}/curl.tar.bz2" 'https://curl.haxx.se/download/curl-7.66.0.tar.bz2'
	mkdir -p $@ && tar -C $@ --strip 1  -xf "${MAKE_ROOT}/curl.tar.bz2"
	rm "${MAKE_ROOT}/curl.tar.bz2"

${THIRD_PARTY_LIB_DEVICE_MAPPER}: ${DEVICEMAPPER} ${CRYPTSETUP_BUILD}
	cd ${DEVICEMAPPER}; [ -f Makefile ] || CC=${HOST_CC} CFLAGS="${THIRD_PARTY_CFLAGS} -Dptrdiff_t=intptr_t" ./configure \
		--prefix=${CRYPTSETUP_BUILD}/ --enable-static_link
	+CC=${HOST_CC} ${MAKE} -C ${DEVICEMAPPER} -j`tools/ncore.sh` device-mapper
	+CC=${HOST_CC} ${MAKE} -C ${DEVICEMAPPER}/libdm -j`tools/ncore.sh` install

${THIRD_PARTY_LIB_EXT2FS}: ${E2FSPROGS}
	# util/ contains build-time tools that must not be built against musl
	cd ${E2FSPROGS}; ./configure; ${MAKE} -C ${E2FSPROGS}/util
	cd ${E2FSPROGS}; CC=${HOST_CC} CFLAGS="${THIRD_PARTY_CFLAGS} -DOMIT_COM_ERR" ./configure \
		--prefix=${E2FSPROGS_BUILD}/
	+CC=${HOST_CC} ${MAKE} -C ${E2FSPROGS} -j`tools/ncore.sh` libs
	+CC=${HOST_CC} ${MAKE} -C ${E2FSPROGS}/lib/ext2fs -j`tools/ncore.sh` install
	# ext2fs.h lacks OMIT_COM_ERR include guard.
	mkdir ${E2FSPROGS_BUILD}/include/et
	touch ${E2FSPROGS_BUILD}/include/et/com_err.h

${THIRD_PARTY_LIB_UUID}: ${UTILLINUX} ${CRYPTSETUP_BUILD}
	cd ${UTILLINUX}; [ -f Makefile ] || CC=${HOST_CC} CFLAGS="${THIRD_PARTY_CFLAGS}" ./autogen.sh
	cd ${UTILLINUX}; [ -f Makefile ] || CC=${HOST_CC} CFLAGS="${THIRD_PARTY_CFLAGS}" ./configure \
		--prefix=${CRYPTSETUP_BUILD}/ --enable-static \
		--disable-all-programs --enable-libuuid --enable-uuid \
		--without-ncurses --without-ncursesw --without-tinfo \
		--disable-bash-completion
	+CC=${HOST_CC} ${MAKE} -C ${UTILLINUX} all install
	cp ${UTILLINUX}/.libs/libuuid.* ${CRYPTSETUP_BUILD}/lib/

${THIRD_PARTY_LIB_POPT}: ${POPT} ${CRYPTSETUP_BUILD}
	cd ${POPT}; [ -f Makefile ] || CC=${HOST_CC} CFLAGS="$(THIRD_PARTY_CFLAGS)" ./configure \
		--prefix=${CRYPTSETUP_BUILD}/ --enable-static
	+CC=${HOST_CC} ${MAKE} -C ${POPT} all install

${THIRD_PARTY_LIB_JSON}: ${JSONC} ${CRYPTSETUP_BUILD}
	cd ${JSONC}; [ -f Makefile ] || CC=${HOST_CC} CFLAGS="${THIRD_PARTY_CFLAGS}" ./autogen.sh && autoreconf -i
	cd ${JSONC}; [ -f Makefile ] || CC=${HOST_CC} CFLAGS="${THIRD_PARTY_CFLAGS}" ./configure \
		--prefix=${CRYPTSETUP_BUILD}/ --enable-static
	+CC=${HOST_CC} CFLAGS=-fPIC ${MAKE} -C ${JSONC} all install

${THIRD_PARTY_LIB_CRYPTSETUP}: ${CRYPTSETUP} ${THIRD_PARTY_LIB_POPT} ${THIRD_PARTY_LIB_DEVICE_MAPPER} ${THIRD_PARTY_LIB_UUID} ${THIRD_PARTY_LIB_JSON} ${CRYPTSETUP_BUILD}
	cd ${CRYPTSETUP}; [ -f Makefile ] || CC=${HOST_CC} CFLAGS="${THIRD_PARTY_CFLAGS} -I${CRYPTSETUP_BUILD}/include -I${LKL_BUILD}/include" LDFLAGS="-L${CRYPTSETUP_BUILD}/lib" ./autogen.sh
	cd ${CRYPTSETUP}; CC=${HOST_CC} CFLAGS="--static -I${CRYPTSETUP_BUILD}/include -I${LKL_BUILD}/include ${THIRD_PARTY_CFLAGS}" LDFLAGS="${LDFLAGS} -L${CRYPTSETUP_BUILD}/lib" ./configure --prefix=${CRYPTSETUP_BUILD}/ --enable-static --with-crypto-backend=kernel
	+CC=${HOST_CC} ${MAKE} -C ${CRYPTSETUP} -j`tools/ncore.sh` install-libLTLIBRARIES
	+CC=${HOST_CC} ${MAKE} -C ${CRYPTSETUP} -j`tools/ncore.sh` install-includeHEADERS

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
		--disable-smb --disable-smbs --disable-netrc
	${MAKE} -C ${CURL}/lib -j`tools/ncore.sh` libcurl.la
	cp ${CURL}/lib/.libs/libcurl.a ${LIB_CURL_BUILD}

clean:
	+[ -f ${CRYPTSETUP}/Makefile ] && ${MAKE} -C ${CRYPTSETUP} distclean || true
	+[ -f ${POPT}/Makefile ] && ${MAKE} -C ${POPT} distclean || true
	+[ -f ${UTILLINUX}/Makefile ] && ${MAKE} -C ${UTILLINUX} distclean || true
	+[ -f ${DEVICEMAPPER}/Makefile ] && ${MAKE} -C ${DEVICEMAPPER} distclean || true
	+[ -f ${E2FSPROGS}/Makefile ] && ${MAKE} -C ${E2FSPROGS} distclean || true
	+[ -f ${JSONC}/Makefile ] && ${MAKE} -C ${JSONC} distclean || true
	+[ -f ${CURL}/Makefile ] && ${MAKE} -C ${CURL} distclean || true
	+rm -rf $(MAKE_ROOT)/cryptsetup.tar.gz
	+rm -rf $(MAKE_ROOT)/devicemapper.tar.gz
	+rm -rf $(MAKE_ROOT)/e2fsprogs.tar.gz
	+rm -rf $(MAKE_ROOT)/popt.tar.gz
	+rm -rf $(MAKE_ROOT)/util-linux.tar.gz
	+rm -rf $(MAKE_ROOT)/json-c.tar.gz
	+rm -rf $(MAKE_ROOT)/wireguard.tar.gz
	+rm -rf ${MAKE_ROOT}/curl.tar.bz2
	+rm -rf ${OE_STUBS} ${LIB_CURL_BUILD}/oe_stubs.o

distclean: clean
	+rm -rf $(MAKE_ROOT)/cryptsetup.tar.gz
	+rm -rf $(MAKE_ROOT)/devicemapper.tar.gz
	+rm -rf $(MAKE_ROOT)/e2fsprogs.tar.gz
	+rm -rf $(MAKE_ROOT)/popt.tar.gz
	+rm -rf $(MAKE_ROOT)/util-linux.tar.gz
	+rm -rf $(MAKE_ROOT)/json-c.tar.gz
	+rm -rf $(MAKE_ROOT)/wireguard.tar.gz
	+rm -rf $(CRYPTSETUP)
	+rm -rf $(DEVICEMAPPER)
	+rm -rf $(E2FSPROGS)
	+rm -rf $(POPT)
	+rm -rf $(UTILLINUX)
	+rm -rf $(JSONC)
	+rm -rf $(WIREGUARD)
	+rm -rf $(CURL)
