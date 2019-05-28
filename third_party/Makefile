include ../config.mak

ARCH ?= x86_64

.PHONY: clean distclean
.INTERMEDIATE: ${MAKE_ROOT}/cryptsetup.tar.gz ${MAKE_ROOT}/devicemapper.tar.gz ${MAKE_ROOT}/util-linux.tar.gz ${MAKE_ROOT}/popt.tar.gz ${MAKE_ROOT}/json-c.tar.gz ${MAKE_ROOT}/wireguard.tar.gz ${MAKE_ROOT}/protobufc.tar.gz \
               ${CRYPTSETUP} ${DEVICEMAPPER} ${UTILLINUX} ${POPT} ${JSONC} ${WIREGUARD} ${PROTOBUFC}

default: all

all: ${CRYPTSETUP_BUILD}/lib/libcryptsetup.a ${MBEDTLS}/mbedtls.a ${PROTOBUFC_RPC}/protobuf-c-rpc.a ${PROTOBUFC_RPC}/protobuf-c-rpc-client.a

MAKE_ROOT=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))

${CRYPTSETUP_BUILD} ${PROTOBUFC_BUILD}:
	@mkdir -p $@

${CRYPTSETUP}:
	wget -O "${MAKE_ROOT}/cryptsetup.tar.gz" 'https://gitlab.com/cryptsetup/cryptsetup/repository/archive.tar.gz?ref=v2.0.2'
	mkdir -p $@ && tar -C $@ --strip 1 -xf ${MAKE_ROOT}/cryptsetup.tar.gz
	rm ${MAKE_ROOT}/cryptsetup.tar.gz

${DEVICEMAPPER}:
	wget -O "${MAKE_ROOT}/devicemapper.tar.gz" 'https://github.com/lvmteam/lvm2/archive/v2_02_98.tar.gz'
	mkdir -p $@ && tar -C $@ --strip 1 -xf ${MAKE_ROOT}/devicemapper.tar.gz
	rm ${MAKE_ROOT}/devicemapper.tar.gz

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
	wget -O "${MAKE_ROOT}/wireguard.tar.gz" 'https://git.zx2c4.com/WireGuard/snapshot/WireGuard-0.0.20190227.tar.xz'
	mkdir -p $@ && tar -C $@ --strip 1 -xf ${MAKE_ROOT}/wireguard.tar.gz
	rm ${MAKE_ROOT}/wireguard.tar.gz

${PROTOBUFC}:
	wget -O "${MAKE_ROOT}/protobuf-c.tar.gz" 'https://github.com/protobuf-c/protobuf-c/releases/download/v1.3.1/protobuf-c-1.3.1.tar.gz'
	mkdir -p $@ && tar -C $@ --strip 1 -xf "${MAKE_ROOT}/protobuf-c.tar.gz"
	# We don't need the command line tool and it depends on headers that
	# seem to be no longer part of the Ubuntu 18.04 repository version of
	# libprotobuf-dev.
	cd $@ && patch -p1 < ../protobufc.patch
	rm "${MAKE_ROOT}/protobuf-c.tar.gz"

${CRYPTSETUP_BUILD}/lib/libdevmapper.a: ${DEVICEMAPPER} ${HOST_MUSL_CC} ${CRYPTSETUP_BUILD}
	cd ${DEVICEMAPPER}; [ -f Makefile ] || CC=${HOST_MUSL_CC} CFLAGS="${THIRD_PARTY_CFLAGS} -fPIC -Dptrdiff_t=intptr_t -Wl,--dynamic-linker=${HOST_MUSL_BUILD}/lib/libc.so" ./configure \
		--prefix=${CRYPTSETUP_BUILD}/ --enable-static_link
	+CC=${HOST_MUSL_CC} ${MAKE} -C ${DEVICEMAPPER} device-mapper
	+CC=${HOST_MUSL_CC} ${MAKE} -C ${DEVICEMAPPER}/libdm install

${CRYPTSETUP_BUILD}/lib/libuuid.a: ${UTILLINUX} ${HOST_MUSL_CC} ${CRYPTSETUP_BUILD}
	cd ${UTILLINUX}; [ -f Makefile ] || CC=${HOST_MUSL_CC} CFLAGS="${THIRD_PARTY_CFLAGS} -fPIC -Wl,--dynamic-linker=${HOST_MUSL_BUILD}/lib/libc.so" ./autogen.sh
	cd ${UTILLINUX}; [ -f Makefile ] || CC=${HOST_MUSL_CC} CFLAGS="${THIRD_PARTY_CFLAGS} -fPIC -Wl,--dynamic-linker=${HOST_MUSL_BUILD}/lib/libc.so" ./configure \
		--prefix=${CRYPTSETUP_BUILD}/ --enable-static \
		--disable-all-programs --enable-libuuid --enable-uuid \
		--without-ncurses --without-ncursesw --without-tinfo \
		--disable-bash-completion
	+CC=${HOST_MUSL_CC} ${MAKE} -C ${UTILLINUX} all install
	cp ${UTILLINUX}/.libs/libuuid.* ${CRYPTSETUP_BUILD}/lib/

${CRYPTSETUP_BUILD}/lib/libpopt.a: ${POPT} ${HOST_MUSL_CC} ${CRYPTSETUP_BUILD}
	cd ${POPT}; [ -f Makefile ] || CC=${HOST_MUSL_CC} CFLAGS="$(THIRD_PARTY_CFLAGS) -fPIC -Wl,--dynamic-linker=${HOST_MUSL_BUILD}/lib/libc.so" ./configure \
		--prefix=${CRYPTSETUP_BUILD}/ --enable-static
	+CC=${HOST_MUSL_CC} ${MAKE} -C ${POPT} all install

${CRYPTSETUP_BUILD}/lib/libjson-c.a: ${JSONC} ${HOST_MUSL_CC} ${CRYPTSETUP_BUILD}
	cd ${JSONC}; [ -f Makefile ] || CC=${HOST_MUSL_CC} CFLAGS="${THIRD_PARTY_CFLAGS} -fPIC" ./autogen.sh && autoreconf -i
	cd ${JSONC}; [ -f Makefile ] || CC=${HOST_MUSL_CC} CFLAGS="${THIRD_PARTY_CFLAGS} -fPIC -Wl,--dynamic-linker=${HOST_MUSL_BUILD}/lib/libc.so" ./configure \
		--prefix=${CRYPTSETUP_BUILD}/ --enable-static
	+CC=${HOST_MUSL_CC} CFLAGS=-fPIC ${MAKE} -C ${JSONC} all install

${CRYPTSETUP_BUILD}/lib/libcryptsetup.a: ${CRYPTSETUP} ${CRYPTSETUP_BUILD}/lib/libpopt.a ${CRYPTSETUP_BUILD}/lib/libdevmapper.a ${CRYPTSETUP_BUILD}/lib/libuuid.a ${CRYPTSETUP_BUILD}/lib/libjson-c.a ${HOST_MUSL_CC} ${CRYPTSETUP_BUILD}
	rsync -rv cryptsetup-override/ ${CRYPTSETUP}/
	cd ${CRYPTSETUP}; [ -f Makefile ] || CC=${HOST_MUSL_CC} CFLAGS="${THIRD_PARTY_CFLAGS} -I${CRYPTSETUP_BUILD}/include -I${LKL_BUILD}/include -fPIC" LDFLAGS="-L${CRYPTSETUP_BUILD}/lib" ./autogen.sh
	cd ${CRYPTSETUP}; CC=${HOST_MUSL_CC} CFLAGS="${THIRD_PARTY_CFLAGS} --static -I${CRYPTSETUP_BUILD}/include -I${LKL_BUILD}/include -fPIC -Wl,--dynamic-linker=${HOST_MUSL_BUILD}/lib/libc.so" LDFLAGS="${LDFLAGS} -L${CRYPTSETUP_BUILD}/lib" ./configure --prefix=${CRYPTSETUP_BUILD}/ --enable-static --with-crypto-backend=kernel
	+CC=${HOST_MUSL_CC} ${MAKE} -C ${CRYPTSETUP} install-libLTLIBRARIES
	+CC=${HOST_MUSL_CC} ${MAKE} -C ${CRYPTSETUP} install-includeHEADERS

${PROTOBUFC_BUILD}/include ${PROTOBUFC_BUILD}/lib/libprotobuf-c.a: ${PROTOBUFC} ${PROTOBUFC_BUILD}
	cd ${PROTOBUFC} && autoreconf -f -i
	cd ${PROTOBUFC} && CFLAGS="${THIRD_PARTY_CFLAGS}" ./configure --prefix=${PROTOBUFC_BUILD} --disable-shared --with-pic
	cd ${PROTOBUFC} && $(MAKE) install-libLTLIBRARIES
	cd ${PROTOBUFC} && $(MAKE) install-nobase_includeHEADERS

MBEDTLS_SRCS = $(wildcard ${MBEDTLS}/*.c)
MBEDTLS_OBJS = $(MBEDTLS_SRCS:.c=.o)

${MBEDTLS}/mbedtls.a: ${MBEDTLS_OBJS}
	ar rc $@ $^

$(MBEDTLS_OBJS): $(MBEDTLS)/%.o: ${MBEDTLS}/%.c
	$(CC) -c --std=gnu11 -I${MBEDTLS}/include $(THIRD_PARTY_CFLAGS) $< -o $@

PROTOBUFC_RPC_SRCS = $(wildcard ${PROTOBUFC_RPC}/*.c)
PROTOBUFC_RPC_OBJS = $(PROTOBUFC_RPC_SRCS:.c=.o)

${PROTOBUFC_RPC}/protobuf-c-rpc.a: ${PROTOBUFC_RPC_OBJS} ${PROTOBUFC_BUILD}/lib/libprotobuf-c.a
	ar rc $@ $^

$(PROTOBUFC_RPC_OBJS): $(PROTOBUFC_RPC)/%.o: ${PROTOBUFC_RPC}/%.c | $(HOST_MUSL_CC) ${PROTOBUFC_BUILD}/include
	$(HOST_MUSL_CC) -fPIC -c --std=gnu11 -DHAVE_CONFIG_H -include $(PROTOBUFC_RPC)/config.h -I. -I$(PROTOBUFC_RPC)/.. -I${PROTOBUFC_BUILD}/include $(THIRD_PARTY_CFLAGS) $< -o $@

PROTOBUFC_RPC_CLIENT_OBJS = $(PROTOBUFC_RPC_SRCS:.c=.client.o)

${PROTOBUFC_RPC}/protobuf-c-rpc-client.a: ${PROTOBUFC_RPC_CLIENT_OBJS}
	ar rc $@ $^

$(PROTOBUFC_RPC_CLIENT_OBJS): $(PROTOBUFC_RPC)/%.client.o: ${PROTOBUFC_RPC}/%.c
	$(CC) -c --std=gnu11 -DHAVE_CONFIG_H -include $(PROTOBUFC_RPC)/config.h -I$(PROTOBUFC_RPC)/.. $(THIRD_PARTY_CFLAGS) $< -o $@

clean:
	+[ -f ${CRYPTSETUP}/Makefile ] && ${MAKE} -C ${CRYPTSETUP} distclean || true
	+[ -f ${POPT}/Makefile ] && ${MAKE} -C ${POPT} distclean || true
	+[ -f ${UTILLINUX}/Makefile ] && ${MAKE} -C ${UTILLINUX} distclean || true
	+[ -f ${DEVICEMAPPER}/Makefile ] && ${MAKE} -C ${DEVICEMAPPER} distclean || true
	+[ -f ${JSONC}/Makefile ] && ${MAKE} -C ${JSONC} distclean || true
	+[ -f ${PROTOBUFC}/Makefile ] && ${MAKE} -C ${PROTOBUFC} distclean || true
	+rm -rf $(MBEDTLS)/mbedtls.a $(MBEDTLS)/*.o
	+rm -rf $(PROTOBUFC_RPC)/protobuf-c-rpc.a $(PROTOBUFC_RPC)/*.o
	+rm -rf $(MAKE_ROOT)/cryptsetup.tar.gz
	+rm -rf $(MAKE_ROOT)/devicemapper.tar.gz
	+rm -rf $(MAKE_ROOT)/popt.tar.gz
	+rm -rf $(MAKE_ROOT)/util-linux.tar.gz
	+rm -rf $(MAKE_ROOT)/json-c.tar.gz
	+rm -rf $(MAKE_ROOT)/protobuf-c.tar.gz
	+rm -rf $(MAKE_ROOT)/wireguard.tar.gz

distclean: clean
	+rm -rf $(MAKE_ROOT)/cryptsetup.tar.gz
	+rm -rf $(MAKE_ROOT)/devicemapper.tar.gz
	+rm -rf $(MAKE_ROOT)/popt.tar.gz
	+rm -rf $(MAKE_ROOT)/util-linux.tar.gz
	+rm -rf $(MAKE_ROOT)/json-c.tar.gz
	+rm -rf $(MAKE_ROOT)/protobuf-c.tar.gz
	+rm -rf $(MAKE_ROOT)/wireguard.tar.gz
	+rm -rf $(CRYPTSETUP)
	+rm -rf $(DEVICEMAPPER)
	+rm -rf $(POPT)
	+rm -rf $(UTILLINUX)
	+rm -rf $(JSONC)
	+rm -rf $(PROTOBUFC)
	+rm -rf $(WIREGUARD)
