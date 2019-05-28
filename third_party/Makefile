include ../config.mak

.PHONY: clean
.INTERMEDIATE: ${MAKE_ROOT}/cryptsetup.tar.gz ${MAKE_ROOT}/devicemapper.tar.gz ${MAKE_ROOT}/util-linux.tar.gz ${MAKE_ROOT}/popt.tar.gz ${MAKE_ROOT}/json-c.tar.gz

ifeq ($(DEBUG),true)
  CFLAGS_MBEDTLS += -DDEBUG -O0 -g3 -ggdb3
else ifeq ($(DEBUG),opt)
  CFLAGS_MBEDTLS += -O3 -g3 -ggdb3
else
  CFLAGS_MBEDTLS += -O3
endif

default: all

all: ${CRYPTSETUP_BUILD}/lib/libcryptsetup.a ${MBEDTLS}/mbedtls.a

MAKE_ROOT=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))

${CRYPTSETUP_BUILD}:
	@mkdir -p $@

# libcryptsetup
${MAKE_ROOT}/cryptsetup.tar.gz:
	wget -O "$@" 'https://gitlab.com/cryptsetup/cryptsetup/repository/archive.tar.gz?ref=v2.0.2'

${MAKE_ROOT}/devicemapper.tar.gz:
	wget -O "$@" 'https://github.com/lvmteam/lvm2/archive/v2_02_98.tar.gz'

${MAKE_ROOT}/util-linux.tar.gz:
	wget -O "$@" 'https://git.kernel.org/pub/scm/utils/util-linux/util-linux.git/snapshot/util-linux-2.29.2.tar.gz'

${MAKE_ROOT}/popt.tar.gz:
	wget -O "$@" 'https://deb.debian.org/debian/pool/main/p/popt/popt_1.16.orig.tar.gz'

${MAKE_ROOT}/json-c.tar.gz:
	wget -O "$@" 'https://github.com/json-c/json-c/archive/json-c-0.13.1-20180305.tar.gz'

${MAKE_ROOT}/wireguard.tar.gz:
	wget -O "$@" 'https://git.zx2c4.com/WireGuard/snapshot/WireGuard-0.0.20190227.tar.xz'

${CRYPTSETUP}: ${MAKE_ROOT}/cryptsetup.tar.gz
	mkdir -p $@ && tar -C $@ --strip 1 -xf $<

${DEVICEMAPPER}: ${MAKE_ROOT}/devicemapper.tar.gz
	mkdir -p $@ && tar -C $@ --strip 1 -xf $<

${UTILLINUX}: ${MAKE_ROOT}/util-linux.tar.gz
	mkdir -p $@ && tar -C $@ --strip 1 -xf $<

${POPT}: ${MAKE_ROOT}/popt.tar.gz
	mkdir -p $@ && tar -C $@ --strip 1 -xf $<

${JSONC}: ${MAKE_ROOT}/json-c.tar.gz
	mkdir -p $@ && tar -C $@ --strip 1 -xf $<

${WIREGUARD}: ${MAKE_ROOT}/wireguard.tar.gz
	mkdir -p $@ && tar -C $@ --strip 1 -xf $<

${CRYPTSETUP_BUILD}/lib/libdevmapper.a: ${DEVICEMAPPER} ${HOST_MUSL_CC} ${CRYPTSETUP_BUILD}
	cd ${DEVICEMAPPER}; [ -f Makefile ] || CC=${HOST_MUSL_CC} CFLAGS="${CRYPTSETUP_CFLAGS} -fPIC -Dptrdiff_t=intptr_t -Wl,--dynamic-linker=${HOST_MUSL_BUILD}/lib/libc.so" ./configure \
		--prefix=${CRYPTSETUP_BUILD}/ --enable-static_link
	+CC=${HOST_MUSL_CC} ${MAKE} -C ${DEVICEMAPPER} device-mapper
	+CC=${HOST_MUSL_CC} ${MAKE} -C ${DEVICEMAPPER}/libdm install

${CRYPTSETUP_BUILD}/lib/libuuid.a: ${UTILLINUX} ${HOST_MUSL_CC} ${CRYPTSETUP_BUILD}
	cd ${UTILLINUX}; [ -f Makefile ] || CC=${HOST_MUSL_CC} CFLAGS="${CRYPTSETUP_CFLAGS} -fPIC -Wl,--dynamic-linker=${HOST_MUSL_BUILD}/lib/libc.so" ./autogen.sh
	cd ${UTILLINUX}; [ -f Makefile ] || CC=${HOST_MUSL_CC} CFLAGS="${CRYPTSETUP_CFLAGS} -fPIC -Wl,--dynamic-linker=${HOST_MUSL_BUILD}/lib/libc.so" ./configure \
		--prefix=${CRYPTSETUP_BUILD}/ --enable-static \
		--disable-all-programs --enable-libuuid --enable-uuid \
		--without-ncurses --without-ncursesw --without-tinfo \
		--disable-bash-completion
	+CC=${HOST_MUSL_CC} ${MAKE} -C ${UTILLINUX} all install
	cp ${UTILLINUX}/.libs/libuuid.* ${CRYPTSETUP_BUILD}/lib/

${CRYPTSETUP_BUILD}/lib/libpopt.a: ${POPT} ${HOST_MUSL_CC} ${CRYPTSETUP_BUILD}
	cd ${POPT}; [ -f Makefile ] || CC=${HOST_MUSL_CC} CFLAGS="$(CRYPTSETUP_CFLAGS) -fPIC -Wl,--dynamic-linker=${HOST_MUSL_BUILD}/lib/libc.so" ./configure \
		--prefix=${CRYPTSETUP_BUILD}/ --enable-static
	+CC=${HOST_MUSL_CC} ${MAKE} -C ${POPT} all install

${CRYPTSETUP_BUILD}/lib/libjson-c.a: ${JSONC} ${HOST_MUSL_CC} ${CRYPTSETUP_BUILD}
	cd ${JSONC}; [ -f Makefile ] || CC=${HOST_MUSL_CC} CFLAGS="${CRYPTSETUP_CFLAGS} -fPIC" ./autogen.sh && autoreconf -i
	cd ${JSONC}; [ -f Makefile ] || CC=${HOST_MUSL_CC} CFLAGS="${CRYPTSETUP_CFLAGS} -fPIC -Wl,--dynamic-linker=${HOST_MUSL_BUILD}/lib/libc.so" ./configure \
		--prefix=${CRYPTSETUP_BUILD}/ --enable-static
	+CC=${HOST_MUSL_CC} CFLAGS=-fPIC ${MAKE} -C ${JSONC} all install

${CRYPTSETUP_BUILD}/lib/libcryptsetup.a: ${CRYPTSETUP} ${CRYPTSETUP_BUILD}/lib/libpopt.a ${CRYPTSETUP_BUILD}/lib/libdevmapper.a ${CRYPTSETUP_BUILD}/lib/libuuid.a ${CRYPTSETUP_BUILD}/lib/libjson-c.a ${HOST_MUSL_CC} ${CRYPTSETUP_BUILD}
	rsync -rv cryptsetup-override/ ${CRYPTSETUP}/
	cd ${CRYPTSETUP}; [ -f Makefile ] || CC=${HOST_MUSL_CC} CFLAGS="${CRYPTSETUP_CFLAGS} -I${CRYPTSETUP_BUILD}/include -I${LKL_BUILD}/include -fPIC" LDFLAGS="-L${CRYPTSETUP_BUILD}/lib" ./autogen.sh
	cd ${CRYPTSETUP}; CC=${HOST_MUSL_CC} CFLAGS="${CRYPTSETUP_CFLAGS} --static -I${CRYPTSETUP_BUILD}/include -I${LKL_BUILD}/include -fPIC -Wl,--dynamic-linker=${HOST_MUSL_BUILD}/lib/libc.so" LDFLAGS="${LDFLAGS} -L${CRYPTSETUP_BUILD}/lib" ./configure --prefix=${CRYPTSETUP_BUILD}/ --enable-static --with-crypto-backend=kernel
	+CC=${HOST_MUSL_CC} ${MAKE} -C ${CRYPTSETUP} install-libLTLIBRARIES
	+CC=${HOST_MUSL_CC} ${MAKE} -C ${CRYPTSETUP} install-includeHEADERS


MBEDTLS_SRCS = $(wildcard ${MBEDTLS}/*.c)
MBEDTLS_OBJS = $(MBEDTLS_SRCS:.c=.o)

${MBEDTLS}/mbedtls.a: ${MBEDTLS_OBJS}
	ar rc $@ $^

$(MBEDTLS_OBJS): $(MBEDTLS)/%.o: ${MBEDTLS}/%.c
	$(CC) -c --std=gnu11 -I${MBEDTLS}/include $(CFLAGS_MBEDTLS) $< -o $@

clean:
	+[ -f ${CRYPTSETUP}/Makefile ] && ${MAKE} -C ${CRYPTSETUP} distclean || true
	+[ -f ${POPT}/Makefile ] && ${MAKE} -C ${POPT} distclean || true
	+[ -f ${UTILLINUX}/Makefile ] && ${MAKE} -C ${UTILLINUX} distclean || true
	+[ -f ${DEVICEMAPPER}/Makefile ] && ${MAKE} -C ${DEVICEMAPPER} distclean || true
	+[ -f ${JSONC}/Makefile ] && ${MAKE} -C ${JSONC} distclean || true
	+rm -rf $(MBEDTLS)/mbedtls.a $(MBEDTLS)/*.o 
