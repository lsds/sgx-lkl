include config.mak

.PHONY: host-musl lkl sgx-lkl-musl-config sgx-lkl-musl sgx-lkl tools clean enclave-debug-key

PREFIX=/usr/local

# Boot memory reserved for LKL/kernel (in MB)
BOOT_MEM=32 # Default in LKL is 64

# Max. number of enclave threads/TCS
NUM_TCS=8

HW_MODE=yes

default: all

# Default is to build everything
all: sgx-lkl-musl sgx-lkl

sim: HW_MODE=no
sim: all

MAKE_ROOT=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))

# Vanilla Musl compiler
host-musl ${HOST_MUSL_CC}: | ${HOST_MUSL}/.git ${HOST_MUSL_BUILD}
	cd ${HOST_MUSL}; [ -f config.mak ] || CFLAGS="$(MUSL_CFLAGS)" ./configure \
		$(MUSL_CONFIGURE_OPTS) \
		--prefix=${HOST_MUSL_BUILD}
	+${MAKE} -C ${HOST_MUSL} CFLAGS="$(MUSL_CFLAGS)" install
	ln -fs ${LINUX_HEADERS_INC}/linux/ ${HOST_MUSL_BUILD}/include/linux
	ln -fs ${LINUX_HEADERS_INC}/x86_64-linux-gnu/asm/ ${HOST_MUSL_BUILD}/include/asm
	ln -fs ${LINUX_HEADERS_INC}/asm-generic/ ${HOST_MUSL_BUILD}/include/asm-generic
	# Fix musl-gcc for gcc version that have been built with --enable-default-pie
	gcc -v 2>&1 | grep "\-\-enable-default-pie" > /dev/null && sed -i 's/"$$@"/-fpie -pie "\$$@"/g' ${HOST_MUSL_BUILD}/bin/musl-gcc || true

# LKL's static library and include/ header directory
lkl ${LIBLKL} ${LKL_BUILD}/include: ${HOST_MUSL_CC} | ${LKL}/.git ${LKL_BUILD} src/lkl/override/defconfig
	# Override lkl's defconfig with our own
	cp -Rv src/lkl/override/defconfig ${LKL}/arch/lkl/defconfig
	cp -Rv src/lkl/override/include/uapi/asm-generic/stat.h ${LKL}/include/uapi/asm-generic/stat.h
	grep "include \"sys/stat.h" lkl/tools/lkl/include/lkl.h > /dev/null || sed  -i '/define _LKL_H/a \\n#include "sys/stat.h"\n#include "time.h"' lkl/tools/lkl/include/lkl.h
	# Set bootmem size (default in LKL is 64MB)
	sed -i 's/static unsigned long mem_size = .*;/static unsigned long mem_size = ${BOOT_MEM} \* 1024 \* 1024;/g' lkl/arch/lkl/kernel/setup.c
	+DESTDIR=${LKL_BUILD} ${MAKE} -C ${LKL}/tools/lkl -j`tools/ncore.sh` CC=${HOST_MUSL_CC} PREFIX="" \
		${LKL}/tools/lkl/liblkl.a
	mkdir -p ${LKL_BUILD}/lib
	cp ${LKL}/tools/lkl/liblkl.a $(LKL_BUILD)/lib
	+DESTDIR=${LKL_BUILD} ${MAKE} -C ${LKL}/tools/lkl -j`tools/ncore.sh` CC=${HOST_MUSL_CC} PREFIX="" \
		TARGETS="" headers_install
	# Bugfix, prefix symbol that collides with musl's one
	find ${LKL_BUILD}/include/ -type f -exec sed -i 's/struct ipc_perm/struct lkl_ipc_perm/' {} \;
	# Bugfix, lkl_host.h redefines struct iovec in older versions of LKL.
	grep "CONFIG_AUTO_LKL_POSIX_HOST" ${LKL_BUILD}/include/lkl_host.h > /dev/null && find ${LKL_BUILD}/include/ -type f -exec sed -i 's/struct iovec/struct lkl__iovec/' {} \; || true # struct lkl_iovec already exists
	+${MAKE} headers_install -C ${LKL} ARCH=lkl INSTALL_HDR_PATH=${LKL_BUILD}/

tools: ${TOOLS_OBJ}

# Generic tool rule (doesn't actually depend on lkl_lib, but on LKL headers)
${TOOLS_BUILD}/%: ${TOOLS}/%.c ${HOST_MUSL_CC} ${LKL_LIB} | ${TOOLS_BUILD}
	${HOST_MUSL_CC} ${SGXLKL_CFLAGS} --static -I${LKL_BUILD}/include/ -o $@ $<

${CRYPTSETUP_BUILD}/lib/libcryptsetup.a ${CRYPTSETUP_BUILD}/lib/libpopt.a ${CRYPTSETUP_BUILD}/lib/libdevmapper.a ${CRYPTSETUP_BUILD}/lib/libuuid.a ${CRYPTSETUP_BUILD}/lib/libjson-c.a ${MBEDTLS}/mbedtls.a: ${LKL_BUILD}/include
	+${MAKE} -C ${MAKE_ROOT}/third_party $@

# More headers required by SGX-Musl not exported by LKL, given by a custom tool's output
${LKL_SGXMUSL_HEADERS}: ${LKL_BUILD}/include/lkl/%.h: ${TOOLS_BUILD}/lkl_%
	$< > $@

# SGX-LKL-Musl
sgx-lkl-musl-config:
	cd ${SGX_LKL_MUSL}; [ -f config.mak ] || CFLAGS="$(MUSL_CFLAGS)" ./configure \
		$(MUSL_CONFIGURE_OPTS) \
		--prefix=${SGX_LKL_MUSL_BUILD} \
		--lklheaderdir=${LKL_BUILD}/include/ \
		--lkllib=${LIBLKL} \
		--sgxlklheaderdir=${MAKE_ROOT}/src/include \
		--sgxlkllib=${BUILD_DIR}/sgxlkl/libsgxlkl.a \
		--cryptsetupheaderdir=${CRYPTSETUP_BUILD}/include/ \
		--cryptsetuplib="${CRYPTSETUP_BUILD}/lib/libcryptsetup.a ${CRYPTSETUP_BUILD}/lib/libpopt.a ${CRYPTSETUP_BUILD}/lib/libdevmapper.a ${CRYPTSETUP_BUILD}/lib/libuuid.a ${CRYPTSETUP_BUILD}/lib/libjson-c.a" \
		--disable-shared \
		--enable-sgx-hw=${HW_MODE}

sgx-lkl-musl: ${LIBLKL} ${LKL_SGXMUSL_HEADERS} ${CRYPTSETUP_BUILD}/lib/libcryptsetup.a sgx-lkl-musl-config sgx-lkl $(ENCLAVE_DEBUG_KEY) | ${SGX_LKL_MUSL_BUILD}
	+${MAKE} -C ${SGX_LKL_MUSL} CFLAGS="$(MUSL_CFLAGS)"
	cp $(SGX_LKL_MUSL)/lib/libsgxlkl.so $(BUILD_DIR)/libsgxlkl.so
# This way the debug info will be automatically picked up when debugging with gdb. TODO: Fix...
	@if [ "$(HW_MODE)" = "yes" ]; then objcopy --only-keep-debug $(BUILD_DIR)/libsgxlkl.so $(BUILD_DIR)/sgx-lkl-run.debug; fi

sgx-lkl-sign: $(BUILD_DIR)/libsgxlkl.so $(ENCLAVE_DEBUG_KEY)
	@if [ "$(HW_MODE)" = "yes" ]; then $(BUILD_DIR)/sgx-lkl-sign -t $(NUM_TCS) -k $(ENCLAVE_DEBUG_KEY) -f $(BUILD_DIR)/libsgxlkl.so; fi

# compile sgx-lkl sources

sgx-lkl: sgx-lkl-musl-config ${MBEDTLS}/mbedtls.a
	make -C src all HW_MODE=$(HW_MODE) LIB_SGX_LKL_BUILD_DIR="$(BUILD_DIR)"

$(ENCLAVE_DEBUG_KEY):
	@mkdir -p $(dir $@ )
	tools/gen_enclave_key.sh $@

enclave-debug-key: $(ENCLAVE_DEBUG_KEY)

# Build directories (one-shot after git clone or clean)
${BUILD_DIR} ${TOOLS_BUILD} ${LKL_BUILD} ${HOST_MUSL_BUILD} ${SGX_LKL_MUSL_BUILD} ${CRYPTSETUP_BUILD}:
	@mkdir -p $@

# Submodule initialisation (one-shot after git clone)
${HOST_MUSL}/.git ${LKL}/.git ${SGX_LKL_MUSL}/.git:
	[ "$(FORCE_SUBMODULES_VERSION)" = "true" ] || git submodule update --init $($@:.git=)

install: $(BUILD_DIR)/libsgxlkl.so $(BUILD_DIR)/sgx-lkl-run
	mkdir -p ${PREFIX}/bin ${PREFIX}/lib
	cp $(BUILD_DIR)/libsgxlkl.so $(PREFIX)/lib
	cp $(BUILD_DIR)/sgx-lkl-run $(PREFIX)/bin
	cp $(BUILD_DIR)/sgx-lkl-sign $(PREFIX)/bin
	cp $(TOOLS)/sgx-lkl-java $(PREFIX)/bin
	cp $(TOOLS)/sgx-lkl-disk $(PREFIX)/bin

uninstall:
	rm -rf ~/.cache/sgxlkl
	rm -f $(PREFIX)/lib/libsgxlkl.so
	rm -f $(PREFIX)/bin/sgx-lkl-run
	rm -f $(PREFIX)/bin/sgx-lkl-sign
	rm -f $(PREFIX)/bin/sgx-lkl-java
	rm -f $(PREFIX)/bin/sgx-lkl-disk

clean:
	rm -rf ${BUILD_DIR}
	+${MAKE} -C ${HOST_MUSL} distclean || true
	+${MAKE} -C ${SGX_LKL_MUSL} distclean || true
	+${MAKE} -C ${LKL} clean || true
	+${MAKE} -C ${LKL}/tools/lkl clean || true
	+${MAKE} -C ${MAKE_ROOT}/third_party clean || true
	+${MAKE} -C src LIB_SGX_LKL_BUILD_DIR="$(BUILD_DIR)" clean || true
	rm -f ${HOST_MUSL}/config.mak
	rm -f ${SGX_LKL_MUSL}/config.mak
