include config.mak

.PHONY: lkl sgx-lkl-musl-config sgx-lkl-musl sgx-lkl-glibc-config \
        sgx-lkl-glibc sgx-lkl tools clean

# Prefix where SGX-LKL is installed with install target
PREFIX ?= /opt/sgx-lkl

OESIGN_CONFIG_PATH = $(SGXLKL_ROOT)/config

.DEFAULT_GOAL:=all
default: all

all: update-git-submodules install-git-pre-commit-hook $(addprefix $(OE_SDK_ROOT)/lib/openenclave/, $(OE_LIBS)) $(BUILD_DIR)/$(SGXLKL_LIB_TARGET_SIGNED) fsgsbase-kernel-module

# Check if the user didn't override the default in-tree OE install location with another OE host install
ifeq ($(OE_SDK_ROOT),$(OE_SDK_ROOT_DEFAULT))
# Build and install Open Enclave locally
$(addprefix $(OE_SDK_ROOT)/lib/openenclave/, $(OE_LIBS)):
	# Don't build tests.
	# TODO replace with build option https://github.com/openenclave/openenclave/issues/2894
	cd $(OE_SUBMODULE) && sed -i '/add_subdirectory(tests)/d' CMakeLists.txt
	mkdir -p $(OE_SUBMODULE)/build
	cd $(OE_SUBMODULE)/build && cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE) -DCMAKE_INSTALL_PREFIX=$(OE_SDK_ROOT) -DENABLE_REFMAN=OFF -DCOMPILE_SYSTEM_EDL=OFF -DWITH_EEID=ON ..
	$(MAKE) -C $(OE_SUBMODULE)/build -j$(scripts/ncore.sh) && $(MAKE) -C $(OE_SUBMODULE)/build install
endif

# Install the glibc headers as for building libsgxlkl.so --nostdincludes is required.
glibc-header-install: | ${SGXLKL_LIBC_SRC_DIR}/.git ${HOST_LIBC_BLD_DIR}
	cd ${HOST_LIBC_BLD_DIR}; ${SGXLKL_LIBC_SRC_DIR}/configure --prefix=${HOST_LIBC_BLD_DIR} ${GLIBC_CONFIG_OPTS}
	cd ${HOST_LIBC_BLD_DIR}; ${MAKE} install-headers
	#cp -rpf ${LINUX_HEADERS_INC}/linux ${SGXLKL_LIBC_BLD_DIR}/include
	#cp -rpf ${LINUX_HEADERS_INC}/x86_64-linux-gnu/asm ${SGXLKL_LIBC_BLD_DIR}/include
	#cp -rpf ${LINUX_HEADERS_INC}/asm-generic ${SGXLKL_LIBC_BLD_DIR}/include
	#cp -rpf ${LINUX_HEADERS_INC}/x86_64-linux-gnu/gnu ${SGXLKL_LIBC_BLD_DIR}/include

# Regular musl host compiler
${HOST_MUSL_BUILD}: | ${HOST_MUSL}/.git ${HOST_LIBC_BLD_DIR}
	cd ${HOST_MUSL}; ( [ -f config.mak ] && [ -d ${HOST_LIBC_BLD_DIR} ] ) || CFLAGS="$(SGXLKL_CFLAGS_EXTRA)" ./configure \
		$(LIBC_CONFIGURE_OPTS) \
		--prefix=${HOST_LIBC_BLD_DIR}
	+${MAKE} -C ${HOST_MUSL} -j`scripts/ncore.sh` CFLAGS="$(SGXLKL_CFLAGS_EXTRA)" install
	ln -fs ${LINUX_HEADERS_INC}/linux/ ${HOST_LIBC_BLD_DIR}/include/linux
	ln -fs ${LINUX_HEADERS_INC}/x86_64-linux-gnu/asm/ ${HOST_LIBC_BLD_DIR}/include/asm
	ln -fs ${LINUX_HEADERS_INC}/asm-generic/ ${HOST_LIBC_BLD_DIR}/include/asm-generic
	# Fix musl-gcc for gcc versions that have been built with --enable-default-pie
	gcc -v 2>&1 | grep "\-\-enable-default-pie" > /dev/null && sed -i 's/"$$@"/-fpie -pie "\$$@"/g' ${HOST_LIBC_BLD_DIR}/bin/musl-gcc || true

${WIREGUARD}:
	+${MAKE} -C ${SGXLKL_ROOT}/third_party $@

${THIRD_PARTY_LIB_CRYPTSETUP} ${THIRD_PARTY_LIB_POPT} ${THIRD_PARTY_LIB_DEVICE_MAPPER} ${THIRD_PARTY_LIB_EXT2FS} ${THIRD_PARTY_LIB_UUID} ${THIRD_PARTY_LIB_JSON} ${THIRD_PARTY_LIB_CURL} ${OE_STUBS}: ${LKL_BUILD}/include
	+${MAKE} -C ${SGXLKL_ROOT}/third_party $@

# LKL's static library and include/ header directory
lkl ${LIBLKL} ${LKL_BUILD}/include: ${HOST_MUSL_BUILD} | ${LKL}/.git ${LKL_BUILD} ${WIREGUARD} src/lkl/override/defconfig
	# Add Wireguard
	cd ${LKL} && (if ! ${WIREGUARD}/contrib/kernel-tree/create-patch.sh | patch -p1 --dry-run --reverse --force >/dev/null 2>&1; then ${WIREGUARD}/contrib/kernel-tree/create-patch.sh | patch --forward -p1; fi) && cd -
	# Override lkl's defconfig with our own
	cp -Rv src/lkl/override/defconfig ${LKL}/arch/lkl/configs/defconfig
	+DESTDIR=${LKL_BUILD} ${MAKE} -C ${LKL}/tools/lkl -j`scripts/ncore.sh` CC=${HOST_CC} EXTRA_CFLAGS="$(LKL_CFLAGS_EXTRA)" PREFIX="" \
		${LKL}/tools/lkl/liblkl.a
	mkdir -p ${LKL_BUILD}/lib
	cp ${LKL}/tools/lkl/liblkl.a $(LKL_BUILD)/lib
	+DESTDIR=${LKL_BUILD} ${MAKE} -C ${LKL}/tools/lkl -j`scripts/ncore.sh` CC=${HOST_CC} EXTRA_CFLAGS="$(LKL_CFLAGS_EXTRA)" PREFIX="" \
		TARGETS="" headers_install
	# Bugfix, prefix symbol that collides with musl's one
	find ${LKL_BUILD}/include/ -type f -exec sed -i 's/struct ipc_perm/struct lkl_ipc_perm/' {} \;
	# Bugfix, lkl_host.h redefines struct iovec in older versions of LKL.
	grep "CONFIG_AUTO_LKL_POSIX_HOST" ${LKL_BUILD}/include/lkl_host.h > /dev/null && find ${LKL_BUILD}/include/ -type f -exec sed -i 's/struct iovec/struct lkl__iovec/' {} \; || true # struct lkl_iovec already exists
	+${MAKE} headers_install -C ${LKL} ARCH=lkl INSTALL_HDR_PATH=${LKL_BUILD}/

tools: ${TOOLS_OBJ}

# TODO remove tools rules after lkl_bits.c/lkl_syscalls.c are gone
#      (see also config.mak)
# Generic tool rule (doesn't actually depend on lkl_lib, but on LKL headers)
${TOOLS_BUILD}/%: ${TOOLS}/%.c ${HOST_MUSL_BUILD} ${LIBLKL} | ${TOOLS_BUILD}
	@echo "${HOST_CC} $<"
	@${HOST_CC} ${SGXLKL_CFLAGS} --static -I${LKL_BUILD}/include/ -o $@ $<

# More headers required by SGX-Musl not exported by LKL, given by a custom tool's output
${LKL_HEADERS}: ${LKL_BUILD}/include/lkl/%.h: ${TOOLS_BUILD}/lkl_%
	$< > $@

# SGX-LKL GLIBC configure
sgx-lkl-glibc-config: glibc-header-install ${SGXLKL_GLIBC_BLD_DIR}
	cd ${SGXLKL_GLIBC_BLD_DIR}; ${SGXLKL_LIBC_SRC_DIR}/configure \
		--prefix=${SGXLKL_LIBC_BLD_DIR} \
		${GLIBC_CONFIG_OPTS}
	# Add the configure options and required modification for supporting glibc

# SGX-LKL GLIBC build for generating libsgxlkl.so
sgx-lkl-glibc: ${LIBLKL} ${LKL_HEADERS} $(SGXLKL_BUILD_VARIANT)-config | ${SGXLKL_LIBC_BLD_DIR}
	+${MAKE} -C ${SGXLKL_GLIBC_BLD_DIR}
	# glibc version of libsgxlkl.so is not ready
	#cp $(SGXLKL_LIBC_BLD_DIR)/lib/$(SGXLKL_LIB_TARGET) $(BUILD_DIR)/$(SGXLKL_LIB_TARGET)

# Generate sgx-lkl-musl config
sgx-lkl-musl-config: ${OPENENCLAVE}
	cd ${SGXLKL_LIBC_SRC_DIR}; ( [ -f config.mak ] && [ -d ${SGXLKL_LIBC_BLD_DIR} ] ) || CFLAGS="$(SGXLKL_CFLAGS_EXTRA)" ./configure \
		$(LIBC_CONFIGURE_OPTS) \
		--prefix=${SGXLKL_LIBC_BLD_DIR} \
		--lklheaderdir=${LKL_BUILD}/include/ \
		--lkllib=${LIBLKL} \
		--sgxlklincludes="${SGXLKL_ROOT}/src/include ${CRYPTSETUP_BUILD}/include/ $(LINUX_SGX)/common/inc $(LINUX_SGX)/common/inc/internal" \
		--sgxlkllib=${BUILD_DIR}/sgxlkl/${SGXLKL_STATIC_LIB} \
		--sgxlkllibs="${THIRD_PARTY_LIB_CRYPTSETUP} ${THIRD_PARTY_LIB_POPT} ${THIRD_PARTY_LIB_DEVICE_MAPPER} ${THIRD_PARTY_LIB_EXT2FS} ${THIRD_PARTY_LIB_UUID} ${THIRD_PARTY_LIB_JSON} \
								  ${THIRD_PARTY_LIB_CURL} ${OE_STUBS} ${OE_SDK_LIBS}/openenclave/enclave/libmbedtls.a" \
		--disable-shared

sgx-lkl-musl: ${LIBLKL} ${LKL_HEADERS} $(SGXLKL_BUILD_VARIANT)-config sgx-lkl ${OE_STUBS} | ${SGXLKL_LIBC_BLD_DIR}
	+${MAKE} -C ${SGXLKL_LIBC_SRC_DIR} -j`scripts/ncore.sh` CFLAGS="$(SGXLKL_CFLAGS_EXTRA)"
	@cp $(SGXLKL_LIBC_SRC_DIR)/lib/$(SGXLKL_LIB_TARGET) $(BUILD_DIR)/$(SGXLKL_LIB_TARGET)

$(SGXLKL_RUN_TARGET):
	make -C src $(SGXLKL_RUN_TARGET)

# Compile SGX-LKL source files
sgx-lkl: ${THIRD_PARTY_LIB_CRYPTSETUP} ${THIRD_PARTY_LIB_EXT2FS} ${THIRD_PARTY_LIB_CURL}
	make -C src all

$(SGXLKL_LIB_TARGET): $(SGXLKL_BUILD_VARIANT)

# Generate the RSA key and sign the libsgxlkl.so
$(BUILD_DIR)/$(SGXLKL_LIB_TARGET_SIGNED): $(SGXLKL_LIB_TARGET)
	@echo "openssl genrsa -out private.pem -3 3072"
	@openssl genrsa -out $(BUILD_DIR)/private.pem -3 3072
	@echo "oesign sign -e $(SGXLKL_LIB_TARGET) -c config/eeid-params.conf -k private.pem"
	@$(OE_OESIGN_TOOL_PATH)/oesign sign -e $(BUILD_DIR)/$(SGXLKL_LIB_TARGET) -c $(OESIGN_CONFIG_PATH)/eeid-params.conf -k $(BUILD_DIR)/private.pem

# Create a link named build to appropiate build directory.
create-build-link:
	@rm -f $(BUILD_LINK_NAME)
	@ln -sf $(BUILD_DIR) $(BUILD_LINK_NAME)

# Build directories for individual (one-shot after git clone or clean)
${BUILD_DIR} ${TOOLS_BUILD} ${LKL_BUILD} ${HOST_LIBC_BLD_DIR} ${SGXLKL_LIBC_BLD_DIR} ${CRYPTSETUP_BUILD} ${SGXLKL_GLIBC_BLD_DIR}: create-build-link
	@mkdir -p $@

# Submodule initialisation (one-shot after git clone)
${HOST_MUSL}/.git ${LKL}/.git ${SGXLKL_LIBC_SRC_DIR}/.git:
	[ "$(FORCE_SUBMODULES_VERSION)" = "true" ] || git submodule update --progress --init $($@:.git=)

update-git-submodules:
	[ "$(FORCE_SUBMODULES_UPDATE)" = "false" ] || git submodule update --progress
	# Initialise the missing Open Enclave submodules
	cd $(OE_SUBMODULE) && git submodule update --recursive --progress --init

# Git pre-commit hook installation
install-git-pre-commit-hook: scripts/pre-commit
	cp scripts/pre-commit .git/hooks

fsgsbase-kernel-module:
	make -C tools/kmod-set-fsgsbase

install:
	mkdir -p ${PREFIX}/bin ${PREFIX}/lib ${PREFIX}/lib/gdb $(PREFIX)/lib/gdb/openenclave ${PREFIX}/share ${PREFIX}/share/schemas ${PREFIX}/tools ${PREFIX}/tools/kmod-set-fsgsbase
	cp $(BUILD_DIR)/$(SGXLKL_LIB_TARGET_SIGNED) $(PREFIX)/lib
	cp $(BUILD_DIR)/$(SGXLKL_RUN_TARGET) $(PREFIX)/bin
	cp $(TOOLS)/sgx-lkl-java $(PREFIX)/bin
	cp $(TOOLS)/sgx-lkl-disk $(PREFIX)/bin
	cp $(TOOLS)/sgx-lkl-setup $(PREFIX)/bin
	cp $(TOOLS)/sgx-lkl-cfg $(PREFIX)/bin
	cp $(TOOLS)/sgx-lkl-docker $(PREFIX)/bin
	cp $(TOOLS)/gdb/sgx-lkl-gdb $(PREFIX)/bin
	cp $(TOOLS)/gdb/gdbcommands.py $(PREFIX)/lib/gdb
	cp $(TOOLS)/gdb/sgx-lkl-gdb.py $(PREFIX)/lib/gdb
	cp -r $(OE_SDK_ROOT)/lib/openenclave/debugger/* $(PREFIX)/lib/gdb/openenclave
	cp ${TOOLS}/schemas/app-config.schema.json $(PREFIX)/share/schemas
	cp ${TOOLS}/schemas/host-config.schema.json $(PREFIX)/share/schemas
	cp ${TOOLS}/kmod-set-fsgsbase/mod_set_cr4_fsgsbase.ko $(PREFIX)/tools/kmod-set-fsgsbase/

uninstall:
	rm -rf ~/.cache/sgxlkl*
	rm -f $(PREFIX)/lib/$(SGXLKL_LIB_TARGET) $(PREFIX)/lib/$(SGXLKL_LIB_TARGET_SIGNED)
	rm -f $(PREFIX)/bin/$(SGXLKL_RUN_TARGET)
	rm -f $(PREFIX)/bin/sgx-lkl-java
	rm -f $(PREFIX)/bin/sgx-lkl-disk
	rm -f $(PREFIX)/bin/sgx-lkl-setup
	rm -f $(PREFIX)/bin/sgx-lkl-cfg
	rm -f $(PREFIX)/bin/sgx-lkl-docker
	rm -f $(PREFIX)/bin/sgx-lkl-gdb
	rm -rf $(PREFIX)/lib/gdb
	rm -rf $(PREFIX)/tools/kmod-set-fsgsbase
	rm -rf $(PREFIX)/share/schemas
	rmdir $(PREFIX)/bin $(PREFIX)/lib $(PREFIX)/tools $(PREFIX)/share
	rmdir $(PREFIX)

builddirs:
	mkdir -p $(SGXLKL_GILBC_BDIR)

# Cleans the tree, but does not clean host_musl and the OE build
clean:
	@rm -rf $(BUILD_LINK_NAME) ${BUILD_DIR}
	+${MAKE} -C ${SGXLKL_LIBC_SRC_DIR} distclean || true
	+${MAKE} -C ${LKL} distclean || true
	+${MAKE} -C ${LKL}/tools/lkl clean || true
	+${MAKE} -C ${SGXLKL_ROOT}/third_party clean || true
	+${MAKE} -C ${SGXLKL_ROOT}/third_party distclean || true
	+${MAKE} -C src clean || true
	+${MAKE} -C tools/kmod-set-fsgsbase clean || true
	rm -f ${HOST_MUSL}/config.mak
	rm -f ${SGXLKL_LIBC_SRC_DIR}/config.mak

# Cleans everyting in the tree
distclean:
	@rm -rf $(BUILD_LINK_NAME) ${BUILD_DIR} $(OE_SUBMODULE)/build
	+${MAKE} -C ${HOST_MUSL} distclean || true
	+${MAKE} -C ${SGXLKL_LIBC_SRC_DIR} distclean || true
	+${MAKE} -C ${LKL} distclean || true
	+${MAKE} -C ${LKL}/tools/lkl clean || true
	+${MAKE} -C ${SGXLKL_ROOT}/third_party clean || true
	+${MAKE} -C ${SGXLKL_ROOT}/third_party distclean || true
	+${MAKE} -C src clean || true
	+${MAKE} -C tools/kmod-set-fsgsbase clean || true
	rm -f ${HOST_MUSL}/config.mak
	rm -f ${SGXLKL_LIBC_SRC_DIR}/config.mak
