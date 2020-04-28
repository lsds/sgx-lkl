# config file for SGX-LKL MUSL libc based project

ARCH                    ?= x86_64
MUSL_LIBC_BASE_DIR      ?= $(SGXLKL_ROOT)
BUILD_DIR               ?= $(MUSL_LIBC_BASE_DIR)/build_musl
HOST_MUSL               ?= $(MUSL_LIBC_BASE_DIR)/host-musl
HOST_LIBC_BLD_DIR       ?= $(BUILD_DIR)/host-musl
HOST_CC                 ?= ${HOST_LIBC_BLD_DIR}/bin/musl-gcc
HOST_MUSL_BUILD         ?= ${HOST_CC}
SGXLKL_LIBC_SRC_DIR     ?= $(MUSL_LIBC_BASE_DIR)/sgx-lkl-musl
SGXLKL_LIBC_BLD_DIR     ?= ${BUILD_DIR}/sgx-lkl-musl
BUILD_VARIANT           ?= musl
SGXLKL_CFLAGS           ?= -std=c11 -Wall -Werror -isystem -I${SGXLKL_LIBC_SRC_DIR}/src/internal/ -DLKL_HOST_CONFIG_VIRTIO_NET=y -DLKL_HOST_CONFIG_POSIX=y -DOPENSSL_EXTRA
GLIBC_CFLAGS            ?= -O2
LIBC_CONFIGURE_OPTS     ?=
LIBC_CFLAGS             ?= -fPIC -D__USE_GNU
THIRD_PARTY_CFLAGS      = -fPIC -Wl,--dynamic-linker=${HOST_LIBC_BLD_DIR}/lib/libc.so
SGXLKL_INCLUDES         ?= -I$(SGXLKL_LIBC_SRC_DIR)/src/internal -I$(SGXLKL_LIBC_SRC_DIR)/src/include -I$(SGXLKL_LIBC_BLD_DIR)/include -I$(SGXLKL_LIBC_SRC_DIR)/arch/$(ARCH)
