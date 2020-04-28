# config file for SGX-LKL GNU libc based project

ARCH                    ?= x86_64
HOST_CC                 ?= /usr/bin/gcc
GLIBC_BASE_DIR          ?= $(SGXLKL_ROOT)
BUILD_DIR               ?= $(GLIBC_BASE_DIR)/build_glibc
SGXLKL_LIBC_SRC_DIR     ?= $(GLIBC_BASE_DIR)/sgx-lkl-glibc
SGXLKL_GLIBC_BLD_DIR    ?= $(GLIBC_BASE_DIR)/sgx-lkl-glibc/build
HOST_LIBC_BLD_DIR       ?= $(BUILD_DIR)/host-glibc
SGXLKL_LIBC_BLD_DIR     ?= ${BUILD_DIR}/sgx-lkl-glibc
BUILD_VARIANT           ?= glibc
SGXLKL_CFLAGS           ?= -std=c11 -Wall -Werror -isystem -DLKL_HOST_CONFIG_VIRTIO_NET=y -DLKL_HOST_CONFIG_POSIX=y -DOPENSSL_EXTRA
GLIBC_CONFIG_OPTS       ?= --disable-profile --disable-nscd --disable-crypt
LIBC_CFLAGS             ?= -fPIC -D__USE_GNU
THIRD_PARTY_CFLAGS      = -fPIC
SGXLKL_INCLUDES         ?= -I$(HOST_LIBC_BLD_DIR)/include
