# Disable verbose output and implicit rules (harder to debug)
#.SUFFIXES:
#MAKEFLAGS += --no-print-directory

#TODO: use autoconf or auto detect
LINUX_HEADERS_INC ?= /usr/include

FORCE_SUBMODULES_VERSION ?= false

ROOT_DIR ?= $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
BUILD_DIR ?= $(ROOT_DIR)/build

TESTS ?= $(ROOT_DIR)/tests
TESTS_BUILD ?= $(BUILD_DIR)/tests
TESTS_SRC ?= $(sort $(wildcard $(TESTS)/*.c))
TESTS_OBJ ?= $(addprefix $(TESTS_BUILD)/, $(notdir $(TESTS_SRC:.c=)))

TOOLS ?= ${ROOT_DIR}/tools
TOOLS_BUILD ?= $(BUILD_DIR)/tools
TOOLS_SRC ?= $(wildcard $(TOOLS)/*.c)
TOOLS_OBJ ?= $(addprefix $(TOOLS_BUILD)/, $(notdir $(TOOLS_SRC:.c=)))

CRYPTSETUP ?= ${ROOT_DIR}/third_party/cryptsetup
CRYPTSETUP_BUILD ?= ${BUILD_DIR}/cryptsetup
DEVICEMAPPER ?= ${ROOT_DIR}/third_party/devicemapper
UTILLINUX ?= ${ROOT_DIR}/third_party/util-linux
POPT ?= ${ROOT_DIR}/third_party/popt
JSONC ?= ${ROOT_DIR}/third_party/json-c
MBEDTLS ?= ${ROOT_DIR}/third_party/mbedtls

LKL ?= $(ROOT_DIR)/lkl
LKL_BUILD ?= ${BUILD_DIR}/lkl
LIBLKL ?= ${LKL_BUILD}/lib/liblkl.a

HOST_MUSL ?= $(ROOT_DIR)/host-musl
HOST_MUSL_BUILD ?= $(BUILD_DIR)/host-musl
HOST_MUSL_CC ?= ${HOST_MUSL_BUILD}/bin/musl-gcc
SGX_LKL_MUSL ?= $(ROOT_DIR)/sgx-lkl-musl
SGX_LKL_MUSL_BUILD ?= ${BUILD_DIR}/sgx-lkl-musl
# Headers not exported by LKL and built by a custom tool's output cat to the file instead
LKL_SGXMUSL_HEADERS ?= ${LKL_BUILD}/include/lkl/bits.h ${LKL_BUILD}/include/lkl/syscalls.h

# Location of enclave debug key (used for signing the enclave)
ENCLAVE_DEBUG_KEY=${BUILD_DIR}/config/enclave_debug.key

SGXLKL_CFLAGS ?= -std=c11 -Wall -Werror -isystem ${SGX_LKL_MUSL}/src/internal/ -DLKL_HOST_CONFIG_VIRTIO_NET=y -DLKL_HOST_CONFIG_POSIX=y

MUSL_CONFIGURE_OPTS ?=
MUSL_CFLAGS ?= -fPIC -D__USE_GNU

CRYPTSETUP_CFLAGS ?=

DEBUG ?= false

ifeq ($(DEBUG),true)
	SGXLKL_CFLAGS += -g3 -ggdb3 -O0
	MUSL_CONFIGURE_OPTS += --disable-optimize --enable-debug
	MUSL_CFLAGS += -g3 -ggdb3 -O0 -DDEBUG
	CRYPTSETUP_CFLAGS += -g3 -ggdb3 -O0
else ifeq ($(DEBUG),opt)
	SGXLKL_CFLAGS += -g3 -ggdb3 -O3
	MUSL_CFLAGS += -g3 -ggdb3 -O3
	CRYPTSETUP_CFLAGS += -g3 -ggdb3 -O3
else
	SGXLKL_CFLAGS += -O3
	MUSL_CFLAGS += -O3
	CRYPTSETUP_CFLAGS += -O3
endif
