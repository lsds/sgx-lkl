# Makefile configuratiuon for the SGX-LKL project

# Create a DEBUG build of SGX-LKL
DEBUG       ?= false

# Turn on debug tracing for LKL
LKL_DEBUG   ?= false

# Select libc version (currently only musl libc is supported)
LIBC        ?= musl

SGXLKL_ROOT                 ?= $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
$(info $$SGXLKL_ROOT        = [${SGXLKL_ROOT}])

SGXLKL_RUN_TARGET           ?= sgx-lkl-run-oe
SGXLKL_LIB_TARGET           ?= libsgxlkl.so
SGXLKL_LIB_TARGET_SIGNED    ?= libsgxlkl.so.signed
SGXLKL_STATIC_LIB           ?= libsgxlkl.a

LINUX_HEADERS_INC           ?= /usr/include
FORCE_SUBMODULES_VERSION    ?= false
FORCE_SUBMODULES_UPDATE     ?= false
BUILD_LINK_NAME             ?= build

SGXLKL_CFLAGS_EXTRA         ?= $(LIBC_CFLAGS)
SGXLKL_BUILD_VARIANT        ?= sgx-lkl-$(BUILD_VARIANT)

TOOLS                       ?= ${SGXLKL_ROOT}/tools
TOOLS_BUILD                 ?= $(BUILD_DIR)/tools
TOOLS_SRC                   ?= $(wildcard $(TOOLS)/*.c)
TOOLS_OBJ                   ?= $(addprefix $(TOOLS_BUILD)/, $(notdir $(TOOLS_SRC:.c=)))

ifeq ($(LIBC),glibc)
include $(SGXLKL_ROOT)/config.glibc.mak
else
ifeq ($(LIBC),musl)
include $(SGXLKL_ROOT)/config.musl.mak
else
$(error LIBC $(LIBC) not supported)
endif
endif

# SGX-LKL third party defines
CRYPTSETUP                          ?= ${SGXLKL_ROOT}/third_party/cryptsetup
CRYPTSETUP_BUILD                    ?= ${BUILD_DIR}/cryptsetup
THIRD_PARTY_LIB_CRYPTSETUP          ?= ${CRYPTSETUP_BUILD}/lib/libcryptsetup.a

# Device mapper library
DEVICEMAPPER                        ?= ${SGXLKL_ROOT}/third_party/devicemapper
THIRD_PARTY_LIB_DEVICE_MAPPER       ?= ${CRYPTSETUP_BUILD}/lib/libdevmapper.a

# ext2fs library
# The ext2fs library is used in combination with cryptsetup to create empty
# encrypted ext4 disk images at start-up within the enclave.
# This opt-in functionality is enabled through the application config and is
# useful for scenarios where data should be passed securily between applications
# in a batch computation style without the end-user knowing the encryption keys.
# Encryption keys are generated within the enclave and securily stored in a key
# store like AKV.
E2FSPROGS                           ?= ${SGXLKL_ROOT}/third_party/e2fsprogs
E2FSPROGS_BUILD                     ?= ${BUILD_DIR}/e2fsprogs
THIRD_PARTY_LIB_EXT2FS              ?= ${E2FSPROGS_BUILD}/lib/libext2fs.a

# Linux utils library
UTILLINUX                           ?= ${SGXLKL_ROOT}/third_party/util-linux
THIRD_PARTY_LIB_UUID                ?= ${CRYPTSETUP_BUILD}/lib/libuuid.a

# Linux popt library
POPT                                ?= ${SGXLKL_ROOT}/third_party/popt
THIRD_PARTY_LIB_POPT                ?= ${CRYPTSETUP_BUILD}/lib/libpopt.a

# json c library
JSONC                               ?= ${SGXLKL_ROOT}/third_party/json-c
THIRD_PARTY_LIB_JSON                ?= ${CRYPTSETUP_BUILD}/lib/libjson-c.a

# Wireguard library
WIREGUARD                           ?= ${SGXLKL_ROOT}/third_party/wireguard

# CURL for HTTP support
CURL                                ?= ${SGXLKL_ROOT}/third_party/curl
LIB_CURL_BUILD                      ?= ${BUILD_DIR}/curl
THIRD_PARTY_LIB_CURL                ?= ${LIB_CURL_BUILD}/libcurl.a

# OE_STUBS for full mbedTLS support
OE_STUBS                            ?= ${LIB_CURL_BUILD}/liboe_stubs.a

# Linux kernel library
LKL                                 ?= $(SGXLKL_ROOT)/lkl
LKL_BUILD                           ?= ${BUILD_DIR}/lkl
LIBLKL                              ?= ${LKL_BUILD}/lib/liblkl.a
LKL_HEADERS                         ?= ${LKL_BUILD}/include/lkl/bits.h ${LKL_BUILD}/include/lkl/syscalls.h
LKL_CFLAGS_EXTRA                    ?= -fPIE

ifeq ($(RELEASE),true)
    SGXLKL_CFLAGS           += -DSGXLKL_RELEASE
    SGXLKL_CFLAGS_EXTRA     += -DSGXLKL_RELEASE
    THIRD_PARTY_CFLAGS      += -DSGXLKL_RELEASE
endif

ifeq ($(DEBUG),true)
    SGXLKL_CFLAGS           += -g3 -ggdb3 -O0

    ifeq ($(LIBC),musl)
        LIBC_CONFIGURE_OPTS     += --disable-optimize --enable-debug
    endif

    SGXLKL_CFLAGS_EXTRA     += -g3 -ggdb3 -O0 -DDEBUG

    ifeq ($(LKL_DEBUG), true)
        SGXLKL_CFLAGS_EXTRA     += -DLKL_DEBUG
        LKL_CFLAGS_EXTRA        += -DLKL_DEBUG
    endif

    ifeq ($(VIRTIO_TEST_HOOK), true)
        SGXLKL_CFLAGS_EXTRA     += -DVIRTIO_TEST_HOOK
    endif

    THIRD_PARTY_CFLAGS      += -g3 -ggdb3 -O0

else ifeq ($(DEBUG),opt)

    SGXLKL_CFLAGS           += -g3 -ggdb3 -O3
    SGXLKL_CFLAGS_EXTRA     += -g3 -ggdb3 -O3
    THIRD_PARTY_CFLAGS      += -g3 -ggdb3 -O3

else

    SGXLKL_CFLAGS           += -O3
    SGXLKL_CFLAGS_EXTRA     += -O3
    THIRD_PARTY_CFLAGS      += -O3

endif

ifeq ($(DEBUG),true)
  CMAKE_BUILD_TYPE=Debug
else
  CMAKE_BUILD_TYPE=Release
endif

# OpenEnclave
export OE_SDK_ROOT := $(shell pkg-config oeenclave-gcc --variable=prefix)
export OE_SDK_INCLUDES := $(OE_SDK_ROOT)/include
export OE_SDK_LIBS := $(OE_SDK_ROOT)/lib
export OE_OESIGN_TOOL_PATH := $(OE_SDK_ROOT)/bin

OPENENCLAVE = ${OE_SDK_ROOT}/lib/openenclave/enclave/liboeenclave.a

ifeq (${OE_SDK_ROOT},)
    $(info Could not find the OpenEnclave SDK installation)
    $(info Did you source {openenclave_root}/share/openenclave/openenclaverc?)
    $(error SGX-LKL requires a modified version of the OpenEnclave SDK to run, which can be \
            found at https://github.com/openenclave/openenclave on the feature/sgx-lkl-support branch)
endif
