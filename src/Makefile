include ../config.mak

LIB_SGXLKL_BUILD ?= $(BUILD_DIR)

srcdir = ${SGXLKL_ROOT}/src
musl_srcdir = $(SGXLKL_LIBC_SRC_DIR)/src
sgxlkl_toolsdir = ../tools

CC = gcc
CROSS_COMPILE =
RANLIB  = $(CROSS_COMPILE)ranlib

CFLAGS_MAIN = -I$(OE_SDK_INCLUDES)
CFLAGS_ENCLAVE = -I$(OE_SDK_INCLUDES) -I${OE_SDK_INCLUDES}/openenclave/3rdparty -fPIE
LINK_MAIN =

GIT_VERSION = "$(shell git describe --dirty --always --tags || echo unknown)"
LKL_VERSION = "$(shell make --quiet -C ${SGXLKL_ROOT}/lkl kernelversion)"

CFLAGS_MAIN += $(SGXLKL_CFLAGS_EXTRA) -DGIT_VERSION=\"$(GIT_VERSION)\" -DLKL_VERSION=\"$(LKL_VERSION)\"

# Copied from sgx-lkl-musl/config.mak after ./configure
# TODO: Do not hardcode cflags here
CFLAGS_AUTO = -g -pipe -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections \
-Werror=implicit-function-declaration -Werror=implicit-int -Werror=pointer-sign -fPIC
CFLAGS_C99FSE = -std=c99 -ffreestanding -fexcess-precision=standard -frounding-math -Wa,--noexecstack

LIBVICSETUP_DIR = $(srcdir)/vicsetup/libvicsetup

CFLAGS_SGXLKL_ALL = $(CFLAGS_C99FSE) $(CFLAGS_AUTO) $(CFLAGS_MAIN) $(MUSL_CFLAGS)
CFLAGS_SGXLKL_ALL += -D_XOPEN_SOURCE=700
CFLAGS_SGXLKL_ALL += $(SGXLKL_INCLUDES) -I$(E2FSPROGS_BUILD)/include -I$(srcdir)/libjson/include -I$(LIBVICSETUP_DIR)/include -I$(LIBVICSETUP_DIR)/argon2/include

# -----------------------------------------------------------------------------------------

all: builddirs $(SGXLKL_RUN_TARGET) $(SGXLKL_STATIC_LIB)

$(SGXLKL_RUN_TARGET): builddirs $(LIB_SGXLKL_BUILD)/$(SGXLKL_RUN_TARGET)

$(SGXLKL_STATIC_LIB): builddirs $(LIB_SGXLKL_BUILD)/sgxlkl/$(SGXLKL_STATIC_LIB)

builddirs:
	@mkdir -p $(LIB_SGXLKL_BUILD)/enclave
	@mkdir -p $(LIB_SGXLKL_BUILD)/main-oe
	@mkdir -p $(LIB_SGXLKL_BUILD)/sgxlkl
	@mkdir -p $(LIB_SGXLKL_BUILD)/deploy

# Build enclave static library: libsgxlkl.a

LIBVICSETUP_SRCS += $(LIBVICSETUP_DIR)/argon2//src/argon2.c
LIBVICSETUP_SRCS += $(LIBVICSETUP_DIR)/argon2//src/core.c
LIBVICSETUP_SRCS += $(LIBVICSETUP_DIR)/argon2//src/blake2/blake2b.c
LIBVICSETUP_SRCS += $(LIBVICSETUP_DIR)/argon2//src/thread.c
LIBVICSETUP_SRCS += $(LIBVICSETUP_DIR)/argon2//src/encoding.c
LIBVICSETUP_SRCS += $(LIBVICSETUP_DIR)/argon2//src/opt.c
LIBVICSETUP_SRCS += $(wildcard $(LIBVICSETUP_DIR)/*.c)

SGXLKL_SRCS = $(wildcard enclave/*.c) $(wildcard shared/*.c) $(wildcard sched/*.c) \
              $(wildcard legacy_host_interface/*.c) $(wildcard lkl/*.c) $(wildcard wireguard/*.c) $(wildcard attestation/*.c) $(wildcard libjson/*.c) $(LIBVICSETUP_SRCS)

OE_ENCLAVE_CALLS = enclave/sgxlkl_t.c
ifeq (,$(findstring ${OE_ENCLAVE_CALLS},$(SGXLKL_SRCS)))
  SGXLKL_SRCS += ${OE_ENCLAVE_CALLS}
endif

SGXLKL_OBJS=$(addprefix $(LIB_SGXLKL_BUILD)/sgxlkl/,$(SGXLKL_SRCS:.c=.o))

${OE_ENCLAVE_CALLS}: sgxlkl.edl
	${OE_OESIGN_TOOL_PATH}/oeedger8r --trusted $< --trusted-dir enclave/
	mv enclave/sgxlkl_t.h include/enclave/; mv enclave/sgxlkl_args.h include/shared/
	sed -i '/#include "sgxlkl_t.h"/c\#include "enclave/sgxlkl_t.h"' enclave/sgxlkl_t.c
	sed -i '/#include "sgxlkl_args.h"/c\#include "shared/sgxlkl_args.h"' enclave/sgxlkl_t.c
	sed -i '/#include "sgxlkl_args.h"/c\#include "shared/sgxlkl_args.h"' include/enclave/sgxlkl_t.h

$(SGXLKL_OBJS): $(LIB_SGXLKL_BUILD)/sgxlkl/%.o: %.c | $(SGXLKL_LIBC_BLD_DIR)/include ${OE_ENCLAVE_CALLS}
	@mkdir -p $(dir $@)
	@echo "CC $<"
	@$(CC) -I$(srcdir)/include $(CFLAGS_SGXLKL_ALL) $(CFLAGS_ENCLAVE) -c -o $@ $<

$(LIB_SGXLKL_BUILD)/sgxlkl/$(SGXLKL_STATIC_LIB): $(SGXLKL_OBJS) builddirs
	@echo "AR rc $@"
	@$(AR) rc $@ $(SGXLKL_OBJS)
	@echo "RANLIB $@"
	@$(RANLIB) $@

# Build run tool: sgx-lkl-run-oe

MAIN_OE_SRCS = $(wildcard main-oe/*.c) $(wildcard shared/*.c) $(wildcard host_interface/*.c)

OE_HOST_CALLS = main-oe/sgxlkl_u.c
ifeq (,$(findstring ${OE_HOST_CALLS},$(MAIN_OE_SRCS)))
  MAIN_OE_SRCS += ${OE_HOST_CALLS}
endif

MAIN_OE_OBJS =$(addprefix $(LIB_SGXLKL_BUILD)/main-oe/,$(MAIN_OE_SRCS:.c=.o))

OE_PKGCONFIG_OUTPUT := $(shell pkg-config oehost-gcc --libs)
ifeq ($(findstring sgx_dcap_ql,$(OE_PKGCONFIG_OUTPUT)),sgx_dcap_ql)
	DCAP_LIB=-lsgx_dcap_ql
endif

${OE_HOST_CALLS}: sgxlkl.edl
	${OE_OESIGN_TOOL_PATH}/oeedger8r --untrusted $< --untrusted-dir main-oe/
	mv main-oe/sgxlkl_u.h include/host/; mv main-oe/sgxlkl_args.h include/shared/
	sed -i '/#include "sgxlkl_u.h"/c\#include "host/sgxlkl_u.h"' main-oe/sgxlkl_u.c
	sed -i '/#include "sgxlkl_args.h"/c\#include "shared/sgxlkl_args.h"' main-oe/sgxlkl_u.c
	sed -i '/#include "sgxlkl_args.h"/c\#include "shared/sgxlkl_args.h"' include/host/sgxlkl_u.h

$(MAIN_OE_OBJS): $(LIB_SGXLKL_BUILD)/main-oe/%.o: %.c | ${OE_HOST_CALLS}
	@mkdir -p $(dir $@)
	@echo "CC $<"
	@$(CC) -I${LKL_BUILD}/include/ -I$(srcdir)/include -I$(srcdir)/main-oe/ $(CFLAGS_MAIN) -c -o $@ $<

$(LIB_SGXLKL_BUILD)/$(SGXLKL_RUN_TARGET): $(LIB_SGXLKL_BUILD)/main-oe/main-oe.a $(OE_SDK_LIBS)/openenclave/host/liboehost.a builddirs
	@echo "CC $<"
	@$(CC) $(CFLAGS_MAIN) -o $@ $(LIB_SGXLKL_BUILD)/main-oe/main-oe.a -ljson-c -lcrypto $(LINK_MAIN) \
	-pthread -ldl -lrt -lz -lm -Wl,-T $(sgxlkl_toolsdir)/sgx-lkl.ld -L$(OE_SDK_LIBS)/openenclave/host -rdynamic \
	-Wl,-z,noexecstack -loehost -ldl -lsgx_enclave_common -lsgx_urts -lssl -lcrypto $(DCAP_LIB)

$(LIB_SGXLKL_BUILD)/main-oe/main-oe.a: $(MAIN_OE_OBJS) builddirs
	@echo "AR rc $@"
	@$(AR) rc $@ $(MAIN_OE_OBJS)
	@echo "RANLIB $@"
	@$(RANLIB) $@

$(SGXLKL_LIBC_BLD_DIR)/include:
	[ "$(GLIBC_BUILD)" = "true" ] || $(MAKE) -C $(SGXLKL_LIBC_SRC_DIR) install-headers

clean:
	rm -rf $(LIB_SGXLKL_BUILD)/enclave
	rm -rf $(LIB_SGXLKL_BUILD)/main-oe
	rm -rf $(LIB_SGXLKL_BUILD)/sgxlkl
	rm -rf $(LIB_SGXLKL_BUILD)/$(SGXLKL_RUN_TARGET)
	rm -rf $(srcdir)/main-oe/sgxlkl_u.c $(srcdir)/include/host/sgxlkl_u.h $(srcdir)/enclave/sgxlkl_t.c $(srcdir)/include/enclave/sgxlkl_t.h

.PHONY: clean builddirs
