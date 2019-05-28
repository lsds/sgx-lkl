include ../config.mak

# TODO Don't set (default) arch in Makefile
ARCH ?= x86_64

LIB_SGX_LKL_BUILD ?= $(BUILD_DIR)

HW_MODE ?= yes

sim: HW_MODE = no
sim: all

srcdir = ${ROOT_DIR}/src
musl_srcdir = $(SGX_LKL_MUSL)/src
sgxlkl_toolsdir = ../tools

CC = gcc
CROSS_COMPILE =
RANLIB  = $(CROSS_COMPILE)ranlib

ifeq ($(HW_MODE),yes)
  CFLAGS_SGX = -DSGXLKL_HW
  CFLAGS_LIBSGX = -DSGXLKL_HW
  CFLAGS_MAIN = -I$(LINUX_SGX)/common/inc/internal -I$(EPID_SDK) -I$(LINUX_SGX)/common/inc
  LINK_MAIN = -lcurl -lssl -lprotobuf-c -lcrypto
else
  CFLAGS_SGX =
  CFLAGS_LIBSGX =
  CFLAGS_MAIN =
  LINK_MAIN =
endif

ifeq ($(RELEASE),true)
  CFLAGS_MAIN += -DSGXLKL_RELEASE
  CFLAGS_SGX += -DSGXLKL_RELEASE
endif


ifeq ($(DEBUG),true)
  CFLAGS_LIBSGX += -DDEBUG -O1 -g3 -ggdb3
  CFLAGS_SGX += -DDEBUG -O0 -g3 -ggdb3
else ifeq ($(DEBUG),opt)
  CFLAGS_LIBSGX += -O3 -g3 -ggdb3
  CFLAGS_SGX += -O3 -g3 -ggdb3
else
  CFLAGS_SGX += -O3
  CFLAGS_LIBSGX = -O3
endif

CFLAGS_MAIN += $(CFLAGS_SGX)

CFLAGS_CTL =  -Ictl -Iinclude -I$(LINUX_SGX)/common/inc/internal -I$(EPID_SDK) -I$(LINUX_SGX)/common/inc -I${PROTOBUFC_RPC}/.. $(CFLAGS_SGX) --std=gnu11
LINK_CTL = -lcurl -lssl -lprotobuf-c -lcrypto

# Copied from sgx-lkl-musl/config.mak after ./configure
# TODO: Do not hardcode cflags here
CFLAGS_AUTO = -g -pipe -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -Werror=implicit-function-declaration -Werror=implicit-int -Werror=pointer-sign -fPIC
CFLAGS_C99FSE = -std=c99 -nostdinc -ffreestanding -fexcess-precision=standard -frounding-math -Wa,--noexecstack

CFLAGS_MUSL_ALL = $(CFLAGS_C99FSE) $(CFLAGS_AUTO) $(CFLAGS_SGX) $(MUSL_CFLAGS)
CFLAGS_MUSL_ALL += -D_XOPEN_SOURCE=700
CFLAGS_MUSL_ALL += -I$(SGX_LKL_MUSL)/src/internal -I$(SGX_LKL_MUSL)/src/include -I$(SGX_LKL_MUSL_BUILD)/include -I$(SGX_LKL_MUSL)/arch/$(ARCH) -I$(CRYPTSETUP_BUILD)/include -I${PROTOBUFC_BUILD}/include -I${PROTOBUFC_RPC}/..

ifeq ($(HW_MODE),yes)
  CFLAGS_MUSL_ALL += -I$(LINUX_SGX)/common/inc -I$(LINUX_SGX)/common/inc/internal
endif

#all: $(LIB_SGX_LKL_BUILD)/sgx-lkl-deploy
all: builddirs $(LIB_SGX_LKL_BUILD)/sgx/libsgx.a $(LIB_SGX_LKL_BUILD)/sgxlkl/libsgxlkl.a $(LIB_SGX_LKL_BUILD)/sgx-lkl-sign $(LIB_SGX_LKL_BUILD)/sgx-lkl-run $(LIB_SGX_LKL_BUILD)/sgx-lkl-ctl

builddirs:
	mkdir -p $(LIB_SGX_LKL_BUILD)/sgx
	mkdir -p $(LIB_SGX_LKL_BUILD)/main
	mkdir -p $(LIB_SGX_LKL_BUILD)/sgxlkl
	mkdir -p $(LIB_SGX_LKL_BUILD)/deploy
	mkdir -p $(LIB_SGX_LKL_BUILD)/ctl

# libsgx ----
LIBSGX_SRCS = sgx/sgx.c sgx/gdb_hook.c sgx/sgx_sign.c
LIBSGX_OBJS = $(addprefix $(LIB_SGX_LKL_BUILD)/,$(LIBSGX_SRCS:.c=.o))

$(LIB_SGX_LKL_BUILD)/sgx/libsgx.a: $(LIBSGX_OBJS)
	$(AR) rc $@ $^ sgx/libs/lible.o
	$(RANLIB) $@

# libsgx needs can't be built with -O0, force -O1
$(LIBSGX_OBJS): ${LIB_SGX_LKL_BUILD}/sgx/%.o: sgx/%.c
	$(CC) -c --std=gnu11 -Isgx/include  -I$(MBEDTLS)/include $(CFLAGS_LIBSGX) $< -o $@

# sgx-lkl-sign ----
SIGN_SRCS = sgxlkl_sign.c sgxlkl_sign_cmdline.c
SIGN_OBJS = $(addprefix $(LIB_SGX_LKL_BUILD)/sgx/,$(SIGN_SRCS:.c=.o))

$(LIB_SGX_LKL_BUILD)/sgx-lkl-sign: $(SIGN_OBJS) $(LIB_SGX_LKL_BUILD)/sgx/libsgx.a ${MBEDTLS}/mbedtls.a
	$(CC) $(CFLAGS_SGX) --std=gnu11 -fno-pie -no-pie -Isgx/include $^ -o $@

${SIGN_OBJS}: $(LIB_SGX_LKL_BUILD)/sgx/%.o: sgx/%.c
	$(CC) $(CFLAGS_SGX) -c --std=gnu11 -Isgx/include $< -o $@

# sgx-lkl-ctl ----
CTL_SRCS = $(wildcard attestation/*.c) $(wildcard ctl/*.c) wireguard/wireguard.c shared/sgxlkl_util.c  main/messages.pb-c.c sgx/sgxlkl_ctl.pb-c.c
CTL_OBJS = $(addprefix $(LIB_SGX_LKL_BUILD)/ctl/,$(CTL_SRCS:.c=.o))

${CTL_OBJS}: $(LIB_SGX_LKL_BUILD)/ctl/%.o: %.c | $(PROTOBUFC_RPC)/protobuf-c-rpc-client.a include/sgxlkl_ctl.pb-c.h include/messages.pb-c.h
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS_CTL) -c $< -o $@

$(LIB_SGX_LKL_BUILD)/sgx-lkl-ctl: builddirs $(CTL_OBJS) include/messages.pb-c.h
	$(CC) $(CFLAGS_CTL) $(CTL_OBJS) $(PROTOBUFC_RPC)/protobuf-c-rpc-client.a $(LINK_CTL) -o $@

# sgx-lkl-run ----
ifeq ($(HW_MODE),yes)
  ATTEST_DEPS = include/messages.pb-c.h
  MAIN_SRCS = $(wildcard attestation/*.c) main/messages.pb-c.c
else
  ATTEST_DEPS =
endif

$(LIB_SGX_LKL_BUILD)/sgx-lkl-run: $(LIB_SGX_LKL_BUILD)/main/main.a $(LIB_SGX_LKL_BUILD)/sgx/libsgx.a ${MBEDTLS}/mbedtls.a $(ATTEST_DEPS) builddirs
	$(CC) $(CFLAGS_MAIN) -o $@ $(LIB_SGX_LKL_BUILD)/main/main.a $(LIB_SGX_LKL_BUILD)/sgx/libsgx.a ${MBEDTLS}/mbedtls.a -ljson-c $(LINK_MAIN) -pthread -ldl -lrt -lz -lm -Wl,-T $(sgxlkl_toolsdir)/sgx-lkl.ld

MAIN_SRCS+=$(wildcard main/*.c) $(wildcard shared/*.c)
MAIN_OBJS=$(addprefix $(LIB_SGX_LKL_BUILD)/main/,$(MAIN_SRCS:.c=.o))

$(MAIN_OBJS): $(LIB_SGX_LKL_BUILD)/main/%.o: %.c | $(ATTEST_DEPS)
	mkdir -p $(dir $@)
	$(CC) -I${LKL_BUILD}/include/ -I$(srcdir)/include -I$(srcdir)/main/ $(CFLAGS_MAIN) -c -o $@ $<

$(LIB_SGX_LKL_BUILD)/main/main.a: $(MAIN_OBJS) builddirs
	$(AR) rc $@ $(MAIN_OBJS)
	$(RANLIB) $@

$(LINUX_SGX) $(EPID_SDK) $(PROTOBUFC_BUILD)/include $(PROTOBUFC_RPC)/protobuf-c-rpc-client.a:
	${MAKE} -C ${ROOT_DIR}/third_party $@

main/messages.pb-c.c include/messages.pb-c.h: ${LINUX_SGX}
	(cd ${LINUX_SGX}/psw/ae/common/proto/; protoc-c messages.proto --c_out=.)
	cp ${LINUX_SGX}/psw/ae/common/proto/messages.pb-c.c main
	cp ${LINUX_SGX}/psw/ae/common/proto/messages.pb-c.h include

sgx/sgxlkl_ctl.pb-c.c include/sgxlkl_ctl.pb-c.h:
	(cd sgx/proto && protoc-c sgxlkl_ctl.proto --c_out=${srcdir}/sgx)
	mv sgx/sgxlkl_ctl.pb-c.h include

# libsgxlkl.a ----
SGXLKL_SRCS=sgx/sgx_enclave_config.c sgx/enclave_mem.c sgx/enclave_signal.c sgx/sgxlkl_debug.c sgx/sgx_enclave_report.c sgx/enclave_cmd.c sgx/sgxlkl_app_config.c sgx/sgxlkl_ctl.pb-c.c $(wildcard shared/*.c) $(wildcard sched/*.c) $(wildcard host/*.c) $(wildcard lkl/*.c) $(wildcard wireguard/*.c)
SGXLKL_OBJS=$(addprefix $(LIB_SGX_LKL_BUILD)/sgxlkl/,$(SGXLKL_SRCS:.c=.o))

$(SGXLKL_OBJS): $(LIB_SGX_LKL_BUILD)/sgxlkl/%.o: %.c | $(SGX_LKL_MUSL_BUILD)/include ${LINUX_SGX} $(PROTOBUFC_BUILD)/include include/sgxlkl_ctl.pb-c.h
	mkdir -p $(dir $@)
	$(CC) -I$(srcdir)/include $(CFLAGS_MUSL_ALL) -c -o $@ $<

$(LIB_SGX_LKL_BUILD)/sgxlkl/libsgxlkl.a: $(SGXLKL_OBJS) builddirs
	$(AR) rc $@ $(SGXLKL_OBJS)
	$(RANLIB) $@

$(SGX_LKL_MUSL_BUILD)/include:
	$(MAKE)  -C $(SGX_LKL_MUSL) install-headers

clean:
	rm -rf $(LIB_SGX_LKL_BUILD)/sgx
	rm -rf $(LIB_SGX_LKL_BUILD)/main
	rm -rf $(LIB_SGX_LKL_BUILD)/sgxlkl
	rm -rf $(LIB_SGX_LKL_BUILD)/sgx-lkl-sign
	rm -rf $(LIB_SGX_LKL_BUILD)/sgx-lkl-run
	rm -rf $(LIB_SGX_LKL_BUILD)/libsgx.so
	rm -rf $(srcdir)/sgx/sgxlkl_ctl.pb-c.c $(srcdir)/include/sgxlkl_ctl.pb-c.h

.PHONY: clean builddirs
