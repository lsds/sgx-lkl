include ../config.mak

# TODO Don't set (default) arch in Makefile
ARCH ?= x86_64

LIB_SGX_LKL_BUILD ?= $(BUILD_DIR)

HW_MODE ?= yes

sim: HW_MODE = no
sim: all


srcdir = .
musl_srcdir = $(SGX_LKL_MUSL)/src
sgxlkl_toolsdir = ../tools

CC = gcc
CROSS_COMPILE = 
RANLIB  = $(CROSS_COMPILE)ranlib

ifeq ($(HW_MODE),yes)
  CFLAGS_SGX = -DSGXLKL_HW
  CFLAGS_LIBSGX = -DSGXLKL_HW
else
  CFLAGS_SGX =
  CFLAGS_LIBSGX =
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

# Copied from sgx-lkl-musl/config.mak after ./configure
# TODO: Do not hardcode cflags here
CFLAGS_AUTO = -g -pipe -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -Werror=implicit-function-declaration -Werror=implicit-int -Werror=pointer-sign -include vis.h -fPIC -DNO_CRYPTSETUP
CFLAGS_C99FSE = -std=c99 -nostdinc -ffreestanding -fexcess-precision=standard -frounding-math -Wa,--noexecstack

CFLAGS_MUSL_ALL = $(CFLAGS_C99FSE) $(CFLAGS_AUTO) $(CFLAGS_SGX) $(MUSL_CFLAGS)
CFLAGS_MUSL_ALL += -D_XOPEN_SOURCE=700
CFLAGS_MUSL_ALL += -I$(SGX_LKL_MUSL)/src/internal -I$(SGX_LKL_MUSL_BUILD)/include -I$(SGX_LKL_MUSL)/arch/$(ARCH)

all: builddirs $(LIB_SGX_LKL_BUILD)/libsgx/libsgx.a $(LIB_SGX_LKL_BUILD)/sgxlkl/libsgxlkl.a $(LIB_SGX_LKL_BUILD)/sgx-lkl-sign $(LIB_SGX_LKL_BUILD)/sgx-lkl-run

builddirs:
	mkdir -p $(LIB_SGX_LKL_BUILD)/libsgx
	mkdir -p $(LIB_SGX_LKL_BUILD)/sgx_sign
	mkdir -p $(LIB_SGX_LKL_BUILD)/main
	mkdir -p $(LIB_SGX_LKL_BUILD)/sgxlkl

clean:
	rm -rf $(LIB_SGX_LKL_BUILD)/libsgx
	rm -rf $(LIB_SGX_LKL_BUILD)/sgx_sign
	rm -rf $(LIB_SGX_LKL_BUILD)/main
	rm -rf $(LIB_SGX_LKL_BUILD)/sgxlkl
	rm -rf $(LIB_SGX_LKL_BUILD)/sgx-lkl-sign
	rm -rf $(LIB_SGX_LKL_BUILD)/sgx-lkl-run
	rm -rf $(LIB_SGX_LKL_BUILD)/libsgx.so

# libsgx ----

LIBSGX_SRCS = $(wildcard libsgx/*.c)
LIBSGX_OBJS = $(addprefix $(LIB_SGX_LKL_BUILD)/,$(LIBSGX_SRCS:.c=.o))

$(LIB_SGX_LKL_BUILD)/libsgx/libsgx.a: $(LIBSGX_OBJS)
	ar rc $@ $^ libsgx/libs/lible.o
	ranlib $(LIB_SGX_LKL_BUILD)/libsgx/libsgx.a

# libsgx needs can't be built with -O0, force -O1
$(LIBSGX_OBJS): $(LIB_SGX_LKL_BUILD)/libsgx/%.o: libsgx/%.c
	$(CC) -c --std=gnu11 -Ilibsgx/include  $(CFLAGS_LIBSGX) $< -o $@

# sgx_lkl_sign ----

SIGN_SRCS = sgx_lkl_sign.c sgx_lkl_sign_cmdline.c
SIGN_OBJS = $(SIGN_SRCS:.c=.o)

$(LIB_SGX_LKL_BUILD)/sgx_sign/%.o: sgx_sign/%.c
	$(CC) $(CFLAGS_SGX)  -c --std=gnu11 -Ilibsgx/include $< -o $@

$(LIB_SGX_LKL_BUILD)/sgx-lkl-sign: $(addprefix $(LIB_SGX_LKL_BUILD)/sgx_sign/,$(SIGN_OBJS)) $(LIB_SGX_LKL_BUILD)/libsgx/libsgx.a
	$(CC) $(CFLAGS_SGX)  --std=gnu11 -fno-pie -no-pie -Ilibsgx/include $^ -o $@

# sgx-lkl-run ----

$(LIB_SGX_LKL_BUILD)/sgx-lkl-run: $(LIB_SGX_LKL_BUILD)/main/main.a $(LIB_SGX_LKL_BUILD)/libsgx/libsgx.a builddirs
	$(CC) $(CFLAGS_SGX) $(LIB_SGX_LKL_BUILD)/main/main.a -o $@ $(LIB_SGX_LKL_BUILD)/libsgx/libsgx.a -pthread -ldl -lrt -Wl,-T $(sgxlkl_toolsdir)/sgx-lkl.ld

MAIN_SRCS=$(wildcard main/*.c) $(wildcard shared/*.c)
MAIN_OBJS=$(addprefix $(LIB_SGX_LKL_BUILD)/main/,$(MAIN_SRCS:.c=.o))

$(MAIN_OBJS): $(LIB_SGX_LKL_BUILD)/main/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) -I${LKL_BUILD}/include/ -I$(srcdir)/include -I$(srcdir)/main/include $(CFLAGS_SGX) -c -o $@ $<

$(LIB_SGX_LKL_BUILD)/main/main.a: $(MAIN_OBJS) builddirs
	$(AR) rc $@ $(MAIN_OBJS)
	$(RANLIB) $@

# libsgxlkl.a ----

SGXLKL_SRCS=$(wildcard sgx/*.c) $(wildcard shared/*.c) $(wildcard sched/*.c) $(wildcard host/*.c) $(wildcard lkl/*.c)
SGXLKL_OBJS=$(addprefix $(LIB_SGX_LKL_BUILD)/sgxlkl/,$(SGXLKL_SRCS:.c=.o))

$(SGXLKL_OBJS): $(LIB_SGX_LKL_BUILD)/sgxlkl/%.o: %.c $(SGX_LKL_MUSL_BUILD)/include
	mkdir -p $(dir $@)
	$(CC) -I$(srcdir)/include $(CFLAGS_MUSL_ALL) -c -o $@ $<

$(LIB_SGX_LKL_BUILD)/sgxlkl/libsgxlkl.a: $(SGXLKL_OBJS) builddirs
	$(AR) rc $@ $(SGXLKL_OBJS)
	$(RANLIB) $@

$(SGX_LKL_MUSL_BUILD)/include:
	$(MAKE)  -C $(SGX_LKL_MUSL) install-headers

.PHONY: clean builddirs
