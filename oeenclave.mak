##==============================================================================
##
## oeenclave.mak:
##
##     This makefile creates oeenclave.o, which contains all objects from the
##     entire OE enclave-side stack. It only exports select symbols. It omits
##     symbols from oelibc and mbedtls.
##
##==============================================================================

BUILDDIR=../openenclave/build
LIBDIR=./lib

##==============================================================================
##
## syms: function to get the globally defined symbols from an object/archive.
##
##==============================================================================

syms = $(shell nm $(1) -g -o --defined-only | awk '{print $$3}' )

##==============================================================================
##
## Define paths to various OE archives:
##
##==============================================================================

LIBOEENCLAVE = $(BUILDDIR)/output/lib/openenclave/enclave/liboeenclave.a
LIBOECRYPTOMBED = $(BUILDDIR)/output/lib/openenclave/enclave/liboecryptombed.a
LIBMBEDTLS = $(BUILDDIR)/3rdparty/mbedtls/libmbedtls.a
LIBMBEDX509 = $(BUILDDIR)/3rdparty/mbedtls/libmbedx509.a
LIBMBEDCRYPTO = $(BUILDDIR)/3rdparty/mbedtls/libmbedcrypto.a
LIBOELIBC = $(BUILDDIR)/output/lib/openenclave/enclave/liboelibc.a
LIBOESYSCALL = $(BUILDDIR)/syscall/liboesyscall.a
LIBOECORE = $(BUILDDIR)/output/lib/openenclave/enclave/liboecore.a

##==============================================================================
##
## all: target to build oeenclave.o
##
##==============================================================================

# Hide these symbols:
LOCAL =
LOCAL += rand
LOCAL += srand
LOCAL += memcpy
LOCAL += __memcpy_fwd
LOCAL += memset
LOCAL += memcmp
LOCAL += memmove
LOCAL += oe_free_sgx_endorsements
LOCAL += oe_get_sgx_endorsements
LOCAL += oe_parse_sgx_endorsements
LOCAL += __stack_chk_fail

# Keep symbols from these archives:
GLOBAL =
GLOBAL += $(call syms,$(LIBOEENCLAVE))
GLOBAL += $(call syms,$(LIBOESYSCALL))
GLOBAL += $(call syms,$(LIBDIR)/oecore.o)

# Linker flags:
LDFLAGS =
LDFLAGS += --whole-archive
LDFLAGS += $(LIBOEENCLAVE)
LDFLAGS += $(LIBOECRYPTOMBED)
LDFLAGS += $(LIBMBEDTLS)
LDFLAGS += $(LIBMBEDX509)
LDFLAGS += $(LIBMBEDCRYPTO)
LDFLAGS += $(LIBOELIBC)
LDFLAGS += $(LIBOESYSCALL)
LDFLAGS += $(LIBDIR)/oecore.o
LDFLAGS += --no-whole-archive

all:
	ld -relocatable -o $(LIBDIR)/oecore.o --whole-archive $(LIBOECORE)
	objcopy $(addprefix -L,$(LOCAL)) $(LIBDIR)/oecore.o
	ld -relocatable -o $(LIBDIR)/oeenclave.o $(LDFLAGS)
	objcopy $(addprefix -G,$(GLOBAL)) $(LIBDIR)/oeenclave.o
	objcopy $(addprefix -L,$(LOCAL)) $(LIBDIR)/oeenclave.o
