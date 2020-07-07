.PHONY: oecore
.PHONY: oeenclave

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
LOCAL_OECORE =
LOCAL_OECORE += rand
LOCAL_OECORE += srand
LOCAL_OECORE += memcpy
LOCAL_OECORE += __memcpy_fwd
LOCAL_OECORE += memset
LOCAL_OECORE += memcmp
LOCAL_OECORE += memmove
LOCAL_OECORE += oe_free_sgx_endorsements
LOCAL_OECORE += oe_get_sgx_endorsements
LOCAL_OECORE += oe_parse_sgx_endorsements
LOCAL_OECORE += __stack_chk_fail

GLOBAL_OECORE += $(call syms,$(LIBOECORE))

# Hide these symbols:
LOCAL_OEENCLAVE =
LOCAL_OEENCLAVE += rand
LOCAL_OEENCLAVE += srand
LOCAL_OEENCLAVE += memcpy
LOCAL_OEENCLAVE += __memcpy_fwd
LOCAL_OEENCLAVE += memset
LOCAL_OEENCLAVE += memcmp
LOCAL_OEENCLAVE += memmove
LOCAL_OEENCLAVE += oe_free_sgx_endorsements
LOCAL_OEENCLAVE += oe_get_sgx_endorsements
LOCAL_OEENCLAVE += oe_parse_sgx_endorsements
LOCAL_OEENCLAVE += __stack_chk_fail

# Keep symbols from these archives:
GLOBAL_OEENCLAVE =
GLOBAL_OEENCLAVE += $(call syms,$(LIBOEENCLAVE))
GLOBAL_OEENCLAVE += $(call syms,$(LIBOESYSCALL))
GLOBAL_OEENCLAVE += $(call syms,$(LIBOECORE))

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

oeenclave: oecore
	ld -relocatable -o $(LIBDIR)/oeenclave.o $(LDFLAGS)
	objcopy $(addprefix -L,$(LOCAL_OEENCLAVE)) $(LIBDIR)/oeenclave.o
	objcopy $(addprefix -G,$(GLOBAL_OEENCLAVE)) $(LIBDIR)/oeenclave.o

oecore:
	ld -relocatable -o $(LIBDIR)/oecore.o --whole-archive $(LIBOECORE)
	objcopy $(addprefix -L,$(LOCAL_OECORE)) $(LIBDIR)/oecore.o
	objcopy $(addprefix -G,$(GLOBAL_OECORE)) $(LIBDIR)/oecore.o

