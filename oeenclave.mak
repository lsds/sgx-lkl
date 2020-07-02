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
LIBOECORE_TMP = $(LIBDIR)/liboecore.a

##==============================================================================
##
## all: target to build oeenclave.o
##
##==============================================================================

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
LDFLAGS += $(LIBOECORE_TMP)
LDFLAGS += --no-whole-archive

# Hide these symbols:
LOCALIZE =
LOCALIZE += rand
LOCALIZE += srand
LOCALIZE += memcpy
LOCALIZE += __memcpy_fwd
LOCALIZE += memset
LOCALIZE += memcmp
LOCALIZE += memmove
LOCALIZE += oe_free_sgx_endorsements
LOCALIZE += oe_get_sgx_endorsements
LOCALIZE += oe_parse_sgx_endorsements
LOCALIZE += __stack_chk_fail

# Keep symbols from these archives:
KEEP =
KEEP += $(call syms,$(LIBOEENCLAVE))
KEEP += $(call syms,$(LIBOESYSCALL))
KEEP += $(call syms,$(LIBOECORE_TMP))

all:
	cp $(LIBOECORE) $(LIBOECORE_TMP)
	objcopy $(addprefix -L,$(LOCALIZE)) $(LIBOECORE_TMP)
	ld -relocatable -o $(LIBDIR)/oeenclave.o $(LDFLAGS)
	objcopy $(addprefix -G,$(KEEP)) $(LIBDIR)/oeenclave.o
	objcopy $(addprefix -L,$(LOCALIZE)) $(LIBDIR)/oeenclave.o
