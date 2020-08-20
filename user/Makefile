TOP = $(abspath ..)

-include $(TOP)/sgx-lkl-musl/muslobjs.mak

TARGET = $(TOP)/build_musl/libsgxlkl-user.so

CFLAGS = -m64 -g -O3 -g -fPIC -Werror -std=c99 -nostdinc -ffreestanding -fexcess-precision=standard -frounding-math -Wa,--noexecstack -D_XOPEN_SOURCE=700 -pipe -fomit-frame-pointer -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -Werror=implicit-function-declaration -Werror=implicit-int -Werror=pointer-sign -D__USE_GNU -DDL_NOMMU_SUPPORT=1

INCLUDES =
INCLUDES += -I$(TOP)/build_musl/sgx-lkl-musl/include
INCLUDES += -I$(TOP)/build_musl/openenclave/include
INCLUDES += -I$(TOP)/build_musl/config
INCLUDES += -I$(TOP)/sgx-lkl-musl/src/internal
INCLUDES += -I$(TOP)/sgx-lkl-musl/arch/x86_64
INCLUDES += -I$(TOP)/src/include

DYNAMIC_LIST = $(TOP)/sgx-lkl-musl/dynamic.list

LDFLAGS1 = -Wl,--sort-section,alignment -Wl,--sort-common -Wl,--gc-sections -Wl,--hash-style=both -Wl,--no-undefined -Wl,--exclude-libs=ALL -Wl,--dynamic-list=$(DYNAMIC_LIST) -nostdlib -nodefaultlibs -nostartfiles
LDFLAGS1 += -Wl,-esgxlkl_user_enter

LDFLAGS2 = -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--export-dynamic -Wl,-pie -Wl,--build-id -Wl,-z,noexecstack -Wl,-z,now

LDFLAGS = $(LDFLAGS1) $(LDFLAGS2)

LDFLAGS += -lgcc

SOURCES = $(wildcard *.c)

ifndef MUSL_OBJECTS
$(error "please run $(TOP)/sgx-lkl-musl/Makefile first")
endif

LOCAL_OBJECTS = $(SOURCES:.c=.o)
OBJECTS = $(LOCAL_OBJECTS) $(MUSL_OBJECTS)

all: $(OBJECTS)
	@ $(CC) -o $(TARGET) $(OBJECTS) $(LDFLAGS)
	@ echo "########## Created $(TARGET)"

%.o: %.c
	$(CC) -c $(CFLAGS) $(INCLUDES) -o $@ $<

clean:
	rm -f $(TARGET) $(LOCAL_OBJECTS)

muslobjs:
	echo $(MUSL_OBJECTS)

nm:
	nm $(TARGET) | grep dls
