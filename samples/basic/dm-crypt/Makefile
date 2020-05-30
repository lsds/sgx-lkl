APP_ROOT=app
PROG=${APP_ROOT}/dm-crypt
PROG_NONPIE=${APP_ROOT}/dm-crypt-nonpie
PROG_C=dm-crypt.c

DISK_IMAGE=sgxlkl-dm-crypt.img
KEY_FILE=key-file
IMAGE_SIZE=64MB

SGXLKL_ROOT=../../..

MUSL_CC=${SGXLKL_ROOT}/build/host-musl/bin/musl-gcc

SGXLKL_STARTER=$(SGXLKL_ROOT)/build/sgx-lkl-run-oe

ifeq ($(SGXLKL_VERBOSE),)
SGXLKL_ENV=\
   SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1 SGXLKL_TRACE_SIGNAL=0\
   SGXLKL_TRACE_HOST_SYSCALL=0 SGXLKL_TRACE_LKL_SYSCALL=0 SGXLKL_TRACE_MMAP=0
else
SGXLKL_ENV=
endif

SGXLKL_ENV += SGXLKL_HD_KEY=pass

SGXLKL_DISK_TOOL=${SGXLKL_ROOT}/tools/sgx-lkl-disk
SGXLKL_GDB=${SGXLKL_ROOT}/tools/gdb/sgx-lkl-gdb

.DELETE_ON_ERROR:
.PHONY: all clean

all: $(DISK_IMAGE)

clean:
	rm -f $(DISK_IMAGE) $(PROG) $(PROG_NONPIE) $(KEY_FILE)

$(PROG): $(PROG_C)
	${MUSL_CC} -fPIE -pie -o $@ $(PROG_C)

# non-PIE executable are currently unsupported by SGX-LKL-OE
$(PROG_NONPIE): $(PROG_C)
	${MUSL_CC} -fno-pie -no-pie -o $@ $(PROG_C)

$(KEY_FILE):
	@ head -c 64 /dev/urandom > $(KEY_FILE)

SGXLKL_DISK_OPTIONS += --size=${IMAGE_SIZE}
SGXLKL_DISK_OPTIONS += --copy=./${APP_ROOT}/
SGXLKL_DISK_OPTIONS += --encrypt
SGXLKL_DISK_OPTIONS += --passphrase=pass
#SGXLKL_DISK_OPTIONS += --pbkdf=pbkdf2

image: $(DISK_IMAGE)

$(DISK_IMAGE): $(PROG) $(PROG_NONPIE) $(KEY_FILE)
	${SGXLKL_DISK_TOOL} create $(SGXLKL_DISK_OPTIONS) ${DISK_IMAGE}

run: run-hw

run-hw: $(DISK_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --hw-debug $(DISK_IMAGE) $(PROG)

run-hw-gdb: $(DISK_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_GDB} --args ${SGXLKL_STARTER} --hw-debug $(DISK_IMAGE) $(PROG)

run-sw: $(DISK_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --sw-debug $(DISK_IMAGE) $(PROG)

run-sw-gdb: $(DISK_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_GDB} --args ${SGXLKL_STARTER} --sw-debug $(DISK_IMAGE) $(PROG)
