
APP_ROOT=app
PROG=${APP_ROOT}/hello-eeid
PROG_C=hello-eeid.c

DISK_IMAGE=sgxlkl-hello-eeid.img
IMAGE_SIZE=10M

SGXLKL_ROOT=../../..

MUSL_CC=${SGXLKL_ROOT}/build/host-musl/bin/musl-gcc

SGXLKL_STARTER=$(SGXLKL_ROOT)/build/sgx-lkl-run-oe

ifeq ($(SGXLKL_VERBOSE),)
SGXLKL_ENV=\
   SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=0 SGXLKL_TRACE_SIGNAL=0\
   SGXLKL_TRACE_HOST_SYSCALL=0 SGXLKL_TRACE_LKL_SYSCALL=0 SGXLKL_TRACE_MMAP=0
else
SGXLKL_ENV=
endif

SGXLKL_DISK_TOOL=${SGXLKL_ROOT}/tools/sgx-lkl-disk
SGXLKL_GDB=${SGXLKL_ROOT}/tools/gdb/sgx-lkl-gdb

.DELETE_ON_ERROR:
.PHONY: all clean

all: $(DISK_IMAGE)

clean:
	rm -f $(DISK_IMAGE) $(PROG)

$(PROG): $(PROG_C)
	${MUSL_CC} -fPIE -pie -g -o $@ $(PROG_C)

$(DISK_IMAGE): $(PROG)
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --copy=./${APP_ROOT}/ ${DISK_IMAGE}

run: run-hw

run-hw: $(DISK_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --hw-debug --app-config app_config.json $(DISK_IMAGE)

run-hw-gdb: $(DISK_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_GDB} --args ${SGXLKL_STARTER} --hw-debug --app-config app_config.json $(DISK_IMAGE)
