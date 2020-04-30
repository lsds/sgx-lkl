SHELL := /bin/bash

APP_ROOT=app
PROG=${APP_ROOT}/keyboard_read.py

DISK_IMAGE=sgxlkl-python.img
IMAGE_SIZE=1024M

SGXLKL_ROOT=../../..

ENCLAVE_CMD=/usr/bin/python ${PROG}

SGXLKL_STARTER=$(SGXLKL_ROOT)/build/sgx-lkl-run-oe

ifeq ($(SGXLKL_VERBOSE),)
SGXLKL_ENV=\
   SGXLKL_GETTIME_VDSO=0\
   SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=0 SGXLKL_TRACE_SIGNAL=0\
   SGXLKL_TRACE_HOST_SYSCALL=0 SGXLKL_TRACE_LKL_SYSCALL=0 SGXLKL_TRACE_MMAP=0
else
SGXLKL_ENV=SGXLKL_GETTIME_VDSO=0
endif

SGXLKL_DISK_TOOL=${SGXLKL_ROOT}/tools/sgx-lkl-disk

.DELETE_ON_ERROR:
.PHONY: all clean

all: $(DISK_IMAGE)

clean:
	rm -f $(DISK_IMAGE)

$(DISK_IMAGE): $(PROG)
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --alpine="python" --copy=./${APP_ROOT}/ ${DISK_IMAGE}

run: run-hw

.ONESHELL:

run-hw: $(DISK_IMAGE)
	${SGXLKL_ENV} expect -c "
		spawn ${SGXLKL_STARTER} --hw-debug $(DISK_IMAGE) $(ENCLAVE_CMD)
		expect \"Prompt\"
		send \"stop\r\"
		expect eof"

run-sw: $(DISK_IMAGE)
	${SGXLKL_ENV} expect -c "
		spawn ${SGXLKL_STARTER} --sw-debug $(DISK_IMAGE) $(ENCLAVE_CMD)
		expect \"Prompt\"
		send \"stop\r\"
		expect eof"
