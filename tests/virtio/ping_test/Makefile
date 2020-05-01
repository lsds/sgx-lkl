include ../../common.mk

SHELL := /bin/bash

PROG=dummy_server
PROG_SRC=$(PROG).c
IMAGE_SIZE=5M

EXECUTION_TIMEOUT=60

SGXLKL_ENV=SGXLKL_ETHREADS=8 SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1
SGXLKL_HW_PARAMS=--hw-debug
SGXLKL_SW_PARAMS=--sw-debug

SGXLKL_ROOTFS=sgx-lkl-rootfs.img

.DELETE_ON_ERROR:
.PHONY: all clean

$(SGXLKL_ROOTFS): $(PROG_SRC)
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --docker=./Dockerfile ${SGXLKL_ROOTFS}

gettimeout:
	@echo ${EXECUTION_TIMEOUT}

.ONESHELL:

run-hw: $(SGXLKL_ROOTFS)
	${SGXLKL_ENV} expect -c "
		spawn $(SGXLKL_STARTER) $(SGXLKL_HW_PARAMS) $(SGXLKL_ROOTFS) $(PROG)
		expect \"Press 'Q' to quit\"
		send \"Q\r\"
		expect eof"

run-sw: $(SGXLKL_ROOTFS)
	${SGXLKL_ENV} expect -c "
		spawn $(SGXLKL_STARTER) $(SGXLKL_HW_PARAMS) $(SGXLKL_ROOTFS) $(PROG)
		expect \"Press 'Q' to quit\"
		send \"Q\r\"
		expect eof"

clean:
	@rm -f $(SGXLKL_ROOTFS)
