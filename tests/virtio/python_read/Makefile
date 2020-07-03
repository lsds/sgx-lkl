include ../../common.mk

SHELL := /bin/bash

APP_ROOT=app
PROG=${APP_ROOT}/keyboard_read.py
IMAGE_SIZE=100M

EXECUTION_TIMEOUT=60

SGXLKL_ENV=SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1
SGXLKL_HW_PARAMS=--hw-debug
SGXLKL_SW_PARAMS=--sw-debug

ENCLAVE_CMD=/usr/bin/python3 ${PROG}

SGXLKL_ROOTFS=sgx-lkl-rootfs.img

.DELETE_ON_ERROR:
.PHONY: all clean

$(SGXLKL_ROOTFS): $(PROG)
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --docker=./Dockerfile ${SGXLKL_ROOTFS}

gettimeout:
	@echo ${EXECUTION_TIMEOUT}

.ONESHELL:

run-hw: $(SGXLKL_ROOTFS)
	${SGXLKL_ENV} expect -c "
		spawn $(SGXLKL_STARTER) $(SGXLKL_HW_PARAMS) $(SGXLKL_ROOTFS) $(ENCLAVE_CMD)
		expect \"Prompt\"
		send \"stop\r\"
		expect eof"

run-sw: $(SGXLKL_ROOTFS)
	${SGXLKL_ENV} expect -c "
		spawn $(SGXLKL_STARTER) $(SGXLKL_HW_PARAMS) $(SGXLKL_ROOTFS) $(ENCLAVE_CMD)
		expect \"Prompt\"
		send \"stop\r\"
		expect eof"

clean:
	@rm -f $(SGXLKL_ROOTFS)
