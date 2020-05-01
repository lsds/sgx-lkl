PROG=illegal_instructions-test
PROG_SRC=$(PROG).c
IMAGE_SIZE=5M

EXECUTION_TIMEOUT=60
SGXLKL_ROOT=../../..
SGXLKL_STARTER=$(SGXLKL_ROOT)/build/sgx-lkl-run-oe
SGXLKL_DISK_TOOL=${SGXLKL_ROOT}/tools/sgx-lkl-disk
SGXLKL_GDB=${SGXLKL_ROOT}/tools/gdb/sgx-lkl-gdb

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

run: run-hw

run-hw: ${SGXLKL_ROOTFS}
	@# Note that the following ! inverts the error code from the enclave
	@! $(SGXLKL_ENV) $(SGXLKL_STARTER) $(SGXLKL_HW_PARAMS) $(SGXLKL_ROOTFS) $(PROG)

run-sw: 
	@echo Test not supported in sw mode

clean:
	rm -f $(SGXLKL_ROOTFS)
