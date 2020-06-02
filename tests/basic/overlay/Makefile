include ../../common.mk

# This test verifies that if the overlay is enabled on a read-only rootfs the following works:
# - Writing a file.
# - Mounting an extra disk without existing mount point folder.

PROG=/bin/touch /foo.txt
IMAGE_SIZE=5M

EXECUTION_TIMEOUT=60

SGXLKL_ROOTFS=sgx-lkl-rootfs.img

SGXLKL_ENV=SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1 \
	SGXLKL_HD_RO=1 SGXLKL_HD_OVERLAY=1 \
	SGXLKL_HDS=${SGXLKL_ROOTFS}:/data:1
SGXLKL_HW_PARAMS=--hw-debug
SGXLKL_SW_PARAMS=--sw-debug


.DELETE_ON_ERROR:
.PHONY: all clean

$(SGXLKL_ROOTFS):
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --docker=./Dockerfile ${SGXLKL_ROOTFS}

gettimeout:
	@echo ${EXECUTION_TIMEOUT}

run: run-hw run-sw

run-gdb: run-hw-gdb

run-hw: ${SGXLKL_ROOTFS}
	  $(SGXLKL_ENV) $(SGXLKL_STARTER) $(SGXLKL_HW_PARAMS) $(SGXLKL_ROOTFS) $(PROG)

run-sw: ${SGXLKL_ROOTFS}
	  $(SGXLKL_ENV) $(SGXLKL_STARTER) $(SGXLKL_SW_PARAMS) $(SGXLKL_ROOTFS) $(PROG)

run-hw-gdb: ${SGXLKL_ROOTFS}
	  $(SGXLKL_ENV) $(SGXLKL_GDB) --args $(SGXLKL_STARTER) $(SGXLKL_HW_PARAMS) $(SGXLKL_ROOTFS) $(PROG)

run-sw-gdb: ${SGXLKL_ROOTFS}
	  $(SGXLKL_ENV) $(SGXLKL_GDB) --args $(SGXLKL_STARTER) $(SGXLKL_SW_PARAMS) $(SGXLKL_ROOTFS) $(PROG)

clean:
	rm -f $(SGXLKL_ROOTFS)
