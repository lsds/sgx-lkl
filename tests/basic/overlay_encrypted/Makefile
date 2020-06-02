include ../../common.mk

# TODO use dm-verity in this test once it is stable
#      (dm-verity makes the disk read-only)

PROG=/bin/touch /foo.txt
IMAGE_SIZE=50M

EXECUTION_TIMEOUT=60

SGXLKL_ROOTFS=sgx-lkl-rootfs.img
SGXLKL_ROOTFS_KEY=$(SGXLKL_ROOTFS).key

SGXLKL_ENV=SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1 \
    SGXLKL_HD_KEY=$(SGXLKL_ROOTFS_KEY) \
	SGXLKL_HD_RO=1 \
	SGXLKL_HD_OVERLAY=1
SGXLKL_HW_PARAMS=--hw-debug
SGXLKL_SW_PARAMS=--sw-debug


.DELETE_ON_ERROR:
.PHONY: all clean

$(SGXLKL_ROOTFS):
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --docker=./Dockerfile --encrypt --key-file ${SGXLKL_ROOTFS}

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
	rm -f $(SGXLKL_ROOTFS) $(SGXLKL_ROOTFS_KEY)
