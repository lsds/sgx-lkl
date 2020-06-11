include ../../common.mk

PROG=hello-eeid
PROG_SRC=$(PROG).c
IMAGE_SIZE=5M

EXECUTION_TIMEOUT=60

SGXLKL_ENV=SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1
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

run-gdb: run-hw-gdb

run-hw: ${SGXLKL_ROOTFS}
	  $(SGXLKL_ENV) $(SGXLKL_STARTER) $(SGXLKL_HW_PARAMS) --app-config app_config.json $(SGXLKL_ROOTFS)

run-hw-gdb: ${SGXLKL_ROOTFS}
	  $(SGXLKL_ENV) $(SGXLKL_GDB) --args $(SGXLKL_STARTER) $(SGXLKL_HW_PARAMS) --app-config app_config.json $(SGXLKL_ROOTFS)

clean:
	rm -f $(SGXLKL_ROOTFS) $(PROG)