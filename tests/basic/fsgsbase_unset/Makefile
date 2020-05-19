include ../../common.mk

PROG=fsgsbase_unset-test
PROG_SRC=$(PROG).c
IMAGE_SIZE=10M

EXECUTION_TIMEOUT=60

SGXLKL_ENV=SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1
SGXLKL_HW_PARAMS=--hw-debug
SGXLKL_SW_PARAMS=--sw-debug

SGXLKL_ROOTFS=sgx-lkl-rootfs.img

SET_FSGSBASE=make -C $(SGXLKL_ROOT)/tools/kmod-set-fsgsbase set-cr4-fsgsbase
UNSET_FSGSBASE=make -C $(SGXLKL_ROOT)/tools/kmod-set-fsgsbase unset-cr4-fsgsbase

.DELETE_ON_ERROR:
.PHONY: all clean

$(SGXLKL_ROOTFS): $(PROG_SRC)
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --docker=./Dockerfile ${SGXLKL_ROOTFS}

gettimeout:
	@echo ${EXECUTION_TIMEOUT}

run: run-hw run-sw

# By default, all tests are run with FSGSBASE enabled,
# so we first disable it and then enable it again to restore the original state.
run-hw: ${SGXLKL_ROOTFS}
	$(UNSET_FSGSBASE)
	$(SGXLKL_ENV) $(SGXLKL_STARTER) $(SGXLKL_HW_PARAMS) $(SGXLKL_ROOTFS) $(PROG);\
	EXIT_CODE=$$?;\
	$(SET_FSGSBASE);\
	exit $$EXIT_CODE

run-sw: ${SGXLKL_ROOTFS}
	$(UNSET_FSGSBASE)
	$(SGXLKL_ENV) $(SGXLKL_STARTER) $(SGXLKL_SW_PARAMS) $(SGXLKL_ROOTFS) $(PROG);\
	EXIT_CODE=$$?;\
	$(SET_FSGSBASE);\
	exit $$EXIT_CODE

run-hw-gdb: ${SGXLKL_ROOTFS}
	$(UNSET_FSGSBASE)
	$(SGXLKL_ENV) $(SGXLKL_GDB) --args $(SGXLKL_STARTER) $(SGXLKL_HW_PARAMS) $(SGXLKL_ROOTFS) $(PROG);\
	EXIT_CODE=$$?;\
	$(SET_FSGSBASE);\
	exit $$EXIT_CODE

run-sw-gdb: ${SGXLKL_ROOTFS}
	$(UNSET_FSGSBASE)
	$(SGXLKL_ENV) $(SGXLKL_GDB) --args $(SGXLKL_STARTER) $(SGXLKL_SW_PARAMS) $(SGXLKL_ROOTFS) $(PROG);\
	EXIT_CODE=$$?;\
	$(SET_FSGSBASE);\
	exit $$EXIT_CODE

clean:
	rm -f $(SGXLKL_ROOTFS)
