include ../../common.mk

PROG1=clone
PROG1_SRC=$(PROG1).c

PROG2=clone_loop
PROG2_SRC=$(PROG1).c
IMAGE_SIZE=5M

EXECUTION_TIMEOUT=60

SGXLKL_ENV=SGXLKL_ETHREADS=8 SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1
SGXLKL_HW_PARAMS=--hw-debug
SGXLKL_SW_PARAMS=--sw-debug

SGXLKL_ROOTFS=sgx-lkl-rootfs.img

.DELETE_ON_ERROR:
.PHONY: all clean

$(SGXLKL_ROOTFS): $(PROG1_SRC) $(PROG2_SRC)
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --docker=./Dockerfile ${SGXLKL_ROOTFS}

gettimeout:
	@echo ${EXECUTION_TIMEOUT}

run: run-hw run-sw

run-gdb: run-hw-gdb-clone

run-hw: ${SGXLKL_ROOTFS} run-hw-clone run-hw-clone-loop

run-hw-clone: ${SGXLKL_ROOTFS}
	  $(SGXLKL_ENV) $(SGXLKL_STARTER) $(SGXLKL_HW_PARAMS) $(SGXLKL_ROOTFS) $(PROG1)

run-hw-clone-loop: ${SGXLKL_ROOTFS}
	  $(SGXLKL_ENV) $(SGXLKL_STARTER) $(SGXLKL_HW_PARAMS) $(SGXLKL_ROOTFS) $(PROG2)


run-sw: ${SGXLKL_ROOTFS} run-sw-clone run-sw-clone-loop

run-sw-clone: ${SGXLKL_ROOTFS}
	  $(SGXLKL_ENV) $(SGXLKL_STARTER) $(SGXLKL_SW_PARAMS) $(SGXLKL_ROOTFS) $(PROG1)

run-sw-clone-loop: ${SGXLKL_ROOTFS}
	  $(SGXLKL_ENV) $(SGXLKL_STARTER) $(SGXLKL_SW_PARAMS) $(SGXLKL_ROOTFS) $(PROG2)

run-hw-gdb-clone: ${SGXLKL_ROOTFS}
	  $(SGXLKL_ENV) $(SGXLKL_GDB) --args $(SGXLKL_STARTER) $(SGXLKL_HW_PARAMS) $(SGXLKL_ROOTFS) $(PROG1)

run-sw-gdb-clone: ${SGXLKL_ROOTFS}
	  $(SGXLKL_ENV) $(SGXLKL_GDB) --args $(SGXLKL_STARTER) $(SGXLKL_SW_PARAMS) $(SGXLKL_ROOTFS) $(PROG1)

run-hw-gdb-clone-loop: ${SGXLKL_ROOTFS}
	  $(SGXLKL_ENV) $(SGXLKL_GDB) --args $(SGXLKL_STARTER) $(SGXLKL_HW_PARAMS) $(SGXLKL_ROOTFS) $(PROG2)

run-sw-gdb-clone-loop: ${SGXLKL_ROOTFS}
	  $(SGXLKL_ENV) $(SGXLKL_GDB) --args $(SGXLKL_STARTER) $(SGXLKL_SW_PARAMS) $(SGXLKL_ROOTFS) $(PROG2)
clean:
	rm -f $(SGXLKL_ROOTFS) $(PROG1)
