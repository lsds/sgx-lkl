include ../../common.mk

PROG=helloworld
PROG_SRC=$(PROG).c
IMAGE_SIZE=5M

EXECUTION_TIMEOUT=60

SGXLKL_ENV=SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1
SGXLKL_HW_PARAMS=--hw-debug
SGXLKL_SW_PARAMS=--sw-debug

SGXLKL_ROOTFS=sgx-lkl-rootfs.img

GDB_CMDS=-batch \
	-ex "handle SIGILL nostop noprint" \
	-ex "set breakpoint pending on" \
	-ex "break print_hello" \
	-ex "run" \
	-ex "backtrace" \
	--args

GDB_MATCH=hit Breakpoint 1, print_hello (count=4) at helloworld.c:7

.DELETE_ON_ERROR:
.PHONY: all clean

$(SGXLKL_ROOTFS): $(PROG_SRC)
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --docker=./Dockerfile ${SGXLKL_ROOTFS}

gettimeout:
	@echo ${EXECUTION_TIMEOUT}

run: run-hw run-sw

run-gdb: run-hw-gdb

.ONESHELL:
ifeq (${SGXLKL_BUILD_MODE},debug)
run-hw: ${SGXLKL_ROOTFS}
	output=$$(${SGXLKL_ENV} ${SGXLKL_GDB} ${GDB_CMDS} ${SGXLKL_STARTER} ${SGXLKL_HW_PARAMS} ${SGXLKL_ROOTFS} ${PROG} 2>&1)
	echo "$$output"
	echo "$$output" | grep '$(GDB_MATCH)'

run-sw: ${SGXLKL_ROOTFS}
	output=$$(${SGXLKL_ENV} ${SGXLKL_GDB} ${GDB_CMDS} ${SGXLKL_STARTER} ${SGXLKL_SW_PARAMS} ${SGXLKL_ROOTFS} ${PROG} 2>&1)
	echo "$$output"
	echo "$$output" | grep '$(GDB_MATCH)'
else
run-hw:
	@echo "Test disabled, SGXLKL_BUILD_MODE != debug"
run-sw:
	@echo "Test disabled, SGXLKL_BUILD_MODE != debug"
endif

run-hw-gdb: ${SGXLKL_ROOTFS}
	$(SGXLKL_ENV) $(SGXLKL_GDB) --args $(SGXLKL_STARTER) $(SGXLKL_HW_PARAMS) $(SGXLKL_ROOTFS) $(PROG)

run-sw-gdb: ${SGXLKL_ROOTFS}
	$(SGXLKL_ENV) $(SGXLKL_GDB) --args $(SGXLKL_STARTER) $(SGXLKL_SW_PARAMS) $(SGXLKL_ROOTFS) $(PROG)

clean:
	rm -f $(SGXLKL_ROOTFS)
