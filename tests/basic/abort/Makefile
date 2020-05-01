
PROG=abort
PROG_C=abort.c

DISK_IMAGE=sgxlkl-abort.img
IMAGE_SIZE=5M

EXECUTION_TIMEOUT=60

SGXLKL_ROOT=../../..
SGXLKL_STARTER=$(SGXLKL_ROOT)/build/sgx-lkl-run-oe
SGXLKL_DISK_TOOL=${SGXLKL_ROOT}/tools/sgx-lkl-disk
SGXLKL_GDB=${SGXLKL_ROOT}/tools/gdb/sgx-lkl-gdb

ifeq ($(SGXLKL_VERBOSE),)
SGXLKL_ENV=\
   SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1 SGXLKL_TRACE_SIGNAL=0\
   SGXLKL_TRACE_HOST_SYSCALL=0 SGXLKL_TRACE_LKL_SYSCALL=0 SGXLKL_TRACE_MMAP=0
else
SGXLKL_ENV=
endif

.DELETE_ON_ERROR:
.PHONY: all clean

$(DISK_IMAGE): $(PROG_C)
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --docker=./Dockerfile ${DISK_IMAGE}

gettimeout:
	@echo ${EXECUTION_TIMEOUT}

run: run-hw run-sw

run-hw: $(DISK_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --hw-debug $(DISK_IMAGE) $(PROG); \
	if [ $$? -eq 134 ]; then \
		echo "TEST PASSED: abort (HW mode)"; \
	else \
		echo "TEST FAILED: abort (HW mode) - exit code: $$?"; \
	fi

run-hw-gdb: $(DISK_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_GDB} --args ${SGXLKL_STARTER} --hw-debug $(DISK_IMAGE) $(PROG)

run-sw: $(DISK_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --sw-debug $(DISK_IMAGE) $(PROG); \
	if [ $$? -eq 134 ]; then \
		echo "TEST PASSED: abort (SW mode)"; \
	else \
		echo "TEST FAILED: abort (SW mode) - exit code: $$?"; \
	fi

run-sw-gdb: $(DISK_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_GDB} --args ${SGXLKL_STARTER} --sw-debug $(DISK_IMAGE) $(PROG)

clean:
	rm -f $(DISK_IMAGE)
