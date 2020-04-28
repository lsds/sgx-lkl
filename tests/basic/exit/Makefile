# Makefile for test application

BUILDDIR=apps

TEST1=$(BUILDDIR)/exit-test
TEST2=$(BUILDDIR)/segfault-test
TEST3=$(BUILDDIR)/raise-test

SRCS=$(wildcard *.c)
DISK_IMAGE=sgxlkl-exit-test.img
IMAGE_SIZE=16M

SGXLKL_ROOT=../../..
MUSL_CC=${SGXLKL_ROOT}/build/host-musl/bin/musl-gcc
SGXLKL_CMD=${SGXLKL_ROOT}/build/sgx-lkl-run-oe
SGXLKL_DISK_TOOL=${SGXLKL_ROOT}/tools/sgx-lkl-disk

SGXLKL_ENV=SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1 SGXLKL_TRACE_SIGNAL=1

SHELL := /bin/bash

.DELETE_ON_ERROR:
.PHONY: clean

$(BUILDDIR)/%: %.c
	@mkdir -p $(BUILDDIR)
	${MUSL_CC} -fPIE -pie -o $@ $<

run: run-hw run-sw

$(DISK_IMAGE): $(TEST1) $(TEST2) $(TEST3)
	rm -f ${DISK_IMAGE}
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --alpine="busybox" --copy=$(BUILDDIR) ${DISK_IMAGE}

run-hw: $(DISK_IMAGE)
	@${SGXLKL_ENV} ${SGXLKL_CMD} --hw-debug ${DISK_IMAGE} $(TEST1); \
            if [ $$? -eq 42 ]; then \
                echo "TEST PASSED: exit() (HW mode)"; \
            else \
                echo "TEST FAILED: exit() (HW mode)"; \
            fi
    # Next we need to filter out the string "Segementation fault", 
    # otherwise the CI pipelines flags the test as failed.
	@set -o pipefail; ${SGXLKL_ENV} ${SGXLKL_CMD} --hw-debug ${DISK_IMAGE} $(TEST2) | grep -v -x "Segmentation fault"; \
			if [ $$? -eq 139 ]; then \
                echo "TEST PASSED: segv (HW mode)"; \
            else \
                echo "TEST FAILED: segv (HW mode)"; \
            fi
	@${SGXLKL_ENV} ${SGXLKL_CMD} --hw-debug ${DISK_IMAGE} $(TEST3); \
	        if [ $$? -eq 143 ]; then \
                echo "TEST PASSED: raise (HW mode)"; \
            else \
                echo "TEST FAILED: raise (HW mode)"; \
            fi

run-sw: $(DISK_IMAGE)
	@${SGXLKL_ENV} ${SGXLKL_CMD} --sw-debug ${DISK_IMAGE} $(TEST1); \
            if [ $$? -eq 42 ]; then \
                echo "TEST PASSED: exit (SW mode)"; \
            else \
                echo "TEST FAILED: segfault (SW mode)"; \
            fi
    # Next we need to filter out the string "Segementation fault", 
    # otherwise the CI pipelines flags the test as failed.
	@set -o pipefail; ${SGXLKL_ENV} ${SGXLKL_CMD} --hw-debug ${DISK_IMAGE} $(TEST2) | grep -v -x "Segmentation fault"; \
			if [ $$? -eq 139 ]; then \
                echo "TEST PASSED: segv (SW mode)"; \
            else \
                echo "TEST FAILED: segv (SW mode)"; \
            fi
	@${SGXLKL_ENV} ${SGXLKL_CMD} --hw-debug ${DISK_IMAGE} $(TEST3); \
			if [ $$? -eq 143 ]; then \
                echo "TEST PASSED: raise (SW mode)"; \
             else \
                echo "TEST FAILED: raise (SW mode)"; \
             fi

clean:
	rm -f $(DISK_IMAGE)
	rm -rf $(BUILDDIR)
