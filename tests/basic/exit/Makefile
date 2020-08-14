include ../../common.mk

TEST_EXIT=exit-test
TEST_SEGFAULT=segfault-test
TEST_RAISE=raise-test
TEST_SPIN=spin-test

SRCS=$(wildcard *.c)

DISK_IMAGE=sgxlkl-exit-test.img
IMAGE_SIZE=5M

SGXLKL_ENV=SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1 SGXLKL_TRACE_SIGNAL=1 SGXLKL_ETHREADS=8

SHELL := /bin/bash

.DELETE_ON_ERROR:
.PHONY: clean run-hw run-sw run-exit-hw run-segfault-hw run-raise-hw run-spin-hw run-exit-sw run-segfault-sw run-raise-sw run-spin-sw

run: run-hw run-sw

run-hw: run-exit-hw run-segfault-hw run-raise-hw run-spin-hw

run-sw: run-exit-sw run-segfault-sw run-raise-sw run-spin-sw

$(DISK_IMAGE): $(SRCS)
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --docker=./Dockerfile ${DISK_IMAGE}

run-exit-hw: $(DISK_IMAGE)
	@${SGXLKL_ENV} ${SGXLKL_STARTER} --hw-debug ${DISK_IMAGE} $(TEST_EXIT); \
            if [ $$? -eq 42 ]; then \
                echo "TEST PASSED: exit() (HW mode)"; \
            else \
                echo "TEST FAILED: exit() (HW mode)" && exit -1; \
            fi

run-segfault-hw: $(DISK_IMAGE)
    # Next we need to filter out the string "Segementation fault", 
    # otherwise the CI pipelines flags the test as failed.
	@set -o pipefail; ${SGXLKL_ENV} ${SGXLKL_STARTER} --hw-debug ${DISK_IMAGE} $(TEST_SEGFAULT) | grep -v -x "Segmentation fault"; \
			if [ $$? -eq 139 ]; then \
                echo "TEST PASSED: segv (HW mode)"; \
            else \
                echo "TEST FAILED: segv (HW mode)" && exit -1; \
            fi

run-raise-hw: $(DISK_IMAGE)
	@${SGXLKL_ENV} ${SGXLKL_STARTER} --hw-debug ${DISK_IMAGE} $(TEST_RAISE); \
	        if [ $$? -eq 143 ]; then \
                echo "TEST PASSED: raise (HW mode)"; \
            else \
                echo "TEST FAILED: raise (HW mode)" && exit -1; \
            fi

run-spin-hw: $(DISK_IMAGE)
	@${SGXLKL_ENV} ${SGXLKL_STARTER} --hw-debug ${DISK_IMAGE} $(TEST_SPIN)

run-exit-sw: $(DISK_IMAGE)
	@${SGXLKL_ENV} ${SGXLKL_STARTER} --sw-debug ${DISK_IMAGE} $(TEST_EXIT); \
            if [ $$? -eq 42 ]; then \
                echo "TEST PASSED: exit (SW mode)"; \
            else \
                echo "TEST FAILED: segfault (SW mode)" && exit -1; \
            fi

run-segfault-sw: $(DISK_IMAGE)
    # Next we need to filter out the string "Segementation fault", 
    # otherwise the CI pipelines flags the test as failed.
	@set -o pipefail; ${SGXLKL_ENV} ${SGXLKL_STARTER} --sw-debug ${DISK_IMAGE} $(TEST_SEGFAULT) | grep -v -x "Segmentation fault"; \
			if [ $$? -eq 139 ]; then \
                echo "TEST PASSED: segv (SW mode)"; \
            else \
                echo "TEST FAILED: segv (SW mode)" && exit -1; \
            fi

run-raise-sw: $(DISK_IMAGE)
	@${SGXLKL_ENV} ${SGXLKL_STARTER} --sw-debug ${DISK_IMAGE} $(TEST_RAISE); \
	        if [ $$? -eq 143 ]; then \
                echo "TEST PASSED: raise (SW mode)"; \
            else \
                echo "TEST FAILED: raise (SW mode)" && exit -1; \
            fi

run-spin-sw: $(DISK_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --sw-debug ${DISK_IMAGE} $(TEST_SPIN)

clean:
	rm -f $(DISK_IMAGE)
