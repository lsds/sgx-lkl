# Makefile for test application

TEST=print_lkl_version-test

DISK_IMAGE=sgxlkl-${TEST}.img
IMAGE_SIZE=16M

SGXLKL_ROOT=../../..
MUSL_CC=${SGXLKL_ROOT}/build/host-musl/bin/musl-gcc
SGXLKL_CMD=${SGXLKL_ROOT}/build/sgx-lkl-run-oe
SGXLKL_DISK_TOOL=${SGXLKL_ROOT}/tools/sgx-lkl-disk

SGXLKL_ENV=SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1

.DELETE_ON_ERROR:
.PHONY: clean

run: run-hw

$(DISK_IMAGE):
	rm -f ${DISK_IMAGE}
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --alpine="busybox" ${DISK_IMAGE}

run-hw: $(DISK_IMAGE)
	@(${SGXLKL_ENV} ${SGXLKL_CMD} --hw-debug ${DISK_IMAGE} /bin/uname -a 2>&1 | grep -E 'LKL version \S+') && echo "TEST PASSED (found LKL version string)"
	
run-sw: $(DISK_IMAGE)
	@(${SGXLKL_ENV} ${SGXLKL_CMD} --sw-debug ${DISK_IMAGE} /bin/uname -a 2>&1 | grep -E 'LKL version \S+') && echo "TEST PASSED (found LKL version string)"

clean:
	rm -f $(DISK_IMAGE)
