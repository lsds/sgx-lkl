# Makefile for test application

TEST=pthread_join-test

SRC=$(TEST).c
DISK_IMAGE=sgxlkl-${TEST}.img
IMAGE_SIZE=16M

SGXLKL_ROOT=../../..
MUSL_CC=${SGXLKL_ROOT}/build/host-musl/bin/musl-gcc
SGXLKL_CMD=${SGXLKL_ROOT}/build/sgx-lkl-run-oe
SGXLKL_DISK_TOOL=${SGXLKL_ROOT}/tools/sgx-lkl-disk

SGXLKL_ENV=SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1 SGXLKL_TRACE_SIGNAL=0

.DELETE_ON_ERROR:
.PHONY: clean

run: run-hw

$(TEST): $(SRC)
	${MUSL_CC} -fPIE -pie -pthread -o $@ $(SRC)

$(DISK_IMAGE): $(TEST)
	rm -f ${DISK_IMAGE}
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --alpine="busybox" --copy=$(TEST) ${DISK_IMAGE}

run-hw: $(DISK_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_CMD} --hw-debug ${DISK_IMAGE} $(TEST)

run-sw: $(DISK_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_CMD} --sw-debug ${DISK_IMAGE} $(TEST)

clean:
	rm -f $(DISK_IMAGE) $(TEST)
