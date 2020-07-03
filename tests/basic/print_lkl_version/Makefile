include ../../common.mk

TEST=print_lkl_version-test

DISK_IMAGE=sgxlkl-${TEST}.img
IMAGE_SIZE=16M

SGXLKL_ENV=SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1

.DELETE_ON_ERROR:
.PHONY: clean

run: run-hw

$(DISK_IMAGE):
	rm -f ${DISK_IMAGE}
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --alpine="busybox" ${DISK_IMAGE}

run-hw: $(DISK_IMAGE)
	@(${SGXLKL_ENV} ${SGXLKL_STARTER} --hw-debug ${DISK_IMAGE} /bin/uname -a 2>&1 | grep -E ' LKL \S+') && echo "TEST PASSED (found LKL version string)"
	
run-sw: $(DISK_IMAGE)
	@(${SGXLKL_ENV} ${SGXLKL_STARTER} --sw-debug ${DISK_IMAGE} /bin/uname -a 2>&1 | grep -E ' LKL \S+') && echo "TEST PASSED (found LKL version string)"

clean:
	rm -f $(DISK_IMAGE)
