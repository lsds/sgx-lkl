include ../../common.mk

APP_ROOT=app
PROG=${APP_ROOT}/python-helloworld.py

DISK_IMAGE=rootfs.img
DATA_IMAGE=data.img
IMAGE_SIZE=100M

CC=python-helloworld-cc
CC_stamp=$(CC).stamp

# This test verifies in-enclave networking.
# TODO verify host-side networking for DCAP Client
CC_DOCKER_ARGS=\
	--rm --privileged --network=host \
	-v $(SGXLKL_PREFIX):$(SGXLKL_PREFIX) \
	-e SGXLKL_VERBOSE=1 -e SGXLKL_KERNEL_VERBOSE=1 -e SGXLKL_TAP=sgxlkl_tap0

.DELETE_ON_ERROR:
.PHONY: run run-hw run-sw clean

$(DISK_IMAGE): $(PROG)
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --docker=./Dockerfile ${DISK_IMAGE}

$(DATA_IMAGE): $(DISK_IMAGE)
	cp $(DISK_IMAGE) $(DATA_IMAGE)

$(CC_stamp): $(DISK_IMAGE) $(DATA_IMAGE)
	$(SGXLKL_DOCKER_TOOL) build-cc --name=$(CC) --mode=$(SGXLKL_BUILD_MODE) --host-cfg=host-config.json --app-cfg=app-config.json
	touch $(CC_stamp)

run: run-hw run-sw

ifeq (${SGXLKL_PREFIX},)
run-hw:
	@echo SGXLKL_PREFIX missing, skipping test

run-sw:
	@echo SGXLKL_PREFIX missing, skipping test
else
run-hw: $(CC_stamp)
	docker run $(CC_DOCKER_ARGS) $(CC) --hw-debug

run-sw: $(CC_stamp)
	# TODO -t as work-around for https://github.com/lsds/sgx-lkl/issues/158
	docker run -t $(CC_DOCKER_ARGS) $(CC) --sw-debug
endif

clean:
	rm -f $(DISK_IMAGE) $(DATA_IMAGE) $(CC)
