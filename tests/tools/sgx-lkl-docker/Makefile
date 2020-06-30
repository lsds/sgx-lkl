include ../../common.mk

APP_ROOT=app
PROG=${APP_ROOT}/python-helloworld.py

DISK_IMAGE=rootfs.img
DATA_IMAGE=data.img
IMAGE_SIZE=100M

# The re-packaged Docker image.
WRAP_DOCKER_IMAGE=test-sgx-lkl-docker
WRAP_DOCKER_IMAGE_STAMP=$(WRAP_DOCKER_IMAGE).stamp
# Note that an arbitrary/non-existing non-root user is used for launching the container.
WRAP_DOCKER_ARGS_COMMON=\
	--rm \
	--user 4242 \
	-v $(SGXLKL_PREFIX):/opt/sgx-lkl \
	-e SGXLKL_VERBOSE=1 -e SGXLKL_KERNEL_VERBOSE=1
WRAP_DOCKER_ARGS_HW=\
	--device /dev/sgx

.DELETE_ON_ERROR:
.PHONY: run run-hw run-sw clean

$(DISK_IMAGE): $(PROG)
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --docker=./Dockerfile ${DISK_IMAGE}

$(DATA_IMAGE): $(DISK_IMAGE)
	cp $(DISK_IMAGE) $(DATA_IMAGE)

$(WRAP_DOCKER_IMAGE_STAMP): $(DISK_IMAGE) $(DATA_IMAGE)
	$(SGXLKL_DOCKER_TOOL) build --name=$(WRAP_DOCKER_IMAGE) --host-cfg=host-config.json --app-cfg=app-config.json
	touch $(WRAP_DOCKER_IMAGE_STAMP)

run: run-hw run-sw

ifeq (${SGXLKL_PREFIX},)
run-hw:
	@echo SGXLKL_PREFIX missing, skipping test. See README.md.

run-sw:
	@echo SGXLKL_PREFIX missing, skipping test. See README.md.
else
run-hw: $(WRAP_DOCKER_IMAGE_STAMP)
	docker run $(WRAP_DOCKER_ARGS_COMMON) $(WRAP_DOCKER_ARGS_HW) $(WRAP_DOCKER_IMAGE) --hw-debug

run-sw: $(WRAP_DOCKER_IMAGE_STAMP)
	# TODO -t as work-around for https://github.com/lsds/sgx-lkl/issues/158
	docker run -t $(WRAP_DOCKER_ARGS_COMMON) $(WRAP_DOCKER_IMAGE) --sw-debug
endif

clean:
	rm -f $(DISK_IMAGE) $(DATA_IMAGE) $(WRAP_DOCKER_IMAGE)
