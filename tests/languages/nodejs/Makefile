include ../../common.mk

PROG=/app/index.js
ENCLAVE_CMD=/usr/bin/node ${PROG}

DISK_IMAGE=sgxlkl-nodejs.img
IMAGE_SIZE=1.2G

ifeq ($(SGXLKL_VERBOSE),)
SGXLKL_ENV=\
   SGXLKL_MMAP_FILES=Shared SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=0 \
        SGXLKL_TRACE_SIGNAL=0 SGXLKL_TRACE_HOST_SYSCALL=0 SGXLKL_TRACE_LKL_SYSCALL=0 SGXLKL_TRACE_MMAP=0
else
SGXLKL_ENV=SGXLKL_MMAP_FILES=Shared
endif

.DELETE_ON_ERROR:
.PHONY: run run-hw run-sw clean

$(DISK_IMAGE): $(PROG_SRC)
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --docker=Dockerfile ${DISK_IMAGE}

run: run-hw run-sw

run-hw: $(DISK_IMAGE)
	@echo "${SGXLKL_ENV} ${SGXLKL_STARTER} --hw-debug ${DISK_IMAGE} ${ENCLAVE_CMD}"
	@${SGXLKL_ENV} ${SGXLKL_STARTER} --hw-debug ${DISK_IMAGE} ${ENCLAVE_CMD}

run-sw: $(DISK_IMAGE)
	@echo "${SGXLKL_ENV} ${SGXLKL_STARTER} --sw-debug ${DISK_IMAGE} ${ENCLAVE_CMD}"
	@${SGXLKL_ENV} ${SGXLKL_STARTER} --sw-debug ${DISK_IMAGE} ${ENCLAVE_CMD}

clean:
	rm -f $(DISK_IMAGE)
