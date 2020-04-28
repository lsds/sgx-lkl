SGXLKL_ROOT=../../..

APP_CONTAINER=alpine-tensorflow
ROOT_IMAGE=alpine-tensorflow.img
ROOT_IMAGE_SIZE=3G

SGXLKL_STARTER=$(SGXLKL_ROOT)/build/sgx-lkl-run-oe

ifeq ($(SGXLKL_VERBOSE),)
SGXLKL_ENV=\
   SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1 SGXLKL_TRACE_SIGNAL=0\
   SGXLKL_TRACE_HOST_SYSCALL=0 SGXLKL_TRACE_LKL_SYSCALL=0 SGXLKL_TRACE_IGNORED_SYSCALL=0 SGXLKL_TRACE_UNSUPPORTED_SYSCALL=0\
   SGXLKL_TRACE_MMAP=0
else
SGXLKL_ENV=
endif

APP=/usr/bin/python3
APP_PARAMS=/app/benchmark/helloworld.py

ESCALATE_CMD=sudo

.DELETE_ON_ERROR:
.PHONY: all clean

all: $(ROOT_IMAGE)

$(ROOT_IMAGE):
	@echo "sgx-lkl-disk create --size ${ROOT_IMAGE_SIZE} --docker=${APP_CONTAINER} --copy=./app ${ROOT_IMAGE}"
	@${SGXLKL_ROOT}/tools/sgx-lkl-disk create --size ${ROOT_IMAGE_SIZE} --docker=${APP_CONTAINER} --copy=./app ${ROOT_IMAGE}

run: run-hw

run-gdb: run-hw-gdb

run-hw: $(ROOT_IMAGE)
	$(SGXLKL_ENV) $(SGXLKL_STARTER) --hw-debug $(ROOT_IMAGE) $(APP) $(APP_PARAMS)

run-hw-gdb: $(ROOT_IMAGE)
	$(SGXLKL_ENV) ${SGXLKL_ROOT}/tools/gdb/sgx-lkl-gdb --args $(SGXLKL_STARTER) --hw-debug $(ROOT_IMAGE) $(APP) $(APP_PARAMS)

run-sw: $(ROOT_IMAGE)
	$(SGXLKL_ENV) $(SGXLKL_STARTER) --sw-debug $(ROOT_IMAGE) $(APP) $(APP_PARAMS)

run-sw-gdb: $(ROOT_IMAGE)
	$(SGXLKL_ENV) ${SGXLKL_ROOT}/tools/gdb/sgx-lkl-gdb --args $(SGXLKL_STARTER) --sw-debug $(ROOT_IMAGE) $(APP) $(APP_PARAMS)

clean:
	test -f $(ROOT_IMAGE) && rm $(ROOT_IMAGE) || true
