
APP_ROOT=app
PROG=/home/user/dldt/bin/intel64/Debug/hello_nv12_input_classification

DISK_IMAGE=sgxlkl-openvino.img
IMAGE_SIZE=4096M

SGXLKL_ROOT=../../..

ENCLAVE_CMD=${PROG} /app/public_models/squeezenet1.1.xml /app/public_models/car.yuv 640x480 CPU

SGXLKL_STARTER=$(SGXLKL_ROOT)/build/sgx-lkl-run-oe

ifeq ($(SGXLKL_VERBOSE),)
SGXLKL_ENV=\
   SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=0 SGXLKL_TRACE_SIGNAL=0\
   SGXLKL_TRACE_HOST_SYSCALL=0 SGXLKL_TRACE_LKL_SYSCALL=0 SGXLKL_TRACE_MMAP=0
else
SGXLKL_ENV=
endif

SGXLKL_DISK_TOOL=${SGXLKL_ROOT}/tools/sgx-lkl-disk
SGXLKL_GDB=${SGXLKL_ROOT}/tools/gdb/sgx-lkl-gdb

.DELETE_ON_ERROR:
.PHONY: all clean

all: $(DISK_IMAGE)

clean:
	rm -f $(DISK_IMAGE)

$(DISK_IMAGE): Dockerfile
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --docker=./Dockerfile --copy=./${APP_ROOT}/ ${DISK_IMAGE}

run: run-hw

run-hw: $(DISK_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --hw-debug $(DISK_IMAGE) $(ENCLAVE_CMD)

run-hw-gdb: $(DISK_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_GDB} --args ${SGXLKL_STARTER} --hw-debug $(DISK_IMAGE) $(ENCLAVE_CMD)

run-sw: $(DISK_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --sw-debug $(DISK_IMAGE) $(ENCLAVE_CMD)

run-sw-gdb: $(DISK_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_GDB} --args ${SGXLKL_STARTER} --sw-debug $(DISK_IMAGE) $(ENCLAVE_CMD)
