include ../../../common.mk

DISK_IMAGE=java-dacapo.img
IMAGE_SIZE=750M

ifeq ($(SGXLKL_VERBOSE),)
SGXLKL_ENV=\
   SGXLKL_TAP=sgxlkl_tap0 SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1 SGXLKL_TRACE_LKL_SYSCALL=0 SGXLKL_TRACE_SIGNAL=0
else
SGXLKL_ENV=
endif

.DELETE_ON_ERROR:
.PHONY: run run-hw run-sw clean

$(DISK_IMAGE): $(PROG_SRC)
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --docker=Dockerfile ${DISK_IMAGE}

run: run-hw run-sw

run-hw: $(DISK_IMAGE)
	sgx-lkl-run-oe --hw-debug 
	${SGXLKL_ENV} ${SGXLKL_STARTER} --hw-debug --host-config=java-dacapo-host_config.json --enclave-config=java-dacapo-enclave_config.json

run-sw: $(DISK_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --sw-debug --host-config=java-dacapo-host_config.json --enclave-config=java-dacapo-enclave_config.json

clean:
	rm -f $(DISK_IMAGE)
