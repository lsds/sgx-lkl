include ../../../common.mk

APP_ROOT=app
PROG_SRC=${APP_ROOT}/HelloWorld.java

DISK_IMAGE=sgxlkl-java.img
IMAGE_SIZE=400M

ifeq ($(SGXLKL_VERBOSE),)
SGXLKL_ENV=\
   SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1 SGXLKL_TRACE_LKL_SYSCALL=0 SGXLKL_TRACE_SIGNAL=0
else
SGXLKL_ENV=
endif

.DELETE_ON_ERROR:
.PHONY: run run-hw run-sw clean

$(DISK_IMAGE): $(PROG_SRC)
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --docker=Dockerfile ${DISK_IMAGE}

run: run-hw run-sw

run-hw: $(DISK_IMAGE)
	@echo "sgx-lkl-java --hw-debug ${DISK_IMAGE} HelloWorld"
	@${SGXLKL_ENV} ${SGXLKL_JAVA_RUN} --hw-debug ${DISK_IMAGE} HelloWorld

run-sw: $(DISK_IMAGE)
	@echo "sgx-lkl-java --sw-debug ${DISK_IMAGE} HelloWorld"
	@${SGXLKL_ENV} ${SGXLKL_JAVA_RUN} --sw-debug ${DISK_IMAGE} HelloWorld

run-hw-gdb: $(DISK_IMAGE)
	@echo "${SGXLKL_ENV} sgx-lkl-java --hw-debug ${DISK_IMAGE} ${PROG}"
	@${SGXLKL_ENV} ${SGXLKL_JAVA_RUN} --hw-debug ${DISK_IMAGE} --debug ${PROG}

clean:
	rm -f $(DISK_IMAGE)
