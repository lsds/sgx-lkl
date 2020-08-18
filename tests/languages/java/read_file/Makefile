include ../../../common.mk

PROG=MainApp
MAINAPP_JAVA=app/MainApp.java
FILEREADER_JAVA=app/FileReadSample.java

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

$(DISK_IMAGE): $(MAINAPP_JAVA) $(FILEREADER_JAVA)
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --docker=Dockerfile ${DISK_IMAGE}

run: run-hw run-sw

ifeq ($(SGXLKL_ETHREADS),1)
skip-run-hw:
	@echo "true"

skip-run-sw:
	@echo "true"
endif

run-hw: $(DISK_IMAGE)
	@echo "sgx-lkl-java --hw-debug ${DISK_IMAGE} ${PROG}"
	@${SGXLKL_ENV} ${SGXLKL_JAVA_RUN} --hw-debug ${DISK_IMAGE} ${PROG}

run-sw: $(DISK_IMAGE)
	@echo "sgx-lkl-java --sw-debug ${DISK_IMAGE} ${PROG}"
	@${SGXLKL_ENV} ${SGXLKL_JAVA_RUN} --sw-debug ${DISK_IMAGE} ${PROG}

clean:
	rm -f $(DISK_IMAGE)
