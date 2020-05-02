include ../../common.mk

APP_ROOT=app
PROG_SRC=${APP_ROOT}/HelloWorld.java
PROG=${APP_ROOT}/HelloWorld.class

DISK_IMAGE=sgxlkl-java-fs.img
IMAGE_SIZE=400M

ifeq ($(SGXLKL_VERBOSE),)
SGXLKL_ENV=\
   SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1 SGXLKL_TRACE_LKL_SYSCALL=0 SGXLKL_TRACE_SIGNAL=0
else
SGXLKL_ENV=
endif

.DELETE_ON_ERROR:
.PHONY: run run-hw run-sw clean

${PROG}: ${PROG_SRC}
	javac -source 1.8 -target 1.8 $<

$(DISK_IMAGE): $(PROG)
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --alpine="iputils iproute2 unzip libstdc++ openjdk8-jre nss" --copy=./${APP_ROOT}/ ${DISK_IMAGE}

run: run-hw run-sw

run-hw: $(DISK_IMAGE)
	@echo "sgx-lkl-java --hw-debug ${DISK_IMAGE} HelloWorld"
	@${SGXLKL_ENV} ${SGXLKL_JAVA_RUN} --hw-debug ${DISK_IMAGE} HelloWorld

run-sw: $(DISK_IMAGE)
	@echo "sgx-lkl-java --sw-debug ${DISK_IMAGE} HelloWorld"
	@${SGXLKL_ENV} ${SGXLKL_JAVA_RUN} --sw-debug ${DISK_IMAGE} HelloWorld

clean:
	rm -f $(DISK_IMAGE) app/${PROG}
