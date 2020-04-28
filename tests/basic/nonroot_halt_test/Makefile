# Makefile for test application

APP_DIRECTORY=app
APP=nonroot_halt_test
SRC=nonroot_halt_test.c

DISK_IMAGE=sgxlkl-${APP}.img
IMAGE_SIZE=64M

SGXLKL_ROOT=../../..
MUSL_CC=${SGXLKL_ROOT}/build/host-musl/bin/musl-gcc
SGXLKL_CMD=${SGXLKL_ROOT}/build/sgx-lkl-run-oe
SGXLKL_DISK_TOOL=${SGXLKL_ROOT}/tools/sgx-lkl-disk

SGXLKL_ENV=SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1 SGXLKL_TRACE_SIGNAL=1

.DELETE_ON_ERROR:
.PHONY: clean

run: run-hw run-sw

$(APP): $(SRC)
	${MUSL_CC} -fPIE -pie -o $@ $(SRC)
	@mkdir -p ${APP_DIRECTORY}
	@mv -f $@ ${APP_DIRECTORY}

$(DISK_IMAGE): $(APP)
	@rm -f ${DISK_IMAGE}
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --alpine="bash shadow sudo" --copy=./${APP_DIRECTORY}/ ${DISK_IMAGE}

run-hw: $(DISK_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_CMD} --hw-debug ${DISK_IMAGE} $(APP_DIRECTORY)/$(APP)

run-sw: $(DISK_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_CMD} --sw-debug ${DISK_IMAGE} $(APP_DIRECTORY)/$(APP)

clean:
	rm -f $(DISK_IMAGE) $(APP)
	@rm -rf $(APP_DIRECTORY)
