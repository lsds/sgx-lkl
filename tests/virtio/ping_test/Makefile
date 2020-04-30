# Makefile for test application

SHELL := /bin/bash

SGXLKL_ROOT=../../..

APP_DIRECTORY=app
APP=dummy_server
SRC=dummy_server.c

DISK_IMAGE=sgxlkl-ping.img
IMAGE_SIZE=128M

MUSL_CC=${SGXLKL_ROOT}/build/host-musl/bin/musl-gcc
SGXLKL_CMD=${SGXLKL_ROOT}/build/sgx-lkl-run-oe
SGXLKL_DISK_TOOL=${SGXLKL_ROOT}/tools/sgx-lkl-disk

SGXLKL_ENV_OPTS=SGXLKL_GETTIME_VDSO=0
SGXLKL_NETWORK_SETTING=SGXLKL_TAP=sgxlkl_tap0 SGXLKL_IP4=10.0.1.2
VERBOSE_OPTS=SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1 SGXLKL_TRACE_SIGNAL=1

ifeq ($(SGXLKL_VERBOSE),)
	SGXLKL_ENV+=${VERBOSE_OPTS}
endif
SGXLKL_ENV+=${SGXLKL_ENV_OPTS} ${SGXLKL_NETWORK_SETTING}

.DELETE_ON_ERROR:
.PHONY: clean

$(APP): $(SRC)
	${MUSL_CC} -fPIE -pie -o $@ $(SRC)
	@mkdir -p ${APP_DIRECTORY}
	@mv -f $@ ${APP_DIRECTORY}

$(DISK_IMAGE): $(APP)
	@rm -f ${DISK_IMAGE}
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --alpine="bash shadow sudo" --copy=./${APP_DIRECTORY}/ ${DISK_IMAGE}

all: $(DISK_IMAGE)

.ONESHELL:

run-hw: $(DISK_IMAGE)
	${SGXLKL_ENV} expect -c "
		spawn ${SGXLKL_CMD} --hw-debug $(DISK_IMAGE) ${APP_DIRECTORY}/${APP}
		expect \"Press 'Q' to quit\"
		send \"Q\r\"
		expect eof"

run-sw: $(DISK_IMAGE)
	${SGXLKL_ENV} expect -c "
		spawn ${SGXLKL_CMD} --sw-debug $(DISK_IMAGE) ${APP_DIRECTORY}/${APP}
		expect \"Press 'Q' to quit\"
		send \"Q\r\"
		expect eof"

clean:
	@rm -f $(DISK_IMAGE)
	@rm -f $(APP_DIRECTORY)/${APP}
