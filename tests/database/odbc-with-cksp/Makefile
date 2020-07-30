include ../../common.mk

PROG=odbc_app
PROG_SRC=odbc_app.c \
odbc_helper.c \
odbc_helper.h \
msodbcsql.h \
cksp.c
IMAGE_SIZE=50M

EXECUTION_TIMEOUT=120
SGXLKL_ENV=SGXLKL_VERBOSE=1 \
SGXLKL_KERNEL_VERBOSE=1 \
SGXLKL_TAP=sgxlkl_tap0

ENCLAVE_CONFIG_FILE=enclave-config.json
ENCLAVE_CONFIG=--enclave-config=$(ENCLAVE_CONFIG_FILE)
SGXLKL_HW_PARAMS=$(ENCLAVE_CONFIG) --hw-debug
SGXLKL_SW_PARAMS=$(ENCLAVE_CONFIG) --sw-debug

SGXLKL_ROOTFS=sgx-lkl-rootfs.img

.DELETE_ON_ERROR:
.PHONY: all clean

$(SGXLKL_ROOTFS): $(PROG_SRC)
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --docker=./Dockerfile ${SGXLKL_ROOTFS}

gettimeout:
	@echo ${EXECUTION_TIMEOUT}

run: run-hw run-sw

run-gdb: run-hw-gdb

run-hw: ${SGXLKL_ROOTFS}
	  $(SGXLKL_ENV) $(SGXLKL_STARTER) $(SGXLKL_HW_PARAMS) $(SGXLKL_ROOTFS)

run-sw: ${SGXLKL_ROOTFS}
	  $(SGXLKL_ENV) $(SGXLKL_STARTER) $(SGXLKL_SW_PARAMS) $(SGXLKL_ROOTFS)

run-hw-gdb: ${SGXLKL_ROOTFS}
	  $(SGXLKL_ENV) $(SGXLKL_GDB) --args $(SGXLKL_STARTER) $(SGXLKL_HW_PARAMS) $(SGXLKL_ROOTFS)

run-sw-gdb: ${SGXLKL_ROOTFS}
	  $(SGXLKL_ENV) $(SGXLKL_GDB) --args $(SGXLKL_STARTER) $(SGXLKL_SW_PARAMS) $(SGXLKL_ROOTFS)

clean:
	rm -f $(PROG) *.so *.o *.img*
