mkfile_dir=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))
export SGXLKL_ROOT=$(realpath $(mkfile_dir)..)

export SGXLKL_DISK_TOOL=${SGXLKL_ROOT}/tools/sgx-lkl-disk
export SGXLKL_JAVA_RUN=${SGXLKL_ROOT}/tools/sgx-lkl-java
export SGXLKL_GDB=${SGXLKL_ROOT}/tools/gdb/sgx-lkl-gdb

ifeq (${SGXLKL_PREFIX},)
	export SGXLKL_STARTER=$(SGXLKL_ROOT)/build/sgx-lkl-run-oe
else
	export SGXLKL_STARTER=$(SGXLKL_PREFIX)/bin/sgx-lkl-run-oe
endif