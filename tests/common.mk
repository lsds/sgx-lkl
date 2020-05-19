mkfile_dir=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))
# Note: SGXLKL_ROOT needs to be exported because LTP tests rely on it.
export SGXLKL_ROOT=$(realpath $(mkfile_dir)..)

ifeq (${SGXLKL_PREFIX},)
	export SGXLKL_STARTER=$(SGXLKL_ROOT)/build/sgx-lkl-run-oe
	export SGXLKL_DISK_TOOL=${SGXLKL_ROOT}/tools/sgx-lkl-disk
	export SGXLKL_DOCKER_TOOL=${SGXLKL_ROOT}/tools/sgx-lkl-docker
	export SGXLKL_GDB=${SGXLKL_ROOT}/tools/gdb/sgx-lkl-gdb
	export SGXLKL_JAVA_RUN=${SGXLKL_ROOT}/tools/sgx-lkl-java
else
	export SGXLKL_STARTER=$(SGXLKL_PREFIX)/bin/sgx-lkl-run-oe
	export SGXLKL_DISK_TOOL=${SGXLKL_PREFIX}/bin/sgx-lkl-disk
	export SGXLKL_DOCKER_TOOL=${SGXLKL_PREFIX}/bin/sgx-lkl-docker
	export SGXLKL_GDB=${SGXLKL_PREFIX}/bin/sgx-lkl-gdb
	export SGXLKL_JAVA_RUN=${SGXLKL_PREFIX}/bin/sgx-lkl-java

	# Infer build mode if not given.
	ifeq (${SGXLKL_BUILD_MODE},)
		ifeq (${SGXLKL_PREFIX},/opt/sgx-lkl-debug)
			export SGXLKL_BUILD_MODE=debug
		else ifeq (${SGXLKL_PREFIX},/opt/sgx-lkl-nonrelease)
			export SGXLKL_BUILD_MODE=nonrelease
		else
			$(error SGXLKL_BUILD_MODE not set and SGXLKL_PREFIX is not a standard path)
		endif
	endif
endif