# Copyright Microsoft. 
# Licensed under the attached Microsoft Software License Terms

.PHONY: all clean alpine-container alpine-binaries lkl-image lkl-run

COMMONS="../common"
SGXLKL_BIN_ROOT="$(SGXLKL_PREFIX)/bin"
BUILD_DIR="/src/sgxlkl_enclave"
SERVER_COMMON="/src/common"

build-alpine-exe = sudo gcc -g -o $(BUILD_DIR)/alpine_server -fshort-wchar $(BUILD_DIR)/client.c $(BUILD_DIR)/tlscli.c $(SERVER_COMMON)/log_utils.c $(SERVER_COMMON)/settings.c -lmbedtls -lmbedx509 -lmbedcrypto -ldl -lcurl

all: lkl-image

clean:
	rm -f clientAgent.o client alpine_server sgxlkl-image.img*

alpine-container:
	docker build -t alpine3.10.build ./alpine

alpine-binaries: alpine-container
	docker run --rm  -v $(CURDIR)/..:/src alpine3.10.build bash -c "$(build-alpine-exe)"
	sudo chown $(USER):$(GROUP) alpine_server

lkl-image: alpine-binaries
	rm -rf sgxlkl-image.img
	$(SGXLKL_BIN_ROOT)/sgx-lkl-disk create --size=100M --docker=./Dockerfile sgxlkl-image.img

lkl-run:
	SGXLKL_VERBOSE=0 SGXLKL_GETTIME_VDSO=0 SGXLKL_TAP=sgxlkl_tap0 $(SGXLKL_BIN_ROOT)/sgx-lkl-run-oe --$(SGXLKL_RUN_MODE)-debug sgxlkl-image.img /client 10.0.1.254 >> $(ATTESTED_TLS_TEST_LOG_FILE) 2>&1