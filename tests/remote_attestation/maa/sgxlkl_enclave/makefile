.PHONY: all build clean alpine-container alpine-binaries lkl-image lkl-run

COMMONS="../common"
SGXLKL_BIN_ROOT="$(SGXLKL_PREFIX)/bin"
BUILD_DIR="/src/sgxlkl_enclave"
SGXLKLAPP_COMMON="/src/common"

build-alpine-exe = sudo gcc -g -o $(BUILD_DIR)/alpine_sgxLklApp -fshort-wchar $(BUILD_DIR)/sgxLklApp.c $(BUILD_DIR)/clientAgent_init.c $(BUILD_DIR)/tlscli.c $(SGXLKLAPP_COMMON)/log_utils.c $(SGXLKLAPP_COMMON)/auth.cpp $(SGXLKLAPP_COMMON)/maa.cpp $(SGXLKLAPP_COMMON)/transport_utils.c $(SGXLKLAPP_COMMON)/curl_helper.cpp $(SGXLKLAPP_COMMON)/json_utils.c $(BUILD_DIR)/oe_private/verify_cert.c $(BUILD_DIR)/oe_private/cert.c -lmbedtls -lmbedx509 -lmbedcrypto -ldl -lcurl


all: lkl-image

clean:
	rm -f clientAgent.o alpine_sgxLklApp sgxlkl-image.img*

alpine-container:
	docker build -t alpine3.10.build ./alpine

alpine-binaries: alpine-container
	docker run --rm  -v $(CURDIR)/..:/src alpine3.10.build bash -c "$(build-alpine-exe)"
	sudo chown $(USER):$(GROUP) alpine_sgxLklApp

lkl-image: alpine-binaries
	rm -rf sgxlkl-image.img
	@echo "sgxlkl_enclave.makefile-MAA_CLIENT_ID: $(MAA_CLIENT_ID)"
	@echo "sgxlkl_enclave.makefile-MAA_CLIENT_SECRET: $(MAA_CLIENT_SECRET)"
	docker build --build-arg MAACLIENTID=$(MAA_CLIENT_ID) --build-arg MAACLIENTSECRET=$(MAA_CLIENT_SECRET) -t sgxlkl-app:dev .
	$(SGXLKL_BIN_ROOT)/sgx-lkl-disk create --size=100M --docker=sgxlkl-app:dev sgxlkl-image.img

# This runs sgxlkl_enclave app inside enclave with SGX-LKL
lkl-run:
	SGXLKL_VERBOSE=0 SGXLKL_GETTIME_VDSO=0 SGXLKL_TAP=sgxlkl_tap0 $(SGXLKL_BIN_ROOT)/sgx-lkl-run-oe  --$(SGXLKL_RUN_MODE)-debug sgxlkl-image.img /sgxLklApp 10.0.1.254  >> $(MAA_TEST1_LOG_FILE) 2>&1

