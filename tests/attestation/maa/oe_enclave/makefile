all: build

build:
	$(MAKE) -C enc
	$(MAKE) -C host

clean:
	$(MAKE) -C enc clean
	$(MAKE) -C host clean

run:
	@host/oeApp_host ./enc/oeApp_enc.signed $(SGXLKL_RUN_MODE) >> $(MAA_TEST1_LOG_FILE) 2>&1 &
	@echo "OE Enclave app started..."

