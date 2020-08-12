all: build

build:
	$(MAKE) -C enc
	$(MAKE) -C host

clean:
	$(MAKE) -C enc clean
	$(MAKE) -C host clean

run:
	@host/tlssrv_host ./enc/tlssrv_enc.signed $(SGXLKL_RUN_MODE) >> $(ATTESTED_TLS_TEST_LOG_FILE) 2>&1 &
	@echo "OE Enclave app started..."
