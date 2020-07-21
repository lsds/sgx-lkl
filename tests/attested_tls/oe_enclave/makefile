# Copyright Microsoft. 
# Licensed under the attached Microsoft Software License Terms.

all: build

build:
	@. /opt/openenclave/share/openenclave/openenclaverc
	$(MAKE) -C enc
	$(MAKE) -C host

clean:
	$(MAKE) -C enc clean
	$(MAKE) -C host clean

run:
	@. /opt/openenclave/share/openenclave/openenclaverc
	@host/tlssrv_host ./enc/tlssrv_enc.signed >> $(ATTESTED_TLS_TEST_LOG_FILE) 2>&1 &
	@echo "OE Enclave app started..."
