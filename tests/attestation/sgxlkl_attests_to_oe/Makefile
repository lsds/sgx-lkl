# This test case runs two enclaves: oe_enclave and sgxlkl_enclave
# oe_enclave runs as tls server and the sgxlkl_enclave will be the tls client
# sgxlkl_enclave should be able to generate the certificate and send to tls server for verify
# however, sgxlkl_enclave not able to gernerate the cert now.
# So this test case only cover the tls server cert verification part
# which use the pregenerated cert

all: run-hw run-sw

skip-run-sw:
	@echo "true"

run-sw:
	@bash run_scenario.sh sw

run-hw:
	@bash run_scenario.sh hw

clean:
	$(MAKE) -C sgxlkl_enclave clean 
	$(MAKE) -C oe_enclave clean

