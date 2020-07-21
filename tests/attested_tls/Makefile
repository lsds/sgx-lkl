# This test case will run two enclaves: oe_enclave and sgxlkl_enclave
# oe_enclave will run as tls server and the sgxlkl_enclave will be the tls client
# sgxlkl_enclave should be able to generate the certificate and send to tls server for verify
# however, sgxlkl_enclave not able to gernerate the cert now.
# So this test case will only cover the tls server cert verification part
# which use the pregenerated cert (type 1)

all: run-hw run-sw

run-sw:
	@export SGXLKL_RUN_MODE=sw
	@bash run_scenario.sh

run-hw:
	@export SGXLKL_RUN_MODE=hw
	@bash run_scenario.sh

clean:
	$(MAKE) -C sgxlkl_enclave clean 
	$(MAKE) -C oe_enclave clean

