include ../../common.mk

all: run-hw run-sw

skip-run-sw:
	@echo "true"

run-sw:
	@bash run_scenario.sh sw

run-hw:
	@bash run_scenario.sh hw

clean:
	$(MAKE) -C sgxlkl_enclave clean 
	$(MAKE) -C oe_enclave  clean

