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

