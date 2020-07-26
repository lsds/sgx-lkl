include ../../common.mk

all: run-hw run-sw

run-sw:
	@. /opt/openenclave/share/openenclave/openenclaverc
	@bash run_scenario.sh sw

run-hw:
	@. /opt/openenclave/share/openenclave/openenclaverc
	@bash run_scenario.sh hw

clean:
	$(MAKE) -C sgxlkl_enclave clean 
	$(MAKE) -C oe_enclave  clean

