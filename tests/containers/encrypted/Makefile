DIRS=app-config-integrity app-config-verity create-disk verify-crypt verify-integrity verify-verity

define NL


endef

all:

tests: run-hw run-sw

run-hw:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) run-hw $(NL) )

run-sw:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) run-sw $(NL) )

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )
