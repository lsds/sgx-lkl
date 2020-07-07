.PHONY: tests

include defs.mak

all: third_party_depends depend
	$(MAKE) -C libvicsetup
	$(MAKE) -C vicsetup

clean:
	$(MAKE) -C libvicsetup clean
	$(MAKE) -C vicsetup clean
	$(MAKE) -C tests clean

tests:
	$(MAKE) -C tests tests

depend:
	$(MAKE) -C libvicsetup depend
	$(MAKE) -C vicsetup depend

loc:
	@ wc -l `find . -name '*.[ch]' | grep -v argon` | grep ' total$$'

third_party_depends: $(LIBJSON_DIR) $(ARGON2_DIR)

$(LIBJSON_DIR):
	$(error "Please pass LIBJSON_DIR variable to make")

$(ARGON2_DIR):
	$(error "Please pass ARGON2_DIR variable to make")
