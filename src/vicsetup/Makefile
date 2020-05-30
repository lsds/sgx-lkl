.PHONY: tests

include defs.mak

all: depend
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
