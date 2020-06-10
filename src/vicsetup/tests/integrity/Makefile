include ../../defs.mak

.PHONY: integrity

export PATH+=:$(TOP)/vicsetup

DISK_SIZE=32M

all:

tests: dirs
	$(MAKE) KEYSIZE=64 INTEGRITY="hmac(sha256)" integrity
	$(MAKE) KEYSIZE=96 INTEGRITY="hmac(sha256)" integrity
	$(MAKE) KEYSIZE=128 INTEGRITY="hmac(sha512)" integrity

UUID=90faa067-e33f-464a-98ab-86a5fd5e56e4
INTEGRITY_OPTS += --luks2
INTEGRITY_OPTS += --uuid $(UUID)
INTEGRITY_OPTS += --integrity "$(INTEGRITY)"
INTEGRITY_OPTS += --keyfile keyfile

integrity:
	head -c $(KEYSIZE) /dev/urandom > keyfile
	head -c $(DISK_SIZE) /dev/zero > integrity
	vicsetup luksFormat $(INTEGRITY_OPTS) integrity pass
	vicsetup luksOpen integrity pass integrity
	$(eval TMP1 := $(shell /bin/mktemp))
	dd if=/dev/urandom of=$(TMP1) bs=4096 count=1
	cat $(TMP1) > /dev/mapper/integrity
	vicsetup luksClose integrity
	vicsetup luksOpen integrity pass integrity
	$(eval TMP2 := $(shell /bin/mktemp))
	dd if=/dev/mapper/integrity of=$(TMP2) bs=4096 count=1
	vicsetup luksClose integrity
	cmp $(TMP1) $(TMP2)
	rm -f $(TMP1) $(TMP2)

CLEAN += integrity keyfile

DIRS += $(TOP)/vicsetup

include ../../rules.mak

100:
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
	$(MAKE) tests
