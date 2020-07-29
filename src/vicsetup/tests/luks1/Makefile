include ../../defs.mak

export PATH+=:$(TOP)/vicsetup

SIZE=32M

UUID=86783a38-07fc-4235-bf45-36fd3982be5e

all:

# AES ciphers:
tests:
	$(MAKE) all_tests CIPHER=aes-ecb KEYSIZE=16
	$(MAKE) all_tests CIPHER=aes-ecb KEYSIZE=32
	$(MAKE) all_tests CIPHER=aes-cbc-plain KEYSIZE=16
	$(MAKE) all_tests CIPHER=aes-cbc-plain KEYSIZE=32
	$(MAKE) all_tests CIPHER=aes-xts-plain64 KEYSIZE=32
	$(MAKE) all_tests CIPHER=aes-xts-plain64 KEYSIZE=64

all_tests: dirs luksFormat luksChangeKey luksAddKey luksRemoveKey luksGetMasterKey luksOpen luksClose

LUKSFORMAT_OPTS += --uuid $(UUID)
LUKSFORMAT_OPTS += --keyfile keyfile
LUKSFORMAT_OPTS += --cipher $(CIPHER)

luksFormat:
	head -c $(KEYSIZE) /dev/urandom > keyfile
	head -c $(SIZE) /dev/zero > luksfile
	vicsetup luksFormat $(LUKSFORMAT_OPTS) luksfile pass1

luksChangeKey:
	vicsetup luksChangeKey luksfile pass1 passx
	vicsetup luksChangeKey luksfile passx pass1

luksAddKey:
	vicsetup luksAddKey luksfile pass1 pass2
	vicsetup luksAddKey luksfile pass2 pass3
	vicsetup luksAddKey luksfile pass3 pass4
	vicsetup luksAddKey luksfile pass4 pass5

luksRemoveKey:
	vicsetup luksRemoveKey luksfile pass2
	vicsetup luksRemoveKey luksfile pass3
	vicsetup luksRemoveKey luksfile pass4

luksGetMasterKey:
	vicsetup luksGetMasterKey luksfile pass1
	vicsetup luksGetMasterKey luksfile pass5
	od -t x1 --address-radix=n keyfile

dump:
	vicsetup luksDump luksfile
	cryptsetup luksDump luksfile

luksOpen:
	vicsetup luksOpen luksfile pass1 luksfile

luksClose:
	vicsetup luksClose luksfile

CLEAN += keyfile
CLEAN += luksfile

DIRS += $(TOP)/vicsetup

include ../../rules.mak
