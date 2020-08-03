include ../../defs.mak

export PATH+=:$(TOP)/vicsetup

SIZE=32M

UUID=fe128cd1-28b6-4dc7-b3a0-835c68408fbb

all:

tests: dirs luksFormat luksChangeKey luksAddKey luksRemoveKey luksGetMasterKey luksOpen luksClose

LUKSFORMAT_OPTS = --luks2
LUKSFORMAT_OPTS += --uuid $(UUID)
LUKSFORMAT_OPTS += --keyfile keyfile
LUKSFORMAT_OPTS += --mk-iterations 1000
LUKSFORMAT_OPTS += --slot-iterations 1000
LUKSFORMAT_OPTS += --pbkdf-memory 4096

luksFormat:
	@ head -c 64 /dev/urandom > keyfile
	head -c $(SIZE) /dev/zero > luksfile
	vicsetup luksFormat $(LUKSFORMAT_OPTS) luksfile pass1

luksChangeKey:
	vicsetup luksChangeKey luksfile pass1 passx
	vicsetup luksChangeKey luksfile passx pass1

LUKSADDKEY_OPTS += --slot-iterations 1000
LUKSADDKEY_OPTS += --pbkdf-memory 1024

luksAddKey:
	vicsetup luksAddKey $(LUKSADDKEY_OPTS) luksfile pass1 pass2
	vicsetup luksAddKey $(LUKSADDKEY_OPTS) luksfile pass2 pass3
	vicsetup luksAddKey $(LUKSADDKEY_OPTS) luksfile pass3 pass4
	vicsetup luksAddKey $(LUKSADDKEY_OPTS) luksfile pass4 pass5

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

CLEAN += keyfile luksfile

DIRS += $(TOP)/vicsetup

include ../../rules.mak
