include ../../defs.mak

.PHONY: format1
.PHONY: format2
.PHONY: csformat1
.PHONY: csformat2

export PATH+=:$(TOP)/vicsetup

all:

tests: dirs format1 format2

##==============================================================================
##
## format1:
##
##==============================================================================

#KEYSIZE1=64
#INTEGRITY1="hmac(sha256)"
KEYSIZE1=96
INTEGRITY1="hmac(sha256)"

FORMAT1_OPTS += --keyfile KEY
FORMAT1_OPTS += --cipher "aes"
FORMAT1_OPTS += --cipher-mode "xts-plain64"
FORMAT1_OPTS += --luks2
FORMAT1_OPTS += --pbkdf argon2i
FORMAT1_OPTS += --iter-time 5
FORMAT1_OPTS += --pbkdf-memory 4096
FORMAT1_OPTS += --pbkdf-parallel 4
FORMAT1_OPTS += --integrity $(INTEGRITY1)

format1: dirs
	head -c $(KEYSIZE1) /dev/urandom > KEY
	head -c 32M /dev/zero > LUKS
	vicsetup cryptsetupLuksFormat $(FORMAT1_OPTS) LUKS pass
	vicsetup luksDump LUKS > /dev/null

##==============================================================================
##
## format2:
##
##==============================================================================

FORMAT2_OPTS += --keyfile KEY
FORMAT2_OPTS += --cipher "aes"
FORMAT2_OPTS += --cipher-mode "xts-plain64"
FORMAT2_OPTS += --luks2
FORMAT2_OPTS += --pbkdf pbkdf2
FORMAT2_OPTS += --hash sha256
FORMAT2_OPTS += --slot-iterations 4000

format2: dirs
	head -c 64 /dev/urandom > KEY
	head -c 32M /dev/zero > LUKS
	vicsetup cryptsetupLuksFormat $(FORMAT2_OPTS) LUKS pass

##==============================================================================
##
## csformat1:
##
##==============================================================================

CSFORMAT1_OPTS += --type luks2
CSFORMAT1_OPTS += --master-key-file KEY
CSFORMAT1_OPTS += --iter-time 8
CSFORMAT1_OPTS += --pbkdf-memory 1024
CSFORMAT1_OPTS += --pbkdf-parallel 2
CSFORMAT1_OPTS += --integrity "hmac-sha256"

csformat1:
	head -c 96 /dev/urandom > KEY
	head -c 32M /dev/zero > LUKS
	cryptsetup luksFormat $(CSFORMAT1_OPTS) LUKS
	vicsetup luksDump LUKS > /dev/null

##==============================================================================
##
## csformat2:
##
##==============================================================================

CSFORMAT2_OPTS += --type luks2
CSFORMAT2_OPTS += --master-key-file KEY
CSFORMAT1_OPTS += --key-size 512
CSFORMAT2_OPTS += --pbkdf pbkdf2
CSFORMAT2_OPTS += --hash sha256
CSFORMAT2_OPTS += --iter-time 1
CSFORMAT2_OPTS += --integrity "hmac-sha512"

csformat2:
	head -c 64 /dev/urandom > KEY
	head -c 32M /dev/zero > LUKS
	cryptsetup luksFormat $(CSFORMAT2_OPTS) LUKS

##==============================================================================
##
## csdump:
##
##==============================================================================

csdump:
	cryptsetup luksDump --dump-master-key LUKS

##==============================================================================
##
## standard rules:
##
##==============================================================================

CLEAN += KEY LUKS

DIRS += $(TOP)/vicsetup

include ../../rules.mak

diff:
	diff format1.out csformat1.out
