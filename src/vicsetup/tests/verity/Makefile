include ../../defs.mak

export PATH+=:$(TOP)/vicsetup

all:

tests: dirs test1 test2 test3

##==============================================================================
##
## test1:
##
##==============================================================================

test1:
	$(MAKE) __test1 TEST1_BLOCKSIZE=512
	$(MAKE) __test1 TEST1_BLOCKSIZE=1024
	$(MAKE) __test1 TEST1_BLOCKSIZE=2048
	$(MAKE) __test1 TEST1_BLOCKSIZE=4096

__test1:
	( BLKSZ=${TEST1_BLOCKSIZE} ./test-verity.sh )
	( BLKSZ=${TEST1_BLOCKSIZE} ./test-verity.sh 2 )
	( BLKSZ=${TEST1_BLOCKSIZE} ./test-verity.sh 4 )
	( BLKSZ=${TEST1_BLOCKSIZE} ./test-verity.sh 7 )
	( BLKSZ=${TEST1_BLOCKSIZE} ./test-verity.sh 13 )
	( BLKSZ=${TEST1_BLOCKSIZE} ./test-verity.sh 112 )
	( BLKSZ=${TEST1_BLOCKSIZE} ./test-verity.sh 4096 )
	( BLKSZ=${TEST1_BLOCKSIZE} ./test-verity.sh 10000 )

##==============================================================================
##
## test2:
##
##==============================================================================

test2: dirs
	dd if=/dev/urandom of=verity bs=4096 count=1000
	rm -f verity.hash
	veritysetup format verity verity.hash
	$(MAKE) __test2

__test2:
	$(eval TEMPFILE := $(shell /bin/tempfile))
	$(eval NAME := $(shell basename $(TEMPFILE)))
	$(eval ROOTHASH := $(shell vicsetup verityDump verity.hash | grep "^Root hash:" | sed 's/Root hash:[\t ]*//g'))
	vicsetup veritysetupOpen verity $(NAME) verity.hash $(ROOTHASH)
	@ echo "Created /dev/mapper/$(NAME)"
	dd if=/dev/mapper/${NAME} of=tmpfile
	cmp tmpfile verity
	vicsetup verityClose $(NAME)
	rm -rf $(TEMPFILE)

##==============================================================================
##
## test3:
##
##==============================================================================

test3: dirs
	$(MAKE) __test3 BS=512 COUNT=8000
	$(MAKE) __test3 BS=1024 COUNT=4000
	$(MAKE) __test3 BS=2048 COUNT=2000
	$(MAKE) __test3 BS=4096 COUNT=1000

BLKSZ_OPTS += --data-block-size=$(BS)
BLKSZ_OPTS += --hash-block-size=$(BS)

__test3:
	dd if=/dev/urandom of=verity bs=$(BS) count=$(COUNT)
	veritysetup format $(BLKSZ_OPTS) verity verity.hash
	$(MAKE) ____test3

____test3:
	@ cp verity file
	@ cat verity.hash >> file
	$(eval TEMPFILE := $(shell /bin/tempfile))
	$(eval NAME := $(shell basename $(TEMPFILE)))
	$(eval DATA_SIZE := $(shell stat --printf=%s verity))
	$(eval HASH_AREA_OFFSET := $(DATA_SIZE))
	vicsetup verityDump verity.hash
	$(eval ROOTHASH := $(shell vicsetup verityDump verity.hash | grep "^Root hash:" | sed 's/Root hash:[\t ]*//g'))
	vicsetup veritysetupOpen $(BLKSZ_OPTS) --data-size $(DATA_SIZE) --hash-area-offset $(HASH_AREA_OFFSET) file $(NAME) file $(ROOTHASH)
	@ echo "Created /dev/mapper/$(NAME)"
	dd if=/dev/mapper/${NAME} of=tmpfile
	cmp tmpfile verity
	vicsetup verityClose $(NAME)
	rm -rf $(TEMPFILE)

##==============================================================================
##
## rules:
##
##==============================================================================

CLEAN += hashtree verity verity.hash file tmpfile

DIRS += $(TOP)/vicsetup

include ../../rules.mak
