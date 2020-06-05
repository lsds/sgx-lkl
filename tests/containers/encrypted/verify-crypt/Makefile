SGXLKL_ROOT=../../../..

# Use this compiler to build the program
CC=${SGXLKL_ROOT}/build/host-musl/bin/musl-gcc

# The program being built
TARGET=verify-crypt

# The root file system for this test:
DISK_IMAGE=disk.img

# The passphrase to unlock the disk image (LUKS2)
PASSPHRASE=pass

# Set up the SGXLKL environment (passed to sgx-lkl-run-oe)
SGXLKL_ENV=

ifdef VERBOSE
SGXLKL_ENV += SGXLKL_VERBOSE=1
SGXLKL_ENV += SGXLKL_KERNEL_VERBOSE=1
SGXLKL_ENV += SGXLKL_TRACE_SIGNAL=0
SGXLKL_ENV += SGXLKL_TRACE_HOST_SYSCALL=0
SGXLKL_ENV += SGXLKL_TRACE_LKL_SYSCALL=0
SGXLKL_ENV += SGXLKL_TRACE_MMAP=0
endif

SGXLKL_ENV += SGXLKL_HD_KEY=$(PASSPHRASE)

# The path to the sgx-lkl startup program
SGXLKL_RUN=$(SGXLKL_ROOT)/build/sgx-lkl-run-oe

##=================================================================================================
##
## all:
##
##=================================================================================================

all: $(TARGET) $(DISK_IMAGE)

##=================================================================================================
##
## run-hw:
## run-sw:
##
##=================================================================================================

run-hw: $(TARGET) $(DISK_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_RUN} --hw-debug $(DISK_IMAGE) /test/$(TARGET)

run-sw: $(TARGET) $(DISK_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_RUN} --sw-debug $(DISK_IMAGE) /test/$(TARGET)

##=================================================================================================
##
## $(TARGET)
##
##=================================================================================================

$(TARGET): main.c
	${CC} -fPIE -pie -o $(TARGET) main.c

##=================================================================================================
##
## $(DISK_IMAGE)
##
##=================================================================================================

DISK_IMAGE_SIZE=32M

FORMAT_OPTS += --type luks2
FORMAT_OPTS += --key-file=-
FORMAT_OPTS += --iter-time 8
FORMAT_OPTS += --pbkdf-memory 1024
FORMAT_OPTS += --pbkdf-parallel 2
#FORMAT_OPTS += --integrity "hmac-sha256"

$(DISK_IMAGE): $(TARGET)
	$(eval TMPNAME=$(shell basename $(shell tempfile)))
	head -c $(DISK_IMAGE_SIZE) /dev/zero > $(DISK_IMAGE)
	( echo -n $(PASSPHRASE) | cryptsetup luksFormat $(FORMAT_OPTS) $(DISK_IMAGE) )
	( echo -n $(PASSPHRASE) | cryptsetup luksOpen $(DISK_IMAGE) --key-file=- $(TMPNAME) )
	mkfs.ext2 /dev/mapper/$(TMPNAME)
	rm -rf /tmp/$(TMPNAME)
	mkdir /tmp/$(TMPNAME)
	mount /dev/mapper/$(TMPNAME) /tmp/$(TMPNAME)
	mkdir /tmp/$(TMPNAME)/test
	cp $(TARGET) /tmp/$(TMPNAME)/test
	cp alphabet /tmp/$(TMPNAME)/test
	umount /tmp/$(TMPNAME)
	dmsetup remove $(TMPNAME)
	@ echo "Created $(DISK_IMAGE)"

##=================================================================================================
##
## clean:
##
##=================================================================================================

clean:
	rm -rf $(TARGET) $(DISK_IMAGE)
