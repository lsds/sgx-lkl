PROG=helloworld
PROG_NONPIE=$(PROG)-nonpie
PROG_C=$(PROG).c

MOUNTPOINT=/media/ext4disk

DISK=sgxlkl-disk.img

LOOP_DEVICE=loop9
IMAGE_SIZE_MB=100

ESCALATE_CMD=sudo

.DELETE_ON_ERROR:
.PHONY: all clean

all: $(DISK)

clean:
	rm -f $(DISK) $(PROG)

$(PROG): $(PROG_C)
	../../build/host-musl/bin/musl-gcc -fPIE -pie -o $@ $(PROG_C)

$(PROG_NONPIE): $(PROG_C)
	../../build/host-musl/bin/musl-gcc -fno-pie -no-pie -o $@ $(PROG_C)

$(DISK): $(PROG) $(PROG_NONPIE)
	dd if=/dev/zero of="$@" count=$(IMAGE_SIZE_MB) bs=1M
	mkfs.ext4 "$@"
	$(ESCALATE_CMD) /bin/bash -euxo pipefail -c '\
		mkdir -p $(MOUNTPOINT); \
		mount -t ext4 -o loop "$@" $(MOUNTPOINT); \
		mkdir -p $(MOUNTPOINT)/app; \
		echo "Hello World!" > $(MOUNTPOINT)/app/helloworld.txt; \
		cp $(PROG)  $(MOUNTPOINT)/app; \
		cp $(PROG_NONPIE)  $(MOUNTPOINT)/app; \
		umount $(MOUNTPOINT); \
		chown $(USER) "$@"; \
	'

test: $(DISK)
	../../build/sgx-lkl-run $(DISK) app/$(PROG)

test-nonpie: $(DISK)
	SGXLKL_NON_PIE=1 ../../build/sgx-lkl-run $(DISK) app/$(PROG_NONPIE)
