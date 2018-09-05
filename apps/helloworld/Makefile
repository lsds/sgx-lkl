PROG=helloworld
PROG_PIE=$(PROG)-pie
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
	../../build/host-musl/bin/musl-gcc -fno-pie -no-pie -o $@ $(PROG_C)

$(PROG_PIE): $(PROG_C)
	../../build/host-musl/bin/musl-gcc -fPIE -pie -o $@ $(PROG_C)

$(DISK): $(PROG) $(PROG_PIE)
	dd if=/dev/zero of="$@" count=$(IMAGE_SIZE_MB) bs=1M
	mkfs.ext4 "$@"
	$(ESCALATE_CMD) /bin/bash -euxo pipefail -c '\
		mkdir -p $(MOUNTPOINT); \
		mount -t ext4 -o loop "$@" $(MOUNTPOINT); \
		mkdir -p $(MOUNTPOINT)/app; \
		echo "Hello World!" > $(MOUNTPOINT)/app/helloworld.txt; \
		cp $(PROG)  $(MOUNTPOINT)/app; \
		cp $(PROG_PIE)  $(MOUNTPOINT)/app; \
		umount $(MOUNTPOINT); \
		chown $(USER) "$@"; \
	'

test: $(DISK)
	SGXLKL_NON_PIE=1 ../../build/sgx-lkl-run $(DISK) app/$(PROG)

test-pie: $(DISK)
	../../build/sgx-lkl-run $(DISK) app/$(PROG_PIE)
