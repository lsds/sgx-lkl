ALPINE_MAJOR=3.6
ALPINE_VERSION=3.6.1
ALPINE_ARCH=x86_64

ROOT_FS=sgxlkl-miniroot-fs.img
ALPINE_TAR=alpine-minirootfs.tar.gz
MOUNTPOINT=/media/ext4disk
IMAGE_SIZE_MB=500

ESCALATE_CMD=sudo

.DELETE_ON_ERROR:
.PHONY: all clean

all: $(ROOT_FS)

clean:
	test -f $(ROOT_FS) && rm $(ROOT_FS) || true

$(ALPINE_TAR):
	curl -L -o "$@" "https://nl.alpinelinux.org/alpine/v$(ALPINE_MAJOR)/releases/$(ALPINE_ARCH)/alpine-minirootfs-$(ALPINE_VERSION)-$(ALPINE_ARCH).tar.gz"

$(ROOT_FS): $(ALPINE_TAR) buildenv.sh 
	dd if=/dev/zero of="$@" count=$(IMAGE_SIZE_MB) bs=1M
	mkfs.ext4 "$@"
	$(ESCALATE_CMD) mkdir -p $(MOUNTPOINT)
	$(ESCALATE_CMD) mount -t ext4 -o loop "$@" $(MOUNTPOINT)
	$(ESCALATE_CMD) tar -C $(MOUNTPOINT) -xvf $(ALPINE_TAR)
	$(ESCALATE_CMD) cp /etc/resolv.conf $(MOUNTPOINT)/etc/resolv.conf
	$(ESCALATE_CMD) install buildenv.sh $(MOUNTPOINT)/usr/sbin
	$(ESCALATE_CMD) chroot $(MOUNTPOINT) /bin/sh /usr/sbin/buildenv.sh
	$(ESCALATE_CMD) umount $(MOUNTPOINT)
	$(ESCALATE_CMD) chown $(USER) "$@"
