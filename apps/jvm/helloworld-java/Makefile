ALPINE_MAJOR=3.9
ALPINE_VERSION=3.9.0
ALPINE_ARCH=x86_64

ALPINE_TAR=alpine-minirootfs.tar.gz

ROOT_FS=sgxlkl-java-fs.img
MOUNTPOINT=/media/ext4disk
IMAGE_SIZE_MB=400

ESCALATE_CMD=sudo

.DELETE_ON_ERROR:
.PHONY: all clean

all: $(ROOT_FS)

clean:
	test -f HelloWorld.class && rm HelloWorld.class || true
	test -f $(ROOT_FS) && rm $(ROOT_FS) || true

$(ALPINE_TAR):
	curl -L -o "$@" "https://nl.alpinelinux.org/alpine/v$(ALPINE_MAJOR)/releases/$(ALPINE_ARCH)/alpine-minirootfs-$(ALPINE_VERSION)-$(ALPINE_ARCH).tar.gz"

HelloWorld.class: HelloWorld.java
	javac HelloWorld.java

$(ROOT_FS): $(ALPINE_TAR) buildenv.sh HelloWorld.class
	dd if=/dev/zero of="$@" count=$(IMAGE_SIZE_MB) bs=1M
	mkfs.ext4 "$@"
	$(ESCALATE_CMD) /bin/bash -euxo pipefail -c '\
		mkdir -p $(MOUNTPOINT); \
		mount -t ext4 -o loop "$@" $(MOUNTPOINT); \
		tar -C $(MOUNTPOINT) -xvf $(ALPINE_TAR); \
		cp /etc/resolv.conf $(MOUNTPOINT)/etc/resolv.conf; \
		install buildenv.sh $(MOUNTPOINT)/usr/sbin; \
		mkdir -p $(MOUNTPOINT)/app; \
		cp HelloWorld.class $(MOUNTPOINT)/app; \
		mkdir -p $(MOUNTPOINT)/opt; \
		chroot $(MOUNTPOINT) /bin/sh /usr/sbin/buildenv.sh; \
		umount $(MOUNTPOINT); \
		chown $(USER) "$@"; \
	'

test: $(ROOT_FS)
	echo "Running java Hello World example:"
	 ${CURDIR}/../../../tools/sgx-lkl-java ${CURDIR}/$(ROOT_FS) HelloWorld

