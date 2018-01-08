ALPINE_MAJOR=3.6
ALPINE_VERSION=3.6.1
ALPINE_ARCH=x86_64

ALPINE_TAR=alpine-minirootfs.tar.gz
JRE_TAR_REMOTE=sgxlkl_openjdk_jre_alpine_8.121.13-r0.tar.gz
JRE_TAR=../$(JRE_TAR_REMOTE)

ROOT_FS=sgxlkl-java-fs.img
MOUNTPOINT=/media/ext4disk
IMAGE_SIZE_MB=500

ESCALATE_CMD=sudo

.DELETE_ON_ERROR:
.PHONY: all clean

all: $(ROOT_FS)

clean:
	test -f HelloWorld.class && rm HelloWorld.class || true
	test -f $(ROOT_FS) && rm $(ROOT_FS) || true

$(ALPINE_TAR):
	curl -L -o "$@" "https://nl.alpinelinux.org/alpine/v$(ALPINE_MAJOR)/releases/$(ALPINE_ARCH)/alpine-minirootfs-$(ALPINE_VERSION)-$(ALPINE_ARCH).tar.gz"

$(JRE_TAR):
	curl -L -o "$@" "https://lsds.doc.ic.ac.uk/files/$(JRE_TAR_REMOTE)"

HelloWorld.class: HelloWorld.java
	javac HelloWorld.java

$(ROOT_FS): $(ALPINE_TAR) $(JRE_TAR) buildenv.sh HelloWorld.class
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
		tar -xf $(JRE_TAR) -C $(MOUNTPOINT)/opt; \
		chroot $(MOUNTPOINT) /bin/sh /usr/sbin/buildenv.sh; \
		umount $(MOUNTPOINT); \
		chown $(USER) "$@"; \
	'

test: $(ROOT_FS)
	echo "Running java Hello World example:"
	${CURDIR}/../../../tools/sgx-lkl-java ${CURDIR}/$(ROOT_FS) HelloWorld

