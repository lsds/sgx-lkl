PROG=signal
PROG_SRC=$(PROG).c
PROG_PATH=/home

EXECUTION_TIMEOUT=180
SGXLKL_STARTER=../../../build/sgx-lkl-run-oe
SGXLKL_ENV=SGXLKL_ETHREADS=8 SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1 SGXLKL_TRACE_SIGNAL=1
SGXLKL_HW_PARAMS=--hw-debug
SGXLKL_SW_PARAMS=--sw-debug

ALPINE_URL=https://nl.alpinelinux.org/alpine
ALPINE_MAJOR=3.9
ALPINE_VERSION=3.9.0
ALPINE_ARCH=x86_64
ALPINE_TAR=alpine-minirootfs.tar.gz

MOUNTPOINT=/media/ext4disk
SGXLKL_ROOTFS=sgx-lkl-rootfs.img

BUILD_CONTAINER=alpine_sdk

IMAGE_SIZE_MB=100

ESCALATE_CMD=sudo

.DELETE_ON_ERROR:
.PHONY: all clean

$(ALPINE_TAR):
	curl -L -o "$@" "$(ALPINE_URL)/v$(ALPINE_MAJOR)/releases/$(ALPINE_ARCH)/alpine-minirootfs-$(ALPINE_VERSION)-$(ALPINE_ARCH).tar.gz"

$(SGXLKL_ROOTFS): $(ALPINE_TAR) buildenv.sh $(PROG) $(PROG2)
	test -f $(SGXLKL_ROOTFS) && rm $(SGXLKL_ROOTFS) || true
	dd if=/dev/zero of="$@" count=$(IMAGE_SIZE_MB) bs=1M
	mkfs.ext4 -q "$@"
	$(ESCALATE_CMD) /bin/bash -euxo pipefail -c '\
		mkdir -p $(MOUNTPOINT); \
		mount -t ext4 -o loop "$@" $(MOUNTPOINT); \
		tar -C $(MOUNTPOINT) -xf $(ALPINE_TAR); \
		cp /etc/resolv.conf $(MOUNTPOINT)/etc/resolv.conf; \
		mkdir -p $(MOUNTPOINT)/home; \
		cp $(PROG) $(MOUNTPOINT)$(PROG_PATH); \
		install buildenv.sh $(MOUNTPOINT)/usr/sbin; \
		chroot $(MOUNTPOINT) /bin/sh /usr/sbin/buildenv.sh; \
		umount $(MOUNTPOINT); \
		chown $(USER) "$@"; \
	'

$(PROG): $(PROG_SRC)
	docker build -t $(BUILD_CONTAINER) .
	docker run --rm -v ${CURDIR}:/src -w /src alpine_sdk gcc -o $(PROG) -O0 -ggdb3 $(PROG_SRC)

gettimeout:
	@echo ${EXECUTION_TIMEOUT}

run: run-hw run-sw

run-gdb: run-hw-gdb

run-hw: ${SGXLKL_ROOTFS}
	  $(SGXLKL_ENV) $(SGXLKL_STARTER) $(SGXLKL_HW_PARAMS) $(SGXLKL_ROOTFS) $(PROG_PATH)/$(PROG)

run-sw: ${SGXLKL_ROOTFS}
	  $(SGXLKL_ENV) $(SGXLKL_STARTER) $(SGXLKL_SW_PARAMS) $(SGXLKL_ROOTFS) $(PROG_PATH)/$(PROG)

run-hw-gdb: ${SGXLKL_ROOTFS}
	  $(SGXLKL_ENV) oegdb --args $(SGXLKL_STARTER) $(SGXLKL_HW_PARAMS) $(SGXLKL_ROOTFS) $(PROG_PATH)/$(PROG)

run-sw-gdb: ${SGXLKL_ROOTFS}
	  $(SGXLKL_ENV) oegdb --args $(SGXLKL_STARTER) $(SGXLKL_SW_PARAMS) $(SGXLKL_ROOTFS) $(PROG_PATH)/$(PROG)

clean:
	test -f $(PROG) && rm -f $(PROG) || true
	test -f $(SGXLKL_ROOTFS) && rm $(SGXLKL_ROOTFS) || true
	test -f $(ALPINE_TAR) && rm $(ALPINE_TAR) || true
