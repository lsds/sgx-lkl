include ../common.mk

ALPINE_MAJOR=3.8
ALPINE_VERSION=3.8.0
ALPINE_ARCH=x86_64

ROOT_FS=sgxlkl-miniroot-fs.img
ALPINE_TAR=alpine-minirootfs.tar.gz
MOUNTPOINT=/media/ext4disk
IMAGE_SIZE_MB=1500

# 1 hours timeout for ltp test execution
LTP_TEST_EXEC_TIMEOUT=3600

LTP_TEST_SCRIPT="./run_ltp_test.sh"
ESCALATE_CMD=sudo

.DELETE_ON_ERROR:
.PHONY: all clean

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
	$(ESCALATE_CMD) chroot $(MOUNTPOINT) /sbin/apk update
	$(ESCALATE_CMD) chroot $(MOUNTPOINT) /sbin/apk add bash
	$(ESCALATE_CMD) cp ltp_fork_disable.patch $(MOUNTPOINT)/
	$(ESCALATE_CMD) cp patches/mount.patch $(MOUNTPOINT)/
	$(ESCALATE_CMD) chroot $(MOUNTPOINT) /bin/bash /usr/sbin/buildenv.sh 'build' '/ltp/testcases/kernel/syscalls'
	$(ESCALATE_CMD) cp $(MOUNTPOINT)/ltp/.c_binaries_list .
	$(ESCALATE_CMD) umount $(MOUNTPOINT)
	$(ESCALATE_CMD) chown $(USER) "$@"

gettimeout:
	@echo ${LTP_TEST_EXEC_TIMEOUT}

run: run-hw run-sw

run-hw: $(ROOT_FS)
	@${LTP_TEST_SCRIPT} --hw-debug

run-sw: $(ROOT_FS)
	@echo "LTP test for --sw-debug is disabled due to overhead in time"
	#@${LTP_TEST_SCRIPT} --sw-debug

clean:
	@test -f $(ALPINE_TAR) && rm $(ALPINE_TAR) || true
	@test -f $(ROOT_FS) && rm $(ROOT_FS) || true
	@rm -f .c_binaries_list

