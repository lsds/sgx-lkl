ifneq (,$(wildcard ../../common.mk))
  include ../../common.mk
  LTP_TEST_SCRIPT=../run_ltp_test.sh
  BUILDENV_SCRIPT=../buildenv.sh
else
  include ../common.mk
  LTP_TEST_SCRIPT=./run_ltp_test.sh
  BUILDENV_SCRIPT=./buildenv.sh
endif

ALPINE_MAJOR=3.8
ALPINE_VERSION=3.8.0
ALPINE_ARCH=x86_64

ROOT_FS=sgxlkl-miniroot-fs.img.master
ROOT_FS_FRESH_COPY=sgxlkl-miniroot-fs.img
ALPINE_TAR=alpine-minirootfs.tar.gz
MOUNTPOINT=/media/ext4disk
IMAGE_SIZE_MB=1500

# 1 hours timeout for ltp test execution
LTP_TEST_EXEC_TIMEOUT=3600

ESCALATE_CMD=sudo

LTP_SOURCE_DIR=$(SGXLKL_ROOT)/ltp

# file system image to be mount in ltp tests
LTP_TEST_MNT_IMG=ltp_tst_mntfs.img
LTP_TEST_MNT_IMG_SIZE=256

.DELETE_ON_ERROR:
.PHONY: all clean

$(LTP_SOURCE_DIR)/.git:
	git submodule update --progress --init $(LTP_SOURCE_DIR)

$(ALPINE_TAR):
	curl -L -o "$@" "https://nl.alpinelinux.org/alpine/v$(ALPINE_MAJOR)/releases/$(ALPINE_ARCH)/alpine-minirootfs-$(ALPINE_VERSION)-$(ALPINE_ARCH).tar.gz"

$(LTP_TEST_MNT_IMG):
	dd if=/dev/zero of=$(LTP_TEST_MNT_IMG) count=$(LTP_TEST_MNT_IMG_SIZE) bs=1M
	mkfs -t ext4 $(LTP_TEST_MNT_IMG)

$(ROOT_FS): $(ALPINE_TAR) $(BUILDENV_SCRIPT) $(LTP_SOURCE_DIR)/.git $(LTP_TEST_MNT_IMG)
	dd if=/dev/zero of="$@" count=$(IMAGE_SIZE_MB) bs=1M
	mkfs.ext4 "$@"
	$(ESCALATE_CMD) mkdir -p $(MOUNTPOINT)
	$(ESCALATE_CMD) mount -t ext4 -o loop "$@" $(MOUNTPOINT)
	$(ESCALATE_CMD) tar -C $(MOUNTPOINT) -xvf $(ALPINE_TAR)
	$(ESCALATE_CMD) cp /etc/resolv.conf $(MOUNTPOINT)/etc/resolv.conf
	$(ESCALATE_CMD) mkdir $(MOUNTPOINT)/ltp
	$(ESCALATE_CMD) cp -R $(SGXLKL_ROOT)/ltp/* $(MOUNTPOINT)/ltp/
	$(ESCALATE_CMD) install $(BUILDENV_SCRIPT) $(MOUNTPOINT)/usr/sbin
	$(ESCALATE_CMD) chroot $(MOUNTPOINT) /sbin/apk update
	$(ESCALATE_CMD) chroot $(MOUNTPOINT) /sbin/apk add bash
	$(ESCALATE_CMD) mkdir $(MOUNTPOINT)/ltp_tst_mnt_fs
	$(ESCALATE_CMD) dd if=/dev/zero of=$(MOUNTPOINT)/ltp_tst_mnt_fs/tstfs_ext4.img count=256 bs=1M
	$(ESCALATE_CMD) mkfs -t ext4 $(MOUNTPOINT)/ltp_tst_mnt_fs/tstfs_ext4.img


	$(ESCALATE_CMD) chroot $(MOUNTPOINT) /bin/bash /usr/sbin/buildenv.sh 'build' '/ltp/testcases/kernel/syscalls'
	$(ESCALATE_CMD) cp $(MOUNTPOINT)/ltp/.c_binaries_list .
	$(ESCALATE_CMD) umount $(MOUNTPOINT)
	$(ESCALATE_CMD) chown $(USER) "$@"

gettimeout:
	@echo ${LTP_TEST_EXEC_TIMEOUT}

run: run-hw run-sw

run-hw: $(ROOT_FS)
	@${LTP_TEST_SCRIPT} run-hw

run-sw: $(ROOT_FS)
	@${LTP_TEST_SCRIPT} run-sw

run-hw-single: $(ROOT_FS)
	@rm -f $(ROOT_FS_FRESH_COPY)
	@cp $(ROOT_FS) $(ROOT_FS_FRESH_COPY)
	${SGXLKL_STARTER} --hw-debug $(ROOT_FS_FRESH_COPY) $(test)

run-sw-single: $(ROOT_FS)
	@rm -f $(ROOT_FS_FRESH_COPY)
	@cp $(ROOT_FS) $(ROOT_FS_FRESH_COPY)
	${SGXLKL_STARTER} --sw-debug $(ROOT_FS_FRESH_COPY) $(test)

run-hw-single-gdb: $(ROOT_FS)
	@rm -f $(ROOT_FS_FRESH_COPY)
	@cp $(ROOT_FS) $(ROOT_FS_FRESH_COPY)
	${SGXLKL_GDB} --args ${SGXLKL_STARTER} --hw-debug $(ROOT_FS_FRESH_COPY) $(test)

run-sw-single-gdb: $(ROOT_FS)
	@rm -f $(ROOT_FS_FRESH_COPY)
	@cp $(ROOT_FS) $(ROOT_FS_FRESH_COPY)
	${SGXLKL_GDB} --args ${SGXLKL_STARTER} --sw-debug $(ROOT_FS_FRESH_COPY) $(test)

clean:
	@test -f $(ALPINE_TAR) && rm $(ALPINE_TAR) || true
	@test -f $(ROOT_FS) && rm $(ROOT_FS) || true
	@test -f $(LTP_TEST_MNT_IMG) && rm $(LTP_TEST_MNT_IMG) || true
	@test -f $(ROOT_FS_FRESH_COPY) && rm $(ROOT_FS_FRESH_COPY) || true
	@rm -f .c_binaries_list

