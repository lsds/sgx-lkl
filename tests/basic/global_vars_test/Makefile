
PROG=global_vars_test
PROG_C=$(PROG).c

MOUNTPOINT=/media/ext4disk

DISK=sgxlkl-disk.img

SGXLKL_RUN_CMD=../../../build/sgx-lkl-run-oe

PROG_ARGS = -a -b -c hello

SGXLKL_ENV=\
   SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=0 SGXLKL_TRACE_SIGNAL=0\
   SGXLKL_TRACE_HOST_SYSCALL=0 SGXLKL_TRACE_LKL_SYSCALL=0 SGXLKL_TRACE_MMAP=0

LOOP_DEVICE=loop9
IMAGE_SIZE_MB=100

ESCALATE_CMD=sudo

.DELETE_ON_ERROR:
.PHONY: all clean

$(PROG): $(PROG_C)
	../../../build/host-musl/bin/musl-gcc -g -o $@ $(PROG_C)

$(DISK): $(PROG) 
	dd if=/dev/zero of="$@" count=$(IMAGE_SIZE_MB) bs=1M
	mkfs.ext4 "$@"
	@$(ESCALATE_CMD) /bin/bash -euxo pipefail -c '\
		mkdir -p $(MOUNTPOINT); \
		mount -t ext4 -o loop "$@" $(MOUNTPOINT); \
		mkdir -p $(MOUNTPOINT)/app; \
		echo "Hello World!" > $(MOUNTPOINT)/app/helloworld.txt; \
		cp $(PROG)  $(MOUNTPOINT)/app; \
		umount $(MOUNTPOINT); \
		chown $(USER) "$@"; \
	'

run: run-hw run-sw

run-hw: $(DISK)
	@echo "\n________Running ${PROG} in --hw-debug mode _______\n"
	${SGXLKL_ENV} ${SGXLKL_RUN_CMD} --hw-debug $(DISK) app/$(PROG) $(PROG_ARGS)

run-hw-gdb: $(DISK)
	${SGXLKL_ENV} ${SGXLKL_ROOT}/tools/gdb/sgx-lkl-gdb --args ${SGXLKL_RUN_CMD} --hw-debug $(DISK) app/$(PROG) $(PROG_ARGS)

run-sw: $(DISK)
	@echo "\n________Running ${PROG} in --sw-debug mode _______\n"
	${SGXLKL_ENV} ${SGXLKL_RUN_CMD} --sw-debug $(DISK) app/$(PROG) $(PROG_ARGS)

run-sw-gdb: $(DISK)
	${SGXLKL_ENV} ${SGXLKL_ROOT}/tools/gdb/sgx-lkl-gdb --args ${SGXLKL_RUN_CMD} --sw-debug $(DISK) app/$(PROG) $(PROG_ARGS)

clean:
	@rm -f $(DISK) $(PROG)
