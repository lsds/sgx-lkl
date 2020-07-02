TOP = $(abspath $(CURDIR)/../..)

LIBC_TEST_DIR = $(TOP)/openenclave/3rdparty/musl/libc-test

MUSL_GCC = $(TOP)/build_musl/host-musl/bin/musl-gcc

all: libc-test build-tests rootfs

build-tests:
	$(MAKE) CC="$(MUSL_GCC) -fPIE -pie" -C libc-test

libc-test:
	cp -r $(LIBC_TEST_DIR) .

RUN=$(TOP)/build/sgx-lkl-run-oe

rootfs:
	$(TOP)/tools/sgx-lkl-disk create --size=64M --copy=./libc-test rootfs

clean:
	rm -rf libc-test
	rm -rf rootfs

ifdef TEST
test:
	@ echo "<<<<<<<<<< test: $(TEST)"
	@ $(RUN) --hw-debug rootfs $(TEST)
	@ echo ">>>>>>>>>> test: $(TEST)"
	@ echo ""
else
test:
	$(warning "Please run as: make test TEST=<path-to-test>")
endif

.PHONY: tests

tests:
	./run-tests
