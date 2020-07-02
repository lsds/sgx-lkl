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

#TESTS += ./libc-test/src/functional/pthread_cancel-points.exe
#TESTS += ./libc-test/src/functional/pthread_mutex_pi-static.exe
#TESTS += ./libc-test/src/functional/pthread_cancel.exe
TESTS += ./libc-test/src/functional/pthread_mutex.exe
TESTS += ./libc-test/src/functional/pthread_mutex_pi.exe
#TESTS += ./libc-test/src/functional/pthread_cancel-points-static.exe
#TESTS += ./libc-test/src/functional/pthread_tsd-static.exe
#TESTS += ./libc-test/src/functional/pthread_robust.exe
#TESTS += ./libc-test/src/functional/pthread_tsd.exe
#TESTS += ./libc-test/src/functional/pthread_cancel-static.exe
#TESTS += ./libc-test/src/functional/pthread_robust-static.exe
#TESTS += ./libc-test/src/functional/pthread_cond-static.exe
#TESTS += ./libc-test/src/functional/pthread_mutex-static.exe
#TESTS += ./libc-test/src/functional/pthread_cond.exe
#TESTS += ./libc-test/src/regression/pthread-robust-detach.exe
#TESTS += ./libc-test/src/regression/pthread_create-oom-static.exe
#TESTS += ./libc-test/src/regression/pthread_exit-cancel.exe
#TESTS += ./libc-test/src/regression/pthread_once-deadlock-static.exe
#TESTS += ./libc-test/src/regression/pthread_rwlock-ebusy-static.exe
#TESTS += ./libc-test/src/regression/pthread_condattr_setclock.exe
#TESTS += ./libc-test/src/regression/pthread-robust-detach-static.exe
#TESTS += ./libc-test/src/regression/pthread_cancel-sem_wait-static.exe
#TESTS += ./libc-test/src/regression/pthread_rwlock-ebusy.exe
#TESTS += ./libc-test/src/regression/pthread_atfork-errno-clobber-static.exe
#TESTS += ./libc-test/src/regression/pthread_atfork-errno-clobber.exe
#TESTS += ./libc-test/src/regression/pthread_exit-dtor.exe
#TESTS += ./libc-test/src/regression/pthread_cond-smasher-static.exe
#TESTS += ./libc-test/src/regression/pthread_cancel-sem_wait.exe
#TESTS += ./libc-test/src/regression/pthread_create-oom.exe
#TESTS += ./libc-test/src/regression/pthread_exit-cancel-static.exe
#TESTS += ./libc-test/src/regression/pthread_once-deadlock.exe
#TESTS += ./libc-test/src/regression/pthread_cond_wait-cancel_ignored.exe
#TESTS += ./libc-test/src/regression/pthread_cond-smasher.exe
#TESTS += ./libc-test/src/regression/pthread_condattr_setclock-static.exe
#TESTS += ./libc-test/src/regression/pthread_exit-dtor-static.exe
#TESTS += ./libc-test/src/regression/pthread_cond_wait-cancel_ignored-static.exe

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
