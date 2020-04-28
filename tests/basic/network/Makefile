
SGXLKL_ROOT=../../..

CC_APP=/usr/bin/curl
CC_APP_CMDLINE=${CC_APP} -v https://www.microsoft.com/

CC_IMAGE_SIZE=128M

CC_IMAGE=sgxlkl-alpine.img

SGXLKL_ENV=SGXLKL_TAP=sgxlkl_tap0

VERBOSE_OPTS=SGXLKL_GETTIME_VDSO=0 SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1

ifeq ($(SGXLKL_VERBOSE),)
	SGXLKL_ENV+=${VERBOSE_OPTS}
endif

SGXLKL_STARTER=$(SGXLKL_ROOT)/build/sgx-lkl-run-oe
SGXLKL_DISK_TOOL=${SGXLKL_ROOT}/tools/sgx-lkl-disk

.DELETE_ON_ERROR:
.PHONY: all clean run-hw run-sw

clean:
	rm -f $(CC_IMAGE)

$(CC_IMAGE):
	${SGXLKL_DISK_TOOL} create --size=${CC_IMAGE_SIZE} --alpine="curl" ${CC_IMAGE}

run-hw: $(CC_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --hw-debug $(CC_IMAGE) $(CC_APP_CMDLINE)

run-sw: $(CC_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --sw-debug $(CC_IMAGE) $(CC_APP_CMDLINE)
