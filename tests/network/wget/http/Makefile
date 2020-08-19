include ../../../common.mk

CC_APP=/usr/bin/wget

# The following used to access https://www.microsoft.com, but this fails
# with Github issue https://github.com/lsds/sgx-lkl/issues/499. Other URLs
# appear to work fine.
CC_APP_CMDLINE=${CC_APP} http://www.wikipedia.org/

CC_IMAGE_SIZE=128M

CC_IMAGE=sgxlkl-alpine.img

SGXLKL_ENV=SGXLKL_TAP=sgxlkl_tap0

VERBOSE_OPTS=SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1

ifeq ($(SGXLKL_VERBOSE),)
	SGXLKL_ENV+=${VERBOSE_OPTS}
endif

.DELETE_ON_ERROR:
.PHONY: all clean run-hw run-sw

clean:
	rm -f $(CC_IMAGE)

$(CC_IMAGE):
	${SGXLKL_DISK_TOOL} create --size=${CC_IMAGE_SIZE} --alpine="wget" ${CC_IMAGE}

run-hw: $(CC_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --hw-debug $(CC_IMAGE) $(CC_APP_CMDLINE)

run-sw: $(CC_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --sw-debug $(CC_IMAGE) $(CC_APP_CMDLINE)
