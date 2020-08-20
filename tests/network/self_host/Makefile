# SGX-LKL has a self host ipv4 network gateway address 10.0.1.254, that can 
# be used by application inside sgxlkl enclave to forward packets from tap
# device. This test ping the self host gateway 10.0.1.254 with a 2 second timeout. 

include ../../common.mk

CC_APP=/bin/ping

CC_APP_CMDLINE=${CC_APP} -c 1 -W 2 10.0.1.254

CC_IMAGE_SIZE=50M

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
	${SGXLKL_DISK_TOOL} create --size=${CC_IMAGE_SIZE} --alpine="bash" ${CC_IMAGE}

run-hw: $(CC_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --hw-debug $(CC_IMAGE) $(CC_APP_CMDLINE)

run-sw: $(CC_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --sw-debug $(CC_IMAGE) $(CC_APP_CMDLINE)
