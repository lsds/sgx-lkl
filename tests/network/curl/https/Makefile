include ../../../common.mk

# Test1 - curl
CURL_APP=/usr/bin/curl
# The following used to access https://www.microsoft.com, but this fails
# with Github issue https://github.com/lsds/sgx-lkl/issues/499. Other URLs
# appear to work fine.
CURL_APP_CMDLINE=${CURL_APP} --trace-ascii - https://www.wikipedia.org/

# Test 2 - iperf
# This test requires iperf3 to be installed on the host.
IPERF_APP=/usr/bin/iperf3
# The following iperf test still suffers from a problem in which the
# throughput collapses to zero after a few seconds.
IPERF_APP_CMDLINE=${IPERF_APP} -V -c 10.0.1.254 -t 60 -P 8

CC_IMAGE_SIZE=64M
CC_IMAGE=sgxlkl-alpine.img
SGXLKL_ENV=SGXLKL_TAP=sgxlkl_tap0

VERBOSE_OPTS=SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1 SGXLKL_ETHREADS=8 SGXLKL_TRACE_LKL_SYSCALL=0 SGXLKL_TRACE_SIGNAL=0

ifeq ($(SGXLKL_VERBOSE),)
	SGXLKL_ENV+=${VERBOSE_OPTS}
endif

.DELETE_ON_ERROR:
.PHONY: all clean run-hw run-sw run-curl-hw run-curl-sw run-iperf-hw run-iperf-sw

clean:
	rm -f $(CC_IMAGE)

$(CC_IMAGE):
	${SGXLKL_DISK_TOOL} create --size=${CC_IMAGE_SIZE} --alpine="curl iperf3" ${CC_IMAGE}

# Only run the curl test by default, as the iperf test is still broken.
run-hw: run-curl-hw

run-curl-hw: $(CC_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --hw-debug $(CC_IMAGE) $(CURL_APP_CMDLINE)

run-iperf-hw: $(CC_IMAGE)
	killall -q iperf3; iperf3 --server --daemon && sleep 2
	${SGXLKL_ENV} ${SGXLKL_STARTER} --hw-debug $(CC_IMAGE) $(IPERF_APP_CMDLINE)
	killall iperf3

# Only runt the curl test by default, as the iperf test is still broken.
run-sw: run-curl-sw

run-curl-sw: $(CC_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --sw-debug $(CC_IMAGE) $(CURL_APP_CMDLINE)

run-iperf-sw: $(CC_IMAGE)
	killall -q iperf3; iperf3 --server --daemon && sleep 2
	${SGXLKL_ENV} ${SGXLKL_STARTER} --sw-debug $(CC_IMAGE) $(IPERF_APP_CMDLINE)
	killall iperf3
