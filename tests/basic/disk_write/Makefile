include ../../common.mk

# This test creates a file on the root file system and then checks if it has
# been persisted properly by running SGX-LKL again and trying to read the file.

CC_APP=/usr/bin/python3	

CC_APP_CMDLINE1=${CC_APP} -c 'import os; \
f = open("test_file.txt", "w+"); \
f.write("TEST WRITE"); \
f.close(); \
print("File `test_file.txt` written to disk")'

CC_APP_CMDLINE2=${CC_APP} -c 'import os; \
f = open("test_file.txt", "r"); \
content = f.read(); \
print("File successfully read" if content == "TEST WRITE" else "Failed to read file"); \
exit (0 if content == "TEST WRITE" else -1)'

CC_IMAGE_SIZE=64M

CC_IMAGE=sgxlkl-alpine.img

VERBOSE_OPTS=SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1

ifeq ($(SGXLKL_VERBOSE),)
	SGXLKL_ENV+=${VERBOSE_OPTS}
endif

.DELETE_ON_ERROR:
.PHONY: all clean run-hw run-sw

clean:
	rm -f $(CC_IMAGE)

$(CC_IMAGE):
	${SGXLKL_DISK_TOOL} create --size=${CC_IMAGE_SIZE} --docker=./Dockerfile ${CC_IMAGE}

run-hw: $(CC_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --hw-debug $(CC_IMAGE) $(CC_APP_CMDLINE1)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --hw-debug $(CC_IMAGE) $(CC_APP_CMDLINE2)

run-sw: $(CC_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --sw-debug $(CC_IMAGE) $(CC_APP_CMDLINE1)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --sw-debug $(CC_IMAGE) $(CC_APP_CMDLINE2)
