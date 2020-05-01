include ../../../common.mk

PROG=/app/HelloWorld.dll

DISK_IMAGE=sgxlkl-dotnet.img
IMAGE_SIZE=250M

ENCLAVE_CMD=/usr/bin/dotnet ${PROG}

ifeq ($(SGXLKL_VERBOSE),)
SGXLKL_ENV=\
   DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 SGXLKL_MMAP_FILES=Shared SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1 \
	SGXLKL_TRACE_SIGNAL=0 SGXLKL_TRACE_HOST_SYSCALL=0 SGXLKL_TRACE_LKL_SYSCALL=0 SGXLKL_TRACE_MMAP=0
else
SGXLKL_ENV=
endif

.DELETE_ON_ERROR:
.PHONY: all clean

all: $(DISK_IMAGE)

clean:
	rm -f $(DISK_IMAGE)

$(DISK_IMAGE):
	docker build -t dotnet-app:dev .
	${SGXLKL_DISK_TOOL} create --size=${IMAGE_SIZE} --docker=dotnet-app:dev ${DISK_IMAGE}

run: run-hw

run-hw: $(DISK_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --hw-debug $(DISK_IMAGE) $(ENCLAVE_CMD)

run-sw: $(DISK_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --sw-debug $(DISK_IMAGE) $(ENCLAVE_CMD)
