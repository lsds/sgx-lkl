ALPINE_MAJOR=3.9
ALPINE_VERSION=3.9.0
ALPINE_ARCH=x86_64

ALPINE_TAR=alpine-minirootfs.tar.gz

ROOT_FS=sgxlkl-dotnet-fs.img
MOUNTPOINT=/media/ext4disk
IMAGE_SIZE_MB=400

ESCALATE_CMD=sudo

.DELETE_ON_ERROR:
.PHONY: all clean

all: $(ROOT_FS)

clean:
	test -f bin && rm bin || true
	test -f obj && rm obj || true
	#test -f HelloWorld.dll && rm HelloWorld.dll || true
	test -f $(ROOT_FS) && rm $(ROOT_FS) || true

$(ALPINE_TAR):
	curl -L -o "$@" "https://nl.alpinelinux.org/alpine/v$(ALPINE_MAJOR)/releases/$(ALPINE_ARCH)/alpine-minirootfs-$(ALPINE_VERSION)-$(ALPINE_ARCH).tar.gz"

HelloWorld.dll: HelloWorld.csproj
	# dotnet build
	# dotnet publish -c Release
	dotnet publish -r linux-musl-x64 -c Debug 

$(ROOT_FS): $(ALPINE_TAR) buildenv.sh HelloWorld.dll
	dd if=/dev/zero of="$@" count=$(IMAGE_SIZE_MB) bs=1M
	mkfs.ext4 "$@"
	$(ESCALATE_CMD) /bin/bash -euxo pipefail -c '\
		mkdir -p $(MOUNTPOINT); \
		mount -t ext4 -o loop "$@" $(MOUNTPOINT); \
		tar -C $(MOUNTPOINT) -xvf $(ALPINE_TAR); \
		cp /etc/resolv.conf $(MOUNTPOINT)/etc/resolv.conf; \
		install buildenv.sh $(MOUNTPOINT)/usr/sbin; \
		mkdir -p $(MOUNTPOINT)/app; \
		cp -rT ./bin/Debug/netcoreapp2.2/linux-musl-x64/ $(MOUNTPOINT)/app; \
		mkdir -p $(MOUNTPOINT)/opt; \
		chroot $(MOUNTPOINT) /bin/sh /usr/sbin/buildenv.sh; \
		umount $(MOUNTPOINT); \
		chown $(USER) "$@"; \
	'

test: $(ROOT_FS)
	echo "Running dotnet Hello World example: ${CURDIR}/$(ROOT_FS)"
	# /sgx-lkl/tools/sgx-lkl-dotnet /sgx-lkl/apps/dotnet/helloworld-dotnet/sgxlkl-dotnet-fs.img HelloWorld
	${CURDIR}/../../../tools/sgx-lkl-dotnet ${CURDIR}/$(ROOT_FS) app/HelloWorld.dll

