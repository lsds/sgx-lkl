
SGXLKL_ROOT=../../../..

CC_APP=/usr/bin/python3
CC_APP_CONFIG_TEMPLATE=sgxlkl-encrypted-python-config-template.json
CC_APP_CONFIG=sgxlkl-encrypted-python-config.json.tmp

CC_IMAGE_SIZE=128M

CC_IMAGE_DATA=data-crypt-verity.img

SGXLKL_ENV_APP_CONFIG=\
SGXLKL_HDS=${CC_IMAGE_DATA}:/data:0

VERBOSE_OPTS=SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1

CC_IMAGE_VERITY=sgxlkl-alpine-crypt-verity.img
CC_IMAGE_VERITY_KEY_FILE=$(CC_IMAGE_VERITY).key
CC_IMAGE_VERITY_ROOTHASH_OFFSET_FILE=$(CC_IMAGE_VERITY).hashoffset
CC_IMAGE_VERITY_ROOTHASH_FILE=$(CC_IMAGE_VERITY).roothash

ifeq ($(SGXLKL_VERBOSE),)
	SGXLKL_ENV_APP_CONFIG+=${VERBOSE_OPTS}
endif

SGXLKL_STARTER=$(SGXLKL_ROOT)/build/sgx-lkl-run-oe
SGXLKL_DISK_TOOL=${SGXLKL_ROOT}/tools/sgx-lkl-disk

.DELETE_ON_ERROR:
.PHONY: clean run-hw run-sw

clean:
	rm -f $(CC_IMAGE_VERITY) $(CC_IMAGE_VERITY_KEY_FILE) $(CC_IMAGE_VERITY_ROOTHASH_OFFSET_FILE) \
	      ${CC_IMAGE_VERITY_ROOTHASH_FILE} ${CC_APP_CONFIG} ${CC_IMAGE_DATA}

$(CC_IMAGE_VERITY):
	# Create mountpoint folder for /data in advance as root disk is read-only.
	mkdir -p data
	${SGXLKL_DISK_TOOL} create --size=${CC_IMAGE_SIZE} --encrypt --key-file --verity \
		--alpine="python3" --copy=data/ ${CC_IMAGE_VERITY}

${CC_APP_CONFIG}: $(CC_IMAGE_VERITY)
	cp ${CC_IMAGE_VERITY} ${CC_IMAGE_DATA}
	cp ${CC_APP_CONFIG_TEMPLATE} ${CC_APP_CONFIG}
	$(eval CC_IMAGE_VERITY_KEY=$(shell xxd -ps -c100 ${CC_IMAGE_VERITY_KEY_FILE}))
	$(eval CC_IMAGE_VERITY_ROOTHASH_OFFSET=$(shell cat ${CC_IMAGE_VERITY_ROOTHASH_OFFSET_FILE}))
	$(eval CC_IMAGE_VERITY_ROOTHASH=$(shell cat ${CC_IMAGE_VERITY_ROOTHASH_FILE}))

	sed -i "/\"key\":/c\\"\"key\"": \"${CC_IMAGE_VERITY_KEY}\"," ${CC_APP_CONFIG}
	sed -i "/\"roothash_offset\":/c\\"\"roothash_offset\"": ${CC_IMAGE_VERITY_ROOTHASH_OFFSET}," ${CC_APP_CONFIG}
	sed -i "/\"roothash\":/c\\"\"roothash\"": \"${CC_IMAGE_VERITY_ROOTHASH}\"" ${CC_APP_CONFIG}

run-hw: ${CC_APP_CONFIG}
	${SGXLKL_ENV_APP_CONFIG} ${SGXLKL_STARTER} --enclave-config=${CC_APP_CONFIG} --hw-debug $(CC_IMAGE_VERITY)

run-sw: ${CC_APP_CONFIG}
	${SGXLKL_ENV_APP_CONFIG} ${SGXLKL_STARTER} --enclave-config=${CC_APP_CONFIG} --sw-debug $(CC_IMAGE_VERITY)
