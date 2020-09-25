include ../../../tests/common.mk

CC_APP=/usr/bin/mysqld
CC_APP_CMDLINE=${CC_APP} --console --user=root --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/mariadb/plugin \
						 --pid-file=/run/mariadb.pid --socket=/run/mysqld.sock --innodb-use-native-aio=OFF

CC_IMAGE_SIZE=5G

CC_IMAGE=sgxlkl-alpine.img

SGXLKL_ENV=SGXLKL_TAP=sgxlkl_tap0 SGXLKL_ETHREADS=4 SGXLKL_CMDLINE="mem=128mb"

VERBOSE_OPTS=SGXLKL_VERBOSE=1 SGXLKL_KERNEL_VERBOSE=1 

ifeq ($(SGXLKL_VERBOSE),)
	SGXLKL_ENV+=${VERBOSE_OPTS}
endif

.DELETE_ON_ERROR:
.PHONY: all clean run-hw run-sw

all: $(CC_IMAGE)

$(CC_IMAGE):
	${SGXLKL_DISK_TOOL} create --size=${CC_IMAGE_SIZE} --docker="./Dockerfile" ${CC_IMAGE}

run-hw: clean $(CC_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --hw-debug $(CC_IMAGE) $(CC_APP_CMDLINE)

run-sw: clean $(CC_IMAGE)
	${SGXLKL_ENV} ${SGXLKL_STARTER} --sw-debug $(CC_IMAGE) $(CC_APP_CMDLINE)

clean:
	rm -f $(CC_IMAGE)*