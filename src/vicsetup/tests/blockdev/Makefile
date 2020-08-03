include ../../defs.mak

PROGRAM = test_blockdev

INCLUDES += -I$(TOP)/libvicsetup/include

SOURCES += main.c

LDFLAGS += -L$(TOP)/libvicsetup -lvicsetup
LDFLAGS += -L$(LIBJSON_DIR) -ljson
LDFLAGS += -ldevmapper
LDFLAGS += -lmbedcrypto
LDFLAGS += -lpthread

DIRS += $(LIBJSON_DIR)
DIRS += $(TOP)/libvicsetup

CLEAN += file

include ../../rules.mak

tests: $(PROGRAM)
	head -c 32768 /dev/urandom > file
	./test_blockdev file
