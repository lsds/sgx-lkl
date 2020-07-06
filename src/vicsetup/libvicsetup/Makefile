include ../defs.mak

ARCHIVE = libvicsetup.a

CFLAGS += -Wno-type-limits

INCLUDES += -I/usr/local/include
INCLUDES += -I../../../third_party/argon2/include
INCLUDES += -Iinclude
INCLUDES += -I$(LIBJSON_DIR)/include

SOURCES += $(wildcard *.c)

include ../rules.mak

-include depend.mak
