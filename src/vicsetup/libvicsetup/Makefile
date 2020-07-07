include ../defs.mak

ARCHIVE = libvicsetup.a

CFLAGS += -Wno-type-limits

INCLUDES += -I$(ARGON2_DIR)/include
INCLUDES += -Iinclude
INCLUDES += -I$(LIBJSON_DIR)/include

SOURCES += $(wildcard *.c)
SOURCES += $(ARGON2_DIR)/src/argon2.c
SOURCES += $(ARGON2_DIR)/src/blake2/blake2b.c
SOURCES += $(ARGON2_DIR)/src/core.c
SOURCES += $(ARGON2_DIR)/src/encoding.c
SOURCES += $(ARGON2_DIR)/src/opt.c
SOURCES += $(ARGON2_DIR)/src/thread.c

include ../rules.mak

-include depend.mak
