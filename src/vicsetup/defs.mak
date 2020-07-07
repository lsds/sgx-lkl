TOP=$(abspath $(dir $(word 2, $(MAKEFILE_LIST))))

ifndef CC
CC = gcc
endif

ifdef DEBUG
CFLAGS += -g
endif

ifdef OPTIMIZE
CFLAGS += $(OPTIMIZE)
else
CFLAGS += -O3
endif

CFLAGS += -Wall
CFLAGS += -Werror
CFLAGS += -Wextra

ifndef LIBJSON_DIR
LIBJSON_DIR = $(TOP)/../libjson
endif

ifndef ARGON2_DIR
ARGON2_DIR = $(TOP)/../../third_party/argon2
endif

define NL


endef
