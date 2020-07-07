TOP=$(abspath $(dir $(word 2, $(MAKEFILE_LIST))))

ifndef CC
CC = gcc
endif

CFLAGS += -g
CFLAGS += -O3
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
