TOP=$(abspath $(dir $(word 2, $(MAKEFILE_LIST))))

ifndef CC
CC = gcc
endif

CFLAGS += -g
CFLAGS += -O3
CFLAGS += -Wall
CFLAGS += -Werror
CFLAGS += -Wextra

LIBJSON_DIR = $(TOP)/../libjson

define NL


endef
