TARGET = libjson.a

CFLAGS += -g
CFLAGS += -O3
CFLAGS += -fPIE
CFLAGS += -Wall
CFLAGS += -Werror
CFLAGS += -Wextra
CFLAGS += -Wno-type-limits

INCLUDES += -Iinclude

SOURCES += json.c

OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET) dirs

$(TARGET): $(OBJECTS)
	ar rv $(TARGET) json.o

%.o: %.c
	gcc -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

json.o: include/json.h

dirs:
	$(MAKE) -C sample1
	$(MAKE) -C sample2
	$(MAKE) -C jsonprint

clean:
	rm -rf $(OBJECTS) libjson.a
	$(MAKE) -C sample1 clean
	$(MAKE) -C sample2 clean
	$(MAKE) -C jsonprint clean

tests:
	@ $(MAKE) -s -C sample1 tests
	@ $(MAKE) -s -C sample2 tests
