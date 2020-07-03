TARGET = sample2
CFLAGS = -Wall
INCLUDES = -I../include
LDFLAGS = -L.. -ljson

SOURCES = main.c ../common/load_file.c

$(TARGET): main.c
	gcc $(CFLAGS) $(INCLUDES) -o $(TARGET) $(SOURCES) $(LDFLAGS)

clean:
	rm -f $(TARGET)

tests: $(TARGET) test1 test2

test1:
	$(eval TMP := $(shell /bin/mktemp))
	sample2 sample.json > $(TMP)
	diff ${TMP} expected.sample.json
	@ echo "=== passed sample2 test1"

test2:
	$(eval TMP := $(shell /bin/mktemp))
	sample2 array.json > $(TMP)
	diff ${TMP} expected.array.json
	@ echo "=== passed sample2 test2"
