TARGET = sample1
CFLAGS = -Wall -Werror
INCLUDES = -I../include
LDFLAGS = -L.. -ljson

$(TARGET): main.c ../libjson.a
	gcc $(CFLAGS) $(INCLUDES) -c main.c
	gcc $(CFLAGS) $(INCLUDES) -c strings.c
	gcc $(CFLAGS) $(INCLUDES) -c ../common/load_file.c
	gcc $(CFLAGS) $(INCLUDES) -o $(TARGET) main.o strings.o load_file.o $(LDFLAGS)

clean:
	rm -f $(TARGET) main.o strings.o

tests: $(TARGET)
	sample1 sample.json
	@ echo "=== passed sample1 test"
