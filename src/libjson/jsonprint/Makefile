TARGET = jsonprint
CFLAGS = -Wall
INCLUDES = -I../include
LDFLAGS = -L.. -ljson

SOURCES = main.c ../common/load_file.c

$(TARGET): main.c
	gcc $(CFLAGS) $(INCLUDES) -o $(TARGET) $(SOURCES) $(LDFLAGS)

clean:
	rm -f $(TARGET)
