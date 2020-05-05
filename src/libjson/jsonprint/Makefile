TARGET = jsonprint
CFLAGS = -Wall
INCLUDES = -I../include
LDFLAGS = -L.. -ljson

$(TARGET): main.c
	gcc $(CFLAGS) $(INCLUDES) -o $(TARGET) main.c $(LDFLAGS)

clean:
	rm -f $(TARGET)
