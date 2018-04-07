CC  = gcc
LDFLAGS = -ldl
CFLAGS  = -D_GNU_SOURCE -fPIC
SRC := se_ptrace.c se_memory.c se_trace.c
OBJ := se_ptrace.o se_memory.o se_trace.o
TARGET := libsgx_ptrace.so

.PHONY: all clean
all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -shared $^ -o $@ $(LDFLAGS)

$(OBJ): %.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

clean:
	rm -f $(OBJ) $(TARGET)
