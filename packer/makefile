# Windows MinGW build
CC      ?= x86_64-w64-mingw32-gcc
CFLAGS  = -O2 -Wall -Wextra -std=c11

TARGET  = packer_loader.exe
OBJS    = vm.o packer_loader.o

.PHONY: all clean

all: $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

clean:
	rm -f $(OBJS) $(TARGET)
