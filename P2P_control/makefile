CC      ?= x86_64-w64-mingw32-gcc
RM      ?= rm -f

CFLAGS  = -O2 -Wall -std=c11
DLL_LDFLAGS = -shared -Wl,--out-implib,libc2config.a
LIBS    = -lcurl -lssl -lcrypto

TARGET_EXE   = watchdog.exe
TARGET_DLL   = c2_config.dll

EXE_OBJS     = main.o watchdog.o def.o p2p_loader.o

.PHONY: all clean

all: $(TARGET_DLL) $(TARGET_EXE)

$(TARGET_DLL): dll/c2_config.c
	$(CC) $(CFLAGS) $(DLL_LDFLAGS) -o $@ $<

$(TARGET_EXE): $(EXE_OBJS)
	$(CC) $(CFLAGS) -o $@ $(EXE_OBJS) $(LIBS)

main.o: main.c watchdog.h def.h p2p_loader.h
watchdog.o: watchdog.c watchdog.h
def.o: def.c def.h
p2p_loader.o: p2p_loader.c p2p_loader.h

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) $(EXE_OBJS) $(TARGET_EXE) $(TARGET_DLL) libc2config.a
