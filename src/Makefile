BOFNAME := breg
BUILD_DIR := ../build
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc

all:
	$(CC_x64) -o $(BUILD_DIR)/$(BOFNAME).x64.o -Os -c $(BOFNAME).c
	$(CC_x86) -o $(BUILD_DIR)/$(BOFNAME).x86.o -Os -c $(BOFNAME).c

