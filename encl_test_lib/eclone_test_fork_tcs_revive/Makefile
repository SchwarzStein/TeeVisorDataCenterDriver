LIB_DIR := enclave_lib
LIB_NAME := libenclave.so
LIB_PATH := $(LIB_DIR)/$(LIB_NAME)
RUNTIME_DIR := ../enclave_runtime

# Compiler and linker
CC      := gcc
LD      := gcc
AS      := gcc
CFLAGS  := -O2 -Wall -fPIC -fpie -ffunction-sections -fdata-sections -fno-stack-protector -g
LDFLAGS := -nostdlib -nostartfiles -pie -fpie -Wl,-T,$(RUNTIME_DIR)/runtime.lds -Wl,--no-dynamic-linker -Wl,--hash-style=both
MAIN_CFLAGS := -Wall -Wno-incompatible-pointer-types -Wno-pointer-to-int-cast -Wextra -O2 -g
MAIN_LDFLAGS := -lcrypto -lssl

# Source files

C_SRCS := $(wildcard $(RUNTIME_DIR)/*.c $(RUNTIME_DIR)/mm/*.c) runtime_test_case.c
ASM_SRCS := $(wildcard $(RUNTIME_DIR)/*.S)

# Object files
OBJS := $(C_SRCS:.c=.o) $(ASM_SRCS:.S=.o)

# Output binary
TARGET := enclave_runtime

# Default target
all: $(TARGET) main

# Compile C sources
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Assemble ASM sources
%.o: %.S
	$(CC) $(CFLAGS) -c $< -o $@

# Link
$(TARGET): $(OBJS)
	$(LD) $(OBJS) $(LDFLAGS) -o $@

main: 
	$(CC) $(MAIN_CFLAGS) main.c ../$(LIB_PATH) -o main $(MAIN_LDFLAGS)

# Clean
clean:
	rm -f $(OBJS) $(TARGET)
	rm -f main

.PHONY: all clean
