# Top-level Makefile
SHELL := /bin/bash
CC := gcc

LIB_DIR := enclave_lib
LIB_NAME := libenclave.so
LIB_PATH := $(LIB_DIR)/$(LIB_NAME)

ENCL_DIRS := encl_print $(wildcard eclone*)

LIB_CFLAGS := -fPIC -shared -g
MAIN_CFLAGS := -Wall -Wextra -O2 -g
MAIN_LDFLAGS := -lcrypto -lssl

.PHONY: all lib $(ENCL_DIRS) clean

all: lib $(ENCL_DIRS)

# ========== Build shared library ==========
lib: $(LIB_PATH)

$(LIB_PATH):
	@echo "=> Building $(LIB_NAME)..."
	@cd $(LIB_DIR) && make offset && $(CC) $(LIB_CFLAGS) *.S *.c -o $(LIB_NAME)
	@echo "=> $(LIB_PATH) built."

# ========== Build all tests/* ==========
$(ENCL_DIRS): lib
	@echo "=> Building main in $@ ..."
	@cd $@ && make
	@echo "=> $@/main built."

# ========== Clean ==========
clean:
	@echo "=> Cleaning..."
	@rm -f $(LIB_PATH)
	@for d in $(ENCL_DIRS); do \
		$(MAKE) -C $$d clean; \
	done
	@echo "=> Clean done."
