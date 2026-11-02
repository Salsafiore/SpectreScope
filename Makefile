CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -march=native -fPIC
LDFLAGS ?= -shared

BUILD_DIR := build
LIB_TARGET := $(BUILD_DIR)/libspectrescope.so
ASLR_BIN   := $(BUILD_DIR)/aslr_probe

.PHONY: all clean test

all: $(LIB_TARGET) $(ASLR_BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(LIB_TARGET): src/native/cache_probe.c src/native/spectre_v1_lab.c src/native/cache_probe.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ src/native/cache_probe.c src/native/spectre_v1_lab.c

$(ASLR_BIN): src/native/aslr_probe.c | $(BUILD_DIR)
	$(CC) -O2 -Wall -Wextra -fPIE -pie -o $@ src/native/aslr_probe.c

clean:
	rm -rf $(BUILD_DIR)
