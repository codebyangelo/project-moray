# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Project Moray: OS-Level Ring 0 Containment Engine

CC ?= gcc
CLANG ?= clang
CFLAGS ?= -Wall -Wextra -Werror -O2 -std=c11
BPF_CFLAGS ?= -target bpf -O2 -g -Wall -Werror -Isrc

ARCH ?= $(shell uname -m)
MULTIARCH_INC ?= /usr/include/$(ARCH)-linux-gnu
ifneq ($(wildcard $(MULTIARCH_INC)),)
    BPF_CFLAGS += -I$(MULTIARCH_INC)
endif

SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin
TESTS_DIR = tests

BPF_SRC = $(SRC_DIR)/moray_kern.bpf.c
BPF_OBJ = $(BUILD_DIR)/moray_kern.bpf.o
DAEMON_SRC = $(SRC_DIR)/morayd.c
DAEMON_BIN = $(BIN_DIR)/morayd
TEST_STRUCT_SRC = $(TESTS_DIR)/test_struct_layout.c
TEST_STRUCT_BIN = $(BUILD_DIR)/test_struct_layout

.PHONY: all clean test bpf daemon dirs

all: dirs bpf daemon test

dirs:
	@mkdir -p $(BUILD_DIR) $(BIN_DIR)

bpf: dirs $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) $(SRC_DIR)/moray.h $(SRC_DIR)/moray_bpf.h
	@echo "[*] Compiling BPF bytecode: $< -> $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

daemon: dirs $(DAEMON_BIN)

$(DAEMON_BIN): $(DAEMON_SRC) $(SRC_DIR)/moray.h
	@echo "[*] Compiling morayd loader daemon: $< -> $@"
	$(CC) $(CFLAGS) -I$(SRC_DIR) $< -o $@

test: dirs $(TEST_STRUCT_BIN)
	@echo "[*] Executing struct alignment & layout tests..."
	@$(TEST_STRUCT_BIN)
	@if command -v pytest >/dev/null 2>&1; then \
		echo "[*] Running Python invariant test suite..."; \
		pytest -q $(TESTS_DIR); \
	fi

$(TEST_STRUCT_BIN): $(TEST_STRUCT_SRC) $(SRC_DIR)/moray.h
	$(CC) $(CFLAGS) -I$(SRC_DIR) $< -o $@

clean:
	@echo "[*] Cleaning build artifacts..."
	rm -rf $(BUILD_DIR) $(BIN_DIR)
