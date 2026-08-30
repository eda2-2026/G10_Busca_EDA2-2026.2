#  Compilador e flags
CC := gcc
CSTD := -std=c11
WARN := -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
CFLAGS := $(CSTD) $(WARN) -g -Iinclude

#  Diretórios 
SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin
TEST_C_DIR := tests/c
UNITY_DIR := tests/unity

#  Os testes em tests/c/ vão linkar direto (sem precisar de um main).
LIB_SRCS := $(filter-out $(SRC_DIR)/main.c,$(wildcard $(SRC_DIR)/*.c))
LIB_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(LIB_SRCS))
MAIN_OBJ := $(BUILD_DIR)/main.o

# Testes em C
# Cada tests/c/test_X.c e' um programa completo, entao cada um vira um binario bin/test_X, em vez de linkar todos
# juntos num so' executavel
TEST_SRCS := $(wildcard $(TEST_C_DIR)/test_*.c)
TEST_BIN_NAMES := $(notdir $(basename $(TEST_SRCS)))
TEST_BINS := $(addprefix $(BIN_DIR)/,$(TEST_BIN_NAMES))
UNITY_OBJ := $(BUILD_DIR)/unity.o

.PHONY: all test test-c test-python clean

# Sem isso, o make apaga os .o dos testes depois de linkar cada bin/test_X

.SECONDARY:

# --- Alvo padrão: o executável principal --------------------------------------
all: $(BIN_DIR)/cve_finder

$(BIN_DIR)/cve_finder: $(LIB_OBJS) $(MAIN_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

# Regra genérica: qualquer src/X.c vira build/X.o
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Testes em C (Unity)
$(BUILD_DIR)/tests/%.o: $(TEST_C_DIR)/%.c | $(BUILD_DIR)/tests
	$(CC) $(CFLAGS) -I$(UNITY_DIR) -c -o $@ $<

$(UNITY_OBJ): $(UNITY_DIR)/unity.c | $(BUILD_DIR)
	$(CC) $(CSTD) -w -c -o $@ $<

# Regra padrão: build/tests/test_X.o + a "biblioteca" + Unity -> bin/test_X
$(BIN_DIR)/test_%: $(BUILD_DIR)/tests/test_%.o $(LIB_OBJS) $(UNITY_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -I$(UNITY_DIR) -o $@ $^

test: test-c test-python

test-c: $(TEST_BINS)
	@set -e; for bin in $(TEST_BINS); do echo "== $$bin =="; ./$$bin; done

test-python:
	pytest tests/python

#  Diretórios de saída 
$(BUILD_DIR) $(BUILD_DIR)/tests $(BIN_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
