# =============================================================================
# Makefile — net-ingress
#
# Usage:
#   make           — compile everything (library + test binaries)
#   make test      — compile and run all tests, report pass/fail
#   make clean     — remove all build artefacts
#   make help      — print this message
#
# Design:
#   We build all .c files in src/ into a static library (libnetingress.a).
#   Each test file in tests/ is compiled and linked against that library.
#   Running 'make test' executes every test binary and collects exit codes.
#
#   Variables are defined at the top so you can override them on the
#   command line, e.g.:
#       make CC=clang
#       make CFLAGS="-O2 -DNDEBUG"
# =============================================================================

CC      := gcc
CFLAGS  := -std=c99 -Wall -Wextra -Wpedantic -Wstrict-prototypes \
           -Wmissing-prototypes -Wshadow -g
INCLUDE := -Iinclude

# Directories
SRC_DIR   := src
TEST_DIR  := tests
BUILD_DIR := build

# Source files and their corresponding object files
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))

# Static library
LIB := $(BUILD_DIR)/libnetingress.a

# Test sources and binaries
TEST_SRCS := $(wildcard $(TEST_DIR)/test_*.c)
TEST_BINS := $(patsubst $(TEST_DIR)/%.c, $(BUILD_DIR)/%, $(TEST_SRCS))

# =============================================================================
# Default target: build the library and all test binaries
# =============================================================================

.PHONY: all
all: $(BUILD_DIR) $(LIB) $(TEST_BINS)
	@echo ""
	@echo "Build complete. Run 'make test' to execute the test suite."

# =============================================================================
# Create build directory
# =============================================================================

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# =============================================================================
# Compile each .c file in src/ into an object file
# =============================================================================

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@

# =============================================================================
# Archive all object files into a static library
#
# 'ar rcs' means:
#   r — insert (or replace) the object files
#   c — create the archive if it does not exist
#   s — write an index (symbol table) for faster linking
# =============================================================================

$(LIB): $(OBJS)
	ar rcs $@ $^

# =============================================================================
# Compile each test binary.
#
# Each test_*.c in tests/ becomes a standalone executable. The test file
# is compiled directly and linked against our library. The test_harness.h
# header is included by the test files themselves — it needs no separate .c.
# =============================================================================

$(BUILD_DIR)/%: $(TEST_DIR)/%.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDE) -I$(TEST_DIR) $< -L$(BUILD_DIR) -lnetingress -o $@

# =============================================================================
# Run all tests
#
# We execute each test binary. Each one prints its own results and exits
# with 0 (all pass) or 1 (any fail). We track the overall result and
# print a final summary.
# =============================================================================

.PHONY: test
test: all
	@echo ""
	@echo "Running tests..."
	@echo "-------------------------------------------"
	@overall=0; \
	for bin in $(TEST_BINS); do \
	    printf "%-30s" "$$(basename $$bin):"; \
	    if $$bin; then \
	        true; \
	    else \
	        overall=1; \
	    fi; \
	done; \
	echo "-------------------------------------------"; \
	if [ $$overall -eq 0 ]; then \
	    echo "ALL TESTS PASSED"; \
	else \
	    echo "SOME TESTS FAILED"; \
	    exit 1; \
	fi

# =============================================================================
# Clean all build artefacts
# =============================================================================

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	@echo "Cleaned."

# =============================================================================
# Help
# =============================================================================

.PHONY: help
help:
	@echo ""
	@echo "net-ingress build system"
	@echo ""
	@echo "  make           build library and test binaries"
	@echo "  make test      build and run the full test suite"
	@echo "  make clean     remove the build/ directory"
	@echo "  make help      show this message"
	@echo ""
	@echo "  CC=<compiler>  override compiler (default: gcc)"
	@echo ""
