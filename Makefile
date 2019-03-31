BIN_DIR := ./bin

TARGET := $(BIN_DIR)/ctr_drbg

SRC_DIR := src

C_SRCS := $(SRC_DIR)/aes.c $(SRC_DIR)/ctr_drbg.c $(SRC_DIR)/main.c $(SRC_DIR)/test_utilities.c
S_SRCS := $(SRC_DIR)/vaes256_key_expansion.S
COMP_FILES := $(C_SRCS) $(S_SRCS)

# Platform flags
CFLAGS := -m64 -maes -mavx2 -msse2 -O3 -std=c99 

# For debug
CFLAGS += -ggdb 

# Warnings flags
CFLAGS += -Wno-missing-braces -Wno-missing-field-initializers -Wall -Werror -Wpedantic
CFLAGS += -mno-red-zone -fvisibility=hidden -funsigned-char -Wall -Wextra -Werror -Wpedantic 
CFLAGS += -Wunused -Wcomment -Wchar-subscripts -Wuninitialized -Wshadow
CFLAGS += -Wcast-align -Wwrite-strings -Wno-deprecated-declarations -Wno-unknown-pragmas -Wformat-security
CFLAGS += -Wcast-qual 

ifdef PERF
    CFLAGS += -DPERF
endif

ifdef COUNT_INSTRUCTIONS
    CFLAGS += -DCOUNT_INSTRUCTIONS -DPERF
endif

ifdef VAES
    CFLAGS += -mavx512f -mavx512dq -mavx512bw -mvaes -DVAES
endif

INC := -I. 

CC ?= gcc

.PHONY: $(BIN_DIR)

all: $(BIN_DIR)
	$(CC) $(COMP_FILES) $(CFLAGS) $(INC) -o $(TARGET)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)
clean:
	rm -rf $(BIN_DIR)
