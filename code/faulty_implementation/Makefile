# Faulty CROSS implementation Makefile
# Usage:
#   make          (build default target main)
#   make main     (same as default)
#   make clean    (remove binary and object files)

CC ?= gcc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wshadow -Wundef -Wno-unused-parameter
DEFS ?= -DRSDP -DCATEGORY_1 -DBALANCED
INCLUDES ?= -Iinclude
LDFLAGS ?= -lm

SRCDIR := lib
TARGET := $(SRCDIR)/main
SRC := $(SRCDIR)/main.c $(SRCDIR)/csprng_hash.c $(SRCDIR)/CROSS.c $(SRCDIR)/fips202.c $(SRCDIR)/keccakf1600.c $(SRCDIR)/pack_unpack.c $(SRCDIR)/merkle.c $(SRCDIR)/seedtree.c $(SRCDIR)/utils.c
OBJ := $(SRC:.c=.o)

.PHONY: all main clean

all: main

main: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(DEFS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

# Pattern rule for object files
$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) $(DEFS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJ)
