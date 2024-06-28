# Makefile for eBPF program

# Compiler
CC = clang

# Flags
CFLAGS = -O2 -target bpf

# Source file
SRC = simple_bpf.c

# Output object file
OBJ = simple_bpf.o

# BPF object directory
OBJ_DIR = /sys/fs/bpf/programs/

# Program name
PROG_NAME = simple_bpf

.PHONY: all clean

all: $(PROG_NAME)

$(PROG_NAME): $(OBJ)
	@echo "Ensuring BPF object directory exists..."
	sudo mkdir -p $(OBJ_DIR)
	@echo "Removing any existing pinned program..."
	sudo rm -rf $(OBJ_DIR)$(PROG_NAME)
	@echo "Loading and pinning the eBPF program..."
	sudo bpftool prog load $(OBJ) $(OBJ_DIR)$(PROG_NAME) type kprobe
	@echo "Getting the latest program ID..."
	PROG_ID=$(shell sudo bpftool prog | grep 'kprobe  name execve_entry' | tail -1 | grep -oP '^\d+')
	@echo "Program ID is $$PROG_ID"
	@echo "Attaching the eBPF program to sys_execve kprobe..."
	sudo bpftool prog attach $$PROG_ID name kprobe sys_execve

$(OBJ): $(SRC)
	$(CC) $(CFLAGS) -c $(SRC) -o $(OBJ)

clean:
	rm -f $(OBJ)
	sudo rm -f $(OBJ_DIR)$(PROG_NAME)
