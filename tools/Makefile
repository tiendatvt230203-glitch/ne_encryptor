CC     = gcc
CLANG  = clang

DIR     = iface_life_harness
BPF_DIR = $(DIR)/bpf
CFLAGS  = -D_GNU_SOURCE -I$(DIR) -Wall -O2
LDFLAGS = -lxdp -lbpf -lelf -lz

BPF_CFLAGS     = -O2 -target bpf -g
KERNEL_HEADERS = /usr/include

OBJS = $(DIR)/main.o $(DIR)/xsk.o
BPF  = $(BPF_DIR)/lan.o $(BPF_DIR)/wan.o
BIN  = $(DIR)/iface-life-harness

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJS) $(BPF)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

$(DIR)/main.o: $(DIR)/main.c $(DIR)/xsk.h
	$(CC) $(CFLAGS) -c $< -o $@

$(DIR)/xsk.o: $(DIR)/xsk.c $(DIR)/xsk.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BPF_DIR)/lan.o: $(BPF_DIR)/lan.c
	@mkdir -p $(BPF_DIR)
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) -c $< -o $@

$(BPF_DIR)/wan.o: $(BPF_DIR)/wan.c
	@mkdir -p $(BPF_DIR)
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) -c $< -o $@

clean:
	rm -f $(BIN) $(OBJS) $(BPF)
