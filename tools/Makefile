CC     = gcc
CLANG  = clang
REPO   = ..

DIR     = iface_life_harness
CFLAGS  = -D_GNU_SOURCE -I$(REPO)/include -I$(DIR) -Wall -O2
LDFLAGS = -L$(REPO)/lib -Wl,-rpath,'$(abspath $(REPO)/lib)' -lxdp -lbpf -lelf -lz

BPF_CFLAGS     = -O2 -target bpf -g
KERNEL_HEADERS = /usr/include

OBJS = $(DIR)/main.o $(DIR)/xsk.o
BPF  = $(DIR)/lan.o $(DIR)/wan.o
BIN  = $(DIR)/iface-life-harness

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJS) $(BPF)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

$(DIR)/main.o: $(DIR)/main.c $(DIR)/xsk.h
	$(CC) $(CFLAGS) -c $< -o $@

$(DIR)/xsk.o: $(DIR)/xsk.c $(DIR)/xsk.h
	$(CC) $(CFLAGS) -c $< -o $@

$(DIR)/lan.o: $(REPO)/bpf/lan.c
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) -I$(REPO)/include -c $< -o $@

$(DIR)/wan.o: $(REPO)/bpf/wan.c
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) -I$(REPO)/include -c $< -o $@

clean:
	rm -f $(BIN) $(OBJS) $(BPF)
