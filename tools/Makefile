CC     = gcc
CLANG  = clang
LD     = ld

CFLAGS = -D_GNU_SOURCE -I./include -Iiface_life_harness -Wall -O2
LDFLAGS = -Wl,-rpath,'$$ORIGIN/../lib' -lbpf -lelf -lz \
          ./lib/libxdp.so.1.6.0

BPF_CFLAGS     = -O2 -target bpf -g
KERNEL_HEADERS = /usr/include

DIR   = iface_life_harness
OBJS  = $(DIR)/main.o $(DIR)/xsk.o
BPF   = $(DIR)/bpf/lan.o $(DIR)/bpf/wan.o
EMBED = $(DIR)/bpf/lan_embed.o $(DIR)/bpf/wan_embed.o
BIN   = $(DIR)/iface-life-harness

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJS) $(EMBED)
	$(CC) -o $@ $(OBJS) $(EMBED) $(LDFLAGS)

$(DIR)/main.o: $(DIR)/main.c $(DIR)/xsk.h
	$(CC) $(CFLAGS) -c $< -o $@

$(DIR)/xsk.o: $(DIR)/xsk.c $(DIR)/xsk.h
	$(CC) $(CFLAGS) -c $< -o $@

$(DIR)/bpf/lan.o: $(DIR)/bpf/lan.c
	@mkdir -p $(DIR)/bpf
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) -I./include -c $< -o $@

$(DIR)/bpf/wan.o: $(DIR)/bpf/wan.c
	@mkdir -p $(DIR)/bpf
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) -I./include -c $< -o $@

$(DIR)/bpf/lan_embed.o: $(DIR)/bpf/lan.o
	cd $(DIR)/bpf && $(LD) -r -b binary lan.o -o lan_embed.o

$(DIR)/bpf/wan_embed.o: $(DIR)/bpf/wan.o
	cd $(DIR)/bpf && $(LD) -r -b binary wan.o -o wan_embed.o

clean:
	rm -f $(BIN) $(OBJS) $(BPF) $(EMBED)
