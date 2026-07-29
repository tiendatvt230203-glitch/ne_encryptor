ROOT     := ..
CC       := gcc
CLANG    := clang
LD       := ld
TARGET   := l4pqc-rss
BUILD    := build

CFLAGS   := -D_GNU_SOURCE -DL4PQC_RSS_STANDALONE \
            -Iinclude -Iinclude/shim \
            -I$(ROOT)/inc -I$(ROOT)/inc/core -I$(ROOT)/inc/crypto \
            -I$(ROOT)/include -I$(ROOT)/src/crypto/pqc/include \
            -Wall -O2 -mcmodel=medium

LDFLAGS  := -Wl,-rpath,'$$ORIGIN/lib' -lbpf -lelf -lz -lpthread \
            $(ROOT)/lib/libxdp.so.1.6.0 \
            $(ROOT)/lib/libssl.so.3 $(ROOT)/lib/libcrypto.so.3 \
            $(ROOT)/lib/libscrypt.so

BPF_CFLAGS := -O2 -target bpf -g -I/usr/include -I$(ROOT)/include

LOCAL_OBJS := \
    $(BUILD)/main.o \
    $(BUILD)/config.o \
    $(BUILD)/pipeline.o \
    $(BUILD)/xsk_pair.o \
    $(BUILD)/l4pqc_crypto.o \
    $(BUILD)/l4pqc_stubs.o \
    $(BUILD)/l4pqc_worker.o

PARENT_OBJS := \
    $(BUILD)/pqc_l4_option.o \
    $(BUILD)/traffic_crypto.o \
    $(BUILD)/packet_crypto.o \
    $(BUILD)/eth_parse.o \
    $(BUILD)/aes_crypto.o \
    $(BUILD)/opt_no_frag_ops.o

EMBED_OBJS := $(BUILD)/bpf/lan_embed.o $(BUILD)/bpf/wan_embed.o

.PHONY: all clean dirs

all: dirs $(TARGET)

dirs:
	@mkdir -p $(BUILD)/bpf

$(TARGET): $(LOCAL_OBJS) $(PARENT_OBJS) $(EMBED_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(BUILD)/pqc_l4_option.c: $(ROOT)/src/crypto/pqc/pqc_l4_option.c
	sed -e 's|\.\./\.\./\.\./inc/core/interface.h|shim/l4pqc_iface_shim.h|g' \
	    -e 's|\.\./\.\./\.\./inc/core/cpu_map.h|shim/cpu_map.h|g' $< > $@

$(BUILD)/%.o: src/%.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/pqc_l4_option.o: $(BUILD)/pqc_l4_option.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/traffic_crypto.o: $(ROOT)/src/crypto/pqc/traffic_crypto.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/packet_crypto.o: $(ROOT)/src/crypto/common/packet_crypto.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/eth_parse.o: $(ROOT)/src/crypto/common/eth_parse.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/aes_crypto.o: $(ROOT)/src/crypto/common/aes_crypto.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/opt_no_frag_ops.o: $(ROOT)/src/crypto/options/common/opt_no_frag_ops.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/l4pqc_worker.o: src/l4pqc_worker.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/bpf/lan.o: bpf/lan.c | dirs
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD)/bpf/wan.o: bpf/wan.c | dirs
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD)/bpf/lan_embed.o: $(BUILD)/bpf/lan.o
	cd $(BUILD)/bpf && $(LD) -r -b binary lan.o -o lan_embed.o

$(BUILD)/bpf/wan_embed.o: $(BUILD)/bpf/wan.o
	cd $(BUILD)/bpf && $(LD) -r -b binary wan.o -o wan_embed.o

clean:
	rm -rf $(BUILD) $(TARGET)
