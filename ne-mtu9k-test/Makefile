CC     = gcc
CLANG  = clang

ROOT   = ..
INCS   = -I. -I$(ROOT)/include -I$(ROOT)/inc -I$(ROOT)/inc/crypto \
         -I$(ROOT)/src/crypto/pqc/include
CFLAGS = -D_GNU_SOURCE -Wall -O2 $(INCS)
LDFLAGS = -Wl,-rpath,'$$ORIGIN/lib' -lbpf -lelf -lz -lpthread \
          ./lib/libxdp.so.1.6.0 ./lib/libscrypt.so ./lib/libssl.so.3 ./lib/libcrypto.so.3

KERNEL_HEADERS = /usr/include
BPF_CFLAGS = -O2 -target bpf -g -I$(KERNEL_HEADERS) -I$(ROOT)/include

TARGET = mtu9k-test
LIBDIR = lib

# ONLY local bpf/ — never ../bpf (production 1500 = SEC("xdp") linear)
BPF_LAN_SRC = bpf/lan.c
BPF_WAN_SRC = bpf/wan.c
BPF_LAN_OBJ = $(LIBDIR)/mtu9k_lan.o
BPF_WAN_OBJ = $(LIBDIR)/mtu9k_wan.o
BPF_OBJ = $(BPF_LAN_OBJ) $(BPF_WAN_OBJ)

APP_SRC = main.c src/xsk_pair.c src/l2_crypto.c src/traffic_crypto_pqc.c
APP_OBJ = $(APP_SRC:.c=.o)

.PHONY: all clean dirs verify-bpf

all: dirs $(BPF_OBJ) verify-bpf $(TARGET)

dirs:
	mkdir -p $(LIBDIR) src

$(TARGET): $(APP_OBJ)
	$(CC) -o $@ $(APP_OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

src/traffic_crypto_pqc.o: $(ROOT)/src/crypto/pqc/traffic_crypto.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BPF_LAN_OBJ): $(BPF_LAN_SRC)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BPF_WAN_OBJ): $(BPF_WAN_SRC)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Fail build if objects are linear xdp (would break ice jumbo)
verify-bpf: $(BPF_OBJ)
	@llvm-objdump -h $(BPF_LAN_OBJ) 2>/dev/null | grep -q 'xdp.frags' || \
		(echo "ERROR: $(BPF_LAN_OBJ) missing xdp.frags — refusing (would load linear/1500-style prog)"; exit 1)
	@llvm-objdump -h $(BPF_WAN_OBJ) 2>/dev/null | grep -q 'xdp.frags' || \
		(echo "ERROR: $(BPF_WAN_OBJ) missing xdp.frags — refusing"; exit 1)
	@echo "OK: $(BPF_LAN_OBJ) $(BPF_WAN_OBJ) have xdp.frags (not production lib/lan.o)"

clean:
	rm -f $(APP_OBJ) $(TARGET) $(BPF_OBJ)
