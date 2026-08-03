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

APP_SRC = main.c src/xsk_pair.c src/l2_crypto.c src/traffic_crypto_pqc.c
APP_OBJ = $(APP_SRC:.c=.o)

BPF_OBJ = $(LIBDIR)/lan.o $(LIBDIR)/wan.o

.PHONY: all clean dirs

all: dirs $(BPF_OBJ) $(TARGET)

dirs:
	mkdir -p $(LIBDIR) src

$(TARGET): $(APP_OBJ)
	$(CC) -o $@ $(APP_OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

src/traffic_crypto_pqc.o: $(ROOT)/src/crypto/pqc/traffic_crypto.c
	$(CC) $(CFLAGS) -c $< -o $@

$(LIBDIR)/lan.o: bpf/lan.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(LIBDIR)/wan.o: bpf/wan.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f $(APP_OBJ) $(TARGET) $(BPF_OBJ)
