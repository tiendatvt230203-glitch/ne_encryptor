CC     = gcc
CLANG  = clang

CFLAGS = -D_GNU_SOURCE -I. -Iinc -Iinc/core -Iinc/crypto -Iinc/db -I./include -Wall -O2 -mcmodel=medium $(shell pg_config --includedir 2>/dev/null | xargs -I{} echo -I{})
LDFLAGS = -L./lib -Wl,-rpath,'$$ORIGIN/lib' -lxdp -lbpf -lelf -lz -lpthread -lssl -lcrypto -lpq -lscrypt
# LDFLAGS = -L./lib -Wl,-rpath,'lib' -lxdp -lbpf -lelf -lz -lpthread -lssl -lcrypto -lpq -lscrypt

BPF_CFLAGS     = -O2 -target bpf -g
KERNEL_HEADERS = /usr/include

LIB_DIR = lib
TARGET  = network-encryptor

APP_SRC = main.c \
          src/core/main_diag.c \
          src/core/cpu_map.c \
          src/core/interface.c \
          src/core/forwarder.c \
          src/core/crypto_route.c \
          src/core/forwarder_wan.c \
          src/core/forwarder_reload.c \
          src/core/forwarder_crypto_runtime.c \
          src/core/profile_iface_xdp.c \
          src/core/dataplane_util.c \
          src/core/dataplane_local.c \
          src/core/dataplane_wan.c \
          src/core/mac_learn.c \
          src/crypto/crypto_policy_utils.c \
          src/crypto/eth_parse.c \
          src/crypto/crypto_dispatch.c \
          src/crypto/packet_crypto.c \
          src/crypto/traffic_crypto.c \
          src/crypto/crypto_layer2.c \
          src/crypto/crypto_layer3.c \
          src/crypto/crypto_layer4.c \
          src/crypto/pqc_handshake.c \
          src/crypto/pqc_l2_handshake.c \
          src/crypto/pqc_logger.c \
          src/crypto/pqc_ipc.c \
          src/core/flow_table.c \
          src/core/fragment.c
APP_OBJ = $(APP_SRC:.c=.o)

DB_SRC = src/db/config.c \
         src/db/db_config.c \
         src/db/db_env.c \
         src/db/db_runtime.c
DB_OBJ = $(DB_SRC:.c=.o)

BPF_OBJ = $(LIB_DIR)/lan.o \
          $(LIB_DIR)/wan.o

.PHONY: all clean dirs

all: dirs $(BPF_OBJ) $(TARGET)

$(TARGET): $(APP_OBJ) $(DB_OBJ)
	$(CC) -o $@ $(APP_OBJ) $(DB_OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB_DIR)/%.o: bpf/%.c
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) -I./include -c $< -o $@

clean:
	rm -rf network-encryptor src/*.o src/core/*.o src/crypto/*.o src/db/*.o *.o $(BPF_OBJ)
