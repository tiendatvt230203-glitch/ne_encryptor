CC     = gcc
CLANG  = clang

CFLAGS = -D_GNU_SOURCE -I. -Iinc -Iinc/core -Iinc/crypto -Iinc/db -I./include -Isrc/crypto/pqc/include -Wall -O2 -mcmodel=medium $(shell pg_config --includedir 2>/dev/null | xargs -I{} echo -I{})
LDFLAGS = -L./lib -Wl,-rpath,'$$ORIGIN/lib' -lxdp -lbpf -lelf -lz -lpthread -lssl -lcrypto -lpq -lscrypt
# LDFLAGS = -L./lib -Wl,-rpath,'lib' -lxdp -lbpf -lelf -lz -lpthread -lssl -lcrypto -lpq -lscrypt

BPF_CFLAGS     = -O2 -target bpf -g
KERNEL_HEADERS = /usr/include

LIB_DIR = lib
TARGET  = network-encryptor

OPT_SRCS = $(wildcard src/crypto/options/common/*.c) \
           $(wildcard src/crypto/options/l2/*/*.c) \
           $(wildcard src/crypto/options/l3/*/*.c) \
           $(wildcard src/crypto/options/l4/*/*.c) \
           src/crypto/options/bypass.c

PQC_SRCS = $(wildcard src/crypto/pqc/*.c)

CORE_SRCS = $(wildcard src/core/forwarder/*.c) \
            $(wildcard src/core/dataplane/*.c) \
            $(wildcard src/core/iface/*.c) \
            $(wildcard src/core/flow/*.c) \
            $(wildcard src/core/util/*.c)

CRYPTO_COMMON_SRCS = $(wildcard src/crypto/common/*.c)

APP_SRC = main.c \
          $(CORE_SRCS) \
          $(CRYPTO_COMMON_SRCS) \
          $(OPT_SRCS) \
          $(PQC_SRCS)
APP_OBJ = $(APP_SRC:.c=.o)

DB_SRC = src/db/config.c \
         src/db/db_config.c \
         src/db/db_env.c \
         src/db/db_runtime.c
DB_OBJ = $(DB_SRC:.c=.o)

BPF_OBJ = $(LIB_DIR)/lan.o \
          $(LIB_DIR)/wan.o

# Copy one soname from system into ./lib (real file + symlink).
define copy_lib_so
	@src=$$(ldconfig -p 2>/dev/null | awk '$$1 == "$(1)" { print $$NF; exit }'); \
	if [ -n "$$src" ] && [ -f "$$src" ]; then \
		real=$$(readlink -f "$$src"); base=$$(basename "$$real"); \
		cp -f "$$real" $(LIB_DIR)/$$base; \
		ln -sfn $$base $(LIB_DIR)/$(1); \
		echo "[lib] $(1) -> $$base"; \
	fi
endef

.PHONY: all clean dirs

all: dirs $(BPF_OBJ) $(TARGET)

dirs:
	mkdir -p $(LIB_DIR)

$(TARGET): $(APP_OBJ) $(DB_OBJ)
	$(CC) -o $@ $(APP_OBJ) $(DB_OBJ) $(LDFLAGS)
	# -rpath=$ORIGIN/lib: binary chỉ ưu tiên ./lib — phải có đủ .so trong đó
	$(call copy_lib_so,libbpf.so.1)
	$(call copy_lib_so,libelf.so.1)
	$(call copy_lib_so,libz.so.1)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB_DIR)/%.o: bpf/%.c
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) -I./include -c $< -o $@

clean:
	rm -rf network-encryptor src/*.o src/core/*/*.o src/crypto/common/*.o \
		src/crypto/options/*.o src/crypto/options/common/*.o \
		src/crypto/options/l2/*/*.o src/crypto/options/l3/*/*.o \
		src/crypto/options/l4/*/*.o src/crypto/pqc/*.o src/db/*.o *.o $(BPF_OBJ)
