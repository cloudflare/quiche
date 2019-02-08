OS := $(shell uname)

SOURCE_DIR = ../src
BUILD_DIR = ../target/debug
INCLUDE_DIR = ../include

CFLAGS = -I. -Wall -pedantic -fsanitize=address

ifeq ($(OS), Darwin)
CFLAGS += -framework Security
endif

LIBCRYPTO_DIR = $(dir $(shell find ${BUILD_DIR} -name libcrypto.a))
LIBSSL_DIR = $(dir $(shell find ${BUILD_DIR} -name libssl.a))

LDFLAGS = -L$(LIBCRYPTO_DIR) -L$(LIBSSL_DIR) -L$(BUILD_DIR)

LIBS = -lcrypto -lssl -lquiche -lev -ldl -pthread

all: client server

client: client.c $(INCLUDE_DIR)/quiche.h $(BUILD_DIR)/libquiche.a
	cc $(CFLAGS) $(LDFLAGS) $< -o $@ -I$(INCLUDE_DIR) $(LIBS)

server: server.c $(INCLUDE_DIR)/quiche.h $(BUILD_DIR)/libquiche.a
	cc $(CFLAGS) $(LDFLAGS) $< -o $@ -I$(INCLUDE_DIR) $(LIBS)

$(BUILD_DIR)/libquiche.a: $(SOURCE_DIR)/*.rs
	cd .. && cargo build
