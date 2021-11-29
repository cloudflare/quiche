OS := $(shell uname)

SOURCE_DIR = ../src
BUILD_DIR = $(CURDIR)/build
LIB_DIR = $(BUILD_DIR)/debug
INCLUDE_DIR = ../include

INCS = -I$(INCLUDE_DIR)
CFLAGS = -I. -Wall -Werror -pedantic -fsanitize=address -g

ifeq ($(OS), Darwin)
CFLAGS += -framework Security
endif

LIBCRYPTO_DIR = $(dir $(shell find ${BUILD_DIR} -name libcrypto.a))
LIBSSL_DIR = $(dir $(shell find ${BUILD_DIR} -name libssl.a))

LDFLAGS = -L$(LIBCRYPTO_DIR) -L$(LIBSSL_DIR) -L$(LIB_DIR)

LIBS = $(LIB_DIR)/libquiche.a -lev -ldl -pthread -lm

all: client server http3-client http3-server

client: client.c $(INCLUDE_DIR)/quiche.h $(LIB_DIR)/libquiche.a
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(INCS) $(LIBS)

server: server.c $(INCLUDE_DIR)/quiche.h $(LIB_DIR)/libquiche.a
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(INCS) $(LIBS)

http3-client: http3-client.c $(INCLUDE_DIR)/quiche.h $(LIB_DIR)/libquiche.a
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(INCS) $(LIBS)

http3-server: http3-server.c $(INCLUDE_DIR)/quiche.h $(LIB_DIR)/libquiche.a
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(INCS) $(LIBS)

$(LIB_DIR)/libquiche.a: $(shell find $(SOURCE_DIR) -type f -name '*.rs')
	cd .. && cargo build --target-dir $(BUILD_DIR) --features ffi

clean:
	@$(RM) -rf client server http3-client http3-server build/ *.dSYM/
