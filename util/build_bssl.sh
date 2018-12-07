#!/bin/sh

set -e

SOURCE_DIR="$PWD/deps/boringssl"
BUILD_DIR="$OUT_DIR/boringssl"
INSTALL_DIR="$OUT_DIR/.openssl"

cmake -S $SOURCE_DIR -B $BUILD_DIR -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC"

make -C $BUILD_DIR VERBOSE=1 -j`nproc` bssl

mkdir -p "$INSTALL_DIR/lib"

cp "$BUILD_DIR/crypto/libcrypto.a" "$BUILD_DIR/ssl/libssl.a" "$INSTALL_DIR/lib/"
ln -f -s "$SOURCE_DIR/include" "$INSTALL_DIR"
