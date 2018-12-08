#!/bin/sh

set -e

SOURCE_DIR="$PWD/deps/boringssl"
BUILD_DIR="$OUT_DIR/boringssl"
INSTALL_DIR="$OUT_DIR/.openssl"

mkdir -p $BUILD_DIR "$INSTALL_DIR/lib"

cd $BUILD_DIR

cmake -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC" $SOURCE_DIR

make -C $BUILD_DIR VERBOSE=1 -j`nproc` bssl

cp "$BUILD_DIR/crypto/libcrypto.a" "$BUILD_DIR/ssl/libssl.a" "$INSTALL_DIR/lib/"
