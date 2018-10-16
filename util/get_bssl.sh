#!/bin/sh

set -e

REPO="https://boringssl.googlesource.com/boringssl"

GIT_DIR="$PWD/boringssl/.git"

INSTALL_DIR="$PWD/boringssl/.openssl"

if [ ! -d "$GIT_DIR" ]; then
    git clone $REPO

    # https://boringssl-review.googlesource.com/c/boringssl/+/31744
    cd boringssl/
    git fetch $REPO refs/changes/44/31744/4
    git checkout FETCH_HEAD
    cd ..
fi

cd boringssl/

cmake -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC" .

make VERBOSE=1 -j`nproc`

mkdir -p "$INSTALL_DIR/lib"

cp crypto/libcrypto.a ssl/libssl.a "$INSTALL_DIR/lib/"
ln -f -s "$PWD/include" "$INSTALL_DIR"
