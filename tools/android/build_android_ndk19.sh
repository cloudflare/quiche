#!/bin/sh
#
# Build quiche for Android NDK 19 or higher
#
# ANDROID_NDK_HOME : android ndk location
# TOOLCHAIN_DIR : where create a toolchain (optional)
#
set -eu

# Change this value if you need a different API level
# 21 is the minimum API tested
API_LEVEL=21

if [ ! -d "${ANDROID_NDK_HOME-}" ]; then
    ANDROID_NDK_HOME=/usr/local/share/android-ndk
fi

if [ ! -d "${TOOLCHAIN_DIR-}" ]; then
    TOOLCHAIN_DIR=$(pwd)
fi

echo "> building quiche for android API $API_LEVEL..."

for arch in arm64-v8a armeabi-v7a x86_64 x86
do
    echo "> building $arch..."

    cargo ndk -t $arch -p $API_LEVEL -- build --features ffi $*
done
