#!/bin/sh
#
# Build quiche for Android
#
# ANDROID_NDK_HOME : android ndk location
# TOOLCHAIN_DIR : where create a toolchain (optional)
#
set -eu

if [ ! -d "${ANDROID_NDK_HOME-}" ]; then
    ANDROID_NDK_HOME=/usr/local/share/android-ndk
fi

if [ ! -d "${TOOLCHAIN_DIR-}" ]; then
    TOOLCHAIN_DIR=$(pwd)
fi

echo "> building quiche for android..."

PATH="${TOOLCHAIN_DIR}/arch/arm64/bin":"${TOOLCHAIN_DIR}/arch/arm/bin":"${TOOLCHAIN_DIR}/arch/x86/bin":${PATH}

for target in aarch64-linux-android arm-linux-androideabi armv7-linux-androideabi i686-linux-android
do
    echo "> target $target..."
    cargo build --target $target $*
done
