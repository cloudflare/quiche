#!/bin/sh
#
# Setup Android cross compile environment.
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

MK_TOOLCHAIN="${ANDROID_NDK_HOME}/build/tools/make_standalone_toolchain.py"

if [ ! -x "${MK_TOOLCHAIN}" ]; then
    echo "* Please install Android NDK and set ANDROID_NDK_HOME"
    exit 1
fi

make_standalone_toolchain() {
    echo "> Generating toolchain -- arch $1 with api level $2..."
    ${MK_TOOLCHAIN} --arch "$1" --api "$2" --install-dir "${TOOLCHAIN_DIR}/arch/$1"
}

echo "> Android NDK: ${ANDROID_NDK_HOME}"
echo "> Toolchain Directory: ${TOOLCHAIN_DIR}"

mkdir -p ${TOOLCHAIN_DIR}/arch
make_standalone_toolchain arm64 $API_LEVEL
make_standalone_toolchain arm $API_LEVEL
make_standalone_toolchain x86 $API_LEVEL

CARGO_CONFIG=cargo-config.toml
sed 's@$TOOLCHAIN_DIR@'"${TOOLCHAIN_DIR}"'@g' > $CARGO_CONFIG <<CARGO_CONFIG_EOF
[target.aarch64-linux-android]
ar = "$TOOLCHAIN_DIR/arch/arm64/bin/aarch64-linux-android-ar"
linker = "$TOOLCHAIN_DIR/arch/arm64/bin/aarch64-linux-android-clang"

[target.arm-linux-androideabi]
ar = "$TOOLCHAIN_DIR/arch/arm/bin/arm-linux-androideabi-ar"
linker = "$TOOLCHAIN_DIR/arch/arm/bin/arm-linux-androideabi-clang"

[target.armv7-linux-androideabi]
ar = "$TOOLCHAIN_DIR/arch/arm/bin/arm-linux-androideabi-ar"
linker = "$TOOLCHAIN_DIR/arch/arm/bin/arm-linux-androideabi-clang"

[target.i686-linux-android]
ar = "$TOOLCHAIN_DIR/arch/x86/bin/i686-linux-android-ar"
linker = "$TOOLCHAIN_DIR/arch/x86/bin/i686-linux-android-clang"
CARGO_CONFIG_EOF

# setup cargo config
mkdir $(pwd)/.cargo || true
cp -f cargo-config.toml $(pwd)/.cargo/config
echo "> cargo config is installed at $(pwd)/.cargo/config"
