# How to build quiche for Android

To get android build, you need the following:

- Android NDK (13b or higher), using Android Studio or install it directly
- Set `ANDROID_NDK_HOME` environment variable to NDK path. For example when using bash,

```
export ANDROID_NDK_HOME=/usr/local/share/android-ndk
```

- Install android architectures for rust

```
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android
```

Then, to prepare cross compiling chain, run the following command:

```
sh setup_android.sh
```

It will create a standalone toolchain for arm64/arm/x86 architecture under
`$TOOLCHAIN_DIR/arch` directory. If you didn't set `TOOLCHAIN_DIR` environment
variable, current directory will be used. Note that minimum API level is
21 for all target architecture.

When it run successfully, run the following script to build libquiche:

```
sh build_android.sh
```

It will build aarch64, armv7 and i686 binary. You can give a parameter to this
script for cargo build. For example if you want to build a release binary with
more logs, do the following:

```
sh build_android.sh --release -vv
```
