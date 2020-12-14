// Additional parameters for Android build of BoringSSL.
//
// Android NDK < 18 with GCC.
const CMAKE_PARAMS_ANDROID_NDK_OLD_GCC: &[(&str, &[(&str, &str)])] = &[
    ("aarch64", &[(
        "ANDROID_TOOLCHAIN_NAME",
        "aarch64-linux-android-4.9",
    )]),
    ("arm", &[(
        "ANDROID_TOOLCHAIN_NAME",
        "arm-linux-androideabi-4.9",
    )]),
    ("x86", &[(
        "ANDROID_TOOLCHAIN_NAME",
        "x86-linux-android-4.9",
    )]),
    ("x86_64", &[(
        "ANDROID_TOOLCHAIN_NAME",
        "x86_64-linux-android-4.9",
    )]),
];

// Android NDK >= 19.
const CMAKE_PARAMS_ANDROID_NDK: &[(&str, &[(&str, &str)])] = &[
    ("aarch64", &[("ANDROID_ABI", "arm64-v8a")]),
    ("arm", &[("ANDROID_ABI", "armeabi-v7a")]),
    ("x86", &[("ANDROID_ABI", "x86")]),
    ("x86_64", &[("ANDROID_ABI", "x86_64")]),
];

// iOS.
const CMAKE_PARAMS_IOS: &[(&str, &[(&str, &str)])] = &[
    ("aarch64", &[
        ("CMAKE_OSX_ARCHITECTURES", "arm64"),
        ("CMAKE_OSX_SYSROOT", "iphoneos"),
    ]),
    ("x86_64", &[
        ("CMAKE_OSX_ARCHITECTURES", "x86_64"),
        ("CMAKE_OSX_SYSROOT", "iphonesimulator"),
    ]),
];

// ARM Linux.
const CMAKE_PARAMS_ARM_LINUX: &[(&str, &[(&str, &str)])] = &[
    ("aarch64", &[("CMAKE_SYSTEM_PROCESSOR", "aarch64")]),
    ("arm", &[("CMAKE_SYSTEM_PROCESSOR", "arm")]),
];

/// Returns the platform-specific output path for lib.
///
/// MSVC generator on Windows place static libs in a target sub-folder,
/// so adjust library location based on platform and build target.
/// See issue: https://github.com/alexcrichton/cmake-rs/issues/18
fn get_boringssl_platform_output_path() -> String {
    if cfg!(windows) {
        // Code under this branch should match the logic in cmake-rs
        let debug_env_var =
            std::env::var("DEBUG").expect("DEBUG variable not defined in env");

        let deb_info = match &debug_env_var[..] {
            "false" => false,
            "true" => true,
            unknown => panic!("Unknown DEBUG={} env var.", unknown),
        };

        let opt_env_var = std::env::var("OPT_LEVEL")
            .expect("OPT_LEVEL variable not defined in env");

        let subdir = match &opt_env_var[..] {
            "0" => "Debug",
            "1" | "2" | "3" =>
                if deb_info {
                    "RelWithDebInfo"
                } else {
                    "Release"
                },
            "s" | "z" => "MinSizeRel",
            unknown => panic!("Unknown OPT_LEVEL={} env var.", unknown),
        };

        subdir.to_string()
    } else {
        "".to_string()
    }
}

/// Returns a new cmake::Config for building BoringSSL.
///
/// It will add platform-specific parameters if needed.
fn get_boringssl_cmake_config() -> cmake::Config {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    let pwd = std::env::current_dir().unwrap();

    let mut boringssl_cmake = cmake::Config::new("deps/boringssl");

    // Add platform-specific parameters.
    match os.as_ref() {
        "android" => {
            let cmake_params_android = if cfg!(feature = "ndk-old-gcc") {
                CMAKE_PARAMS_ANDROID_NDK_OLD_GCC
            } else {
                CMAKE_PARAMS_ANDROID_NDK
            };

            // We need ANDROID_NDK_HOME to be set properly.
            let android_ndk_home = std::env::var("ANDROID_NDK_HOME")
                .expect("Please set ANDROID_NDK_HOME for Android build");
            let android_ndk_home = std::path::Path::new(&android_ndk_home);
            for (android_arch, params) in cmake_params_android {
                if *android_arch == arch {
                    for (name, value) in *params {
                        boringssl_cmake.define(name, value);
                    }
                }
            }
            let toolchain_file =
                android_ndk_home.join("build/cmake/android.toolchain.cmake");
            let toolchain_file = toolchain_file.to_str().unwrap();
            boringssl_cmake.define("CMAKE_TOOLCHAIN_FILE", toolchain_file);

            // 21 is the minimum level tested. You can give higher value.
            boringssl_cmake.define("ANDROID_NATIVE_API_LEVEL", "21");
            boringssl_cmake.define("ANDROID_STL", "c++_shared");

            boringssl_cmake
        },

        "ios" => {
            for (ios_arch, params) in CMAKE_PARAMS_IOS {
                if *ios_arch == arch {
                    for (name, value) in *params {
                        boringssl_cmake.define(name, value);
                    }
                }
            }

            // Bitcode is always on.
            let bitcode_cflag = "-fembed-bitcode";

            // Hack for Xcode 10.1.
            let target_cflag = if arch == "x86_64" {
                "-target x86_64-apple-ios-simulator"
            } else {
                ""
            };

            let cflag = format!("{} {}", bitcode_cflag, target_cflag);

            boringssl_cmake.define("CMAKE_ASM_FLAGS", &cflag);
            boringssl_cmake.cflag(&cflag);

            boringssl_cmake
        },

        "linux" => match arch.as_ref() {
            "aarch64" | "arm" => {
                for (arm_arch, params) in CMAKE_PARAMS_ARM_LINUX {
                    if *arm_arch == arch {
                        for (name, value) in *params {
                            boringssl_cmake.define(name, value);
                        }
                    }
                }
                boringssl_cmake.define("CMAKE_SYSTEM_NAME", "Linux");
                boringssl_cmake.define("CMAKE_SYSTEM_VERSION", "1");

                boringssl_cmake
            },

            "x86" => {
                boringssl_cmake.define(
                    "CMAKE_TOOLCHAIN_FILE",
                    pwd.join("deps/boringssl/src/util/32-bit-toolchain.cmake")
                        .as_os_str(),
                );

                boringssl_cmake
            },

            _ => boringssl_cmake,
        },

        _ => {
            // Configure BoringSSL for building on 32-bit non-windows platforms.
            if arch == "x86" && os != "windows" {
                boringssl_cmake.define(
                    "CMAKE_TOOLCHAIN_FILE",
                    pwd.join("deps/boringssl/src/util/32-bit-toolchain.cmake")
                        .as_os_str(),
                );
            }

            boringssl_cmake
        },
    }
}

fn write_pkg_config() {
    use std::io::prelude::*;

    let profile = std::env::var("PROFILE").unwrap();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let target_dir = format!("{}/target/{}", manifest_dir, profile);

    let out_path = std::path::Path::new(&target_dir).join("quiche.pc");
    let mut out_file = std::fs::File::create(&out_path).unwrap();

    let include_dir = format!("{}/include", manifest_dir);
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();

    let output = format!(
        "# quiche

includedir={}
libdir={}

Name: quiche
Description: quiche library
URL: https://github.com/cloudflare/quiche
Version: {}
Libs: -Wl,-rpath,${{libdir}} -L${{libdir}} -lquiche
Cflags: -I${{includedir}}
",
        include_dir, target_dir, version
    );

    out_file.write_all(output.as_bytes()).unwrap();
}

fn main() {
    if cfg!(feature = "boringssl-vendored") && !cfg!(feature = "boring-sys") {
        let bssl_dir = std::env::var("QUICHE_BSSL_PATH").unwrap_or_else(|_| {
            let mut cfg = get_boringssl_cmake_config();

            if cfg!(feature = "fuzzing") {
                cfg.cxxflag("-DBORINGSSL_UNSAFE_DETERMINISTIC_MODE")
                    .cxxflag("-DBORINGSSL_UNSAFE_FUZZER_MODE");
            }

            cfg.build_target("bssl").build().display().to_string()
        });

        let build_path = get_boringssl_platform_output_path();
        let build_dir = format!("{}/build/{}", bssl_dir, build_path);
        println!("cargo:rustc-link-search=native={}", build_dir);

        println!("cargo:rustc-link-lib=static=crypto");
        println!("cargo:rustc-link-lib=static=ssl");
    }

    if cfg!(feature = "boring-sys") {
        println!("cargo:rustc-link-lib=static=crypto");
        println!("cargo:rustc-link-lib=static=ssl");
    }

    // MacOS: Allow cdylib to link with undefined symbols
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-undefined,dynamic_lookup");
    }

    if cfg!(feature = "pkg-config-meta") {
        write_pkg_config();
    }
}
