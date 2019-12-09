// Additional parameters for Android build of BoringSSL.
const CMAKE_PARAMS_ANDROID: &[(&str, &[(&str, &str)])] = &[
    ("aarch64", &[
        ("ANDROID_TOOLCHAIN_NAME", "aarch64-linux-android-4.9"),
        ("ANDROID_NATIVE_API_LEVEL", "21"),
        (
            "CMAKE_TOOLCHAIN_FILE",
            "${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake",
        ),
        ("ANDROID_STL", "c++_shared"),
    ]),
    ("arm", &[
        ("ANDROID_TOOLCHAIN_NAME", "arm-linux-androideabi-4.9"),
        ("ANDROID_NATIVE_API_LEVEL", "21"),
        (
            "CMAKE_TOOLCHAIN_FILE",
            "${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake",
        ),
        ("ANDROID_STL", "c++_shared"),
    ]),
    ("x86", &[
        ("ANDROID_TOOLCHAIN_NAME", "x86-linux-android-4.9"),
        ("ANDROID_NATIVE_API_LEVEL", "21"),
        (
            "CMAKE_TOOLCHAIN_FILE",
            "${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake",
        ),
        ("ANDROID_STL", "c++_shared"),
    ]),
    ("x86_64", &[
        ("ANDROID_TOOLCHAIN_NAME", "x86_64-linux-android-4.9"),
        ("ANDROID_NATIVE_API_LEVEL", "21"),
        (
            "CMAKE_TOOLCHAIN_FILE",
            "${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake",
        ),
        ("ANDROID_STL", "c++_shared"),
    ]),
];

const CMAKE_PARAMS_IOS: &[(&str, &[(&str, &str)])] = &[
    ("aarch64", &[
        ("CMAKE_OSX_ARCHITECTURES", "arm64"),
        ("CMAKE_OSX_SYSROOT", "iphoneos"),
    ]),
    ("arm", &[
        ("CMAKE_OSX_ARCHITECTURES", "arm"),
        ("CMAKE_OSX_SYSROOT", "iphoneos"),
    ]),
    ("x86", &[
        ("CMAKE_OSX_ARCHITECTURES", "x86"),
        ("CMAKE_OSX_SYSROOT", "iphonesimulator"),
    ]),
    ("x86_64", &[
        ("CMAKE_OSX_ARCHITECTURES", "x86_64"),
        ("CMAKE_OSX_SYSROOT", "iphonesimulator"),
    ]),
];

/// Returns the platform-specific output path for lib.
///
/// MSVC generator on Windows place static libs in a target sub-folder,
/// so adjust library location based on platform and build target.
/// See issue: https://github.com/alexcrichton/cmake-rs/issues/18
fn get_boringssl_platform_output_path(lib: &str) -> String {
    if cfg!(windows) {
        if cfg!(debug_assertions) {
            return format!("{}/Debug", lib);
        } else {
            return format!("{}/RelWithDebInfo", lib);
        }
    } else {
        return format!("{}", lib);
    };
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
    return match os.as_ref() {
        "android" => {
            // We need ANDROID_NDK_HOME to be set properly.
            let android_ndk_home = std::env::var("ANDROID_NDK_HOME")
                .expect("Please set ANDROID_NDK_HOME for Android build");
            for (android_arch, params) in CMAKE_PARAMS_ANDROID {
                if *android_arch == arch {
                    for (name, value) in *params {
                        let value = value
                            .replace("${ANDROID_NDK_HOME}", &android_ndk_home);
                        eprintln!("android arch={} add {}={}", arch, name, value);
                        boringssl_cmake.define(name, value);
                    }
                }
            }

            boringssl_cmake
        },

        "ios" => {
            for (ios_arch, params) in CMAKE_PARAMS_IOS {
                if *ios_arch == arch {
                    for (name, value) in *params {
                        eprintln!("ios arch={} add {}={}", arch, name, value);
                        boringssl_cmake.define(name, value);
                    }
                }
            }

            // bitcode on
            boringssl_cmake.define("CMAKE_ASM_FLAGS", "-fembed-bitcode");
            boringssl_cmake.cflag("-fembed-bitcode");

            boringssl_cmake
        },

        _ => {
            // Configure BoringSSL for building on 32-bit non-windows platforms.
            if arch == "x86" && os != "windows" {
                boringssl_cmake.define(
                    "CMAKE_TOOLCHAIN_FILE",
                    pwd.join("deps/boringssl/util/32-bit-toolchain.cmake")
                        .as_os_str(),
                );
            }

            boringssl_cmake
        },
    };
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
    if cfg!(feature = "boringssl-vendored") {
        let bssl_dir = std::env::var("QUICHE_BSSL_PATH").unwrap_or_else(|_| {
            let mut cfg = get_boringssl_cmake_config();

            if cfg!(feature = "fuzzing") {
                cfg.cxxflag("-DBORINGSSL_UNSAFE_DETERMINISTIC_MODE")
                    .cxxflag("-DBORINGSSL_UNSAFE_FUZZER_MODE");
            }

            cfg.build_target("bssl").build().display().to_string()
        });

        let crypto_path = get_boringssl_platform_output_path("crypto");
        let crypto_dir = format!("{}/build/{}", bssl_dir, crypto_path);
        println!("cargo:rustc-link-search=native={}", crypto_dir);
        println!("cargo:rustc-link-lib=static=crypto");

        let ssl_path = get_boringssl_platform_output_path("ssl");
        let ssl_dir = format!("{}/build/{}", bssl_dir, ssl_path);
        println!("cargo:rustc-link-search=native={}", ssl_dir);
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
