// Additional parameters for Android build of BoringSSL.
//
// Requires Android NDK >= 19.
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
    if cfg!(target_env = "msvc") {
        // Code under this branch should match the logic in cmake-rs
        let debug_env_var =
            std::env::var("DEBUG").expect("DEBUG variable not defined in env");

        let deb_info = match &debug_env_var[..] {
            "false" => false,
            "true" => true,
            unknown => panic!("Unknown DEBUG={unknown} env var."),
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
            unknown => panic!("Unknown OPT_LEVEL={unknown} env var."),
        };

        subdir.to_string()
    } else {
        "".to_string()
    }
}

/// Returns a new cmake::Config for building BoringSSL.
///
/// It will add platform-specific parameters if needed.
fn get_boringssl_cmake_config<P: AsRef<std::path::Path>>(
    src: P,
) -> cmake::Config {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    let pwd = std::env::current_dir().unwrap();

    let mut boringssl_cmake = cmake::Config::new(src);

    // Add platform-specific parameters.
    match os.as_ref() {
        "android" => {
            // We need ANDROID_NDK_HOME to be set properly.
            let android_ndk_home = std::env::var("ANDROID_NDK_HOME")
                .expect("Please set ANDROID_NDK_HOME for Android build");
            let android_ndk_home = std::path::Path::new(&android_ndk_home);
            for (android_arch, params) in CMAKE_PARAMS_ANDROID_NDK {
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

            let cflag = format!("{bitcode_cflag} {target_cflag}");

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

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let target_dir = target_dir_path();

    let out_path = target_dir.as_path().join("quiche.pc");
    let mut out_file = std::fs::File::create(out_path).unwrap();

    let include_dir = format!("{manifest_dir}/include");

    let version = std::env::var("CARGO_PKG_VERSION").unwrap();

    let output = format!(
        "# quiche

includedir={include_dir}
libdir={}

Name: quiche
Description: quiche library
URL: https://github.com/cloudflare/quiche
Version: {version}
Libs: -Wl,-rpath,${{libdir}} -L${{libdir}} -lquiche
Cflags: -I${{includedir}}
",
        target_dir.to_str().unwrap(),
    );

    out_file.write_all(output.as_bytes()).unwrap();
}

fn target_dir_path() -> std::path::PathBuf {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_dir = std::path::Path::new(&out_dir);

    for p in out_dir.ancestors() {
        if p.ends_with("build") {
            return p.parent().unwrap().to_path_buf();
        }
    }

    unreachable!();
}

/// Copies `deps/boringssl` to a scratch directory under `$OUT_DIR` and
/// applies `patches/boring-pq.patch` on top. Returns the path to the
/// patched copy, suitable to pass to `cmake::Config::new`.
///
/// The copy is cached across builds: if the scratch directory already
/// contains a sentinel file recording the submodule HEAD and patch
/// contents, the copy is skipped.
fn prepare_patched_boringssl() -> std::path::PathBuf {
    use std::path::Path;
    use std::path::PathBuf;

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest_dir = Path::new(&manifest_dir);
    let src = manifest_dir.join("deps/boringssl");
    let patch = manifest_dir.join("patches/boring-pq.patch");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let patched = PathBuf::from(&out_dir).join("boringssl-patched");
    let sentinel = patched.join(".quiche-pq-patch-applied");

    // Re-run build.rs if either the patch file or the submodule HEAD
    // changes. `HEAD` of a submodule is the contents of
    // `.git/modules/.../HEAD` in the superproject, which we can't easily
    // reference. `deps/boringssl/.git` is a gitlink file pointing into the
    // superproject's .git/modules/... so rerun on that.
    println!("cargo:rerun-if-changed={}", patch.display());
    let gitlink = src.join(".git");
    if gitlink.exists() {
        println!("cargo:rerun-if-changed={}", gitlink.display());
    }

    // Compute a sentinel value that identifies this (source, patch) pair.
    // We don't need cryptographic strength; a cheap hash of the patch
    // contents plus the gitlink contents is enough to detect changes.
    use std::hash::Hasher;
    let patch_bytes = std::fs::read(&patch)
        .unwrap_or_else(|e| panic!("reading {}: {e}", patch.display()));
    let gitlink_bytes = std::fs::read(&gitlink).unwrap_or_default();
    let mut hasher = std::hash::DefaultHasher::new();
    hasher.write(&patch_bytes);
    let sentinel_contents = format!(
        "patch_len={} patch_hash={:x} gitlink={}",
        patch_bytes.len(),
        hasher.finish(),
        String::from_utf8_lossy(&gitlink_bytes).trim(),
    );

    if let Ok(existing) = std::fs::read_to_string(&sentinel) {
        if existing == sentinel_contents {
            return patched;
        }
    }

    // Stale or missing: rebuild the patched tree from scratch.
    if patched.exists() {
        std::fs::remove_dir_all(&patched)
            .unwrap_or_else(|e| panic!("cleaning {}: {e}", patched.display()));
    }
    copy_dir_recursive(&src, &patched);

    // Initialize a fresh git repo in the copied tree. Without this, `git
    // apply` walks up to the nearest ancestor `.git` (here, the quiche
    // repo itself) and refuses to modify files that fall under that
    // repo's `.gitignore` (e.g. `target/`). Same trick as `boring-sys`.
    let init = std::process::Command::new("git")
        .arg("init")
        .arg("--quiet")
        .current_dir(&patched)
        .output()
        .expect("running `git init` for patched BoringSSL copy");
    if !init.status.success() {
        panic!(
            "`git init` failed in {}:\n{}",
            patched.display(),
            String::from_utf8_lossy(&init.stderr)
        );
    }

    let out = std::process::Command::new("git")
        .arg("apply")
        .arg("--verbose")
        .arg(&patch)
        .current_dir(&patched)
        .output()
        .expect("running `git apply` for boring-pq.patch");
    if !out.status.success() {
        panic!(
            "failed to apply {} to {}\nstdout:\n{}\nstderr:\n{}",
            patch.display(),
            patched.display(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }

    std::fs::write(&sentinel, sentinel_contents)
        .unwrap_or_else(|e| panic!("writing {}: {e}", sentinel.display()));
    patched
}

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) {
    std::fs::create_dir_all(dst)
        .unwrap_or_else(|e| panic!("mkdir {}: {e}", dst.display()));
    for entry in std::fs::read_dir(src)
        .unwrap_or_else(|e| panic!("readdir {}: {e}", src.display()))
    {
        let entry = entry.expect("readdir entry");
        // Skip git metadata: submodules expose a `.git` gitlink file that
        // would confuse `git apply` if copied over.
        if entry.file_name() == ".git" || entry.file_name() == ".gitignore" {
            continue;
        }
        let ty = entry.file_type().expect("file_type");
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&src_path, &dst_path);
        } else {
            // `std::fs::copy` dereferences symlinks to regular files;
            // BoringSSL's source tree doesn't rely on in-tree symlinks.
            std::fs::copy(&src_path, &dst_path).unwrap_or_else(|e| {
                panic!(
                    "copy {} -> {}: {e}",
                    src_path.display(),
                    dst_path.display()
                )
            });
        }
    }
}

fn main() {
    if cfg!(feature = "boringssl-vendored") &&
        !cfg!(feature = "boringssl-boring-crate") &&
        !cfg!(feature = "openssl")
    {
        // Select the BoringSSL source tree. When the `boringssl-pq-patch`
        // feature is on, we copy the pristine submodule to `$OUT_DIR`,
        // apply `boring-pq.patch`, and build from the copy. Otherwise we
        // build directly from the submodule.
        let bssl_src: std::path::PathBuf = if cfg!(feature = "boringssl-pq-patch")
        {
            prepare_patched_boringssl()
        } else {
            "deps/boringssl".into()
        };

        let bssl_dir = std::env::var("QUICHE_BSSL_PATH").unwrap_or_else(|_| {
            let mut cfg = get_boringssl_cmake_config(&bssl_src);

            if cfg!(feature = "fuzzing") {
                cfg.cxxflag("-DBORINGSSL_UNSAFE_DETERMINISTIC_MODE")
                    .cxxflag("-DBORINGSSL_UNSAFE_FUZZER_MODE");
                cfg.cflag("-DBORINGSSL_UNSAFE_DETERMINISTIC_MODE")
                    .cflag("-DBORINGSSL_UNSAFE_FUZZER_MODE");
            }

            cfg.build_target("ssl").build();
            cfg.build_target("crypto").build().display().to_string()
        });

        println!("cargo:rustc-link-arg=-Wl,-rpath,{bssl_dir}");

        let build_path = get_boringssl_platform_output_path();
        let mut build_dir = format!("{bssl_dir}/build/{build_path}");

        // If build directory doesn't exist, use the specified path as is.
        if !std::path::Path::new(&build_dir).is_dir() {
            build_dir = bssl_dir;
        }

        println!("cargo:rustc-link-search=native={build_dir}");

        let bssl_link_kind = std::env::var("QUICHE_BSSL_LINK_KIND")
            .unwrap_or("static".to_string());
        println!("cargo:rustc-link-lib={bssl_link_kind}=ssl");
        println!("cargo:rustc-link-lib={bssl_link_kind}=crypto");

        // Recent BoringSSL revisions use the C++ standard library (exceptions,
        // `operator new`/`delete`, etc.), so the final binary needs to link a
        // C++ runtime. cmake's `ssl`/`crypto` static archives don't carry this
        // dependency themselves.
        let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
        let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap();
        let target_family = std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap();
        let cxx_stdlib = match target_os.as_str() {
            "macos" | "ios" | "freebsd" | "openbsd" | "android" => Some("c++"),
            _ if target_family == "unix" || target_env == "gnu" => Some("stdc++"),
            _ => None,
        };
        if let Some(lib) = cxx_stdlib {
            println!("cargo:rustc-link-lib={lib}");
        }
    }

    if cfg!(feature = "boringssl-boring-crate") {
        println!("cargo:rustc-link-lib=static=ssl");
        println!("cargo:rustc-link-lib=static=crypto");
    }

    // MacOS: Allow cdylib to link with undefined symbols
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os == "macos" {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-undefined,dynamic_lookup");
    }

    #[cfg(feature = "openssl")]
    {
        let pkgcfg = pkg_config::Config::new();

        if pkgcfg.probe("libcrypto").is_err() {
            panic!("no libcrypto found");
        }

        if pkgcfg.probe("libssl").is_err() {
            panic!("no libssl found");
        }
    }

    if cfg!(feature = "pkg-config-meta") {
        write_pkg_config();
    }

    #[cfg(feature = "ffi")]
    if target_os != "windows" {
        cdylib_link_lines::metabuild();
    }
}
