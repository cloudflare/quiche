use cmake;

/// Generate the platform-specific output path for lib
///
/// MSVC generator on Windows place static libs in a target sub-folder,
/// so adjust library location based on platform and build target.
/// See issue: https://github.com/alexcrichton/cmake-rs/issues/18
fn platform_output_path(lib: &str) -> String {
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

fn main() {
    #[cfg(feature = "no_bssl")]
    return;

    let bssl_dir = std::env::var("QUICHE_BSSL_PATH").unwrap_or_else(|_| {
        cmake::Config::new("deps/boringssl")
            .cflag("-fPIC")
            .build_target("bssl")
            .build()
            .display()
            .to_string()
    });

    let crypto_dir =
        format!("{}/build/{}", bssl_dir, platform_output_path("crypto"));
    println!("cargo:rustc-link-search=native={}", crypto_dir);
    println!("cargo:rustc-link-lib=static=crypto");

    let ssl_dir = format!("{}/build/{}", bssl_dir, platform_output_path("ssl"));
    println!("cargo:rustc-link-search=native={}", ssl_dir);
    println!("cargo:rustc-link-lib=static=ssl");
}
