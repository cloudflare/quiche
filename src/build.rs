use cmake;

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

    let crypto_dir = format!("{}/build/crypto", bssl_dir);
    println!("cargo:rustc-link-search=native={}", crypto_dir);
    println!("cargo:rustc-link-lib=static=crypto");

    let ssl_dir = format!("{}/build/ssl", bssl_dir);
    println!("cargo:rustc-link-search=native={}", ssl_dir);
    println!("cargo:rustc-link-lib=static=ssl");
}
