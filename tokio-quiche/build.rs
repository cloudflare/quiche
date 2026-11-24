fn main() {
    // Emit `cfg(boring_v5)` if boring version 5.x is detected. This
    // is used to pick which APIs to expect and to guide test
    // expectations. (Larger post-quantum key shares are enabled by
    // default in boring 5.x but not boring 4.x.) 4.x is the assumed
    // default. Mirrors `quiche/src/build.rs`.
    //
    // `boring-sys` >= 5.2 emits `cargo:version_major=<N>` from its
    // build script, which cargo surfaces here as
    // `DEP_BORINGSSL_VERSION_MAJOR`. When absent (boring-sys < 5.2)
    // we assume 4.x.
    println!("cargo::rustc-check-cfg=cfg(boring_v5)");
    if std::env::var("DEP_BORINGSSL_VERSION_MAJOR").ok().as_deref() == Some("5") {
        println!("cargo:rustc-cfg=boring_v5");
    }

    // Emit `cfg(apple_fast)` for a macOS target built with the
    // `fast-apple-datapath` feature.
    println!("cargo::rustc-check-cfg=cfg(apple_fast)");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") &&
        std::env::var_os("CARGO_FEATURE_FAST_APPLE_DATAPATH").is_some()
    {
        println!("cargo:rustc-cfg=apple_fast");
    }
}
