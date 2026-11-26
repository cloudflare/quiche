fn main() {
    // Emit `cfg(boring_v4)` if boring version 4.x is detected. This
    // is used to pick which APIs to expect and to guide test
    // expectations. (Larger post-quantum key shares are enabled by
    // default in boring 5.x but not boring 4.x.) 5.x is the assumed
    // default. Mirrors `quiche/src/build.rs`.
    //
    // `boring-sys` >= 5.2 emits `cargo:version_major=<N>` from its
    // build script, which cargo surfaces here as
    // `DEP_BORINGSSL_VERSION_MAJOR`. When absent (boring-sys < 5.2)
    // we assume 4.x.
    println!("cargo::rustc-check-cfg=cfg(boring_v4)");
    if std::env::var("DEP_BORINGSSL_VERSION_MAJOR").is_err() {
        println!("cargo:rustc-cfg=boring_v4");
    }
}
