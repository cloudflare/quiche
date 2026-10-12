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

fn main() {
    // Emit `cfg(boring_v5)` if boring version 5.x is detected. This
    // is used to pick which APIs to expect and to guide test
    // expectations. (Larger post-quantum key shares are enabled by
    // default in boring 5.x but not boring 4.x.) 4.x is the assumed
    // default.
    //
    // `boring-sys` >= 5.2 emits `cargo:version_major=<N>` from its
    // build script, which cargo surfaces here as
    // `DEP_BORINGSSL_VERSION_MAJOR`. When absent (boring-sys < 5.2,
    // or the `boringssl-boring-crate` feature is off) we assume 4.x.
    //
    // The cfg is always registered (even when the backend feature is
    // off) so rustc doesn't warn about unknown cfg names.
    println!("cargo::rustc-check-cfg=cfg(boring_v5)");
    if cfg!(feature = "boringssl-boring-crate") {
        if std::env::var("DEP_BORINGSSL_VERSION_MAJOR").ok().as_deref() ==
            Some("5")
        {
            println!("cargo:rustc-cfg=boring_v5");
        }
        println!("cargo:rustc-link-lib=static=ssl");
        println!("cargo:rustc-link-lib=static=crypto");
    }

    // MacOS: Allow cdylib to link with undefined symbols
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os == "macos" {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-undefined,dynamic_lookup");
    }

    if cfg!(feature = "pkg-config-meta") {
        write_pkg_config();
    }

    #[cfg(feature = "ffi")]
    if target_os != "windows" {
        cdylib_link_lines::metabuild();
    }
}
