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

/// Returns true if cargo resolved `boring` to a 5.x version.
///
/// Walks up from `OUT_DIR` looking for a `Cargo.lock`, then scans it
/// for the `boring` package. We use `Cargo.lock` rather than shelling
/// out to `cargo metadata` because (a) the lockfile is guaranteed to
/// exist at this point in the build, (b) parsing it is cheap and has
/// no extra dependencies, and (c) it avoids re-entering cargo from a
/// build script.
///
/// 4.x is the *default* branch (assumed when the lockfile is missing
/// or unparseable); `cfg(boring_v5)` opts into 5.x-specific code
/// paths. New non-version-specific code should live in the
/// `not(boring_v5)` arm — i.e. compile under the default 4.x — so
/// the cfg can be flipped to the forward-looking side later without
/// churn.
fn detect_boring_v5() -> bool {
    let Some(lockfile) = find_cargo_lock() else {
        // No lockfile (shouldn't happen in normal cargo builds, but
        // be conservative). Assume 4.x — the default. Downstream can
        // fix this by generating a lockfile (`cargo generate-lockfile`).
        println!(
            "cargo:warning=quiche: Cargo.lock not found; assuming boring 4.x"
        );
        return false;
    };

    println!("cargo:rerun-if-changed={}", lockfile.display());

    let contents = match std::fs::read_to_string(&lockfile) {
        Ok(s) => s,
        Err(e) => {
            println!(
                "cargo:warning=quiche: failed to read {}: {e}; assuming boring 4.x",
                lockfile.display(),
            );
            return false;
        },
    };

    // The lockfile is TOML but a regex-light scan is enough: find a
    // `[[package]]` whose `name = "boring"` (not "boring-sys") and
    // read its `version`.
    let mut in_boring = false;
    for line in contents.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            in_boring = false;
            continue;
        }
        if line == "name = \"boring\"" {
            in_boring = true;
            continue;
        }
        if in_boring {
            if let Some(rest) = line.strip_prefix("version = \"") {
                let version = rest.trim_end_matches('"');
                let major = version.split('.').next().unwrap_or("");
                return major == "5";
            }
        }
    }

    // `boring` not present in the lockfile (e.g.
    // `boringssl-boring-crate` is off). Doesn't matter what we return
    // since the `cfg` won't be observed.
    false
}

fn find_cargo_lock() -> Option<std::path::PathBuf> {
    // Start from `CARGO_MANIFEST_DIR` and walk up. Cargo guarantees
    // the lockfile lives at the workspace root, which is an ancestor
    // of the manifest dir.
    let manifest_dir =
        std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR")?);
    for dir in manifest_dir.ancestors() {
        let candidate = dir.join("Cargo.lock");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
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
    // Emit `cfg(boring_v5)` if boring version 5.x is detected. This is used to
    // pick which APIs to expect and to guide test expectations. (Larger post
    // quantum key shares are enabled by default in boring 5.x but not boring
    // 4.x.) 4.x is the assumed default.
    //
    // The cfg is always registered (even when the backend feature is
    // off) so rustc doesn't warn about unknown cfg names.
    println!("cargo::rustc-check-cfg=cfg(boring_v5)");
    if cfg!(feature = "boringssl-boring-crate") {
        if detect_boring_v5() {
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
