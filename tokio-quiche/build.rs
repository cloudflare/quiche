fn main() {
    // Emit `cfg(boring_v4)` if boring version 4.x is detected. This is used to
    // pick which APIs to expect and to guide test expectations. (Larger post
    // quantum key shares are enabled by default in boring 5.x but not boring
    // 4.x.) Mirrors `quiche/src/build.rs`.
    println!("cargo::rustc-check-cfg=cfg(boring_v4)");
    if detect_boring_v4() {
        println!("cargo:rustc-cfg=boring_v4");
    }
}

/// Returns true if cargo resolved `boring` to a 4.x version.
fn detect_boring_v4() -> bool {
    let Some(lockfile) = find_cargo_lock() else {
        println!(
            "cargo:warning=tokio-quiche: Cargo.lock not found; assuming boring 5.x"
        );
        return false;
    };

    println!("cargo:rerun-if-changed={}", lockfile.display());

    let contents = match std::fs::read_to_string(&lockfile) {
        Ok(s) => s,
        Err(e) => {
            println!(
                "cargo:warning=tokio-quiche: failed to read {}: {e}; assuming boring 5.x",
                lockfile.display(),
            );
            return false;
        },
    };

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
                return major == "4";
            }
        }
    }

    false
}

fn find_cargo_lock() -> Option<std::path::PathBuf> {
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
