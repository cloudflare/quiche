use std::process::Command;

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let bssl_dir_default = format!("{}/.openssl/lib", out_dir);
    let bssl_dir = std::env::var("QUICHE_BSSL_PATH").unwrap_or(bssl_dir_default);

    if std::env::var_os("QUICHE_BSSL_PATH").is_none() {
        let out = Command::new("util/build_bssl.sh").output().unwrap();

        if !out.status.success() {
            panic!("failed to build BoringSSL: \nstdout\n{}\nstderr\n{}",
                   std::str::from_utf8(&out.stdout).unwrap(),
                   std::str::from_utf8(&out.stderr).unwrap());
        }
    }

    println!("cargo:rustc-link-search=native={}", bssl_dir);
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=ssl");
}
