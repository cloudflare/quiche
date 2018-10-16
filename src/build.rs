use std::env;

fn main() {
    let bssl_dir_default = String::from("./boringssl/.openssl/lib");
    let bssl_dir = env::var("QUICHE_BSSL_PATH").unwrap_or(bssl_dir_default);

    println!("cargo:rustc-link-search=native={}", bssl_dir);
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=ssl");
}
