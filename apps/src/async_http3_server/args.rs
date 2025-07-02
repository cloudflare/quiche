use clap::arg;
use clap::command;
use clap::Parser;

/// Args for setting up an example tokio-quiche server.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// The address for the server to listen on.
    #[arg(short, long)]
    pub address: String,

    /// Path for the TLS certificate.
    #[arg(long, default_value_t = default_cert_path())]
    pub tls_cert_path: String,

    /// Path for the TLS private key.
    #[arg(long, default_value_t = default_private_key_path())]
    pub tls_private_key_path: String,
}

fn default_cert_path() -> String {
    path_relative_to_manifest_dir("src/bin/cert.crt")
}

fn default_private_key_path() -> String {
    path_relative_to_manifest_dir("src/bin/cert.key")
}

fn path_relative_to_manifest_dir(path: &str) -> String {
    std::fs::canonicalize(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path),
    )
    .unwrap()
    .to_string_lossy()
    .into_owned()
}
