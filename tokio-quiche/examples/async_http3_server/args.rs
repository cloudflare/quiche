// Copyright (C) 2025, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
    path_relative_to_manifest_dir("examples/cert.crt")
}

fn default_private_key_path() -> String {
    path_relative_to_manifest_dir("examples/cert.key")
}

fn path_relative_to_manifest_dir(path: &str) -> String {
    match std::fs::canonicalize(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path)) {
        Ok(result) => result.to_string_lossy().into_owned(),
        Err(_) => {
            panic!(
                "Example certificates not found in {}/{}",
                env!("CARGO_MANIFEST_DIR"),
                path
            )
        }
    }
}
