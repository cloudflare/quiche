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

mod args;
mod body;
mod server;

use crate::args::Args;
use crate::server::service_fn;
use crate::server::Server;
use clap::Parser;
use futures::stream::StreamExt;
use tokio::net::UdpSocket;
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::SimpleConnectionIdGenerator;
use tokio_quiche::settings::CertificateKind::{
    self,
};
use tokio_quiche::settings::Hooks;
use tokio_quiche::settings::QuicSettings;
use tokio_quiche::settings::TlsCertificatePaths;
use tokio_quiche::ConnectionParams;
use tokio_quiche::ServerH3Driver;

#[tokio::main]
async fn main() {
    env_logger::builder().format_timestamp_nanos().init();

    // Create listening socket. Note that we use `ConnectionParams::new_server()`
    // to denote that we're creating a server.
    let args = Args::parse();
    let socket = UdpSocket::bind(&args.address)
        .await
        .expect("UDP socket should be bindable");

    let mut quic_settings = QuicSettings::default();
    quic_settings.cc_algorithm = args.cc_algorithm;

    let mut listeners = listen(
        [socket],
        ConnectionParams::new_server(
            quic_settings,
            TlsCertificatePaths {
                cert: &args.tls_cert_path,
                private_key: &args.tls_private_key_path,
                kind: CertificateKind::X509,
            },
            Hooks::default(),
        ),
        SimpleConnectionIdGenerator,
        DefaultMetrics,
    )
    .expect("should be able to create a listener from a UDP socket");

    // Pull connections off the socket and serve them.
    let accepted_connection_stream = &mut listeners[0];
    while let Some(conn_res) = accepted_connection_stream.next().await {
        match conn_res {
            Ok(conn) => {
                log::info!("received new connection!");

                // Create an `H3Driver` to serve the connection.
                let (driver, mut controller) =
                    ServerH3Driver::new(Http3Settings::default());

                // Start the driver. This will execute the handshake under the
                // hood, which lets us start receiving
                // ServerH3Events without needing to do
                // anything extra after this future resolves.
                conn.start(driver);

                // Spawn a task to process the new connection.
                tokio::spawn(async move {
                    let mut server = Server::new(service_fn);

                    // tokio-quiche will send events to the `H3Controller`'s
                    // receiver for processing.
                    let _ = server
                        .serve_connection(controller.event_receiver_mut())
                        .await;
                });
            },
            Err(e) => {
                log::error!("could not create connection: {e:?}");
            },
        }
    }
}
