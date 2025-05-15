use clap::Parser;
use futures::stream::StreamExt;
use quiche_apps::async_http3_server::service_fn;
use quiche_apps::async_http3_server::Args;
use quiche_apps::async_http3_server::Server;
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
async fn main() -> Result<()> {
    env_logger::builder().format_timestamp_nanos().init();

    // Create listening socket. Note that we use `ConnectionParams::new_server()`
    // to denote that we're creating a server.
    let args = Args::parse();
    let socket = UdpSocket::bind(&args.address)
        .await
        .expect("couldn't bind udp socket");
    let mut listeners = listen(
        [socket],
        ConnectionParams::new_server(
            QuicSettings::default(),
            TlsCertificatePaths {
                cert: &args.tls_cert_path,
                private_key: &args.tls_private_key_path,
                kind: CertificateKind::X509,
            },
            Hooks::default(),
        ),
        SimpleConnectionIdGenerator,
        DefaultMetrics,
    )?;

    // Pull connections off the socket and serve them.
    let accepted_connection_stream = &mut listeners[0];
    while let Some(conn) = accepted_connection_stream.next().await {
        log::info!("received new connection!");

        // Create an `H3Driver` to serve the connection.
        let (driver, mut controller) =
            ServerH3Driver::new(Http3Settings::default());

        // Start the driver. This will execute the handshake under the hood, which
        // lets us start receiving ServerH3Events without needing to do
        // anything extra after this future resolves.
        conn?.start(driver);

        // Spawn a task to process the new connection.
        tokio::spawn(async move {
            let mut server = Server::new(service_fn);

            let _ = server
                .serve_connection(controller.event_receiver_mut())
                .await;
        });
    }

    Ok(())
}
