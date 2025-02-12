# Tokio Quiche

Bridging the gap between [quiche][quiche] and [tokio][tokio].

tokio-quiche connects [quiche::Connection][q-connection]s and
[quiche::h3::Connection][q-h3-connection]s to tokio's event loop. Users have the
choice between implementing their own, custom <code>[ApplicationOverQuic]</code>
or using the ready-made <code>[H3Driver]</code> for HTTP/3 clients and servers.

# Starting an HTTP/3 Server

A server listens on a UDP socket for QUIC connections and spawns a new tokio
task to handle each individual connection.

```rust
use futures::stream::StreamExt;
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::SimpleConnectionIdGenerator;
use tokio_quiche::{ConnectionParams, listen, ServerH3Driver};

async fn start_a_server() -> tokio_quiche::QuicResult<()> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:443").await?;
    let mut listeners = listen(
        [socket],
        ConnectionParams::default(),
        SimpleConnectionIdGenerator,
        DefaultMetrics,
    )?;
    let mut accept_stream = &mut listeners[0];

    while let Some(conn) = accept_stream.next().await {
        let (driver, mut controller) = ServerH3Driver::new(Http3Settings::default());
        conn?.start(driver);

        tokio::spawn(async move {
            // `controller` is the handle to our established HTTP/3 connection.
            // For example, inbound requests are available as H3Events via:
            let event = controller.event_receiver_mut().recv().await;
        });
    }
    Ok(())
}
```

For client-side use cases, check out our <code>[connect]</code> API.

# Feature Flags

tokio-quiche supports a number of feature flags to enable experimental features,
performance enhancements, and additional telemetry. By default, no feature flags are
enabled.

- `rpk`: Support for raw public keys (RPK) in QUIC handshakes (via [boring]).
- `capture_keylogs`: Optional `SSLKEYLOGFILE` capturing for QUIC connections.
- `gcongestion`: Replace quiche's original congestion control implementation with one
   adapted from google/quiche (via quiche-mallard).
- `zero-copy`: Use zero-copy sends with quiche-mallard (implies `gcongestion`).
- `perf-quic-listener-metrics`: Extra telemetry for QUIC handshake durations,
  including protocol overhead and network delays.
- `tokio-task-metrics`: Scheduling & poll duration histograms for tokio tasks.


# Server usage architecture

![server-arch](https://github.com/cloudflare/quiche/blob/master/tokio-quiche/docs/arch-server.drawio.svg?raw=true)

# Client usage architecture

![client-arch](https://github.com/cloudflare/quiche/blob/master/tokio-quiche/docs/arch-client.drawio.svg?raw=true)

[quiche]: https://docs.quic.tech/quiche/
[tokio]: https://tokio.rs
[q-connection]: https://docs.quic.tech/quiche/struct.Connection.html
[q-h3-connection]: https://docs.quic.tech/quiche/h3/struct.Connection.html
[connect]: https://docs.rs/tokio-quiche/latest/tokio_quiche/quic/fn.connect.html
[ApplicationOverQuic]: https://docs.rs/tokio-quiche/latest/tokio_quiche/trait.ApplicationOverQuic.html
[H3Driver]: https://docs.rs/tokio-quiche/latest/tokio-quiche/http3/driver/struct.H3Driver.html
