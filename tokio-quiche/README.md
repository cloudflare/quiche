# Tokio Quiche

Bridging the gap between [quiche][quiche] and [tokio][tokio].

tokio-quiche connects [quiche::Connection][q-connection]s and
[quiche::h3::Connection][q-h3-connection]s to tokio's event loop. Users have the
choice between implementing their own, custom <code>[ApplicationOverQuic]</code>
or using the ready-made <code>[H3Driver]</code> for HTTP/3 clients and servers.

# Examples

An example client and server implementation can be found in `src/bin`. To run the server execute `cargo run --bin tokio-server -- --cert <path/to/cert.crt> --key <path/to/cert.key>  --root .`,
the client can be executed using `cargo run --bin tokio-client -- http://127.0.0.1:4433/README.md`.

# Feature Flags

tokio-quiche supports a number of feature flags to enable experimental features,
performance enhancements, and additional telemetry. By default, no feature flags are
enabled.

- `rpk`: Support for raw public keys (RPK) in QUIC handshakes (via [boring]).
- `gcongestion`: Replace quiche's original congestion control implementation with one
   adapted from google/quiche.
- `zero-copy`: Use zero-copy sends with quiche (implies `gcongestion`).
- `perf-quic-listener-metrics`: Extra telemetry for QUIC handshake durations,
  including protocol overhead and network delays.
- `tokio-task-metrics`: Scheduling & poll duration histograms for tokio tasks.

Other parts of the crate are enabled by separate build flags instead, to be
controlled by the final binary:

- `--cfg capture_keylogs`: Optional `SSLKEYLOGFILE` capturing for QUIC connections.


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
[boring]: https://docs.rs/boring/latest/boring/
