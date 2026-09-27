# Running the example server

⚠️ This example demonstrate simples usage of the tokio-quiche API. It is not
intended to be used in production environments; no performance, security or
reliability guarantees are provided.

First, start the server. In this example, we'll be listening on
`127.0.0.1:5757`. We can pass that to the `address` argument to specify it as
the listening address:

```shell
RUST_LOG=info cargo run --example async_http3_server -- --address <listening_address>
```

Verbosities can be specified with typical [`env_logger`](https://docs.rs/env_logger/latest/env_logger/#enabling-logging) syntax.

The default TLS certificate covers `test.com`. Certificates can be passed via
the `--tls-cert-path` CLI argument, while private keys can be passed via the
`--tls-private-key-path` argument.

Once the server is up and running, you can hit it with your favorite client:

```shell
❮ RUST_LOG=debug cargo run --bin quiche-client -- https://test.com --no-verify --connect-to 127.0.0.1:5757

    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.13s
     Running `target/debug/quiche-client 'https://test.com' --no-verify --connect-to '127.0.0.1:5757'`
[2025-07-08T00:06:11.363952000Z INFO  quiche_apps::client] connecting to 127.0.0.1:5757 from 0.0.0.0:55110 with scid 531c918fbe27cc86abb7bd3e92695f2caf0d7809
[2025-07-08T00:06:11.369728000Z DEBUG quiche_apps::common] Sent HTTP request [":method: GET", ":scheme: https", ":authority: test.com", ":path: /", "user-agent: quiche"]
[2025-07-08T00:06:11.371084000Z DEBUG quiche_apps::common] got response headers [(":status", "200")] on stream id 0
[2025-07-08T00:06:11.371113000Z DEBUG quiche_apps::common] 1/1 responses received
[2025-07-08T00:06:11.371121000Z INFO  quiche_apps::common] 1/1 response(s) received in 6.605ms, closing...
[2025-07-08T00:06:11.402352000Z INFO  quiche_apps::client] connection closed, recv=9 sent=13 lost=0 retrans=0 sent_bytes=2793 recv_bytes=2436 lost_bytes=0 [local_addr=0.0.0.0:55110 peer_addr=127.0.0.1:5757 validation_state=Validated active=true recv=9 sent=13 lost=0 retrans=0 rtt=2.396186ms min_rtt=Some(199.677µs) rttvar=1.915735ms cwnd=13500 sent_bytes=2793 recv_bytes=2436 lost_bytes=0 stream_retrans_bytes=0 pmtu=1350 delivery_rate=1137163]
```

The server should print the events something like this:

```shell
[2025-07-08T00:06:11.365942000Z INFO  async_http3_server] received new connection!
[2025-07-08T00:06:11.370735000Z INFO  async_http3_server::server] received unhandled event: IncomingSettings { settings: [(2777032016412723649, 2920255815440916575)] }
[2025-07-08T00:06:11.370759000Z INFO  async_http3_server::server] received headers: IncomingH3Headers { stream_id: 0, headers: [":method: GET", ":scheme: https", ":authority: test.com", ":path: /", "user-agent: quiche"], read_fin: true, h3_audit_stats: H3AuditStats { stream_id: 0, downstream_bytes_sent: 0, downstream_bytes_recvd: 0, recvd_stop_sending_error_code: -1, recvd_reset_stream_error_code: -1, sent_stop_sending_error_code: -1, sent_reset_stream_error_code: -1, recvd_stream_fin: AtomicCell { value: Explicit }, sent_stream_fin: AtomicCell { value: None } } }
[2025-07-08T00:06:11.370838000Z INFO  async_http3_server::server] received unhandled event: BodyBytesReceived { stream_id: 0, num_bytes: 0, fin: true }
[2025-07-08T00:06:11.370983000Z INFO  async_http3_server::server] received unhandled event: StreamClosed { stream_id: 0 }
```

Logging can be suppressed entirely by omitting the `RUST_LOG` environment variable.

The server also exposes a `/stream-bytes/<n>` endpoint. When a request is made to said
endpoint, `n` bytes will come back in the response body:

```shell
❯ RUST_LOG=debug cargo run --bin quiche-client -- https://test.com/stream-bytes/3 --no-verify --connect-to 127.0.0.1:5757

   Compiling quiche v0.24.4 (/Users/erittenhouse/Documents/projects/quiche/quiche)
   Compiling quiche_apps v0.1.0 (/Users/erittenhouse/Documents/projects/quiche/apps)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.66s
     Running `target/debug/quiche-client 'https://test.com/stream-bytes/3' --no-verify --connect-to '127.0.0.1:5757'`
[2025-07-08T00:05:42.201487000Z INFO  quiche_apps::client] connecting to 127.0.0.1:5757 from 0.0.0.0:61497 with scid d6d1a81656e0a650c9466cb97de14faba3c8d7f8
[2025-07-08T00:05:42.210185000Z DEBUG quiche_apps::common] Sent HTTP request [":method: GET", ":scheme: https", ":authority: test.com", ":path: /stream-bytes/3", "user-agent: quiche"]
[2025-07-08T00:05:42.211799000Z DEBUG quiche_apps::common] got response headers [(":status", "200")] on stream id 0
[2025-07-08T00:05:42.211834000Z DEBUG quiche_apps::common] got 3 bytes of response data on stream 0
[2025-07-08T00:05:42.211845000Z DEBUG quiche_apps::common] 1/1 responses received
[2025-07-08T00:05:42.211850000Z INFO  quiche_apps::common] 1/1 response(s) received in 9.849541ms, closing...
[2025-07-08T00:05:42.270737000Z INFO  quiche_apps::client] connection closed, recv=9 sent=13 lost=0 retrans=0 sent_bytes=2805 recv_bytes=2436 lost_bytes=0 [local_addr=0.0.0.0:61497 peer_addr=127.0.0.1:5757 validation_state=Validated active=true recv=9 sent=13 lost=0 retrans=0 rtt=5.045481ms min_rtt=Some(130.486µs) rttvar=3.559643ms cwnd=13500 sent_bytes=2805 recv_bytes=2436 lost_bytes=0 stream_retrans_bytes=0 pmtu=1350 delivery_rate=1104879]
```
