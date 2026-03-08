# tokio-quiche

## OVERVIEW

Async tokio wrapper for `quiche`. Spawns per-connection IO worker tasks driven by an `ApplicationOverQuic` trait. Ships a ready-made `H3Driver` for HTTP/3. Uses `foundations` for structured logging (slog), telemetry, and settings.

## STRUCTURE

```
src/
  lib.rs              Re-exports, listen(), capture_quiche_logs()
  buf_factory.rs      BufFactory: tiered static pools, QuicheBuf (zero-copy feature)
  result.rs           BoxError = Box<dyn Error+Send+Sync>, QuicResult<T>
  settings/           ConnectionParams → quiche::Config → h3::Config cascade
  metrics/            Metrics trait (pluggable); DefaultMetrics (foundations Prometheus)
  socket/             Socket<Tx,Rx>, QuicListener, SocketCapabilities (GSO/GRO)
  quic/               connect(), start_listener(), ApplicationOverQuic, IoWorker, router
  http3/              H3Driver<H>, DriverHooks (sealed), client/server controllers
```

## WHERE TO LOOK

| Task | Location |
|------|----------|
| Server entrypoint | `lib.rs` — `listen()`, `listen_with_capabilities()` |
| Client entrypoint | `quic/mod.rs` — `connect()`, `connect_with_config()` |
| Custom app trait | `quic/connection/mod.rs:663` — `ApplicationOverQuic` |
| H3 driver (main logic) | `http3/driver/mod.rs` — `H3Driver<H>` |
| Per-connection IO loop | `quic/io/worker.rs` — `IoWorker` |
| Packet routing/demux | `quic/router/mod.rs` — `InboundPacketRouter` |
| Config cascade | `settings/config.rs` — `Config::new()` |
| Buffer pools | `buf_factory.rs` — `BufFactory`, static pools |
| Metrics interface | `metrics/mod.rs` — `Metrics` trait |

## CODE MAP

| Symbol | Type | Location | Role |
|--------|------|----------|------|
| `ApplicationOverQuic` | trait | `quic/connection/mod.rs` | Extension point: on_conn_established, process_reads/writes, wait_for_data |
| `H3Driver<H>` | struct | `http3/driver/mod.rs` | Implements `ApplicationOverQuic` for HTTP/3 |
| `DriverHooks` | sealed trait | `http3/driver/hooks.rs` | Client vs server H3 behavior |
| `IoWorker<Tx,M,S>` | struct | `quic/io/worker.rs` | Per-connection state machine (recv -> app -> send) |
| `InboundPacketRouter` | struct | `quic/router/mod.rs` | Sole owner of socket recv; routes by DCID |
| `ConnectionAcceptor` | struct | `quic/router/acceptor.rs` | Server RETRY + yields InitialQuicConnection |
| `InitialQuicConnection` | struct | `quic/connection/mod.rs` | Pre-handshake handle; `.start(app)` spawns worker |
| `QuicConnection` | struct | `quic/connection/mod.rs` | Post-handshake metadata handle (not the qconn itself) |
| `ConnectionParams` | struct | `settings/mod.rs` | QuicSettings + TLS + Hooks + session |
| `Config` | struct(crate) | `settings/config.rs` | Builds quiche::Config from ConnectionParams |
| `BufFactory` | struct | `buf_factory.rs` | Handle to static tiered buffer pools |
| `QuicheBuf` | struct | `buf_factory.rs` | Zero-copy splittable buffer (zero-copy feature) |
| `Metrics` | trait | `metrics/mod.rs` | Pluggable telemetry; `DefaultMetrics` uses foundations |
| `QuicCommand` | enum | `quic/connection/mod.rs` | ConnectionClose / Custom / Stats commands |
| `BoxError` | type alias | `result.rs` | `Box<dyn Error + Send + Sync>` — deliberate choice, see docstring |

## CONVENTIONS (crate-specific)

- Re-exports: `pub extern crate quiche`, `pub use buffer_pool`, `pub use datagram_socket`.
- `foundations` for logging (slog), not `log` directly. `capture_quiche_logs()` bridges quiche's `log` into slog.
- `DriverHooks` is **sealed** — prevents external `H3Driver` variants.
- `QuicAuditStats` (from `datagram-socket`) threaded through all connections via `Arc`.
- Task spawning via `metrics::tokio_task::spawn()` / `spawn_with_killswitch()` — wraps `tokio::spawn` with optional schedule/poll histograms.
- `ConnectionStage` FSM: `Handshake` -> `RunningApplication` -> `Close`.

## ANTI-PATTERNS

- `connection_not_present()` returns `TlsFail` in driver — misleading sentinel. Don't propagate.
- `Error::Done` used as success signal in H3 driver write path. Don't replicate.
- Don't add new `ApplicationOverQuic` methods without considering the worker loop order (recv -> reads -> writes -> send).
- Don't block in `wait_for_data` — it's polled concurrently with packet recv and timers.

## NOTES

- Hardcodes `quiche/boringssl-boring-crate` + `quiche/qlog` in Cargo.toml deps.
- Features: `zero-copy` implies `gcongestion`. `rpk` enables raw public keys via `boring/rpk`.
- `--cfg capture_keylogs` (build flag, not feature) enables SSLKEYLOGFILE support.
- `perf-quic-listener-metrics` adds handshake timing instrumentation.
- `tokio-task-metrics` adds schedule/poll duration histograms per spawned task.
- Linux-only: `libc`/`nix` deps for signal handling and socket options.
- One client connection per socket — no multiplexing on client side.
