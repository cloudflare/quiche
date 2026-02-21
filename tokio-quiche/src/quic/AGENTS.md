# tokio-quiche/src/quic/

## OVERVIEW

Async QUIC connection management. Splits socket into recv-half (one `InboundPacketRouter` task) and send-half (shared by many `IoWorker` tasks). Entrypoints: `connect()`/`connect_with_config()` for clients, `start_listener()` for servers. `raw` submodule bypasses the router for manual packet injection.

## STRUCTURE

```
mod.rs                        # Entrypoints: connect, connect_with_config, start_listener
raw.rs                        # wrap_quiche_conn(): bypass router, manual packet feed
hooks.rs                      # ConnectionHook trait (custom SslContextBuilder)
addr_validation_token.rs      # RETRY token generation/validation for server

connection/
  mod.rs                      # InitialQuicConnection, QuicConnection, ApplicationOverQuic trait
  error.rs                    # HandshakeError enum, make_handshake_result()
  id.rs                       # ConnectionIdGenerator trait, SimpleConnectionIdGenerator
  map.rs                      # ConnectionMap: BTreeMap<CidOwned, mpsc::Sender<Incoming>>

io/
  connection_stage.rs         # ConnectionStage trait + stages: Handshake, RunningApplication, Close
  worker.rs                   # IoWorker<Tx,M,S>: per-connection recv→process→send loop
  gso.rs                      # GSO/GRO send_to(), UDP_MAX_GSO_PACKET_SIZE
  utilization_estimator.rs    # BandwidthReporter for max bandwidth/loss tracking

router/
  mod.rs                      # InboundPacketRouter: Future, demux by DCID, ConnectionMapCommand
  acceptor.rs                 # ConnectionAcceptor: server-side InitialPacketHandler (RETRY flow)
  connector.rs                # ClientConnector: client-side InitialPacketHandler (handshake FSM)
```

## WHERE TO LOOK

| Task | File | Symbol/Line |
|------|------|-------------|
| Add lifecycle callback | `connection/mod.rs` | `ApplicationOverQuic` trait (~:663) |
| Connection state machine | `io/connection_stage.rs` | `ConnectionStage` trait, `Handshake`/`RunningApplication`/`Close` |
| Worker main loop | `io/worker.rs` | `IoWorker::work_loop()` (~:216) |
| Packet routing/demux | `router/mod.rs` | `InboundPacketRouter::on_incoming()` (~:229) |
| CID management | `io/worker.rs` | `fill_available_scids()`, `refresh_connection_ids()` |
| Server accept flow | `router/acceptor.rs` | `ConnectionAcceptor::handle_initials()` |
| Client connect flow | `router/connector.rs` | `ClientConnector::on_incoming()` |
| Connection spawn path | `connection/mod.rs` | `InitialQuicConnection::start()` / `handshake()` / `resume()` |
| CID-to-connection map | `connection/map.rs` | `ConnectionMap` (optimized `CidOwned` for v1 CIDs) |
| Raw/manual connections | `raw.rs` | `wrap_quiche_conn()`, `ConnCloseReceiver` |

## ANTI-PATTERNS

- **`InitialQuicConnection` is `#[must_use]`** -- dropping silently discards connection. Always call `.start()`, `.handshake()`, or `.handshake_fut()`.
- **`handshake()` spawns with `AbortOnDropHandle`** -- dropping the future kills the handshake task. Hold the handle.
- **`fill_available_scids` sends `ConnectionMapCommand::MapCid` to router** -- silently fails if router channel dropped. Don't assume CID registration succeeded.
- **`transmute` of `Instant` in `gso.rs`** -- fragile platform-dependent hack. Do not extend or replicate.
- **One client connection per socket** -- `connect()` docs explicitly warn. Sharing socket loses packets.
- **`#[cfg(feature = "zero-copy")]` gates `QuicheConnection` type alias** -- `quiche::Connection<BufFactory>` vs `quiche::Connection`. Check both paths when modifying connection creation.
- **`wait_for_quiche` returns `TlsFail` on gather error** -- misleading sentinel error, don't propagate this pattern.

## NOTES

- `IoWorker` is generic: `IoWorker<Tx, M, S: ConnectionStage>`. Stage transitions consume the worker via `From<IoWorker<..>> for IoWorkerParams<..>` and construct a new `IoWorker` with the next stage.
- `select!` in `work_loop` is **biased** -- timeout arm must stay first to prevent starvation.
- `ConnectionMap` uses `CidOwned::Optimized([u64; 3])` for v1 CIDs (<=20 bytes) to avoid heap allocation on lookup.
- `InboundPacketRouter` implements `Future` directly (not async fn) -- polled as a spawned task.
- `short_dcid()` fast-path extracts DCID from short header packets without full `Header::from_slice`.
- Router tests are `#[cfg(all(test, unix))]` in `router/mod.rs` -- not Windows-compatible.
