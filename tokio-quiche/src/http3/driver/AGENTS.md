# HTTP/3 Driver (`tokio-quiche/src/http3/driver/`)

## OVERVIEW

Async HTTP/3 driver bridging `quiche::h3::Connection` to Tokio tasks via channels. `H3Driver<H: DriverHooks>` is generic over sealed client/server hooks; users interact through `H3Controller` + typed event/command channels.

## STRUCTURE

| File | Role |
|------|------|
| `mod.rs` | `H3Driver`, `H3Controller`, `H3Event`, `H3Command`, `OutboundFrame`/`InboundFrame`, channel types, `ApplicationOverQuic` impl |
| `hooks.rs` | `DriverHooks` trait (sealed). Defines `headers_received`, `conn_established`, `conn_command`, `wait_for_action` |
| `client.rs` | `ClientHooks` impl, `ClientH3Driver`/`ClientH3Controller` aliases, `ClientH3Event`/`ClientH3Command` |
| `server.rs` | `ServerHooks` impl, `ServerH3Driver`/`ServerH3Controller` aliases, `ServerH3Event`/`ServerH3Command` |
| `streams.rs` | `StreamCtx`, `FlowCtx`, `WaitForStream` future, capacity/readiness signals |
| `datagram.rs` | DATAGRAM/CONNECT-UDP flow handling |
| `connection.rs` | `H3Conn` wrapper exposing `h3::Connection` operations |
| `test_utils.rs` | `DriverTestHelper<H>` -- wraps `Pipe` + `H3Driver` for unit tests |
| `tests.rs` | ~1500 lines of driver tests |

## WHERE TO LOOK

| Task | Start at |
|------|----------|
| Channel architecture | `mod.rs:332` (`H3Driver` struct fields: `h3_event_sender`, `cmd_recv`, `stream_map`, `waiting_streams`) |
| `select!` loop / priority ordering | `mod.rs` `wait_for_data` impl -- uses `biased` select! |
| Stream lifecycle | `cleanup_stream`, `shutdown_stream`, `process_h3_fin`, `process_h3_data` in `mod.rs` |
| Per-stream backpressure | `streams.rs` -- `FuturesUnordered<WaitForStream>`, `WaitForDownstreamData`, `WaitForUpstreamCapacity` |
| Adding endpoint-specific behavior | `hooks.rs` -- add method to `DriverHooks`, impl in `client.rs`/`server.rs` |
| Writing tests | `test_utils.rs` for `DriverTestHelper`, `tests.rs` for examples |

## ANTI-PATTERNS

- **`connection_not_present()` returns `TlsFail`** -- misleading sentinel error. Do not propagate this pattern.
- **`process_write_frame` uses `Error::Done` as success** -- non-obvious control flow, don't replicate elsewhere.
- **`DriverHooks` is sealed** -- `mod hooks` is `pub(crate)`, trait has `#[allow(private_interfaces)]`. Do not expose.
- **Stream cleanup is distributed** across 4+ functions (`cleanup_stream`, `shutdown_stream`, `process_h3_fin`, `process_h3_data`). Understand all paths before modifying.
- **`STREAM_CAPACITY`** is 1 in test/debug, 16 in release. Tests exercise backpressure differently from prod.

## NOTES

- `H3Driver::new()` returns `(H3Driver<H>, H3Controller<H>)` -- paired at construction, connected by unbounded mpsc channels.
- Per-stream channels are bounded (`STREAM_CAPACITY`); per-connection event/cmd channels are unbounded.
- Datagram flows use a shared `FLOW_CAPACITY=2048` bounded channel, separate from stream channels.
- `H3Event` variants: `IncomingSettings`, `IncomingHeaders`, `NewFlow`, `ResetStream`, `ConnectionError`, `ConnectionShutdown`, `BodyBytesReceived`, `StreamClosed`.
- `H3Command` variants: `QuicCmd`, `GoAway`, `ShutdownStream`.
- Type aliases (`ClientH3Driver`, `ServerH3Driver`, etc.) are the public API; `H3Driver<H>` and `DriverHooks` are internal.
