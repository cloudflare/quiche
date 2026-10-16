# HTTP/3 Driver (`tokio-quiche/src/http3/driver/`)

## OVERVIEW

Async HTTP/3 driver bridging `quiche::h3::Connection` to Tokio tasks via channels. `H3Driver<H: DriverHooks>` is generic over sealed client/server hooks; users interact through `H3Controller` + typed event/command channels.

## STRUCTURE

| File | Role |
|------|------|
| `mod.rs` | `H3Driver`, `H3Controller`, `H3Event`, `H3Command`, `OutboundFrame`/`InboundFrame`, channel types, `ApplicationOverQuic` impl |
| `hooks.rs` | `DriverHooks` trait (sealed). Defines `headers_received`, `stream_recv_closed`, `stream_closed`, `conn_established`, `conn_command`, `wait_for_action` |
| `client.rs` | `ClientHooks` impl, `ClientH3Driver`/`ClientH3Controller` aliases, `ClientH3Event`/`ClientH3Command` |
| `server.rs` | `ServerHooks` impl, `ServerH3Driver`/`ServerH3Controller` aliases, `ServerH3Event`/`ServerH3Command` |
| `streams.rs` | `StreamCtx`, `FlowCtx`, shared per-stream waker and channel waiting flags |
| `datagram.rs` | DATAGRAM/CONNECT-UDP flow handling |
| `connection.rs` | `H3Conn` wrapper exposing `h3::Connection` operations |
| `test_utils.rs` | `DriverTestHelper<H>` -- wraps `Pipe` + `H3Driver` for unit tests |
| `tests.rs` | ~1500 lines of driver tests |

## WHERE TO LOOK

| Task | Start at |
|------|----------|
| Channel architecture | `mod.rs` (`H3Driver` struct fields: `h3_event_sender`, `cmd_recv`, `stream_map`, `ready_streams`) |
| `select!` loop / priority ordering | `mod.rs` `wait_for_data` impl -- uses `biased` select! |
| Stream lifecycle | `cleanup_stream`, `shutdown_stream`, `process_h3_fin`, `process_h3_data` in `mod.rs` |
| Per-stream backpressure | `streams.rs` keeps endpoints in `StreamCtx`; one generic waker queues each stream ID once, and the driver re-polls both waiting directions |
| Adding endpoint-specific behavior | `hooks.rs` -- add method to `DriverHooks`, impl in `client.rs`/`server.rs` |
| Writing tests | `test_utils.rs` for `DriverTestHelper`, `tests.rs` for examples |

## ANTI-PATTERNS

- Store receive and send lifecycle states explicitly; channel absence does not
  imply completion. Received FIN and app-channel FIN delivery are distinct
  receive states. Open and pending receive states own an `InboundDelivery` payload
  with its sender and capacity-wait flag; closing the state drops both. FIN
  preserves the payload, including an existing wait. The outbound receiver is
  independent: queued FIN can drop it
  while the transport still has body data to send.
- Do not add overlapping boolean completion methods for these states. A single
  derived helper can centralize the cleanup decision without conflating pending
  FIN with closed delivery. Match lifecycle enums exhaustively where a new
  variant could require a different transition or cleanup outcome. Simple
  predicates suit yes/no decisions with an obvious safe default; payload
  wildcards and independent readiness queries are fine.
- **`connection_not_present()` returns `TlsFail`** -- misleading sentinel error. Do not propagate this pattern.
- **`process_write_frame` uses `Error::Done` as success** -- non-obvious control flow, don't replicate elsewhere.
- **`DriverHooks` is sealed** -- `mod hooks` is `pub(crate)`, trait has `#[allow(private_interfaces)]`. Do not expose.
- **Stream cleanup is distributed** across 4+ functions (`cleanup_stream`, `shutdown_stream`, `process_h3_fin`, `process_h3_data`). Understand all paths before modifying.
- **Waiting-stream cancellation must be keyed** -- clear flags and drop endpoints
  through `stream_map`; do not linearly scan the ready queue.
- `ReadyStreams` owns queue acknowledgment: dequeueing clears the queued wake
  flag before returning the stream ID. Channel polling never changes that flag.
  Keep waiting flags set on `Pending`, including spurious wakes and
  cooperative-budget yields.
- Stream cleanup drops channel endpoints immediately; stale ready IDs are ignored.
- STOP_SENDING discards ordinary outbound frames, but a buffered `PeerStreamError`
  must still shut down both directions.
- **`STREAM_CAPACITY`** is 1 in test/debug, 16 in release. Tests exercise backpressure differently from prod.

## NOTES

- `H3Driver::new()` returns `(H3Driver<H>, H3Controller<H>)` -- paired at construction, connected by unbounded mpsc channels.
- Per-stream channels are bounded (`STREAM_CAPACITY`); per-connection event/cmd channels are unbounded.
- Datagram flows use a shared `FLOW_CAPACITY=2048` bounded channel, separate from stream channels.
- `H3Event` variants: `IncomingSettings`, `IncomingHeaders`, `NewFlow`, `ResetStream`, `ConnectionError`, `ConnectionShutdown`, `BodyBytesReceived`, `StreamClosed`.
- `H3Command` variants: `QuicCmd`, `GoAway`, `ShutdownStream`.
- Type aliases (`ClientH3Driver`, `ServerH3Driver`, etc.) are the public API; `H3Driver<H>` and `DriverHooks` are internal.
