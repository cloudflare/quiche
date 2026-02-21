# qlog/

qlog data model for QUIC and HTTP/3 per IETF drafts (`draft-ietf-quic-qlog-main-schema`, `draft-ietf-quic-qlog-quic-events`, `draft-ietf-quic-qlog-h3-events`). Pure data types + serde serialization; no IO (deferred to consumers).

## STRUCTURE

```
src/
  lib.rs          # Core types: Qlog, QlogSeq, Trace, TraceSeq, VantagePoint, Configuration, Error
  streamer.rs     # QlogStreamer -- streaming JSON-SEQ writer with state machine
  reader.rs       # QlogSeqReader -- streaming JSON-SEQ reader/iterator
  events/
    mod.rs        # Event, EventData (giant enum), EventType, Eventable trait, EventImportance
    quic.rs       # QUIC event types (packet_sent, packet_received, frames, etc.)
    h3.rs         # HTTP/3 event types
    qpack.rs      # QPACK event types
    connectivity.rs  # Connection-level events (state changes, path updates)
    security.rs   # TLS/crypto events
  testing/
    mod.rs        # Test helpers
    event_tests.rs
    trace_tests.rs
```

## WHERE TO LOOK

| Task | File | Notes |
|------|------|-------|
| Add new event variant | `events/mod.rs` `EventData` enum | Add to relevant `events/*.rs`, wire into `EventData` |
| Modify serialization | `lib.rs` | Heavy `serde_with` usage; `#[serde(rename)]` everywhere |
| Streaming output | `streamer.rs` | `QlogStreamer` writes JSON-SEQ (RFC 7464) via `Write` trait |
| Parse qlog files | `reader.rs` | `QlogSeqReader` iterates events from `BufRead` |
| `Eventable` trait | `events/mod.rs:310` | Requires `importance()` and event name; impl on all event enums |
| Two output modes | `lib.rs` | Buffered (`Qlog`/`Trace`) vs streaming (`QlogSeq`/`TraceSeq`) |

## NOTES

- Deps: `serde`, `serde_json` (preserve_order), `serde_with`, `smallvec`. No async, no IO beyond `Write`/`BufRead`.
- `EventData` is a massive enum (~200 variants) spanning all protocol categories. Grep, don't scroll.
- JSON field names follow IETF draft conventions (`snake_case`), mapped via `#[serde(rename)]`.
- `serde_json::preserve_order` keeps field insertion order in output.
- `HexSlice` helper for hex-encoding byte arrays in JSON.
- No feature flags.
