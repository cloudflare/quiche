# h3i

## OVERVIEW

Low-level HTTP/3 testing client. Sends arbitrary/malformed H3 frames to probe server RFC compliance. Both library (`lib.rs`) and CLI binary (`main.rs`). Used programmatically as test driver in tokio-quiche integration tests.

## STRUCTURE

```
src/
  lib.rs              # Crate root: quiche re-export, QPACK encoding, stream type constants
  main.rs             # CLI binary: clap arg parsing, qlog I/O, dispatches to sync/async client
  config.rs           # Config struct (QUIC transport params, TLS, host/port) + builder
  frame.rs            # H3iFrame enum (Headers/QuicheH3/ResetStream), EnrichedHeaders, CloseTriggerFrame
  frame_parser.rs     # Per-stream incremental frame parser (FrameParser, FrameParseResult)
  actions/
    h3.rs             # Action enum: SendFrame, SendHeadersFrame, StreamBytes, SendDatagram,
                      #   OpenUniStream, ResetStream, StopSending, ConnectionClose, Wait, FlushPackets
  client/
    mod.rs            # Client trait, execute_action(), parse_streams(), shared logic
    sync_client.rs    # Blocking mio-based client: connect() -> ConnectionSummary
    async_client.rs   # tokio-quiche-based client (behind `async` feature)
    connection_summary.rs  # ConnectionSummary: StreamMap + Stats + PathStats + close details
  prompts/
    h3/               # Interactive CLI prompts (inquire crate) for building Actions
  recordreplay/
    qlog.rs           # Action <-> qlog event conversion; replay from qlog files
```

## WHERE TO LOOK

| Task | File | Notes |
|------|------|-------|
| Define new action type | `actions/h3.rs` | Add variant to `Action` enum |
| Modify frame parsing | `frame_parser.rs` | `FrameParser::try_parse_frame` |
| Change connection output | `client/connection_summary.rs` | `ConnectionSummary`, `StreamMap` (640 lines) |
| Add CLI flags | `main.rs` | `config_from_clap()` uses clap v3 |
| Library config | `config.rs` | `Config` struct + builder pattern |
| Custom frame types | `frame.rs` | `H3iFrame` enum wraps quiche frames |
| qlog record/replay | `recordreplay/qlog.rs` | Bidirectional: Action->qlog and qlog->Action |
| Use as library | `lib.rs` doc example | `sync_client::connect(config, actions, close_triggers)` |

## NOTES

- **Feature gate**: `async` feature swaps sync mio client for tokio-quiche async client. Also changes quiche re-export path (`quiche` vs `tokio_quiche::quiche`).
- **quiche `internal` feature**: always enabled -- accesses `quiche::h3::frame::Frame` internals for raw frame construction.
- **Stream type constants**: `HTTP3_CONTROL_STREAM_TYPE_ID` (0x0), `QPACK_ENCODER_STREAM_TYPE_ID` (0x2), `QPACK_DECODER_STREAM_TYPE_ID` (0x3) in `lib.rs`.
- **Action execution**: `client/mod.rs::execute_action()` matches on `Action` variants, writes directly to `quiche::Connection` streams -- no H3 connection layer.
- **ConnectionSummary**: returned from both sync/async `connect()`. Contains per-stream frame maps, QUIC stats, path stats, close reason. Custom `Serialize` impl truncates binary at 16KB.
- **Literal header encoding**: `encode_header_block_literal()` bypasses Huffman + lowercase normalization for testing malformed headers.
- **Close triggers**: optional `CloseTriggerFrame` list causes automatic connection close when matching frame received.
