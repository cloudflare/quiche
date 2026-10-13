# quiche/src/h3/ — HTTP/3 Module

## OVERVIEW

HTTP/3 wire protocol over QUIC. `Connection` manages H3 state (streams, QPACK, SETTINGS, GOAWAY) on top of `quiche::Connection<F>`. Event-driven: caller loops `poll()` → `Event`. Own `Error`/`Result` types, separate from `quiche::Error`.

## STRUCTURE

```
mod.rs       (7549 lines)  H3 Connection, Config, Error, Event, Header, NameValue, Priority
stream.rs    (1565)        H3 stream state machine (Type, State enums; frame parsing FSM)
frame.rs     (1337)        H3 frame encode/decode (Frame enum, settings constants)
ffi.rs                     C FFI for H3 — behind `ffi` feature
qpack/
  mod.rs                   Re-exports
  encoder.rs               QPACK encoder
  decoder.rs               QPACK decoder
  static_table.rs          Static header table (RFC 9204)
```

## WHERE TO LOOK

| Task | Location |
|------|----------|
| Send/recv requests+responses | `mod.rs` — `send_request()`, `send_response()`, `poll()` |
| Body data | `mod.rs` — `send_body()`, `recv_body()` |
| Priority handling | `mod.rs` — `Priority` struct, `send_priority_update_for_request()` |
| H3 stream lifecycle | `stream.rs` — `Stream` struct, `State` FSM |
| Frame wire format | `frame.rs` — `Frame` enum, `encode()`/`decode()` |
| QPACK header compression | `qpack/encoder.rs`, `qpack/decoder.rs` |
| H3 C API | `ffi.rs` |

## ANTI-PATTERNS

- Represent related HTTP/3 message-phase flags with explicit enums. Preserve
  message phase separately from local termination, including termination
  before initial headers and trailers sent without FIN.
- `StreamKind` owns type-specific state: request origins, message phases,
  local termination, DATA notifications, and pending priority updates; control
  SETTINGS initialization; and push DATA notifications. Match it directly for
  stream dispatch and cleanup. `Type` is only a wire-decoding/qlog value.
- Match phase enums exhaustively in transitions and validation decisions where
  a new variant could require a different outcome. Simple predicates are suitable
  for yes/no decisions with an obvious safe default for new variants. Keep
  independent termination flags separate; payload wildcards are fine.
- **h3::Error != quiche::Error.** 19 variants; `TransportError(quiche::Error)` wraps transport errors. Don't confuse.
- **`Error::Done` is success** in poll/read loops. Not a failure — signals "no more work".
- **`to_wire()` maps `BufferTooShort` → `0x999`** — non-standard wire code. Don't propagate this pattern.
- **`to_c()` skips -12** — was previously `TransportError`. Gap is intentional for ABI stability.
- **`to_c()` for `TransportError`:** offsets by `-1000` from underlying `quic_error.to_c()`.
- **`send_request()` sends empty `b""` to create QUIC stream** before writing headers. Required because QUIC stream doesn't exist until first write.
- **stream.rs `Stream` ≠ quiche::stream::Stream.** H3 stream is a frame-parsing state machine layered on top.

## NOTES

- Methods are generic over `F: BufFactory` (zero-copy) and `T: NameValue` (header access).
- `NameValue` trait: `name() -> &[u8]`, `value() -> &[u8]`. Blanket impl for `(N, V)` tuples.
- `Header` is `(Vec<u8>, Vec<u8>)` newtype implementing `NameValue`.
- `Event` variants: `Headers`, `Data`, `Finished`, `Reset(u64)`, `PriorityUpdate`, `GoAway`.
- Priority: RFC 9218 Extensible Priorities. `sfv` feature enables `TryFrom` parsing.
- `PRIORITY_URGENCY_OFFSET = 124` maps external urgency 0-7 to internal quiche priority.
- `APPLICATION_PROTOCOL = &[b"h3"]` — ALPN constant.
- `From<quiche::Error>` converts `Done→Done`, everything else → `TransportError(e)`.
- `From<octets::BufferTooShortError>` → `Error::BufferTooShort`.
- All `#[cfg(feature = "qlog")]` instrumentation inline in mod.rs — heavy conditional compilation.
