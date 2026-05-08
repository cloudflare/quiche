# quiche/ — Core QUIC + HTTP/3 Library

## OVERVIEW

Low-level QUIC transport and HTTP/3 in Rust. App provides IO/timers; this crate handles protocol state. Also exposes C FFI via `staticlib`/`cdylib`.

## STRUCTURE

```
src/
  lib.rs          (9k lines) Connection struct, Config, connect()/accept() entry points
  h3/
    mod.rs        (7.5k)     HTTP/3 connection — own Error/Result types, NOT quiche::Error
    qpack/                   QPACK header compression
  recovery/
    mod.rs                   Recovery enum, RecoveryOps trait (enum_dispatch)
    congestion/              Legacy CC (Cubic, Reno, Hystart++)
    gcongestion/             Google-derived CC (BBR2) — behind `gcongestion` feature
  stream/                    Stream state machine, flow control per-stream
  tls/                       TLS backend abstraction (BoringSSL)
  crypto/                    Packet protection, key derivation
  packet.rs       (2.3k)     Packet parsing, ConnectionId, Header
  frame.rs                   QUIC frame encode/decode
  path.rs                    Multi-path state, PathEvent, migration
  pmtud.rs                   Path MTU discovery
  cid.rs                     Connection ID management
  ffi.rs          (2.3k)     C FFI — behind `ffi` feature
  transport_params.rs        QUIC transport parameter encode/decode
  flowcontrol.rs             Connection-level flow control
  ranges.rs                  ACK range tracking
  buffers.rs                 BufFactory/BufSplit/DefaultBufFactory traits and types
  range_buf.rs               RangeBuf — ordered byte buffer for stream reassembly
  dgram.rs                   DATAGRAM frame support
  rand.rs                    Random number generation
  minmax.rs                  Windowed min/max filter
  test_utils.rs              Pipe struct for in-memory QUIC pairs (pub via `internal` feature)
  tests.rs        (12k)      Integration tests
  build.rs                   Link directives + pkg-config metadata (NOTE: lives in src/, not crate root)
include/
  quiche.h        (1.2k)     C API header — mirrors ffi.rs
```

BoringSSL itself is built by `boring-sys` (no in-tree submodule).

## WHERE TO LOOK

| Task | Start here |
|------|-----------|
| Connection lifecycle | `lib.rs` — `Connection` struct, `recv()`, `send()` |
| HTTP/3 streams/headers | `h3/mod.rs` — `h3::Connection` |
| Loss detection / CC | `recovery/mod.rs` → `congestion/` or `gcongestion/` |
| Packet parse/serialize | `packet.rs`, `frame.rs` |
| TLS handshake | `tls/mod.rs` — cfg-gated per backend |
| C bindings | `ffi.rs` + `include/quiche.h` |
| Test harness | `test_utils.rs` (`Pipe` struct) |
| Build system | `src/build.rs` — link directives + pkg-config metadata (BoringSSL is built by `boring-sys`) |

## ANTI-PATTERNS

- **h3::Error != quiche::Error** — don't mix or convert carelessly; they have different variant sets.
- **`Error::Done` is a success signal** in many read/write loops — not a failure.
- **Don't add new CC impls** outside `recovery/` — two parallel impls (congestion + gcongestion) already exist.
- **`unsafe` only at FFI boundaries** — `tls/`, `crypto/`, `ffi.rs`; don't add elsewhere.
- **`#[cfg(feature = "fuzzing")]`** disables real crypto — never accidentally gate non-test code on it.

## NOTES

- `build.rs` is at `src/build.rs` (Cargo.toml: `build = "src/build.rs"`), not crate root. Emits link directives and, with `pkg-config-meta`, writes `quiche.pc`; BoringSSL itself is built by `boring-sys`.
- Single TLS backend: `boringssl-boring-crate` (default), via the `boring`/`boring-sys` crates.
- `quiche::Error` is `Copy + Clone` — intentional for hot-path ergonomics.
- `test_utils::Pipe` exposed via `internal` feature for downstream crate integration tests.
- Tests use `rstest` with `#[values("cubic", "bbr2_gcongestion")]` parameterization for CC coverage.
- `BORING_BSSL_PATH` env var (consumed by `boring-sys`) points at a custom BoringSSL source tree.
- Crate-type: `lib` + `staticlib` + `cdylib` — the latter two for C consumers.
- `BufFactory` trait (`buffers.rs`) enables zero-copy buffer creation; `Connection<F>` is generic over it.
