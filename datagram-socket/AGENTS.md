# datagram-socket/

UDP socket abstraction layer shared across the quiche workspace. Two main concerns:
`DgramBuffer` (a headroom-aware zero-copy byte buffer for datagrams) and
`DatagramSocket*` traits (uniform async send/recv over `UdpSocket`/`UnixDatagram`
with Linux `recvmmsg`/`sendmmsg` batching).

## STRUCTURE

```
src/
  lib.rs          Re-exports, is_nonblocking() helper
  buffer.rs       DgramBuffer — headroom-aware buffer for zero-copy datagram handling
  datagram.rs     DatagramSocket/Send/Recv traits, MaybeConnectedSocket, MAX_DATAGRAM_SIZE
  mmsg.rs         recvmmsg/sendmmsg + poll_recvmmsg!/poll_sendmmsg! macros (Linux only)
  shutdown.rs     ShutdownConnection trait
  socket_stats.rs SocketStats, QuicAuditStats, AsSocketStats
```

## WHERE TO LOOK

| Task | File | Notes |
|------|------|-------|
| Prepend a flow ID to an outbound datagram | `buffer.rs` | `try_add_prefix` (fast, zero-copy) or `splice_headroom` + retry (slow, O(n)) |
| Strip a prefix from an inbound datagram | `buffer.rs` | `advance(n)` — zero copy |
| Implement a new socket type | `datagram.rs` | Implement `DatagramSocketSend` + `DatagramSocketRecv`; `DatagramSocket` is automatic |
| Batch recv/send on Linux | `mmsg.rs` | Use `poll_recvmmsg!` / `poll_sendmmsg!` macros |
| Track connection-level metrics | `socket_stats.rs` | `QuicAuditStats` (atomic/lock-protected); `SocketStats` (plain Copy struct) |

## DgramBuffer DESIGN

Wraps a `Vec<u8>` with a `pos` cursor dividing it into `[headroom: 0..pos][payload: pos..]`. `as_slice()` / `len()` expose only the payload. `BufMut` writes append to the tail, independent of `pos`.

**Fast path:** allocate with `with_capacity_and_headroom`, fill payload via `BufMut`, call `try_add_prefix` to slide `pos` left and write the prefix into headroom — no allocation, no memmove.

**Slow path:** if no headroom was pre-allocated, `splice_headroom(n)` does an O(payload_len) memmove to insert n bytes at the front; then retry `try_add_prefix`.

**Stripping a prefix:** `advance(n)` increments `pos` — zero-copy.

## ANTI-PATTERNS

- **`splice_headroom` is O(n).** Prefer pre-allocated headroom via `with_capacity_and_headroom` on hot paths.
- **`MaybeConnectedSocket` snapshots connectedness at construction.** If the underlying socket's connected state changes after wrapping, the routing behavior will be stale.
- **`recvmmsg`/`sendmmsg` assume a connected socket** (no `msg_name`). Do not use on unconnected sockets.

## NOTES

- No feature flags — platform-gating via `#[cfg(target_os = "linux")]` and `#[cfg(unix)]`.
- `tokio-quiche` sets `type DgramBuf = DgramBuffer` in its `BufFactory` impl, so all QUIC DATAGRAMs flowing through `quiche::Connection` in tokio-quiche are `DgramBuffer` instances.
- In `quiche` itself, `BufFactory::DgramBuf` defaults to `Vec<u8>` — `DgramBuffer` is only used when tokio-quiche's `BufFactory` is active.
- `DGRAM_HEADROOM = 16` in `tokio-quiche/src/buf_factory.rs` — sized to hold two QUIC varints (max 8 bytes each).
- `MAX_DATAGRAM_SIZE = 1500` bytes.
- `unsafe impl BufMut for DgramBuffer` delegates entirely to `Vec<u8>`'s trusted implementation; `pos` and `BufMut`'s write pointer operate on non-overlapping regions.
