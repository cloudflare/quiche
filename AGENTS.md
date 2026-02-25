# PROJECT KNOWLEDGE BASE

**Generated:** 2026-02-20
**Commit:** 89d1850f
**Branch:** master

## OVERVIEW

Cloudflare's QUIC and HTTP/3 implementation in Rust. Workspace of 11 crates: core `quiche` protocol library, `tokio-quiche` async integration, CLI tools (`apps`, `h3i`), logging/analysis (`qlog`, `qlog-dancer`, `netlog`), and supporting primitives (`octets`, `buffer-pool`, `datagram-socket`, `task-killswitch`).

## STRUCTURE

```
quiche/                     # Core QUIC+H3 library (C FFI, BoringSSL submodule)
tokio-quiche/               # Async tokio wrapper (server/client drivers)
apps/                       # CLI binaries: quiche-client, quiche-server
h3i/                        # HTTP/3 interactive testing/debugging tool
qlog/                       # qlog event schema (RFC draft)
qlog-dancer/                # qlog/netlog visualization (native + wasm)
netlog/                     # Chrome netlog parser
octets/                     # Zero-copy byte buffer primitives
buffer-pool/                # Sharded lock-free buffer pool
datagram-socket/            # UDP socket abstraction (sendmmsg/recvmmsg)
task-killswitch/            # Async task cancellation primitive
fuzz/                       # Fuzz targets (excluded from workspace)
tools/                      # Android build tooling, http3_test harness
```

## DEPENDENCY GRAPH

```
octets  buffer-pool  task-killswitch  qlog  netlog    (Layer 0: no workspace deps)
  |         |              |            |      |
  v         v              |            v      v
quiche  datagram-socket    |        qlog-dancer        (Layer 1)
  |   \     |              |
  v    \    v              v
  tokio-quiche  <----------+                           (Layer 2: depends on most)
  |     |
  v     v
 h3i   apps                                           (Layer 3: end-user tools)
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| QUIC connection logic | `quiche/src/lib.rs` | 9k lines, core `Connection` struct |
| HTTP/3 protocol | `quiche/src/h3/mod.rs` | Own `Error`/`Result` types |
| Congestion control | `quiche/src/recovery/` | Two impls: `congestion/` (legacy) + `gcongestion/` (BBR2) |
| TLS/crypto backends | `quiche/src/tls/`, `quiche/src/crypto/` | BoringSSL + OpenSSL, cfg-gated |
| C FFI | `quiche/src/ffi.rs` + `quiche/include/quiche.h` | Behind `ffi` feature |
| Async server/client | `tokio-quiche/src/` | `ApplicationOverQuic` trait is the extension point |
| H3 async driver | `tokio-quiche/src/http3/driver/` | `DriverHooks` sealed trait, channels |
| QUIC IO worker | `tokio-quiche/src/quic/io/worker.rs` | Connection FSM, GSO/GRO |
| Packet routing | `tokio-quiche/src/quic/router/` | Demux by DCID |
| Test infra | `quiche/src/test_utils.rs` | `Pipe` struct for in-memory QUIC pairs |
| Config cascade | `tokio-quiche/src/settings/` → `quiche::Config` | `ConnectionParams` → `quiche::Config` → `h3::Config` |

## CODE MAP

| Symbol | Type | Location | Role |
|--------|------|----------|------|
| `Connection` | struct | `quiche/src/lib.rs` | Core QUIC connection |
| `Config` | struct | `quiche/src/lib.rs` | Transport configuration |
| `h3::Connection` | struct | `quiche/src/h3/mod.rs` | HTTP/3 over QUIC |
| `ApplicationOverQuic` | trait | `tokio-quiche/src/quic/` | Async app lifecycle hook |
| `H3Driver<H>` | struct | `tokio-quiche/src/http3/driver/` | Generic H3 driver |
| `IoWorker<Tx,M,S>` | struct | `tokio-quiche/src/quic/io/worker.rs` | Per-connection IO loop |
| `Pipe` | struct | `quiche/src/test_utils.rs` | In-memory test connection pair |
| `BufFactory` | trait | `quiche/src/range_buf.rs` | Zero-copy buffer creation |
| `Recovery` | enum | `quiche/src/recovery/mod.rs` | CC dispatch via enum_dispatch |
| `RecoveryOps` | trait | `quiche/src/recovery/mod.rs` | 40+ method CC interface |

## CONVENTIONS

- **Line width 82** (`rustfmt.toml`), comments 80. Nightly rustfmt required.
- **One `use` per item** (`imports_granularity = "Item"`, vertical layout).
- **`pub(crate)`** for cross-module internals; `pub` only for true public API.
- **BSD-2-Clause copyright header** on every `.rs` file.
- **`#[macro_use] extern crate log`** (legacy style, no `use log::*`).
- **Domain abbreviations**: `cid`, `scid`/`dcid`, `pkt`, `dgram`, `bidi`/`uni`, `rtt`.
- **`mod.rs` pattern** for submodules (not inline `foo/` + `foo.rs`).
- **Debug symbols in release** (`profile.release.debug = true`).
- **`#![warn(missing_docs)]`** -- public items must be documented.

## ANTI-PATTERNS (THIS PROJECT)

- **Do not use `any` types or type assertions** -- this is Rust; no equivalent concern, but `unsafe` is restricted to FFI boundaries (`tls/`, `crypto/`, `ffi.rs`, `gso.rs`).
- **Do not add clippy `#[allow]` without justification** -- 33 existing overrides all have documented reasons.
- **Cognitive complexity lint disabled** (`clippy.toml: 100`) -- complex functions accepted for protocol code, but don't add new ones casually.
- **Two `Acked` types exist** in `recovery/congestion` and `recovery/gcongestion` -- not unified, don't create a third.
- **`connection_not_present()` returns `TlsFail`** in tokio-quiche driver -- misleading sentinel, don't propagate this pattern.
- **`Error::Done` used as success signal** in H3 driver write path -- non-obvious, don't replicate.
- **`transmute` of `Instant`** in `gso.rs` -- fragile, platform-dependent, don't extend.

## FEATURE FLAGS

```
quiche:        default=boringssl-vendored | boringssl-boring-crate | openssl
               qlog, gcongestion, internal, ffi, fuzzing, sfv, custom-client-dcid
tokio-quiche:  fuzzing, quiche_internal, gcongestion, zero-copy, rpk
               (hardcodes: quiche/boringssl-boring-crate + quiche/qlog)
h3i:           async (enables tokio-quiche dependency)
```

## COMMANDS

```bash
# Dev
cargo build                                           # build workspace (vendored BoringSSL)
cargo test --all-targets --features=async,ffi,qlog --workspace  # full test suite
cargo test --doc --features=async,ffi,qlog --workspace          # doc tests (separate!)

# Lint
cargo clippy --features=boringssl-vendored --workspace -- -D warnings
cargo fmt -- --check                                  # nightly only

# Fuzz
cargo fuzz run packet_recv_client -- -runs=1

# Docker
make docker-build                                     # quiche-base + quiche-qns images
```

## NOTES

- **Git submodules required**: `git submodule update --init --recursive` for BoringSSL.
- **MSRV 1.85**: `rust-version` field in Cargo.toml.
- **Doc tests are separate**: `cargo test --all-targets` does NOT run doc tests (cargo#6669).
- **`QUICHE_BSSL_PATH`**: env var to skip vendored BoringSSL build (use pre-built).
- **`RUSTFLAGS="-D warnings"`**: CI enforces; all warnings are errors.
- **Cargo.lock is gitignored** (library project).
- **Dual CI**: GitHub Actions (real) + GitLab CI (no-op stub).
- **`cargo package` disabled**: commented out due to unpublished local crate version issues.
