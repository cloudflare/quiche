// Copyright (C) 2026, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Thin integration test: drive a real tokio-quiche server+client
//! handshake with `QuicSettings::qlog_compression` set, and assert
//! the server produces a qlog file with the expected extension.
//!
//! Full writer-reader round-trips (decoding the file, validating the
//! JSON-SEQ structure, asserting events are present) live in the
//! `qlog` crate's `compression_roundtrip` integration test. This
//! file's only job is to confirm the `QuicSettings -> Config ->
//! ConnectionAcceptorConfig` plumbing threads the compression
//! selection all the way to the emitted file on disk.

#[cfg(all(feature = "qlog-gzip", feature = "qlog-zstd"))]
use crate::fixtures::*;

#[cfg(all(feature = "qlog-gzip", feature = "qlog-zstd"))]
use std::time::Duration;

#[cfg(all(feature = "qlog-gzip", feature = "qlog-zstd"))]
use tokio::time::sleep;
#[cfg(all(feature = "qlog-gzip", feature = "qlog-zstd"))]
use tokio_quiche::settings::QlogCompression;

/// Short sleep used after the request completes but before we read
/// the qlog file, so the server-side connection's drop path runs
/// and the compressor's end-of-stream trailer (if any) is flushed.
/// Connection teardown on localhost typically takes <10 ms; 200 ms
/// is generous and keeps the test fast.
#[cfg(all(feature = "qlog-gzip", feature = "qlog-zstd"))]
const DRAIN_DELAY: Duration = Duration::from_millis(200);

/// Drive one H3 request against a server configured with the given
/// `compression` + `qlog_dir`, wait for the drop path to flush, and
/// assert the server produced a file whose name ends with
/// `expected_suffix`.
#[cfg(all(feature = "qlog-gzip", feature = "qlog-zstd"))]
async fn assert_server_emits_suffix(
    compression: QlogCompression, expected_suffix: &str,
) {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut quic_settings = QuicSettings::default();
    quic_settings.qlog_dir = Some(dir.path().to_string_lossy().into_owned());
    quic_settings.qlog_compression = compression;

    let hook = TestConnectionHook::new();
    let (url, _audit_rx) = start_server_with_settings(
        quic_settings,
        Http3Settings::default(),
        hook,
        handle_connection,
    );

    let url = format!("{url}/1");
    let _ = request(url, 1).await.expect("request failed");

    sleep(DRAIN_DELAY).await;

    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("qlog dir readable")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "expected 1 qlog file under {:?}, got {entries:?}",
        dir.path()
    );
    let name = entries[0]
        .file_name()
        .and_then(|s| s.to_str())
        .expect("file name");
    assert!(
        name.ends_with(expected_suffix),
        "expected name ending in {expected_suffix}, got {name}"
    );
}

/// Proves the full `QuicSettings::qlog_compression` plumbing path by
/// driving two real handshakes back-to-back with gzip and zstd, and
/// asserting each produced the correct file extension on disk. The
/// file *contents* are covered by the qlog crate's round-trip tests;
/// this test is about TQ-side plumbing.
#[cfg(all(feature = "qlog-gzip", feature = "qlog-zstd"))]
#[tokio::test]
async fn qlog_compression_threads_through_to_disk() {
    assert_server_emits_suffix(QlogCompression::Gzip, ".sqlog.gz").await;
    assert_server_emits_suffix(QlogCompression::Zstd, ".sqlog.zst").await;
}
