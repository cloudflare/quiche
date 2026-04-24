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

//! Writer-reader round-trip tests for [`qlog::compression`].
//!
//! Each test produces a qlog stream via [`qlog::streamer::QlogStreamer`]
//! written through the selected [`qlog::compression::QlogCompression`]
//! variant into a file on disk, then reads the file back via
//! [`qlog::reader::QlogSeqReader::with_file`] and asserts the header
//! plus at least one event round-tripped.
//!
//! These tests do not depend on tokio-quiche or any QUIC connection
//! machinery: they exercise the writer-reader symmetry directly, which
//! is the reusable value of owning compression in the qlog crate.

use std::path::Path;
use std::time::Instant;

use qlog::compression::make_qlog_writer;
use qlog::compression::qlog_file_name;
use qlog::compression::QlogCompression;
use qlog::events::quic;
use qlog::events::EventData;
use qlog::events::EventImportance;
use qlog::events::RawInfo;
use qlog::reader::Event;
use qlog::reader::QlogSeqReader;
use qlog::streamer::EventTimePrecision;
use qlog::streamer::QlogStreamer;
use qlog::testing;

/// Minimal qlog event used by every round-trip test: a single
/// `quic:packet_sent`. The specific contents do not matter for this
/// test -- we just need the reader to parse at least one event.
fn make_event() -> EventData {
    EventData::QuicPacketSent(quic::PacketSent {
        header: testing::make_pkt_hdr(quic::PacketType::Handshake),
        frames: Some(vec![quic::QuicFrame::Stream {
            stream_id: 0,
            offset: Some(0),
            raw: Some(Box::new(RawInfo {
                length: None,
                payload_length: Some(100),
                data: None,
            })),
            fin: Some(true),
        }]),
        raw: Some(RawInfo {
            length: Some(1251),
            payload_length: Some(1224),
            data: None,
        }),
        ..Default::default()
    })
}

/// Drive a `QlogStreamer` from start_log through one event to
/// finish_log, through `make_qlog_writer(file, compression)`, and
/// return the path of the emitted file.
fn emit_one_event(
    compression: QlogCompression, dir: &Path,
) -> std::path::PathBuf {
    let path = dir.join(qlog_file_name("test", compression));
    let file = std::fs::File::create(&path).expect("create qlog file");
    let writer = make_qlog_writer(file, compression).expect("make writer");

    let mut streamer = QlogStreamer::new(
        Some("round-trip test".to_string()),
        Some("round-trip description".to_string()),
        Instant::now(),
        testing::make_trace_seq(),
        EventImportance::Base,
        EventTimePrecision::NanoSeconds,
        writer,
    );

    streamer.start_log().expect("start_log");
    streamer
        .add_event_data_now(make_event())
        .expect("add_event_data_now");
    streamer.finish_log().expect("finish_log");

    // Drop the streamer so the compressor's frame trailer is flushed
    // (in particular for the zstd variant, which relies on
    // `ZstdFinishOnDrop::drop` to write the trailer).
    drop(streamer);

    path
}

/// Open `path` via `QlogSeqReader::with_file` and assert the header
/// plus at least one event are produced.
fn assert_roundtrip(path: &Path) {
    let mut reader =
        QlogSeqReader::with_file(path).expect("QlogSeqReader::with_file");
    let header = reader.qlog.clone();
    let events: Vec<Event> = (&mut reader).collect();

    assert_eq!(header.serialization_format, "JSON-SEQ");
    assert!(!events.is_empty(), "expected at least one qlog event");
}

#[test]
fn roundtrip_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = emit_one_event(QlogCompression::None, dir.path());
    assert_eq!(
        path.extension().and_then(|s| s.to_str()),
        Some("sqlog"),
        "expected .sqlog extension"
    );
    assert_roundtrip(&path);
}

#[cfg(feature = "gzip")]
#[test]
fn roundtrip_gzip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = emit_one_event(QlogCompression::Gzip, dir.path());
    assert!(
        path.to_str().unwrap().ends_with(".sqlog.gz"),
        "expected .sqlog.gz extension, got {path:?}"
    );
    assert_roundtrip(&path);
}

#[cfg(feature = "zstd")]
#[test]
fn roundtrip_zstd() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = emit_one_event(QlogCompression::Zstd, dir.path());
    assert!(
        path.to_str().unwrap().ends_with(".sqlog.zst"),
        "expected .sqlog.zst extension, got {path:?}"
    );
    // If `ZstdFinishOnDrop::drop` failed to write the trailer,
    // `QlogSeqReader::with_file` would observe a truncated frame and
    // either fail to parse the header or the iterator would stop early.
    assert_roundtrip(&path);
}

/// Proves that both the `gzip` and `zstd` features can be enabled in
/// the same binary and that writer + reader pick the correct
/// decoder by extension for each.
#[cfg(all(feature = "gzip", feature = "zstd"))]
#[test]
fn roundtrip_both_features_coexist() {
    let dir = tempfile::tempdir().expect("tempdir");
    let gz = emit_one_event(QlogCompression::Gzip, dir.path());
    // Second file goes into a separate subdir so the two paths don't
    // collide (both use id = "test").
    let zst_dir = dir.path().join("zstd-subdir");
    std::fs::create_dir(&zst_dir).expect("create subdir");
    let zst = emit_one_event(QlogCompression::Zstd, &zst_dir);

    assert_roundtrip(&gz);
    assert_roundtrip(&zst);
}
