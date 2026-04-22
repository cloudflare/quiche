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

//! Writer-reader round-trip tests for [`qlog::writer`].
//!
//! Each test produces a qlog stream via [`qlog::streamer::QlogStreamer`]
//! written through the selected [`qlog::writer::QlogCompression`]
//! variant into a file on disk, then reads the file back via
//! [`qlog::reader::QlogSeqReader::with_file`] and asserts the header
//! plus at least one event round-tripped.
//!
//! These tests do not depend on tokio-quiche or any QUIC connection
//! machinery: they exercise the writer-reader symmetry directly,
//! which is the reusable value of owning compression in the qlog
//! crate.

use std::path::Path;
use std::time::Instant;

use qlog::events::quic;
use qlog::events::EventData;
use qlog::events::EventImportance;
use qlog::events::RawInfo;
use qlog::reader::Event;
use qlog::reader::QlogSeqReader;
use qlog::streamer::EventTimePrecision;
use qlog::streamer::QlogStreamer;
use qlog::testing;
use qlog::writer::make_qlog_writer_from_path;
use qlog::writer::qlog_file_name;
use qlog::writer::QlogCompression;

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
/// finish_log, through `make_qlog_writer_from_path(path,
/// compression)`, and return the path of the emitted file.
fn emit_one_event(
    compression: QlogCompression, dir: &Path,
) -> std::path::PathBuf {
    let path = dir.join(qlog_file_name("test", compression));
    let writer = make_qlog_writer_from_path(&path, compression)
        .expect("make_qlog_writer_from_path");

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

/// Read the leading bytes of `path` and assert they match the magic
/// for `compression`. Catches a regression where a future edit to
/// `make_qlog_writer` silently drops the compressor and emits a raw
/// JSON-SEQ stream into a `.sqlog.gz` / `.sqlog.zst` file: without
/// this check the filename suffix would still match and
/// [`assert_roundtrip`] would only fail later on the decoder side,
/// far from the writer.
fn assert_file_magic(path: &Path, compression: QlogCompression) {
    use std::io::Read;
    let mut bytes = [0u8; 4];
    let n = std::fs::File::open(path)
        .expect("open qlog file")
        .read(&mut bytes)
        .expect("read magic bytes");
    assert!(n >= 4, "qlog file too short to inspect magic: {n} bytes");

    match compression {
        // 0x1e is the JSON-SEQ record separator (RFC 7464). The
        // streamer writes a leading null record so an uncompressed
        // qlog file's first byte is 0x1e.
        QlogCompression::None => assert_eq!(
            bytes[0], 0x1e,
            "expected JSON-SEQ record separator, got {bytes:02x?}"
        ),
        #[cfg(feature = "gzip")]
        QlogCompression::Gzip => assert_eq!(
            &bytes[..3],
            &[0x1f, 0x8b, 0x08],
            "expected gzip magic, got {bytes:02x?}"
        ),
        #[cfg(feature = "zstd")]
        QlogCompression::Zstd => assert_eq!(
            &bytes[..4],
            &[0x28, 0xb5, 0x2f, 0xfd],
            "expected zstd magic, got {bytes:02x?}"
        ),
    }
}

#[test]
fn roundtrip_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = emit_one_event(QlogCompression::None, dir.path());
    assert!(
        path.to_str().unwrap().ends_with(".sqlog"),
        "expected .sqlog extension, got {path:?}"
    );
    assert_file_magic(&path, QlogCompression::None);
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
    assert_file_magic(&path, QlogCompression::Gzip);
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
    assert_file_magic(&path, QlogCompression::Zstd);
    // If `ZstdFinishOnDrop::drop` failed to write the trailer,
    // `QlogSeqReader::with_file` would observe a truncated frame and
    // either fail to parse the header or the iterator would stop
    // early.
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

    assert_file_magic(&gz, QlogCompression::Gzip);
    assert_file_magic(&zst, QlogCompression::Zstd);
    assert_roundtrip(&gz);
    assert_roundtrip(&zst);
}

/// Run `QlogSeqReader::with_file(path)`, expect an error, and assert
/// the error message contains `expected_substr`. Mirrors
/// `Result::expect_err` but does not require `T: Debug`
/// ([`QlogSeqReader`] does not implement [`std::fmt::Debug`]).
fn assert_with_file_err(path: &Path, expected_substr: &str) {
    match QlogSeqReader::with_file(path) {
        Ok(_) => panic!("expected error, got Ok for {path:?}"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains(expected_substr),
                "expected error message containing {expected_substr:?}, \
                 got {msg:?}"
            );
        },
    }
}

/// Regression test: `QlogSeqReader::with_file` must reject filenames
/// that have a `.gz` or `.zst` extension but lack the `.sqlog`
/// segment. The earlier implementation used [`std::path::Path::extension`],
/// which strips only the last component and would have accepted
/// `archive.tar.gz` as a gzip-compressed qlog.
#[cfg(feature = "gzip")]
#[test]
fn rejects_non_qlog_gz_extension() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("archive.tar.gz");
    std::fs::write(&path, b"not a qlog file").expect("write");
    assert_with_file_err(&path, "does not match a known qlog extension");
}

/// Regression test: a bare `.gz` extension (without `.sqlog`) is also
/// rejected. The legacy single-component extension match silently
/// accepted these.
#[cfg(feature = "gzip")]
#[test]
fn rejects_bare_gz_extension() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("data.gz");
    std::fs::write(&path, b"not a qlog file").expect("write");
    assert_with_file_err(&path, "does not match a known qlog extension");
}

/// Regression test: a bare `.zst` extension (without `.sqlog`) is
/// rejected. Symmetric to [`rejects_bare_gz_extension`].
#[cfg(feature = "zstd")]
#[test]
fn rejects_bare_zst_extension() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("data.zst");
    std::fs::write(&path, b"not a qlog file").expect("write");
    assert_with_file_err(&path, "does not match a known qlog extension");
}

/// Regression test: unknown extensions surface a clear error message.
#[test]
fn rejects_unknown_extension() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("data.txt");
    std::fs::write(&path, b"not a qlog file").expect("write");
    assert_with_file_err(&path, "does not match a known qlog extension");
}
