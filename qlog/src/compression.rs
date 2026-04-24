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

//! Compressed QLOG output support.
//!
//! This module owns the writer-side plumbing for emitting compressed
//! JSON-SEQ qlog streams. It is a deliberate exception to the qlog
//! crate's otherwise pure-data posture: the writer helpers and the
//! enum live here so that any consumer (tokio-quiche,
//! [`crate::reader::QlogSeqReader::with_file`], external tooling)
//! shares a single canonical compression story.
//!
//! Compression is opt-in via Cargo features:
//! * `gzip` pulls in [`flate2`].
//! * `zstd` pulls in the [`zstd`] crate (C dependency via `zstd-sys`).
//!
//! The [`QlogCompression`] enum's `Gzip` and `Zstd` variants are
//! compile-time gated on their respective features, so a build that
//! disables one of them cannot construct the unsupported variant.
//!
//! Bytes flow `producer -> [compressor] -> W` where `W` is any
//! `Write + Send + Sync + 'static`. No buffering is added here: both
//! `flate2` and `zstd` emit output in large chunks (DEFLATE blocks /
//! zstd frames), so an extra `BufWriter` is redundant; callers are
//! free to add one if they need to.

/// Compression algorithm applied to QLOG output streams.
///
/// `None` is always available. `Gzip` and `Zstd` are compile-time
/// gated on the `gzip` and `zstd` Cargo features respectively; a
/// build that disables one of those features cannot reference the
/// corresponding variant.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    serde::Deserialize,
    serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum QlogCompression {
    /// No compression. Emit raw `.sqlog` files.
    #[default]
    None,
    /// Gzip streaming compression (DEFLATE + gzip framing). Emits
    /// `.sqlog.gz` files. Requires the `gzip` Cargo feature.
    #[cfg(feature = "gzip")]
    Gzip,
    /// Zstd streaming compression. Emits `.sqlog.zst` files. Requires
    /// the `zstd` Cargo feature.
    #[cfg(feature = "zstd")]
    Zstd,
}

#[cfg(feature = "foundations")]
impl foundations::settings::Settings for QlogCompression {}

/// Return the qlog filename (not including the directory) that
/// matches `compression` for a stream whose identifier is `id`.
///
/// Kept alongside [`make_qlog_writer`] so the filename convention
/// lives in one place: `<id>.sqlog`, `<id>.sqlog.gz`, or
/// `<id>.sqlog.zst`.
pub fn qlog_file_name(id: &str, compression: QlogCompression) -> String {
    match compression {
        QlogCompression::None => format!("{id}.sqlog"),
        #[cfg(feature = "gzip")]
        QlogCompression::Gzip => format!("{id}.sqlog.gz"),
        #[cfg(feature = "zstd")]
        QlogCompression::Zstd => format!("{id}.sqlog.zst"),
    }
}

/// Wrap `inner` in the streaming encoder selected by `compression`
/// and return a boxed `Write` that a qlog producer (e.g. quiche via
/// `set_qlog`) writes into.
///
/// The generic `W` bound lets production call sites pass a
/// `std::fs::File` while tests can pass an in-process buffer (e.g.
/// `Vec<u8>`). No buffering is added here.
pub fn make_qlog_writer<W>(
    inner: W, compression: QlogCompression,
) -> std::io::Result<Box<dyn std::io::Write + Send + Sync>>
where
    W: std::io::Write + Send + Sync + 'static,
{
    match compression {
        QlogCompression::None => Ok(Box::new(inner)),
        #[cfg(feature = "gzip")]
        QlogCompression::Gzip => {
            let encoder = flate2::write::GzEncoder::new(
                inner,
                flate2::Compression::default(),
            );
            Ok(Box::new(encoder))
        },
        #[cfg(feature = "zstd")]
        QlogCompression::Zstd => {
            // Level 3 is the zstd default: a balanced point on the
            // ratio-vs-speed curve.
            let encoder = zstd::Encoder::new(inner, 3)?;
            Ok(Box::new(ZstdFinishOnDrop {
                encoder: Some(encoder),
            }))
        },
    }
}

/// `Write` wrapper that calls [`zstd::Encoder::finish`] on drop so
/// the zstd frame trailer is written to the inner sink.
///
/// `zstd::Encoder` does not flush its frame trailer implicitly on
/// drop, so a qlog stream written through a bare `Encoder` would be
/// missing the end-of-frame marker and fail to decode.
/// `AutoFinishEncoder` from the `zstd` crate solves this but is
/// `!Sync` (it stores a user-supplied `FnMut` closure), while some
/// producers (e.g. `quiche::Connection::set_qlog`) require
/// `Send + Sync`. This local wrapper preserves those bounds because
/// it only holds an `Option<Encoder<_, W>>`, where `Encoder` is
/// `Send + Sync` whenever `W` is.
#[cfg(feature = "zstd")]
struct ZstdFinishOnDrop<W: std::io::Write> {
    encoder: Option<zstd::Encoder<'static, W>>,
}

#[cfg(feature = "zstd")]
impl<W: std::io::Write> std::io::Write for ZstdFinishOnDrop<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.encoder
            .as_mut()
            .expect("encoder present until drop")
            .write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.encoder
            .as_mut()
            .expect("encoder present until drop")
            .flush()
    }
}

#[cfg(feature = "zstd")]
impl<W: std::io::Write> Drop for ZstdFinishOnDrop<W> {
    fn drop(&mut self) {
        if let Some(encoder) = self.encoder.take() {
            if let Err(error) = encoder.finish() {
                // qlog crate has no structured-logging dependency; use
                // `eprintln!` so trailer-flush failures surface on
                // stderr rather than silently truncating the stream.
                eprintln!("qlog: failed to finish zstd encoder: {error}");
            }
        }
    }
}
