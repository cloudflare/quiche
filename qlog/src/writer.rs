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

//! QLOG file writer plumbing -- compression-aware companion to
//! [`crate::reader`].
//!
//! This module owns the writer-side surface for emitting JSON-SEQ
//! qlog streams, optionally wrapped in a streaming compressor. It is
//! a deliberate exception to the qlog crate's otherwise pure-data
//! posture: the writer helpers, the compression enum, and the
//! filename / extension conventions live here so any consumer
//! (tokio-quiche, [`crate::reader::QlogSeqReader::with_file`],
//! external tooling) shares a single canonical writer story.
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

use std::fs::File;
use std::io;
use std::io::Write;
use std::path::Path;

use crate::SQLOG_EXT;
#[cfg(feature = "gzip")]
use crate::SQLOG_GZ_EXT;
#[cfg(feature = "zstd")]
use crate::SQLOG_ZST_EXT;

/// Boxed `Write` returned by [`make_qlog_writer`] /
/// [`make_qlog_writer_from_path`].
///
/// Producers (e.g. `quiche::Connection::set_qlog`) typically require
/// `Send + Sync`; the boxed form keeps the writer object-safe across
/// the compression-vs-no-compression branches.
pub type QlogFileWriter = Box<dyn Write + Send + Sync>;

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

/// Return the qlog filename (not including the directory) for a
/// stream whose identifier is `id`, with the suffix matching
/// `compression`: `<id>.sqlog`, `<id>.sqlog.gz`, or `<id>.sqlog.zst`.
pub fn qlog_file_name(id: &str, compression: QlogCompression) -> String {
    match compression {
        QlogCompression::None => format!("{id}{SQLOG_EXT}"),
        #[cfg(feature = "gzip")]
        QlogCompression::Gzip => format!("{id}{SQLOG_GZ_EXT}"),
        #[cfg(feature = "zstd")]
        QlogCompression::Zstd => format!("{id}{SQLOG_ZST_EXT}"),
    }
}

/// Wrap `inner` in the streaming encoder selected by `compression`
/// and return a boxed `Write` that a qlog producer (e.g. quiche via
/// `set_qlog`) writes into.
///
/// The generic `W` bound lets production call sites pass a
/// `std::fs::File` while tests can pass an in-process buffer (e.g.
/// `Vec<u8>`). For the common case of "open a file at this path and
/// pick the compressor by extension" use
/// [`make_qlog_writer_from_path`].
///
/// No buffering is added here.
pub fn make_qlog_writer<W>(
    inner: W, compression: QlogCompression,
) -> io::Result<QlogFileWriter>
where
    W: Write + Send + Sync + 'static,
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

/// Convenience function to create a File at `path` with a writer
/// based on `compression`.
///
/// Equivalent to manually creating a File and passing it to
/// [`make_qlog_writer`].
pub fn make_qlog_writer_from_path<P: AsRef<Path>>(
    path: P, compression: QlogCompression,
) -> io::Result<QlogFileWriter> {
    let file = File::create(path.as_ref())?;
    make_qlog_writer(file, compression)
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
struct ZstdFinishOnDrop<W: Write> {
    encoder: Option<zstd::Encoder<'static, W>>,
}

#[cfg(feature = "zstd")]
impl<W: Write> Write for ZstdFinishOnDrop<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.encoder
            .as_mut()
            .expect("encoder present until drop")
            .write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.encoder
            .as_mut()
            .expect("encoder present until drop")
            .flush()
    }
}

#[cfg(feature = "zstd")]
impl<W: Write> Drop for ZstdFinishOnDrop<W> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_name_uses_constants_for_none() {
        let name = qlog_file_name("abc", QlogCompression::None);
        assert_eq!(name, "abc.sqlog");
        assert!(name.ends_with(SQLOG_EXT));
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn file_name_uses_constants_for_gzip() {
        let name = qlog_file_name("abc", QlogCompression::Gzip);
        assert_eq!(name, "abc.sqlog.gz");
        assert!(name.ends_with(SQLOG_GZ_EXT));
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn file_name_uses_constants_for_zstd() {
        let name = qlog_file_name("abc", QlogCompression::Zstd);
        assert_eq!(name, "abc.sqlog.zst");
        assert!(name.ends_with(SQLOG_ZST_EXT));
    }
}
