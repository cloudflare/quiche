// Copyright (C) 2023, Cloudflare, Inc.
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

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use crate::QlogSeq;

/// Represents the format of the read event.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum Event {
    /// A native qlog event type.
    Qlog(crate::events::Event),

    // An extended JSON event type.
    Json(crate::events::JsonEvent),
}

/// A helper object specialized for reading JSON-SEQ qlog from a [`BufRead`]
/// trait.
///
/// [`BufRead`]: https://doc.rust-lang.org/std/io/trait.BufRead.html
pub struct QlogSeqReader<'a> {
    pub qlog: QlogSeq,
    reader: Box<dyn std::io::BufRead + Send + Sync + 'a>,
}

impl<'a> QlogSeqReader<'a> {
    pub fn new(
        mut reader: Box<dyn std::io::BufRead + Send + Sync + 'a>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // "null record" skip it
        Self::read_record(reader.as_mut());

        let header = Self::read_record(reader.as_mut()).ok_or_else(|| {
            std::io::Error::other("error reading file header bytes")
        })?;

        let res: Result<QlogSeq, serde_json::Error> =
            serde_json::from_slice(&header);
        match res {
            Ok(qlog) => Ok(Self { qlog, reader }),

            Err(e) => Err(e.into()),
        }
    }

    /// Convenience constructor that opens `path` and picks a streaming
    /// decoder based on the file extension:
    ///
    /// * `.sqlog` -> raw JSON-SEQ (always available).
    /// * `.sqlog.gz` -> gzip via `flate2` (requires the `gzip` feature).
    /// * `.sqlog.zst` -> zstd via `zstd` (requires the `zstd` feature).
    ///
    /// Unknown extensions, or compressed extensions whose matching
    /// feature is not enabled, return an [`std::io::ErrorKind::Unsupported`]
    /// error with a message pointing at the feature that is needed.
    ///
    /// This is the intended single entry point for reading a qlog
    /// file regardless of compression.
    pub fn with_file(
        path: impl AsRef<Path>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let path = path.as_ref();
        let file = File::open(path)?;
        let ext = path.extension().and_then(|s| s.to_str());

        let reader: Box<dyn std::io::BufRead + Send + Sync> = match ext {
            Some("sqlog") | None => Box::new(BufReader::new(file)),
            #[cfg(feature = "gzip")]
            Some("gz") =>
                Box::new(BufReader::new(flate2::read::GzDecoder::new(file))),
            #[cfg(feature = "zstd")]
            Some("zst") => {
                let decoder = zstd::Decoder::new(file)?;
                Box::new(BufReader::new(decoder))
            },
            Some(other) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!(
                        "qlog file extension {other:?} requires a \
                         matching feature on the qlog crate (enable \
                         `gzip` for .gz, `zstd` for .zst)"
                    ),
                )
                .into());
            },
        };

        Self::new(reader)
    }

    fn read_record(
        reader: &mut (dyn std::io::BufRead + Send + Sync),
    ) -> Option<Vec<u8>> {
        let mut buf = Vec::<u8>::new();
        let size = reader.read_until(b'', &mut buf).unwrap();
        if size <= 1 {
            return None;
        }

        buf.truncate(buf.len() - 1);

        Some(buf)
    }
}

impl Iterator for QlogSeqReader<'_> {
    type Item = Event;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        // Attempt to deserialize events but skip them if that fails for any
        // reason, ensuring we always read all bytes in the reader.
        while let Some(bytes) = Self::read_record(&mut self.reader) {
            let r: serde_json::Result<crate::events::Event> =
                serde_json::from_slice(&bytes);

            if let Ok(event) = r {
                return Some(Event::Qlog(event));
            }

            let r: serde_json::Result<crate::events::JsonEvent> =
                serde_json::from_slice(&bytes);

            if let Ok(event) = r {
                return Some(Event::Json(event));
            }
        }

        None
    }
}
