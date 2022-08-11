// Copyright (C) 2019, Cloudflare, Inc.
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

//! HTTP/3 header compression (QPACK).

const INDEXED: u8 = 0b1000_0000;
const INDEXED_WITH_POST_BASE: u8 = 0b0001_0000;
const LITERAL: u8 = 0b0010_0000;
const LITERAL_WITH_NAME_REF: u8 = 0b0100_0000;

/// A specialized [`Result`] type for quiche QPACK operations.
///
/// This type is used throughout quiche's QPACK public API for any operation
/// that can produce an error.
///
/// [`Result`]: https://doc.rust-lang.org/std/result/enum.Result.html
pub type Result<T> = std::result::Result<T, Error>;

/// A QPACK error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The provided buffer is too short.
    BufferTooShort,

    /// The QPACK header block's huffman encoding is invalid.
    InvalidHuffmanEncoding,

    /// The QPACK static table index provided doesn't exist.
    InvalidStaticTableIndex,

    /// The decoded QPACK header name or value is not valid.
    InvalidHeaderValue,

    /// The decoded header list exceeded the size limit.
    HeaderListTooLarge,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::convert::From<octets::BufferTooShortError> for Error {
    fn from(_err: octets::BufferTooShortError) -> Self {
        Error::BufferTooShort
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    use super::*;

    #[test]
    fn encode_decode() {
        let mut encoded = [0u8; 240];

        let headers = vec![
            h3::Header::new(b":path", b"/rsrc.php/v3/yn/r/rIPZ9Qkrdd9.png"),
            h3::Header::new(b"accept-encoding", b"gzip, deflate, br"),
            h3::Header::new(b"accept-language", b"en-US,en;q=0.9"),
            h3::Header::new(b"user-agent", b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.70 Safari/537.36"),
            h3::Header::new(b"accept", b"image/webp,image/apng,image/*,*/*;q=0.8"),
            h3::Header::new(b"referer", b"https://static.xx.fbcdn.net/rsrc.php/v3/yT/l/0,cross/dzXGESIlGQQ.css"),
            h3::Header::new(b":authority", b"static.xx.fbcdn.net"),
            h3::Header::new(b":scheme", b"https"),
            h3::Header::new(b":method", b"GET"),
        ];

        let mut enc = Encoder::new();
        assert_eq!(enc.encode(&headers, &mut encoded), Ok(240));

        let mut dec = Decoder::new();
        assert_eq!(dec.decode(&mut encoded, std::u64::MAX), Ok(headers));
    }

    #[test]
    fn lower_case() {
        let mut encoded = [0u8; 35];

        let headers_expected = vec![
            crate::h3::Header::new(b":status", b"200"),
            crate::h3::Header::new(b":path", b"/HeLlO"),
            crate::h3::Header::new(b"woot", b"woot"),
            crate::h3::Header::new(b"hello", b"WorlD"),
            crate::h3::Header::new(b"foo", b"BaR"),
        ];

        // Header.
        let headers_in = vec![
            crate::h3::Header::new(b":StAtUs", b"200"),
            crate::h3::Header::new(b":PaTh", b"/HeLlO"),
            crate::h3::Header::new(b"WooT", b"woot"),
            crate::h3::Header::new(b"hello", b"WorlD"),
            crate::h3::Header::new(b"fOo", b"BaR"),
        ];

        let mut enc = Encoder::new();
        assert_eq!(enc.encode(&headers_in, &mut encoded), Ok(35));

        let mut dec = Decoder::new();
        let headers_out = dec.decode(&mut encoded, std::u64::MAX).unwrap();

        assert_eq!(headers_expected, headers_out);

        // HeaderRef.
        let headers_in = vec![
            crate::h3::HeaderRef::new(b":StAtUs", b"200"),
            crate::h3::HeaderRef::new(b":PaTh", b"/HeLlO"),
            crate::h3::HeaderRef::new(b"WooT", b"woot"),
            crate::h3::HeaderRef::new(b"hello", b"WorlD"),
            crate::h3::HeaderRef::new(b"fOo", b"BaR"),
        ];

        let mut enc = Encoder::new();
        assert_eq!(enc.encode(&headers_in, &mut encoded), Ok(35));

        let mut dec = Decoder::new();
        let headers_out = dec.decode(&mut encoded, std::u64::MAX).unwrap();

        assert_eq!(headers_expected, headers_out);
    }
}

pub use decoder::Decoder;
pub use encoder::Encoder;

mod decoder;
mod encoder;
mod huffman;
mod static_table;
