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

/// A name-value pair representing a raw HTTP header.
#[derive(Clone, Debug, PartialEq)]
pub struct Header(String, String);

/// A vector of Headers representing an HTTP header list.
pub type HeaderList = Vec<Header>;

impl Header {
    /// Creates a new header.
    pub fn new(name: &str, value: &str) -> Header {
        Header(String::from(name), String::from(value))
    }

    /// Returns the header's name.
    pub fn name(&self) -> &str {
        &self.0
    }

    /// Returns the header's value.
    pub fn value(&self) -> &str {
        &self.1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode() {
        let mut encoded = [0u8; 240];

        let headers = vec![
            Header::new(":path", "/rsrc.php/v3/yn/r/rIPZ9Qkrdd9.png"),
            Header::new("accept-encoding", "gzip, deflate, br"),
            Header::new("accept-language", "en-US,en;q=0.9"),
            Header::new("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.70 Safari/537.36"),
            Header::new("accept", "image/webp,image/apng,image/*,*/*;q=0.8"),
            Header::new("referer", "https://static.xx.fbcdn.net/rsrc.php/v3/yT/l/0,cross/dzXGESIlGQQ.css"),
            Header::new(":authority", "static.xx.fbcdn.net"),
            Header::new(":scheme", "https"),
            Header::new(":method", "GET"),
        ];

        let mut enc = Encoder::new();
        assert!(enc.encode(&headers, &mut encoded).is_ok());

        let mut dec = Decoder::new();
        assert_eq!(dec.decode(&mut encoded), Ok(headers));
    }
}

pub use decoder::Decoder;
pub use encoder::Encoder;

mod decoder;
mod encoder;
mod huffman;
