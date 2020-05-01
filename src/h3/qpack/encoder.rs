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

use super::Result;

use crate::octets;

use crate::h3::Header;

use super::INDEXED;
use super::LITERAL;
use super::LITERAL_WITH_NAME_REF;

/// A QPACK encoder.
pub struct Encoder {}

impl Default for Encoder {
    fn default() -> Encoder {
        Encoder {}
    }
}

impl Encoder {
    /// Creates a new QPACK encoder.
    pub fn new() -> Encoder {
        Encoder::default()
    }

    /// Encodes a list of headers into a QPACK header block.
    pub fn encode(
        &mut self, headers: &[Header], out: &mut [u8],
    ) -> Result<usize> {
        let mut b = octets::OctetsMut::with_slice(out);

        // Request Insert Count.
        encode_int(0, 0, 8, &mut b)?;

        // Base.
        encode_int(0, 0, 7, &mut b)?;

        for h in headers {
            match lookup_static(h) {
                Some((idx, true)) => {
                    const STATIC: u8 = 0x40;

                    // Encode as statically indexed.
                    encode_int(idx, INDEXED | STATIC, 6, &mut b)?;
                },

                Some((idx, false)) => {
                    const STATIC: u8 = 0x10;

                    // Encode value as literal with static name reference.
                    encode_int(idx, LITERAL_WITH_NAME_REF | STATIC, 4, &mut b)?;
                    encode_str(&h.1, 7, &mut b)?;
                },

                None => {
                    // Encode as fully literal.
                    let name_len =
                        super::huffman::encode_output_length(h.0.as_bytes())?;

                    encode_int(name_len as u64, LITERAL | 0x08, 3, &mut b)?;

                    super::huffman::encode(h.0.as_bytes(), &mut b)?;

                    encode_str(&h.1, 7, &mut b)?;
                },
            };
        }

        Ok(b.off())
    }
}

fn lookup_static(h: &Header) -> Option<(u64, bool)> {
    let name = h.0.as_ref();
    let value = h.1.as_ref();

    let idx = match (name, value) {
        (":authority", _) => (0, false),
        (":path", "/") => (1, true),
        ("age", "0") => (2, true),
        ("content-disposition", _) => (3, false),
        ("content-length", "0") => (4, true),
        ("cookie", _) => (5, false),
        ("date", _) => (6, false),
        ("etag", _) => (7, false),
        ("if-modified-since", _) => (8, false),
        ("if-none-match", _) => (9, false),
        ("last-modified", _) => (10, false),
        ("link", _) => (11, false),
        ("location", _) => (12, false),
        ("referer", _) => (13, false),
        ("set-cookie", _) => (14, false),
        (":method", "CONNECT") => (15, true),
        (":method", "DELETE") => (16, true),
        (":method", "GET") => (17, true),
        (":method", "HEAD") => (18, true),
        (":method", "OPTIONS") => (19, true),
        (":method", "POST") => (20, true),
        (":method", "PUT") => (21, true),
        (":scheme", "http") => (22, true),
        (":scheme", "https") => (23, true),
        (":status", "103") => (24, true),
        (":status", "200") => (25, true),
        (":status", "304") => (26, true),
        (":status", "404") => (27, true),
        (":status", "503") => (28, true),
        ("accept", "*/*") => (29, true),
        ("accept", "application/dns-message") => (30, true),
        ("accept-encoding", "gzip, deflate, br") => (31, true),
        ("accept-ranges", "bytes") => (32, true),
        ("access-control-allow-headers", "cache-control") => (33, true),
        ("access-control-allow-headers", "content-type") => (34, true),
        ("access-control-allow-origin", "*") => (35, true),
        ("cache-control", "max-age=0") => (36, true),
        ("cache-control", "max-age=2592000") => (37, true),
        ("cache-control", "max-age=604800") => (38, true),
        ("cache-control", "no-cache") => (39, true),
        ("cache-control", "no-store") => (40, true),
        ("cache-control", "public, max-age=31536000") => (41, true),
        ("content-encoding", "br") => (42, true),
        ("content-encoding", "gzip") => (43, true),
        ("content-type", "application/dns-message") => (44, true),
        ("content-type", "application/javascript") => (45, true),
        ("content-type", "application/json") => (46, true),
        ("content-type", "application/x-www-form-urlencoded") => (47, true),
        ("content-type", "image/gif") => (48, true),
        ("content-type", "image/jpeg") => (49, true),
        ("content-type", "image/png") => (50, true),
        ("content-type", "text/css") => (51, true),
        ("content-type", "text/html; charset=utf-8") => (52, true),
        ("content-type", "text/plain") => (53, true),
        ("content-type", "text/plain;charset=utf-8") => (54, true),
        ("range", "bytes=0-") => (55, true),
        ("strict-transport-security", "max-age=31536000") => (56, true),
        ("strict-transport-security", "max-age=31536000; includesubdomains") =>
            (57, true),
        (
            "strict-transport-security",
            "max-age=31536000; includesubdomains; preload",
        ) => (58, true),
        ("vary", "accept-encoding") => (59, true),
        ("vary", "origin") => (60, true),
        ("x-content-type-options", "nosniff") => (61, true),
        ("x-xss-protection", "1; mode=block") => (62, true),
        (":status", "100") => (63, true),
        (":status", "204") => (64, true),
        (":status", "206") => (65, true),
        (":status", "302") => (66, true),
        (":status", "400") => (67, true),
        (":status", "403") => (68, true),
        (":status", "421") => (69, true),
        (":status", "425") => (70, true),
        (":status", "500") => (71, true),
        ("accept-language", _) => (72, false),
        ("access-control-allow-credentials", "FALSE") => (73, true),
        ("access-control-allow-credentials", "TRUE") => (74, true),
        ("access-control-allow-headers", "*") => (75, true),
        ("access-control-allow-methods", "get") => (76, true),
        ("access-control-allow-methods", "get, post, options") => (77, true),
        ("access-control-allow-methods", "options") => (78, true),
        ("access-control-expose-headers", "content-length") => (79, true),
        ("access-control-request-headers", "content-type") => (80, true),
        ("access-control-request-method", "get") => (81, true),
        ("access-control-request-method", "post") => (82, true),
        ("alt-svc", "clear") => (83, true),
        ("authorization", _) => (84, false),
        (
            "content-security-policy",
            "script-src 'none'; object-src 'none'; base-uri 'none'",
        ) => (85, true),
        ("early-data", "1") => (86, true),
        ("expect-ct", _) => (87, false),
        ("forwarded", _) => (88, false),
        ("if-range", _) => (89, false),
        ("origin", _) => (90, false),
        ("purpose", "prefetch") => (91, true),
        ("server", _) => (92, false),
        ("timing-allow-origin", "*") => (93, true),
        ("upgrade-insecure-requests", "1") => (94, true),
        ("user-agent", _) => (95, false),
        ("x-forwarded-for", _) => (96, false),
        ("x-frame-options", "deny") => (97, true),
        ("x-frame-options", "sameorigin") => (98, true),

        (":path", _) => (1, false),
        ("age", _) => (2, false),
        ("content-length", _) => (4, false),
        (":method", _) => (15, false),
        (":scheme", _) => (22, false),
        (":status", _) => (24, false),
        ("accept", _) => (29, false),
        ("accept-encoding", _) => (31, false),
        ("accept-ranges", _) => (32, false),
        ("access-control-allow-headers", _) => (33, false),
        ("access-control-allow-origin", _) => (35, false),
        ("cache-control", _) => (36, false),
        ("content-encoding", _) => (42, false),
        ("content-type", _) => (44, false),
        ("range", _) => (55, false),
        ("strict-transport-security", _) => (56, false),
        ("vary", _) => (59, false),
        ("x-content-type-options", _) => (61, false),
        ("x-xss-protection", _) => (62, false),
        ("access-control-allow-credentials", _) => (73, false),
        ("access-control-allow-methods", _) => (76, false),
        ("access-control-expose-headers", _) => (79, false),
        ("access-control-request-headers", _) => (80, false),
        ("access-control-request-method", _) => (81, false),
        ("alt-svc", _) => (83, false),
        ("content-security-policy", _) => (85, false),
        ("early-data", _) => (86, false),
        ("purpose", _) => (91, false),
        ("timing-allow-origin", _) => (93, false),
        ("upgrade-insecure-requests", _) => (94, false),
        ("x-frame-options", _) => (97, false),

        _ => return None,
    };

    Some(idx)
}

fn encode_int(
    mut v: u64, first: u8, prefix: usize, b: &mut octets::OctetsMut,
) -> Result<()> {
    let mask = 2u64.pow(prefix as u32) - 1;

    // Encode I on N bits.
    if v < mask {
        b.put_u8(first | v as u8)?;
        return Ok(());
    }

    // Encode (2^N - 1) on N bits.
    b.put_u8(first | mask as u8)?;

    v -= mask;

    while v >= 128 {
        // Encode (I % 128 + 128) on 8 bits.
        b.put_u8((v % 128 + 128) as u8)?;

        v >>= 7;
    }

    // Encode I on 8 bits.
    b.put_u8(v as u8)?;

    Ok(())
}

fn encode_str(v: &str, prefix: usize, b: &mut octets::OctetsMut) -> Result<()> {
    let len = super::huffman::encode_output_length(v.as_bytes())?;

    encode_int(len as u64, 0x80, prefix, b)?;

    super::huffman::encode(v.as_bytes(), b)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::octets;

    #[test]
    fn encode_int1() {
        let expected = [0b01010];
        let mut encoded = [0; 1];
        let mut b = octets::OctetsMut::with_slice(&mut encoded);

        assert!(encode_int(10, 0, 5, &mut b).is_ok());

        assert_eq!(expected, encoded);
    }

    #[test]
    fn encode_int2() {
        let expected = [0b11111, 0b10011010, 0b00001010];
        let mut encoded = [0; 3];
        let mut b = octets::OctetsMut::with_slice(&mut encoded);

        assert!(encode_int(1337, 0, 5, &mut b).is_ok());

        assert_eq!(expected, encoded);
    }

    #[test]
    fn encode_int3() {
        let expected = [0b101010];
        let mut encoded = [0; 1];
        let mut b = octets::OctetsMut::with_slice(&mut encoded);

        assert!(encode_int(42, 0, 8, &mut b).is_ok());

        assert_eq!(expected, encoded);
    }
}
