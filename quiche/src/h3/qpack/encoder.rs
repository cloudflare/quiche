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

use crate::h3::NameValue;

use super::INDEXED;
use super::LITERAL;
use super::LITERAL_WITH_NAME_REF;

/// A QPACK encoder.
#[derive(Default)]
pub struct Encoder {}

impl Encoder {
    /// Creates a new QPACK encoder.
    pub fn new() -> Encoder {
        Encoder::default()
    }

    /// Encodes a list of headers into a QPACK header block.
    pub fn encode<T: NameValue>(
        &mut self, headers: &[T], out: &mut [u8],
    ) -> Result<usize> {
        let mut b = octets::OctetsMut::with_slice(out);

        // Required Insert Count.
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
                    encode_str::<false>(h.value(), 0, 7, &mut b)?;
                },

                None => {
                    // Encode as fully literal.

                    encode_str::<true>(h.name(), LITERAL, 3, &mut b)?;
                    encode_str::<false>(h.value(), 0, 7, &mut b)?;
                },
            };
        }

        Ok(b.off())
    }
}

fn lookup_static<T: NameValue>(h: &T) -> Option<(u64, bool)> {
    // Fetch the right encoding table for this header length.
    let table_for_len =
        super::static_table::STATIC_ENCODE_TABLE.get(h.name().len())?;

    // Similar to [`eq_ignore_ascii_case`], but only lowercases the second
    // operand, as the entries in the table are already lower cased.
    let cmp_lowercase = |a: &[u8], b: &[u8]| {
        std::iter::zip(a, b).all(|(a, b)| a.eq(&b.to_ascii_lowercase()))
    };

    for (name, values) in table_for_len.iter() {
        // Match header name first.
        if cmp_lowercase(name, h.name()) {
            // Second iterate over possible values for the header.
            for (value, enc) in values.iter() {
                // Match header value.
                if value.is_empty() {
                    return Some((*enc, false));
                }

                if h.value() == *value {
                    return Some((*enc, true));
                }
            }
            // Only matched the header, not the value.
            return Some((values.first()?.1, false));
        }
    }

    None
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

#[inline]
fn encode_str<const LOWER_CASE: bool>(
    v: &[u8], first: u8, prefix: usize, b: &mut octets::OctetsMut,
) -> Result<()> {
    // Huffman-encoding generally saves space but in some cases it doesn't, for
    // those just encode the literal string.
    match super::huffman::encode_output_length::<LOWER_CASE>(v) {
        Ok(len) => {
            encode_int(len as u64, first | 1 << prefix, prefix, b)?;
            super::huffman::encode::<LOWER_CASE>(v, b)?;
        },

        Err(super::Error::InflatedHuffmanEncoding) => {
            encode_int(v.len() as u64, first, prefix, b)?;
            if LOWER_CASE {
                b.put_bytes(&v.to_ascii_lowercase())?;
            } else {
                b.put_bytes(v)?;
            }
        },

        Err(e) => return Err(e),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn encode_static_header() {
        let mut encoded = [0; 3];
        Encoder::default()
            .encode(&[(b":method", b"GET")], &mut encoded)
            .unwrap();
        assert_eq!(encoded, [0, 0, INDEXED | 0x40 | 17]);
    }

    #[test]
    fn encode_static_header_name_only() {
        let mut encoded = [0; 11];
        let mut expected = [0; 11];
        let mut buf = octets::OctetsMut::with_slice(&mut expected[..]);
        buf.put_u16(0).unwrap();
        buf.put_u8(LITERAL_WITH_NAME_REF | 0x10 | 15).unwrap();
        buf.put_u8(0).unwrap();
        encode_str::<false>(b"FORGET", 0, 7, &mut buf).unwrap();

        Encoder::default()
            .encode(&[(b":method", b"FORGET")], &mut encoded)
            .unwrap();
        assert_eq!(encoded, expected);
    }
}
