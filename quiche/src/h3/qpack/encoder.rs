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
                    encode_str(h.value(), 7, &mut b)?;
                },

                None => {
                    // Encode as fully literal.
                    let name_len =
                        super::huffman::encode_output_length(h.name(), true)?;

                    encode_int(name_len as u64, LITERAL | 0x08, 3, &mut b)?;

                    super::huffman::encode(h.name(), &mut b, true)?;

                    encode_str(h.value(), 7, &mut b)?;
                },
            };
        }

        Ok(b.off())
    }
}

fn lookup_static<T: NameValue>(h: &T) -> Option<(u64, bool)> {
    let mut name_match = None;

    for (i, e) in super::static_table::STATIC_TABLE.iter().enumerate() {
        // Match header name first.
        if h.name().len() == e.0.len() && h.name().eq_ignore_ascii_case(e.0) {
            // No header value to match, return early.
            if e.1.is_empty() {
                return Some((i as u64, false));
            }

            // Match header value.
            if h.value().len() == e.1.len() && h.value() == e.1 {
                return Some((i as u64, true));
            }

            // Remember name-only match for later, but keep searching.
            name_match = Some((i as u64, false));
        }
    }

    name_match
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

fn encode_str(v: &[u8], prefix: usize, b: &mut octets::OctetsMut) -> Result<()> {
    let len = super::huffman::encode_output_length(v, false)?;

    encode_int(len as u64, 0x80, prefix, b)?;

    super::huffman::encode(v, b, false)?;

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
}
