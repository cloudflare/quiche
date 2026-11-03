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

//! Parsing of encoder instructions (RFC 9204, Section 4.3).
//!
//! The peer's encoder sends instructions on its encoder stream to tell the
//! decoder how to update the dynamic table: set the table's capacity, insert an
//! entry, or duplicate an existing entry.
//!
//! Like any stream, the encoder stream is a sequence of bytes, and a read can
//! end in the middle of an instruction. Parsing therefore distinguishes data
//! that is incomplete, which can be parsed again once more bytes arrive, from
//! data that is malformed, which is a connection error of type
//! QPACK_ENCODER_STREAM_ERROR.
//!
//! See <https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3>.

use std::sync::Arc;

/// An error parsing an encoder instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ParseError {
    /// The data ends before the instruction does.
    ///
    /// The caller can keep the data and parse it again once more bytes arrive.
    /// It may already be invalid, though, as some checks wait for more of the
    /// instruction: a literal name, for example, is only decoded once the value
    /// has arrived too.
    Incomplete,

    /// The data can't be a valid instruction, whatever bytes follow.
    ///
    /// This is a connection error of type QPACK_ENCODER_STREAM_ERROR.
    Malformed,
}

/// Running out of bytes only means that the rest of the instruction hasn't
/// arrived yet, so reads can use `?` to return `ParseError::Incomplete`.
impl From<octets::BufferTooShortError> for ParseError {
    fn from(_err: octets::BufferTooShortError) -> Self {
        ParseError::Incomplete
    }
}

/// An encoder instruction (RFC 9204, Section 4.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EncoderInstruction {
    /// Sets the dynamic table's capacity, in bytes.
    SetDynamicTableCapacity { capacity: u64 },

    /// Inserts an entry named after the static table entry at `static_index`.
    InsertWithStaticNameReference { static_index: u64, value: Arc<[u8]> },

    /// Inserts an entry named after the dynamic table entry at
    /// `encoder_relative_index`, where 0 is the most recently inserted entry.
    InsertWithDynamicNameReference {
        encoder_relative_index: u64,
        value: Arc<[u8]>,
    },

    /// Inserts an entry with a literal name.
    InsertWithLiteralName { name: Arc<[u8]>, value: Arc<[u8]> },

    /// Re-inserts the dynamic table entry at `encoder_relative_index`, where 0
    /// is the most recently inserted entry.
    Duplicate { encoder_relative_index: u64 },
}

impl EncoderInstruction {
    /// Parses the instruction at the start of `b`, and advances `b` past it.
    ///
    /// Names and values that decode to more than `max_string_len` bytes are
    /// malformed. Indices and entry sizes are checked when the instruction is
    /// applied to the dynamic table, not here.
    ///
    /// On `Incomplete`, `b` may be left partway through the instruction, which
    /// must be parsed again from its start once more bytes arrive.
    pub(crate) fn from_bytes(
        b: &mut octets::Octets, max_string_len: usize,
    ) -> Result<Self, ParseError> {
        let first = b.peek_u8()?;

        // The first byte's leading bits give the instruction type, and its x
        // bits are the prefix of the first integer or string length. Inserts
        // end with the value, a string with a 7-bit prefix.
        let instruction = match first {
            // 1Txxxxxx: Insert with Name Reference (Section 4.3.2), where T
            // says whether the index is into the static table (1) or relative
            // to the dynamic table (0).
            0x80..=0xff => {
                let index = decode_prefixed_integer(b, 6)?;
                let value = decode_string(b, 7, max_string_len)?;

                if first & 0x40 != 0 {
                    Self::InsertWithStaticNameReference {
                        static_index: index,
                        value,
                    }
                } else {
                    Self::InsertWithDynamicNameReference {
                        encoder_relative_index: index,
                        value,
                    }
                }
            },

            // 01Hxxxxx: Insert with Literal Name (Section 4.3.3), where H is
            // the name's Huffman bit.
            0x40..=0x7f => {
                // Decode neither string until both have arrived. Incomplete
                // instructions are parsed again from the start, so decoding
                // the name early would repeat that work each time more of the
                // value arrives.
                let name = read_string(b, 5, max_string_len)?;
                let value = read_string(b, 7, max_string_len)?;

                Self::InsertWithLiteralName {
                    name: name.decode()?,
                    value: value.decode()?,
                }
            },

            // 001xxxxx: Set Dynamic Table Capacity (Section 4.3.1).
            0x20..=0x3f => Self::SetDynamicTableCapacity {
                capacity: decode_prefixed_integer(b, 5)?,
            },

            // 000xxxxx: Duplicate (Section 4.3.4).
            0x00..=0x1f => Self::Duplicate {
                encoder_relative_index: decode_prefixed_integer(b, 5)?,
            },
        };

        Ok(instruction)
    }
}

/// Decodes an integer with an N-bit prefix, where `prefix` is N (RFC 9204,
/// Section 4.1.1).
///
/// The bits of the first byte before the prefix belong to the instruction and
/// are ignored. Malformed if the value doesn't fit in 64 bits, or if the
/// encoding is longer than 11 bytes, even when the extra bytes add nothing to
/// the value.
fn decode_prefixed_integer(
    b: &mut octets::Octets, prefix: u8,
) -> Result<u64, ParseError> {
    // Prefixes are 1 to 8 bits, as the prefix is part of the first byte.
    debug_assert!((1..=8).contains(&prefix));

    // A prefix with all its bits set, 2^N - 1, means that the value continues
    // in the following bytes.
    let mask = (1u64 << prefix) - 1;

    // Keep only the prefix bits of the first byte.
    let mut value = u64::from(b.get_u8()?) & mask;

    if value < mask {
        return Ok(value);
    }

    // How far left the next payload goes, as payloads arrive least significant
    // first.
    let mut shift = 0;

    loop {
        let byte = b.get_u8()?;

        // The low 7 bits are part of the value. The high bit says whether
        // another byte follows.
        let payload = u64::from(byte & 0x7f);

        // Reject a value that doesn't fit in 64 bits. `checked_shl` fails only
        // once `shift` reaches 64, so also check that shifting kept all of the
        // payload's bits.
        let increment = payload
            .checked_shl(shift)
            .filter(|increment| increment >> shift == payload)
            .ok_or(ParseError::Malformed)?;

        // Adding the payload can still exceed 64 bits.
        value = value.checked_add(increment).ok_or(ParseError::Malformed)?;

        if byte & 0x80 == 0 {
            return Ok(value);
        }

        shift += 7;
    }
}

/// Decodes a string literal whose length has an N-bit prefix, where `prefix`
/// is N (RFC 9204, Section 4.1.2).
///
/// The bit right before the prefix says whether the string is Huffman-encoded.
/// Strings that decode to more than `max_len` bytes are malformed. When the
/// length alone shows this, they are rejected without waiting for their bytes.
fn decode_string(
    b: &mut octets::Octets, prefix: u8, max_len: usize,
) -> Result<Arc<[u8]>, ParseError> {
    read_string(b, prefix, max_len)?.decode()
}

/// A string literal whose bytes have all arrived, but that isn't decoded yet.
struct UndecodedString<'a> {
    /// Whether `bytes` are Huffman-encoded.
    huffman: bool,

    bytes: &'a [u8],

    /// The most bytes that the string may decode to.
    max_len: usize,
}

/// Reads a string literal like `decode_string`, but without decoding it.
///
/// This lets an instruction with two strings decode them only once all of its
/// bytes have arrived.
fn read_string<'a>(
    b: &mut octets::Octets<'a>, prefix: u8, max_len: usize,
) -> Result<UndecodedString<'a>, ParseError> {
    debug_assert!((1..=7).contains(&prefix));

    let huffman = b.peek_u8()? & (1 << prefix) != 0;

    let len = decode_prefixed_integer(b, prefix)?;

    // A Huffman code is at most 30 bits long, so a Huffman-encoded string of
    // up to `max_len` bytes takes at most `max_len * 30 / 8` bytes, rounded up.
    // This is computed in u128 so that it can't overflow, and a limit that
    // doesn't fit in usize allows every length that does.
    let max_encoded_len = if huffman {
        usize::try_from((max_len as u128 * 30).div_ceil(8)).unwrap_or(usize::MAX)
    } else {
        max_len
    };

    // Check the length before waiting for the bytes, so that the caller doesn't
    // keep buffering a string that will be rejected anyway.
    let len = match usize::try_from(len) {
        Ok(len) if len <= max_encoded_len => len,
        _ => return Err(ParseError::Malformed),
    };

    Ok(UndecodedString {
        huffman,
        bytes: b.get_bytes(len)?.buf(),
        max_len,
    })
}

impl UndecodedString<'_> {
    /// Decodes the string.
    fn decode(self) -> Result<Arc<[u8]>, ParseError> {
        if !self.huffman {
            // `read_string` already checked that it's at most `max_len` bytes.
            return Ok(Arc::from(self.bytes));
        }

        // All the bytes are there, so a failure means that the string is
        // invalid or decodes to more than `max_len` bytes, not that it's
        // incomplete.
        let decoded = octets::Octets::with_slice(self.bytes)
            .get_huffman_decoded_with_max_length(self.max_len)
            .map_err(|_| ParseError::Malformed)?;

        Ok(Arc::from(decoded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::h3::qpack::encode_int;

    /// Decodes an integer from `buf`, returning it and the number of bytes it
    /// took.
    fn decode(buf: &[u8], prefix: u8) -> Result<(u64, usize), ParseError> {
        let mut b = octets::Octets::with_slice(buf);
        let value = decode_prefixed_integer(&mut b, prefix)?;

        Ok((value, b.off()))
    }

    /// Decodes a string from `buf`, returning it and the number of bytes it
    /// took.
    fn decode_str(
        buf: &[u8], prefix: u8, max_len: usize,
    ) -> Result<(Vec<u8>, usize), ParseError> {
        let mut b = octets::Octets::with_slice(buf);
        let value = decode_string(&mut b, prefix, max_len)?;

        Ok((value.to_vec(), b.off()))
    }

    /// "www.example.com", Huffman-encoded (RFC 7541, Appendix C.4.1).
    const HUFFMAN_WWW_EXAMPLE_COM: [u8; 12] = [
        0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
    ];

    /// Parses an instruction from `buf`, returning it and the number of bytes
    /// it took.
    fn parse(
        buf: &[u8], max_string_len: usize,
    ) -> Result<(EncoderInstruction, usize), ParseError> {
        let mut b = octets::Octets::with_slice(buf);
        let instruction = EncoderInstruction::from_bytes(&mut b, max_string_len)?;

        Ok((instruction, b.off()))
    }

    fn bytes(s: &str) -> Arc<[u8]> {
        Arc::from(s.as_bytes())
    }

    /// Concatenates the parts of an encoded instruction.
    fn concat(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    /// The instructions on the encoder stream in RFC 9204, Appendix B, and
    /// what each parses to. They include every type of instruction.
    fn rfc_instructions() -> Vec<(Vec<u8>, EncoderInstruction)> {
        vec![
            // B.2: Set Dynamic Table Capacity=220.
            (
                vec![0x3f, 0xbd, 0x01],
                EncoderInstruction::SetDynamicTableCapacity { capacity: 220 },
            ),
            // B.2: Insert With Name Reference, Static Table, Index=0
            // (:authority=www.example.com).
            (
                concat(&[&[0xc0, 0x0f], b"www.example.com"]),
                EncoderInstruction::InsertWithStaticNameReference {
                    static_index: 0,
                    value: bytes("www.example.com"),
                },
            ),
            // B.2: Insert With Name Reference, Static Table, Index=1
            // (:path=/sample/path).
            (
                concat(&[&[0xc1, 0x0c], b"/sample/path"]),
                EncoderInstruction::InsertWithStaticNameReference {
                    static_index: 1,
                    value: bytes("/sample/path"),
                },
            ),
            // B.3: Insert With Literal Name (custom-key=custom-value).
            (
                concat(&[&[0x4a], b"custom-key", &[0x0c], b"custom-value"]),
                EncoderInstruction::InsertWithLiteralName {
                    name: bytes("custom-key"),
                    value: bytes("custom-value"),
                },
            ),
            // B.4: Duplicate (Relative Index = 2).
            (vec![0x02], EncoderInstruction::Duplicate {
                encoder_relative_index: 2,
            }),
            // B.5: Insert With Name Reference, Dynamic Table, Relative
            // Index = 1 (custom-key=custom-value2).
            (
                concat(&[&[0x81, 0x0d], b"custom-value2"]),
                EncoderInstruction::InsertWithDynamicNameReference {
                    encoder_relative_index: 1,
                    value: bytes("custom-value2"),
                },
            ),
        ]
    }

    #[test]
    fn rfc_examples() {
        // The examples from RFC 7541, Appendix C.1: 10 and 1337 with 5-bit
        // prefixes, and 42 with an 8-bit prefix, which fills the first byte.
        assert_eq!(decode(&[0x0a], 5), Ok((10, 1)));
        assert_eq!(decode(&[0x1f, 0x9a, 0x0a], 5), Ok((1337, 3)));
        assert_eq!(decode(&[0x2a], 8), Ok((42, 1)));
    }

    #[test]
    fn ignores_bits_before_prefix() {
        // 0xea is 111 01010: the bits before the 5-bit prefix don't change the
        // value.
        assert_eq!(decode(&[0xea], 5), Ok((10, 1)));
        assert_eq!(decode(&[0xff, 0x9a, 0x0a], 5), Ok((1337, 3)));

        // 4096, where the first byte, 0x3f, also holds the instruction type
        // (Set Dynamic Table Capacity).
        assert_eq!(decode(&[0x3f, 0xe1, 0x1f], 5), Ok((4096, 3)));
    }

    #[test]
    fn stops_at_end_of_integer() {
        // The byte after the integer belongs to whatever follows it in the
        // instruction, such as a string, so it's left unread.
        assert_eq!(decode(&[0x1f, 0x9a, 0x0a, 0xff], 5), Ok((1337, 3)));
    }

    #[test]
    fn round_trip_and_truncation() {
        for prefix in 1..=8 {
            for value in
                [0, 1, 30, 31, 32, 127, 128, 1337, (1 << 62) - 1, u64::MAX]
            {
                let mut buf = [0; 16];
                let mut b = octets::OctetsMut::with_slice(&mut buf);
                encode_int(value, 0, usize::from(prefix), &mut b).unwrap();
                let len = b.off();
                let encoded = &buf[..len];

                assert_eq!(decode(encoded, prefix), Ok((value, len)));

                // Every truncation is incomplete, not malformed.
                for end in 0..len {
                    assert_eq!(
                        decode(&encoded[..end], prefix),
                        Err(ParseError::Incomplete)
                    );
                }
            }
        }
    }

    #[test]
    fn rejects_values_over_64_bits() {
        // u64::MAX is [0x1f, 0xe0, 0xff * 8, 0x01], so this is 2^64.
        let mut buf = vec![0x1f, 0xe1];
        buf.extend([0xff; 8]);
        buf.push(0x01);
        assert_eq!(decode(&buf, 5), Err(ParseError::Malformed));

        // 31 + 2^64, where the last payload's high bit would be shifted out.
        let mut buf = vec![0x1f];
        buf.extend([0x80; 9]);
        buf.push(0x02);
        assert_eq!(decode(&buf, 5), Err(ParseError::Malformed));
    }

    #[test]
    fn rejects_overlong_encodings() {
        // Continuation bytes past 64 bits are malformed even with zero
        // payloads, so an incomplete integer never exceeds 11 bytes.
        let mut buf = vec![0x1f];
        buf.extend([0x80; 10]);
        assert_eq!(decode(&buf, 5), Err(ParseError::Incomplete));

        buf.push(0x00);
        assert_eq!(decode(&buf, 5), Err(ParseError::Malformed));
    }

    #[test]
    fn plain_string() {
        // With a 7-bit prefix, as for values, the Huffman bit is 0x80.
        let mut buf = vec![0x0b];
        buf.extend(b"example.com");
        assert_eq!(decode_str(&buf, 7, 100), Ok((b"example.com".to_vec(), 12)));
    }

    #[test]
    fn huffman_string() {
        // 0x8c sets the Huffman bit, and the length is 12.
        let mut buf = vec![0x8c];
        buf.extend(HUFFMAN_WWW_EXAMPLE_COM);
        assert_eq!(
            decode_str(&buf, 7, 100),
            Ok((b"www.example.com".to_vec(), 13))
        );
    }

    #[test]
    fn empty_string() {
        assert_eq!(decode_str(&[0x00], 7, 0), Ok((vec![], 1)));
        assert_eq!(decode_str(&[0x80], 7, 0), Ok((vec![], 1)));
    }

    #[test]
    fn huffman_bit_precedes_prefix() {
        // Insert with Literal Name gives the name's length a 5-bit prefix,
        // after the instruction type 01. 0x4a is 01 0 01010: a plain string of
        // 10 bytes (RFC 9204, Appendix B.3).
        let mut buf = vec![0x4a];
        buf.extend(b"custom-key");
        assert_eq!(decode_str(&buf, 5, 100), Ok((b"custom-key".to_vec(), 11)));

        // 0x6c is 01 1 01100: the Huffman bit 0x20 is set, and the length is
        // 12.
        let mut buf = vec![0x6c];
        buf.extend(HUFFMAN_WWW_EXAMPLE_COM);
        assert_eq!(
            decode_str(&buf, 5, 100),
            Ok((b"www.example.com".to_vec(), 13))
        );
    }

    #[test]
    fn stops_at_end_of_string() {
        // The byte after the string belongs to the next instruction.
        assert_eq!(
            decode_str(&[0x01, b'a', 0xff], 7, 100),
            Ok((b"a".to_vec(), 2))
        );
    }

    #[test]
    fn string_truncation_is_incomplete() {
        let mut plain = vec![0x0b];
        plain.extend(b"example.com");
        let mut huffman = vec![0x8c];
        huffman.extend(HUFFMAN_WWW_EXAMPLE_COM);

        for encoded in [plain, huffman] {
            for end in 0..encoded.len() {
                assert_eq!(
                    decode_str(&encoded[..end], 7, 100),
                    Err(ParseError::Incomplete)
                );
            }
        }
    }

    #[test]
    fn rejects_strings_longer_than_max_len() {
        let mut buf = vec![0x0b];
        buf.extend(b"example.com");
        assert_eq!(decode_str(&buf, 7, 11), Ok((b"example.com".to_vec(), 12)));
        assert_eq!(decode_str(&buf, 7, 10), Err(ParseError::Malformed));

        // Rejected as soon as the length is known, without waiting for the
        // string's bytes, even when it claims to be hundreds of megabytes.
        assert_eq!(decode_str(&buf[..1], 7, 10), Err(ParseError::Malformed));
        assert_eq!(
            decode_str(&[0x7f, 0xff, 0xff, 0xff, 0x7f], 7, 4096),
            Err(ParseError::Malformed)
        );
    }

    #[test]
    fn rejects_huffman_strings_decoding_past_max_len() {
        // The 12 encoded bytes decode to 15.
        let mut buf = vec![0x8c];
        buf.extend(HUFFMAN_WWW_EXAMPLE_COM);
        assert_eq!(
            decode_str(&buf, 7, 15),
            Ok((b"www.example.com".to_vec(), 13))
        );
        assert_eq!(decode_str(&buf, 7, 14), Err(ParseError::Malformed));
    }

    #[test]
    fn limits_huffman_encoded_length() {
        // With codes of at most 30 bits, a Huffman-encoded string of at most 1
        // byte takes at most 4 bytes. Longer ones are rejected without waiting
        // for their bytes.
        assert_eq!(decode_str(&[0x84], 7, 1), Err(ParseError::Incomplete));
        assert_eq!(decode_str(&[0x85], 7, 1), Err(ParseError::Malformed));
    }

    #[test]
    fn huffman_length_limit_does_not_overflow() {
        // max_len * 30 overflows usize, but the limit, max_len * 30 / 8, fits.
        let k = usize::MAX / 30;
        let (max_len, limit) = (8 * k, 30 * k);

        let huffman_len = |len: usize| {
            let mut buf = [0; 16];
            let mut b = octets::OctetsMut::with_slice(&mut buf);
            encode_int(len as u64, 0x80, 7, &mut b).unwrap();
            let off = b.off();
            buf[..off].to_vec()
        };

        assert_eq!(
            decode_str(&huffman_len(limit), 7, max_len),
            Err(ParseError::Incomplete)
        );
        assert_eq!(
            decode_str(&huffman_len(limit + 1), 7, max_len),
            Err(ParseError::Malformed)
        );
    }

    #[test]
    fn rejects_invalid_huffman() {
        // 32 set bits contain the 30-bit EOS code, which must not appear in a
        // string (RFC 7541, Section 5.2).
        assert_eq!(
            decode_str(&[0x84, 0xff, 0xff, 0xff, 0xff], 7, 100),
            Err(ParseError::Malformed)
        );

        // Padding longer than 7 bits (RFC 7541, Section 5.2).
        assert_eq!(
            decode_str(&[0x81, 0xff], 7, 100),
            Err(ParseError::Malformed)
        );

        // Padding must be the start of the EOS code, which is all ones, but
        // 0x00 is the 5-bit code for '0' followed by 3 zero bits.
        assert_eq!(
            decode_str(&[0x81, 0x00], 7, 100),
            Err(ParseError::Malformed)
        );
    }

    #[test]
    fn parses_each_instruction_type() {
        for (encoded, instruction) in rfc_instructions() {
            assert_eq!(parse(&encoded, 100), Ok((instruction, encoded.len())));
        }
    }

    #[test]
    fn uses_correct_prefix_for_each_field() {
        // Most RFC examples would parse the same with a wrong prefix size.
        // Here, integers fill their prefixes, and strings are Huffman-encoded,
        // with the Huffman bit right before the prefix.

        // Static table index 63, which fills the 6-bit prefix.
        let buf = concat(&[&[0xff, 0x00, 0x8c], &HUFFMAN_WWW_EXAMPLE_COM]);
        assert_eq!(
            parse(&buf, 100),
            Ok((
                EncoderInstruction::InsertWithStaticNameReference {
                    static_index: 63,
                    value: bytes("www.example.com"),
                },
                15
            ))
        );

        // The name's Huffman bit is 0x20.
        let buf = concat(&[
            &[0x6c],
            &HUFFMAN_WWW_EXAMPLE_COM,
            &[0x8c],
            &HUFFMAN_WWW_EXAMPLE_COM,
        ]);
        assert_eq!(
            parse(&buf, 100),
            Ok((
                EncoderInstruction::InsertWithLiteralName {
                    name: bytes("www.example.com"),
                    value: bytes("www.example.com"),
                },
                26
            ))
        );

        // Relative index 31, which fills the 5-bit prefix.
        assert_eq!(
            parse(&[0x1f, 0x00], 100),
            Ok((
                EncoderInstruction::Duplicate {
                    encoder_relative_index: 31,
                },
                2
            ))
        );
    }

    #[test]
    fn stops_at_end_of_instruction() {
        // On the encoder stream, instructions are back to back, and parsing
        // one leaves the next one unread.
        let instructions = rfc_instructions();
        let stream: Vec<u8> = instructions
            .iter()
            .flat_map(|(encoded, _)| encoded)
            .copied()
            .collect();

        let mut b = octets::Octets::with_slice(&stream);
        let mut end = 0;

        for (encoded, instruction) in instructions {
            end += encoded.len();

            assert_eq!(
                EncoderInstruction::from_bytes(&mut b, 100),
                Ok(instruction)
            );
            assert_eq!(b.off(), end);
        }
    }

    #[test]
    fn instruction_truncation_is_incomplete() {
        for (encoded, _) in rfc_instructions() {
            for end in 0..encoded.len() {
                assert_eq!(
                    parse(&encoded[..end], 100),
                    Err(ParseError::Incomplete)
                );
            }
        }
    }

    #[test]
    fn limits_name_and_value_lengths() {
        // custom-key=custom-value has a 10-byte name and a 12-byte value.
        let literal_name =
            concat(&[&[0x4a], b"custom-key", &[0x0c], b"custom-value"]);
        assert!(parse(&literal_name, 12).is_ok());
        assert_eq!(parse(&literal_name, 11), Err(ParseError::Malformed));

        // The name's length alone shows whether the name fits.
        assert_eq!(parse(&literal_name[..1], 10), Err(ParseError::Incomplete));
        assert_eq!(parse(&literal_name[..1], 9), Err(ParseError::Malformed));

        // :authority=www.example.com references its name, and has a 15-byte
        // value.
        let name_reference = concat(&[&[0xc0, 0x0f], b"www.example.com"]);
        assert!(parse(&name_reference, 15).is_ok());
        assert_eq!(parse(&name_reference, 14), Err(ParseError::Malformed));
    }

    #[test]
    fn decodes_strings_once_whole_instruction_arrives() {
        // A literal name whose name, 0xff, isn't valid Huffman code, and whose
        // value is "a". The name is only decoded, and found to be invalid,
        // once the value has arrived too.
        let buf = [0x61, 0xff, 0x01, b'a'];
        assert_eq!(parse(&buf[..3], 100), Err(ParseError::Incomplete));
        assert_eq!(parse(&buf, 100), Err(ParseError::Malformed));
    }
}
