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

//! Parsing helpers for encoder instructions (RFC 9204, Section 4.3).
//!
//! The peer's encoder sends instructions on its encoder stream to tell the
//! decoder how to update the dynamic table: set the table's capacity, insert an
//! entry, or duplicate an existing entry.
//!
//! The decoder parses instructions and updates the table. These helpers parse
//! their prefixed integers and strings, distinguishing incomplete input from
//! malformed input. The prefixed-integer helper is also used for field
//! sections.
//!
//! See <https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3>.

use std::sync::Arc;

/// An error parsing QPACK data or applying an encoder instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ParseError {
    /// The data ends before the instruction does.
    ///
    /// On the encoder stream, the caller can keep the data and parse it again
    /// once more bytes arrive. It may already be invalid, though, as some
    /// checks wait for more of the instruction: a literal name, for example,
    /// is only decoded once the value has arrived too.
    Incomplete,

    /// The data is invalid or can't be applied, whatever bytes follow.
    ///
    /// On the encoder stream, this is a connection error of type
    /// QPACK_ENCODER_STREAM_ERROR.
    Malformed,
}

/// A short buffer is incomplete input, so reads can use `?` to return
/// `ParseError::Incomplete`.
impl From<octets::BufferTooShortError> for ParseError {
    fn from(_err: octets::BufferTooShortError) -> Self {
        ParseError::Incomplete
    }
}

/// Decodes an integer with an N-bit prefix, where `prefix` is N (RFC 9204,
/// Section 4.1.1).
///
/// The bits of the first byte before the prefix belong to the instruction and
/// are ignored. Malformed if the value doesn't fit in 64 bits, or if the
/// encoding is longer than 11 bytes, even when the extra bytes add nothing to
/// the value.
pub(super) fn decode_prefixed_integer(
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
pub(super) fn decode_string(
    b: &mut octets::Octets, prefix: u8, max_len: usize,
) -> Result<Arc<[u8]>, ParseError> {
    read_string(b, prefix, max_len)?.decode()
}

/// A string literal whose bytes have all arrived, but that isn't decoded yet.
pub(super) struct UndecodedString<'a> {
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
pub(super) fn read_string<'a>(
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
    /// Minimum decoded length without decoding the string.
    ///
    /// Each Huffman symbol uses at most 30 bits; the string has at most seven
    /// padding bits. Invalid encodings are still rejected by `decode`.
    pub(super) fn minimum_decoded_len(&self) -> usize {
        if !self.huffman {
            return self.bytes.len();
        }

        let encoded_bits = self.bytes.len() as u128 * 8;
        let minimum = encoded_bits.saturating_sub(7).div_ceil(30);
        usize::try_from(minimum).unwrap_or(usize::MAX)
    }

    /// Decodes the string.
    pub(super) fn decode(self) -> Result<Arc<[u8]>, ParseError> {
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
}
