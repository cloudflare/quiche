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

use super::Error;
use super::Result;

use super::dynamic_table::DynamicTable;
use super::dynamic_table::EntryName;
use super::dynamic_table::ENTRY_OVERHEAD;
use super::encoder_instructions::decode_prefixed_integer;
use super::encoder_instructions::decode_string;
use super::encoder_instructions::read_string;
use super::encoder_instructions::ParseError;

use crate::h3::Header;

use super::INDEXED;
use super::INDEXED_WITH_POST_BASE;
use super::LITERAL;
use super::LITERAL_WITH_NAME_REF;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Representation {
    Indexed,
    IndexedWithPostBase,
    Literal,
    LiteralWithNameRef,
    LiteralWithPostBase,
}

impl Representation {
    pub fn from_byte(b: u8) -> Representation {
        if b & INDEXED == INDEXED {
            return Representation::Indexed;
        }

        if b & LITERAL_WITH_NAME_REF == LITERAL_WITH_NAME_REF {
            return Representation::LiteralWithNameRef;
        }

        if b & LITERAL == LITERAL {
            return Representation::Literal;
        }

        if b & INDEXED_WITH_POST_BASE == INDEXED_WITH_POST_BASE {
            return Representation::IndexedWithPostBase;
        }

        Representation::LiteralWithPostBase
    }
}

/// Helper for tracking decoded field list sizes.
///
/// The size of a field list is calculated based on the uncompressed size of
/// fields, including the length of the name and value in bytes plus an overhead
/// of 32 bytes for each field. See
/// <https://datatracker.ietf.org/doc/html/rfc9114#section-4.2.2>
struct FieldListSizeTracker {
    remaining: u64,
}

impl FieldListSizeTracker {
    /// Initialize tracker with the maximum field list size.
    ///
    /// The `max_size` parameter is the maximum size in bytes of the full
    /// decoded field list. See
    /// <https://datatracker.ietf.org/doc/html/rfc9114#section-4.2.2>
    fn new(max_size: u64) -> Self {
        Self {
            remaining: max_size,
        }
    }

    /// Mark the start of parsing a new field.
    ///
    /// Must be called when a new field is ready to be parsed.
    fn on_field_start(&mut self) -> Result<()> {
        // Each complete field has a 32-byte overhead, so subtract that first.
        self.remaining = self
            .remaining
            .checked_sub(32)
            .ok_or(Error::HeaderListTooLarge)?;

        Ok(())
    }

    /// Marks when a field part (either name or value) has been decoded.
    ///
    /// The `len` parameter is the size in bytes of the decoded part.
    ///
    /// Must be called when a new field part has been decoded.
    fn on_field_part_decoded(&mut self, len: u64) -> Result<()> {
        self.remaining = self
            .remaining
            .checked_sub(len)
            .ok_or(Error::HeaderListTooLarge)?;

        Ok(())
    }

    /// The remaining number of bytes in the tracker.
    fn left(&self) -> u64 {
        self.remaining
    }
}

/// A QPACK decoder.
pub struct Decoder {
    /// The dynamic table, which the peer's encoder updates with encoder
    /// instructions.
    table: DynamicTable,

    /// The start of an encoder instruction whose remaining bytes haven't
    /// arrived yet.
    partial_instruction: Vec<u8>,
    // TODO: queue decoder instructions (RFC 9204, Section 4.4) for the
    // connection to send on the decoder stream.
}

impl Default for Decoder {
    fn default() -> Decoder {
        Decoder::new()
    }
}

impl Decoder {
    /// Creates a new QPACK decoder.
    pub fn new() -> Decoder {
        Decoder::with_max_table_capacity(0)
    }

    /// Creates a new QPACK decoder whose dynamic table has a maximum capacity
    /// of `max_table_capacity`.
    ///
    /// `max_table_capacity` must be the `SETTINGS_QPACK_MAX_TABLE_CAPACITY`
    /// value advertised to the peer (RFC 9204, Section 3.2.3).
    pub(crate) fn with_max_table_capacity(max_table_capacity: usize) -> Decoder {
        Decoder {
            table: DynamicTable::new(max_table_capacity),
            partial_instruction: Vec::new(),
        }
    }

    pub(crate) fn should_parse_encoder_stream(&self) -> bool {
        self.table.max_capacity() > 0
    }

    /// Processes encoder instructions (RFC 9204, Section 4.3) from the peer's
    /// encoder stream, applying them to the dynamic table.
    ///
    /// `buf` must hold the next bytes of the stream. It may end partway through
    /// an instruction, which is kept until the rest arrives in a later call.
    ///
    /// An error is a connection error of type QPACK_ENCODER_STREAM_ERROR, and
    /// the decoder must not be used afterwards: instructions before the invalid
    /// one may already have been applied.
    pub fn control(&mut self, buf: &[u8]) -> Result<()> {
        // With a maximum capacity of zero, the encoder must not send any
        // instructions (RFC 9204, Section 3.2.3), but some encoders still send
        // Set Dynamic Table Capacity 0 when a maximum of zero is advertised
        // explicitly. As it changes nothing, it's accepted, and the table
        // rejects every other instruction.
        self.partial_instruction.extend_from_slice(buf);

        let mut b = octets::Octets::with_slice(&self.partial_instruction);

        loop {
            let start = b.off();

            // No string longer than the table's capacity fits in an entry, so
            // strings whose length alone shows that they're too long are
            // rejected without waiting for their bytes.
            match apply_encoder_instruction(&mut b, &mut self.table) {
                Ok(()) => (),

                Err(ParseError::Incomplete) => {
                    // Keep the incomplete instruction for the next call.
                    if start == self.partial_instruction.len() {
                        self.partial_instruction = Vec::new();
                    } else if start > 0 {
                        self.partial_instruction =
                            self.partial_instruction.split_off(start);
                    }

                    return Ok(());
                },

                Err(ParseError::Malformed) =>
                    return Err(Error::InvalidEncoderInstruction),
            }
        }
    }

    /// Decodes a QPACK header block into a list of headers.
    pub fn decode(&mut self, buf: &[u8], max_size: u64) -> Result<Vec<Header>> {
        let mut b = octets::Octets::with_slice(buf);

        let mut out = Vec::new();

        let mut size_tracker = FieldListSizeTracker::new(max_size);

        let req_insert_count =
            decode_prefixed_integer(&mut b, 8).map_err(header_integer_error)?;
        let base =
            decode_prefixed_integer(&mut b, 7).map_err(header_integer_error)?;

        // TODO: decode the Required Insert Count and Base (RFC 9204, Section
        // 4.5.1). With SETTINGS_QPACK_BLOCKED_STREAMS set to 0, a Required
        // Insert Count above the dynamic table's insert count is a connection
        // error of type QPACK_DECOMPRESSION_FAILED (RFC 9204, Section 2.1.2).

        trace!("Header count={req_insert_count} base={base}");

        while b.cap() > 0 {
            let first = b.peek_u8()?;

            size_tracker.on_field_start()?;

            match Representation::from_byte(first) {
                Representation::Indexed => {
                    const STATIC: u8 = 0x40;

                    let s = first & STATIC == STATIC;
                    let index = decode_prefixed_integer(&mut b, 6)
                        .map_err(header_integer_error)?;

                    trace!("Indexed index={index} static={s}");

                    if !s {
                        // TODO: implement dynamic table
                        return Err(Error::InvalidHeaderValue);
                    }

                    let (name, value) = lookup_static(index)?;

                    size_tracker.on_field_part_decoded(
                        (name.len() + value.len()) as u64,
                    )?;

                    let hdr = Header::new(name, value);
                    out.push(hdr);
                },

                Representation::IndexedWithPostBase => {
                    let index = decode_prefixed_integer(&mut b, 4)
                        .map_err(header_integer_error)?;

                    trace!("Indexed With Post Base index={index}");

                    // TODO: implement dynamic table
                    return Err(Error::InvalidHeaderValue);
                },

                Representation::Literal => {
                    let name_huff = b.as_ref()[0] & 0x08 == 0x08;
                    let name_len = usize::try_from(
                        decode_prefixed_integer(&mut b, 3)
                            .map_err(header_integer_error)?,
                    )
                    .map_err(|_| Error::InvalidHeaderValue)?;

                    let mut name = b.get_bytes(name_len)?;

                    let name = if name_huff {
                        name.get_huffman_decoded_with_max_length(
                            size_tracker.left() as usize,
                        )
                        .map_err(|_| Error::HeaderListTooLarge)?
                    } else {
                        if name_len > size_tracker.left() as usize {
                            return Err(Error::HeaderListTooLarge);
                        }
                        name.to_vec()
                    };

                    size_tracker.on_field_part_decoded(name.len() as u64)?;

                    let value = decode_str(&mut b, size_tracker.left() as usize)?;

                    trace!(
                        "Literal Without Name Reference name={name:?} value={value:?}",
                    );

                    size_tracker.on_field_part_decoded(value.len() as u64)?;

                    // Instead of calling Header::new(), create Header directly
                    // from `name` and `value`.
                    let hdr = Header(name, value);
                    out.push(hdr);
                },

                Representation::LiteralWithNameRef => {
                    const STATIC: u8 = 0x10;

                    let s = first & STATIC == STATIC;

                    if !s {
                        // TODO: implement dynamic table
                        return Err(Error::InvalidHeaderValue);
                    }

                    let name_idx = decode_prefixed_integer(&mut b, 4)
                        .map_err(header_integer_error)?;

                    let (name, _) = lookup_static(name_idx)?;

                    size_tracker.on_field_part_decoded(name.len() as u64)?;

                    let value = decode_str(&mut b, size_tracker.left() as usize)?;

                    trace!(
                        "Literal name_idx={name_idx} static={s} value={value:?}"
                    );

                    size_tracker.on_field_part_decoded(value.len() as u64)?;

                    // Instead of calling Header::new(), create Header directly
                    // from `value`, but clone `name` as it is just a reference.
                    let hdr = Header(name.to_vec(), value);
                    out.push(hdr);
                },

                Representation::LiteralWithPostBase => {
                    trace!("Literal With Post Base");

                    // TODO: implement dynamic table
                    return Err(Error::InvalidHeaderValue);
                },
            }
        }

        Ok(out)
    }
}

fn apply_encoder_instruction(
    b: &mut octets::Octets, table: &mut DynamicTable,
) -> std::result::Result<(), ParseError> {
    let first = b.peek_u8()?;
    let max_string_len = table.capacity();

    match first {
        // Insert with Name Reference: https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3.2
        0x80..=0xff => {
            let index = decode_prefixed_integer(b, 6)?;
            let value = decode_string(b, 7, max_string_len)?;

            let name = if first & 0x40 != 0 {
                let (name, _) =
                    lookup_static(index).map_err(|_| ParseError::Malformed)?;
                EntryName::Static(name)
            } else {
                table
                    .get_by_encoder_relative_index(index)
                    .map_err(|_| ParseError::Malformed)?
                    .name
                    .clone()
            };

            table.insert(name, value).map_err(|_| ParseError::Malformed)
        },

        // Insert with Literal Name: https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3.3
        0x40..=0x7f => {
            let entry_data_limit = table
                .capacity()
                .checked_sub(ENTRY_OVERHEAD)
                .ok_or(ParseError::Malformed)?;
            let name = read_string(b, 5, entry_data_limit)?;
            let value_limit = entry_data_limit
                .checked_sub(name.minimum_decoded_len())
                .ok_or(ParseError::Malformed)?;
            let value = read_string(b, 7, value_limit)?;

            table
                .insert(EntryName::Shared(name.decode()?), value.decode()?)
                .map_err(|_| ParseError::Malformed)
        },

        // Set Dynamic Table Capacity: https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3.1
        0x20..=0x3f => {
            let capacity = decode_prefixed_integer(b, 5)?;
            table
                .set_dynamic_table_capacity(capacity)
                .map_err(|_| ParseError::Malformed)
        },

        // Duplicate: https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3.4
        0x00..=0x1f => {
            let index = decode_prefixed_integer(b, 5)?;
            let entry = table
                .get_by_encoder_relative_index(index)
                .map_err(|_| ParseError::Malformed)?;
            let name = entry.name.clone();
            let value = entry.value.clone();

            table.insert(name, value).map_err(|_| ParseError::Malformed)
        },
    }
}

fn lookup_static(idx: u64) -> Result<(&'static [u8], &'static [u8])> {
    if idx >= super::static_table::STATIC_DECODE_TABLE.len() as u64 {
        return Err(Error::InvalidStaticTableIndex);
    }

    Ok(super::static_table::STATIC_DECODE_TABLE[idx as usize])
}

fn header_integer_error(error: ParseError) -> Error {
    match error {
        ParseError::Incomplete => Error::BufferTooShort,

        ParseError::Malformed => Error::InvalidHeaderValue,
    }
}

fn decode_str(b: &mut octets::Octets, max_len: usize) -> Result<Vec<u8>> {
    let first = b.peek_u8()?;

    let huff = first & 0x80 == 0x80;

    let len = usize::try_from(
        decode_prefixed_integer(b, 7).map_err(header_integer_error)?,
    )
    .map_err(|_| Error::InvalidHeaderValue)?;

    let mut val = b.get_bytes(len)?;

    let val = if huff {
        val.get_huffman_decoded_with_max_length(max_len)
            .map_err(|_| Error::HeaderListTooLarge)?
    } else {
        if len > max_len {
            return Err(Error::HeaderListTooLarge);
        }
        val.to_vec()
    };

    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Decoder {
        pub(crate) fn dynamic_table_entry(
            &self, index: u64,
        ) -> Option<(&[u8], &[u8])> {
            self.table
                .get_by_absolute_index(index)
                .map(|entry| (entry.name(), entry.value()))
        }
    }

    const HUFFMAN_WWW_EXAMPLE_COM: [u8; 12] = [
        0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
    ];

    /// LiteralWithNameRef with the dynamic table flag (S=0) must be
    /// rejected since dynamic table references are not decoded yet.
    #[test]
    fn literal_with_name_ref_dynamic_table_rejected() {
        let mut dec = Decoder::new();

        // QPACK header block:
        //   [0x00, 0x00]  required insert count=0, base=0
        //   [0x40]        LiteralWithNameRef (0b0100_0000), S=0 (dynamic),
        //                 name_idx=0
        //   [0x01, 0x61]  value: non-huffman, length=1, 'a'
        let encoded = [0x00, 0x00, 0x40, 0x01, 0x61];

        assert_eq!(
            dec.decode(&encoded, u64::MAX),
            Err(Error::InvalidHeaderValue),
        );
    }

    /// Non-Huffman value in decode_str must be rejected before allocation
    /// when it exceeds the remaining budget (max_len).
    ///
    /// Uses a LiteralWithNameRef with static `:authority` (index 0, 10
    /// bytes) and a non-Huffman value of 5 bytes. Budget is set so only
    /// 4 bytes remain for the value after the name is charged.
    #[test]
    fn non_huffman_value_exceeding_budget_rejected() {
        // QPACK header block:
        //   [0x00, 0x00]  required insert count=0, base=0
        //   [0x50]        LiteralWithNameRef, S=1 (static), name_idx=0
        //                 (:authority, 10 bytes)
        //   [0x05]        value: non-huffman (bit 7=0), length=5
        //   "abcde"       value bytes
        let encoded = [0x00, 0x00, 0x50, 0x05, 0x61, 0x62, 0x63, 0x64, 0x65];

        // Exact fit: 32 (overhead) + 10 (name) + 5 (value) = 47.
        assert!(Decoder::new().decode(&encoded, 47).is_ok());

        // One byte too small: budget = 46.
        // After overhead (32) and name (10): 4 bytes remain, but
        // value is 5 bytes → rejected.
        assert_eq!(
            Decoder::new().decode(&encoded, 46),
            Err(Error::HeaderListTooLarge),
        );
    }

    /// Non-Huffman name in the Literal arm must be rejected before
    /// allocation when it exceeds the remaining budget.
    ///
    /// Uses a Literal with a 10-byte non-Huffman name and a 1-byte
    /// non-Huffman value. Budget is set so only 9 bytes remain for the
    /// name after overhead.
    #[test]
    fn non_huffman_name_exceeding_budget_rejected() {
        // QPACK header block:
        //   [0x00, 0x00]  required insert count=0, base=0
        //   [0x27, 0x03]  Literal (0b0010_0000), N=0, H=0 (no huffman),
        //                 name_len=10 (3-bit prefix 0b111 + overflow 0x03)
        //   "x-custom99"  name bytes (10 bytes)
        //   [0x01, 0x61]  value: non-huffman, length=1, 'a'
        let encoded = [
            0x00, 0x00, // header block prefix
            0x27, 0x03, // Literal, name_len=10
            0x78, 0x2d, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x39,
            0x39, // "x-custom99"
            0x01, 0x61, // value: length=1, 'a'
        ];

        // Exact fit: 32 (overhead) + 10 (name) + 1 (value) = 43.
        assert!(Decoder::new().decode(&encoded, 43).is_ok());

        // Two bytes too small: budget = 41.
        // After overhead (32): 9 bytes remain, name is 10 bytes →
        // rejected at name check.
        assert_eq!(
            Decoder::new().decode(&encoded, 41),
            Err(Error::HeaderListTooLarge),
        );
    }

    /// Verify that both Literal and LiteralWithNameRef charge the name to
    /// the budget *before* Huffman-decoding the value, so the max_len
    /// passed to the Huffman decoder is equally strict in both paths.
    #[test]
    fn literal_with_name_ref_value_budget_ordering() {
        use crate::h3::qpack;

        // Static table index 0 = `:authority` (10 bytes).
        // We'll encode the same value two ways:
        //   1. LiteralWithNameRef using `:authority` (encoder matches static
        //      table)
        //   2. Literal using a custom 10-byte name not in the static table
        //
        // Both have name_len=10, so budget arithmetic is comparable.
        let value = b"aaaaaaaaaaaaaaaa"; // 16 bytes; Huffman compresses to 10

        // -- Encode as LiteralWithNameRef --
        let headers_nameref = vec![Header::new(b":authority", value)];
        let mut buf = [0u8; 64];
        let mut enc = qpack::Encoder::new();
        let nameref_len = enc.encode(&headers_nameref, &mut buf).unwrap();
        let encoded_nameref = buf[..nameref_len].to_vec();

        // -- Encode as Literal (name not in static table) --
        let headers_literal = vec![Header::new(b"x-custom99", value)];
        let mut buf = [0u8; 64];
        let mut enc = qpack::Encoder::new();
        let literal_len = enc.encode(&headers_literal, &mut buf).unwrap();
        let encoded_literal = buf[..literal_len].to_vec();

        // Exact budget: 32 (overhead) + 10 (name) + 16 (value) = 58.
        // Both representations succeed.
        assert_eq!(
            Decoder::new().decode(&encoded_nameref, 58),
            Ok(headers_nameref.clone()),
        );
        assert_eq!(
            Decoder::new().decode(&encoded_literal, 58),
            Ok(headers_literal.clone()),
        );

        // One byte too small: budget = 57.
        // Total decoded field size = 10 + 16 = 26, overhead = 32,
        // so 32 + 26 = 58 > 57. Both reject with HeaderListTooLarge.
        //
        // Both paths now follow the same budget ordering:
        //   1. name charged first (10 bytes) → remaining = 15
        //   2. decode_str max_len = 15
        //   3. Huffman decode produces 16 bytes > 15 → rejected
        assert_eq!(
            Decoder::new().decode(&encoded_nameref, 57),
            Err(Error::HeaderListTooLarge),
        );
        assert_eq!(
            Decoder::new().decode(&encoded_literal, 57),
            Err(Error::HeaderListTooLarge),
        );
    }

    /// The encoder stream in RFC 9204, Appendix B.
    fn rfc_encoder_stream() -> Vec<u8> {
        let instructions: [&[u8]; 6] = [
            // B.2: Set Dynamic Table Capacity=220.
            b"\x3f\xbd\x01",
            // B.2: Insert With Name Reference, Static Table, Index=0.
            b"\xc0\x0fwww.example.com",
            // B.2: Insert With Name Reference, Static Table, Index=1.
            b"\xc1\x0c/sample/path",
            // B.3: Insert With Literal Name.
            b"\x4acustom-key\x0ccustom-value",
            // B.4: Duplicate (Relative Index = 2).
            b"\x02",
            // B.5: Insert With Name Reference, Dynamic Table, Relative Index
            // = 1.
            b"\x81\x0dcustom-value2",
        ];

        instructions.concat()
    }

    fn capacity_instruction(capacity: u64) -> Vec<u8> {
        let mut buf = [0; 16];
        let mut bytes = octets::OctetsMut::with_slice(&mut buf);
        super::super::encode_int(capacity, 0x20, 5, &mut bytes).unwrap();
        let len = bytes.off();
        buf[..len].to_vec()
    }

    /// The dynamic table at the end of RFC 9204, Appendix B.5, by absolute
    /// index.
    const RFC_TABLE: [Option<(&str, &str)>; 6] = [
        None,
        Some((":path", "/sample/path")),
        Some(("custom-key", "custom-value")),
        Some((":authority", "www.example.com")),
        Some(("custom-key", "custom-value2")),
        None,
    ];

    /// Returns a decoder whose dynamic table has the given maximum capacity.
    fn decoder_with_max_capacity(max_capacity: usize) -> Decoder {
        Decoder::with_max_table_capacity(max_capacity)
    }

    /// Returns the name and value of each dynamic table entry with an absolute
    /// index in `indices`, or `None` for those not in the table.
    fn table_entries(
        dec: &Decoder, indices: std::ops::Range<u64>,
    ) -> Vec<Option<(&str, &str)>> {
        indices
            .map(|index| {
                dec.table.get_by_absolute_index(index).map(|entry| {
                    (
                        std::str::from_utf8(entry.name()).unwrap(),
                        std::str::from_utf8(entry.value()).unwrap(),
                    )
                })
            })
            .collect()
    }

    #[test]
    fn control_applies_and_buffers_instructions() {
        let mut stream = rfc_encoder_stream();
        stream.extend(capacity_instruction(2048));
        stream.extend([0xff, 0x00, 0x8c]);
        stream.extend(HUFFMAN_WWW_EXAMPLE_COM);
        stream.push(0x6c);
        stream.extend(HUFFMAN_WWW_EXAMPLE_COM);
        stream.push(0x8c);
        stream.extend(HUFFMAN_WWW_EXAMPLE_COM);

        let long_value = "v".repeat(127);
        stream.extend([0xc0, 0x7f, 0x00]);
        stream.extend(long_value.as_bytes());
        stream.extend([0xc2, 0x00, 0xc2, 0x80]);

        for _ in 0..27 {
            stream.extend([0xc2, 0x01, b'v']);
        }
        stream.extend([0x1f, 0x00]);

        let mut expected = RFC_TABLE[..5].to_vec();
        expected.extend([
            Some((":status", "www.example.com")),
            Some(("www.example.com", "www.example.com")),
            Some((":authority", long_value.as_str())),
            Some(("age", "")),
            Some(("age", "")),
        ]);
        expected.extend(std::iter::repeat_n(Some(("age", "v")), 27));
        expected.push(Some((":status", "www.example.com")));

        // Split in two at every position, so that every instruction is split
        // at every byte, and some calls end with part of an instruction after
        // complete ones.
        for i in 0..=stream.len() {
            let mut dec = decoder_with_max_capacity(2048);
            assert_eq!(dec.control(&stream[..i]), Ok(()));
            assert_eq!(dec.control(&stream[i..]), Ok(()));
            assert_eq!(table_entries(&dec, 0..expected.len() as u64), expected);
            assert!(dec.partial_instruction.is_empty());
        }

        let mut dec = decoder_with_max_capacity(80);
        dec.control(&capacity_instruction(80)).unwrap();
        dec.control(b"\x44key0\x04val0").unwrap();
        dec.control(b"\x44key1\x04val1").unwrap();
        assert_eq!(table_entries(&dec, 0..3), [
            Some(("key0", "val0")),
            Some(("key1", "val1")),
            None
        ]);

        dec.control(b"\x44key2\x04val2").unwrap();
        assert_eq!(table_entries(&dec, 0..4), [
            None,
            Some(("key1", "val1")),
            Some(("key2", "val2")),
            None
        ]);

        dec.control(&capacity_instruction(40)).unwrap();
        assert_eq!(table_entries(&dec, 0..4), [
            None,
            None,
            Some(("key2", "val2")),
            None
        ]);
        dec.control(&[0x20]).unwrap();
        assert_eq!(table_entries(&dec, 0..4), [None; 4]);
        dec.control(&capacity_instruction(40)).unwrap();
        dec.control(b"\x44key3\x04val3").unwrap();
        assert_eq!(table_entries(&dec, 0..5), [
            None,
            None,
            None,
            Some(("key3", "val3")),
            None
        ]);

        let mut dec = decoder_with_max_capacity(40);
        dec.control(&capacity_instruction(40)).unwrap();
        dec.control(b"\xc2\x05value").unwrap();
        dec.control(&[0x00]).unwrap();
        dec.control(b"\x80\x05other").unwrap();
        assert_eq!(table_entries(&dec, 0..4), [
            None,
            None,
            Some(("age", "other")),
            None
        ]);

        let mut encoded = [0; 8];
        let mut bytes = octets::OctetsMut::with_slice(&mut encoded);
        bytes.put_huffman_encoded::<false>(b"\n\n").unwrap();
        assert_eq!(bytes.off(), encoded.len());

        let mut dec = decoder_with_max_capacity(36);
        dec.control(&capacity_instruction(36)).unwrap();
        let mut instruction = vec![0x68];
        instruction.extend(encoded);
        instruction.push(0x88);
        instruction.extend(encoded);
        assert_eq!(dec.control(&instruction), Ok(()));
        assert_eq!(table_entries(&dec, 0..1), [Some(("\n\n", "\n\n"))]);

        let mut dec = decoder_with_max_capacity(64);
        dec.control(&capacity_instruction(64)).unwrap();
        let mut stream = b"\x41x\x01y".repeat(1000);
        stream.extend([0x41, b'z']);
        assert_eq!(dec.control(&stream), Ok(()));
        assert_eq!(dec.partial_instruction, [0x41, b'z']);
        assert!(dec.partial_instruction.capacity() < stream.len() / 2);
        assert_eq!(table_entries(&dec, 999..1001), [Some(("x", "y")), None]);
        assert_eq!(dec.control(&[0x01, b'v']), Ok(()));
        assert!(dec.partial_instruction.is_empty());
        assert_eq!(dec.partial_instruction.capacity(), 0);
        assert_eq!(table_entries(&dec, 999..1001), [None, Some(("z", "v"))]);
    }

    #[test]
    fn control_rejects_invalid_instructions() {
        let mut name = vec![0x54];
        name.extend([b'a'; 20]);

        let mut dec = decoder_with_max_capacity(64);
        dec.control(&capacity_instruction(64)).unwrap();
        let mut incomplete = name.clone();
        incomplete.push(0xad);
        assert_eq!(dec.control(&incomplete), Ok(()));
        assert_eq!(dec.partial_instruction.len(), incomplete.len());

        let mut dec = decoder_with_max_capacity(64);
        dec.control(&capacity_instruction(64)).unwrap();
        assert_eq!(dec.control(&name), Ok(()));
        assert_eq!(dec.partial_instruction.len(), name.len());
        assert_eq!(dec.control(&[0xae]), Err(Error::InvalidEncoderInstruction));

        name.push(0x0d);

        let mut encoded_name = [0; 4];
        let mut name_bytes = octets::OctetsMut::with_slice(&mut encoded_name);
        name_bytes.put_huffman_encoded::<false>(b"\n").unwrap();
        assert_eq!(name_bytes.off(), encoded_name.len());
        let mut oversized = vec![0x64];
        oversized.extend(encoded_name);
        oversized.push(0x85);

        for max_capacity in [0, 220, usize::MAX] {
            if let Some(excess) = (max_capacity as u64).checked_add(1) {
                let mut dec = decoder_with_max_capacity(max_capacity);
                assert_eq!(
                    dec.control(&capacity_instruction(excess)),
                    Err(Error::InvalidEncoderInstruction)
                );
            }

            let mut dec = decoder_with_max_capacity(max_capacity);
            assert_eq!(
                dec.control(&capacity_instruction(max_capacity as u64)),
                Ok(())
            );
        }

        let mut overflow = vec![0x3f, 0xe1];
        overflow.extend([0xff; 8]);
        overflow.push(0x01);

        let mut high_bits_overflow = vec![0x3f];
        high_bits_overflow.extend([0x80; 9]);
        high_bits_overflow.push(0x02);

        let mut overlong_integer = vec![0x3f];
        overlong_integer.extend([0x80; 10]);
        overlong_integer.push(0x00);

        let mut oversized_huffman = vec![0xc2, 0x8c];
        oversized_huffman.extend(HUFFMAN_WWW_EXAMPLE_COM);

        let mut eos_huffman = vec![0xc2, 0x84];
        eos_huffman.extend([0xff; 4]);

        let mut huge_length = vec![0xc2, 0x7f];
        huge_length.extend([0xff; 3]);
        huge_length.push(0x7f);

        let too_large_value = "x".repeat(45);
        let mut exact_fit = b"\x44key0\x2c".to_vec();
        exact_fit.extend([b'x'; 44]);
        let mut literal = b"\x44key1\x2d".to_vec();
        literal.extend(too_large_value.as_bytes());
        let mut dynamic_name = vec![0x80, 45];
        dynamic_name.extend(too_large_value.as_bytes());
        let mut static_name = vec![0xc2, 46];
        static_name.extend([b'x'; 46]);

        let no_setup: &[&[u8]] = &[];
        let evicted_setup: &[&[u8]] = &[b"\x44key0\x04val0", b"\x44key1\x04val1"];
        let dynamic_name_setup: &[&[u8]] = &[exact_fit.as_slice()];

        let cases = [
            (0, no_setup, &b"\xc0\x00"[..]),
            (0, no_setup, b"\x80\x00"),
            (0, no_setup, b"\x40\x00"),
            (0, no_setup, b"\x00"),
            (0, no_setup, b"\x41"),
            (220, no_setup, b"\x00"),
            (220, no_setup, b"\x80\x00"),
            (220, no_setup, b"\xff\x24\x00"),
            (220, no_setup, &overflow),
            (220, no_setup, &high_bits_overflow),
            (220, no_setup, &overlong_integer),
            (220, no_setup, &huge_length),
            (220, no_setup, &eos_huffman),
            (220, no_setup, b"\xc2\x81\xff"),
            (220, no_setup, b"\xc2\x81\x00"),
            (220, no_setup, b"\x61\xff\x00"),
            (64, no_setup, b"\x5f\x22"),
            (64, no_setup, b"\x40\x41"),
            (64, no_setup, b"\xc0\x41"),
            (34, no_setup, b"\x41a\x85"),
            (14, no_setup, &oversized_huffman),
            (40, no_setup, b"\xc2\x06values"),
            (64, no_setup, &name),
            (34, no_setup, &oversized),
            (80, no_setup, &literal),
            (80, no_setup, &static_name),
            (40, evicted_setup, b"\x01"),
            (40, evicted_setup, b"\x81\x00"),
            (80, dynamic_name_setup, &dynamic_name),
        ];

        for (capacity, setup, instruction) in cases {
            let mut dec = decoder_with_max_capacity(capacity);
            if capacity > 0 {
                dec.control(&capacity_instruction(capacity as u64)).unwrap();
            }
            for setup_instruction in setup {
                dec.control(setup_instruction).unwrap();
            }
            assert_eq!(
                dec.control(instruction),
                Err(Error::InvalidEncoderInstruction),
                "capacity={capacity}, instruction={instruction:?}"
            );
        }
    }
}
