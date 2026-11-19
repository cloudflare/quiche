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

    /// The remaining number of bytes, capped to what fits in a `usize`.
    fn left(&self) -> usize {
        usize::try_from(self.remaining).unwrap_or(usize::MAX)
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

        let (req_insert_count, base) = decode_field_section_prefix(
            &mut b,
            self.table.max_capacity(),
            self.table.insert_count(),
        )?;

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

                    let (name, value) = if s {
                        lookup_static(index)?
                    } else {
                        let absolute_index = base
                            .checked_sub(index)
                            .and_then(|index| index.checked_sub(1))
                            .ok_or(Error::InvalidHeaderValue)?;
                        lookup_dynamic(
                            &self.table,
                            absolute_index,
                            req_insert_count,
                        )?
                    };

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

                    let absolute_index = base
                        .checked_add(index)
                        .ok_or(Error::InvalidHeaderValue)?;
                    let (name, value) = lookup_dynamic(
                        &self.table,
                        absolute_index,
                        req_insert_count,
                    )?;

                    size_tracker.on_field_part_decoded(
                        (name.len() + value.len()) as u64,
                    )?;

                    let hdr = Header::new(name, value);
                    out.push(hdr);
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
                            size_tracker.left(),
                        )
                        .map_err(|_| Error::HeaderListTooLarge)?
                    } else {
                        if name_len > size_tracker.left() {
                            return Err(Error::HeaderListTooLarge);
                        }
                        name.to_vec()
                    };

                    size_tracker.on_field_part_decoded(name.len() as u64)?;

                    let value = decode_str(&mut b, size_tracker.left())?;

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
                    let name_idx = decode_prefixed_integer(&mut b, 4)
                        .map_err(header_integer_error)?;

                    let (name, _) = if s {
                        lookup_static(name_idx)?
                    } else {
                        let absolute_index = base
                            .checked_sub(name_idx)
                            .and_then(|index| index.checked_sub(1))
                            .ok_or(Error::InvalidHeaderValue)?;
                        lookup_dynamic(
                            &self.table,
                            absolute_index,
                            req_insert_count,
                        )?
                    };

                    size_tracker.on_field_part_decoded(name.len() as u64)?;

                    let value = decode_str(&mut b, size_tracker.left())?;

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
                    let name_idx = decode_prefixed_integer(&mut b, 3)
                        .map_err(header_integer_error)?;

                    let absolute_index = base
                        .checked_add(name_idx)
                        .ok_or(Error::InvalidHeaderValue)?;
                    let (name, _) = lookup_dynamic(
                        &self.table,
                        absolute_index,
                        req_insert_count,
                    )?;

                    size_tracker.on_field_part_decoded(name.len() as u64)?;

                    let value = decode_str(&mut b, size_tracker.left())?;

                    trace!(
                        "Literal With Post Base name_idx={name_idx} value={value:?}"
                    );

                    size_tracker.on_field_part_decoded(value.len() as u64)?;

                    let hdr = Header(name.to_vec(), value);
                    out.push(hdr);
                },
            }
        }

        Ok(out)
    }
}

/// Decodes the Required Insert Count and Base (RFC 9204, Section 4.5.1).
fn decode_field_section_prefix(
    b: &mut octets::Octets, max_table_capacity: usize, total_insert_count: u64,
) -> Result<(u64, u64)> {
    let encoded_insert_count =
        decode_prefixed_integer(b, 8).map_err(header_integer_error)?;

    // Compute in u128 to keep the wraparound arithmetic valid even when the
    // maximum capacity and insert count are both large.
    let max_entries = (max_table_capacity / ENTRY_OVERHEAD) as u128;
    let full_range = 2 * max_entries;

    let req_insert_count = if encoded_insert_count == 0 {
        0
    } else {
        if u128::from(encoded_insert_count) > full_range {
            return Err(Error::InvalidHeaderValue);
        }

        let max_value = u128::from(total_insert_count) + max_entries;
        let max_wrapped = (max_value / full_range) * full_range;
        let mut required = max_wrapped + u128::from(encoded_insert_count) - 1;

        if required > max_value {
            if required <= full_range {
                return Err(Error::InvalidHeaderValue);
            }

            required -= full_range;
        }

        if required == 0 {
            return Err(Error::InvalidHeaderValue);
        }

        u64::try_from(required).map_err(|_| Error::InvalidHeaderValue)?
    };

    let negative = b.peek_u8()? & 0x80 != 0;
    let delta_base =
        decode_prefixed_integer(b, 7).map_err(header_integer_error)?;
    let base = if negative {
        req_insert_count
            .checked_sub(delta_base)
            .and_then(|base| base.checked_sub(1))
    } else {
        req_insert_count.checked_add(delta_base)
    }
    .ok_or(Error::InvalidHeaderValue)?;

    // Only zero blocked streams are supported. A field section that needs
    // unseen insertions cannot be decoded (RFC 9204, Section 2.1.2).
    if req_insert_count > total_insert_count {
        return Err(Error::InvalidHeaderValue);
    }

    Ok((req_insert_count, base))
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

fn lookup_dynamic(
    table: &DynamicTable, absolute_index: u64, req_insert_count: u64,
) -> Result<(&[u8], &[u8])> {
    // The Required Insert Count must include every referenced entry.
    if absolute_index >= req_insert_count {
        return Err(Error::InvalidHeaderValue);
    }

    let entry = table
        .get_by_absolute_index(absolute_index)
        .ok_or(Error::InvalidHeaderValue)?;
    Ok((entry.name(), entry.value()))
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
        // TODO: In a follow-up PR, distinguish malformed Huffman from
        // decoded-size overflow in octets. Map malformed data to
        // InvalidHuffmanEncoding here and in the literal-name path above,
        // while keeping HeaderListTooLarge for size overflow.
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

    #[test]
    fn field_section_prefix_decodes_count_and_base() {
        for (encoded, max_capacity, total_inserts, expected) in [
            (&[0x00, 0x00][..], 0, 0, (0, 0)),
            (&[0x00, 0x05][..], 0, 0, (0, 5)),
            (&[0x03, 0x81][..], 220, 2, (2, 0)),
            (&[0x04, 0x82][..], 100, 10, (9, 6)),
            (&[0x04, 0x02][..], 100, 10, (9, 11)),
            (&[0x04, 0x88][..], 100, 10, (9, 0)),
            (&[0x05, 0x00][..], 100, 10, (10, 10)),
            (&[0x04, 0x00][..], 64, u64::MAX, (u64::MAX, u64::MAX)),
        ] {
            let mut b = octets::Octets::with_slice(encoded);
            assert_eq!(
                decode_field_section_prefix(&mut b, max_capacity, total_inserts),
                Ok(expected)
            );
            assert_eq!(b.cap(), 0);
        }
    }

    #[test]
    fn field_section_prefix_rejects_invalid_counts_and_base() {
        for (encoded, max_capacity, total_inserts) in [
            (&[0x01, 0x00][..], 0, 0),
            (&[0x01, 0x00][..], 31, 0),
            (&[0x07, 0x00][..], 100, 10),
            (&[0x01, 0x00][..], 64, 0),
            (&[0x04, 0x00][..], 64, 0),
            (&[0x02, 0x00][..], 64, 0),
            (&[0x06, 0x00][..], 100, 10),
            (&[0x04, 0x89][..], 100, 10),
            (&[0x01, 0x00][..], 64, u64::MAX),
            (&[0x00, 0x80][..], 0, 0),
        ] {
            let mut b = octets::Octets::with_slice(encoded);
            assert_eq!(
                decode_field_section_prefix(&mut b, max_capacity, total_inserts),
                Err(Error::InvalidHeaderValue)
            );
        }

        for encoded in [&[][..], &[0x00][..], &[0x04, 0xff][..]] {
            let mut b = octets::Octets::with_slice(encoded);
            assert_eq!(
                decode_field_section_prefix(&mut b, 100, 10),
                Err(Error::BufferTooShort)
            );
        }

        let mut encoded = [0; 16];
        let mut out = octets::OctetsMut::with_slice(&mut encoded);
        out.put_u8(0x04).unwrap();
        super::super::encode_int(u64::MAX, 0, 7, &mut out).unwrap();
        let len = out.off();
        let mut b = octets::Octets::with_slice(&encoded[..len]);
        assert_eq!(
            decode_field_section_prefix(&mut b, 100, 10),
            Err(Error::InvalidHeaderValue)
        );

        assert_eq!(
            Decoder::new().decode(&[0x01, 0x00], u64::MAX),
            Err(Error::InvalidHeaderValue)
        );
        assert_eq!(
            Decoder::with_max_table_capacity(64).decode(&[0x02, 0x00], u64::MAX),
            Err(Error::InvalidHeaderValue)
        );
    }

    #[test]
    fn large_field_section_limit_does_not_wrap_on_32_bit() {
        // After the overhead (32) and :authority (10), exactly 2^32 bytes
        // remain. Truncating that budget to usize would reject a 1-byte value
        // on a 32-bit target, even though the decoded field needs only 43.
        let max_size = (1_u64 << 32) + 42;
        assert_eq!(
            Decoder::new().decode(b"\x00\x00\x50\x01a", max_size),
            Ok(vec![Header::new(b":authority", b"a")])
        );

        // The same budget is also passed to the bounded Huffman decoder.
        let mut huffman_value = b"\x00\x00\x50\x8c".to_vec();
        huffman_value.extend(HUFFMAN_WWW_EXAMPLE_COM);
        assert_eq!(
            Decoder::new().decode(&huffman_value, max_size),
            Ok(vec![Header::new(b":authority", b"www.example.com")])
        );

        // Exercise both the literal name check and the value check after
        // charging that name: each can encounter exactly 2^32 bytes left.
        for max_size in [(1_u64 << 32) + 32, (1_u64 << 32) + 33] {
            assert_eq!(
                Decoder::new().decode(b"\x00\x00\x21a\x01b", max_size),
                Ok(vec![Header::new(b"a", b"b")])
            );
        }

        let mut huffman_name = b"\x00\x00\x2f\x05".to_vec();
        huffman_name.extend(HUFFMAN_WWW_EXAMPLE_COM);
        huffman_name.extend(b"\x01a");
        assert_eq!(
            Decoder::new().decode(&huffman_name, (1_u64 << 32) + 32),
            Ok(vec![Header::new(b"www.example.com", b"a")])
        );

        let mut dec = decoder_with_custom_entries();
        let dynamic_limit = (1_u64 << 32) + 38;
        let dynamic_expected = vec![Header::new(b"x-dddd", b"a")];
        for encoded in [
            &b"\x05\x00\x40\x01a"[..], // Dynamic name reference.
            &b"\x05\x81\x09\x01a"[..], // Post-base name reference.
        ] {
            assert_eq!(
                dec.decode(encoded, dynamic_limit),
                Ok(dynamic_expected.clone())
            );
        }
    }

    #[test]
    fn literal_fields_enforce_size_limits() {
        let mut dec = decoder_with_custom_entries();

        for (encoded, exact_size, too_small) in [
            (&b"\x00\x00\x50\x05abcde"[..], 47, 46),
            (&b"\x00\x00\x27\x03x-custom99\x01a"[..], 43, 41),
        ] {
            assert!(dec.decode(encoded, exact_size).is_ok());
            assert_eq!(
                dec.decode(encoded, too_small),
                Err(Error::HeaderListTooLarge),
                "encoded={encoded:?}"
            );
        }

        let value = b"aaaaaaaaaaaaaaaa"; // 16 bytes; Huffman compresses to 10
        for (prefix, name, exact_size) in [
            (&b"\x00\x00\x50"[..], &b":authority"[..], 58),
            (&b"\x00\x00\x27\x03x-custom99"[..], &b"x-custom99"[..], 58),
            (&b"\x05\x00\x40"[..], &b"x-dddd"[..], 54),
            (&b"\x05\x81\x09"[..], &b"x-dddd"[..], 54),
        ] {
            let mut encoded = [0; 64];
            let mut out = octets::OctetsMut::with_slice(&mut encoded);
            out.put_bytes(prefix).unwrap();
            super::super::encode_str::<false>(value, 0, 7, &mut out).unwrap();
            let len = out.off();
            assert_ne!(encoded[prefix.len()] & 0x80, 0);
            assert_eq!(
                dec.decode(&encoded[..len], exact_size),
                Ok(vec![Header::new(name, value)]),
                "prefix={prefix:?}"
            );
            assert_eq!(
                dec.decode(&encoded[..len], exact_size - 1),
                Err(Error::HeaderListTooLarge),
                "prefix={prefix:?}"
            );
        }

        // Charge the referenced name before reading the value.
        assert_eq!(
            dec.decode(b"\x05\x00\x40", 37),
            Err(Error::HeaderListTooLarge)
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

    fn decoder_with_custom_entries() -> Decoder {
        let mut dec = decoder_with_max_capacity(192);
        dec.control(&capacity_instruction(192)).unwrap();
        dec.control(
            b"\x43x-a\x03red\x44x-bb\x04blue\x45x-ccc\x05green\x46x-dddd\x04gold",
        )
        .unwrap();
        dec
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
    fn dynamic_references_decode_and_enforce_field_limits() {
        let mut dec = decoder_with_custom_entries();

        for (encoded, max_size, expected) in [
            // RIC=4, Base=2: relative index 0 and post-base indices 0 and 1.
            (&b"\x05\x81\x80\x10\x11"[..], 124, vec![
                Header::new(b"x-bb", b"blue"),
                Header::new(b"x-ccc", b"green"),
                Header::new(b"x-dddd", b"gold"),
            ]),
            (&b"\x05\x83\x12"[..], 42, vec![Header::new(
                b"x-ccc", b"green",
            )]),
            // RIC=3, Base=5: relative index 2 refers to absolute index 2.
            (&b"\x04\x02\x82"[..], 42, vec![Header::new(
                b"x-ccc", b"green",
            )]),
            (&b"\x04\x02\x42\x01x"[..], 38, vec![Header::new(
                b"x-ccc", b"x",
            )]),
            // RIC=4, Base=4: relative indices 0 and 1. The N bit is set on
            // the second field line, whose value differs from the table entry.
            (&b"\x05\x00\x40\x03new\x61\x03alt"[..], 81, vec![
                Header::new(b"x-dddd", b"new"),
                Header::new(b"x-ccc", b"alt"),
            ]),
            // RIC=4, Base=2: post-base indices 0 and 1. The N bit is set
            // on the second field line.
            (&b"\x05\x81\x00\x03new\x09\x03alt"[..], 81, vec![
                Header::new(b"x-ccc", b"new"),
                Header::new(b"x-dddd", b"alt"),
            ]),
        ] {
            assert_eq!(
                dec.decode(encoded, max_size),
                Ok(expected),
                "encoded={encoded:?}"
            );
            assert_eq!(
                dec.decode(encoded, max_size - 1),
                Err(Error::HeaderListTooLarge),
                "encoded={encoded:?}"
            );
        }
    }

    #[test]
    fn dynamic_references_reject_invalid_indices_and_truncation() {
        let mut dec = decoder_with_max_capacity(80);
        dec.control(&capacity_instruction(80)).unwrap();
        dec.control(b"\x41a\x01x\x41b\x01y\x41c\x01z").unwrap();

        for encoded in [b"\x04\x00\x80", b"\x04\x82\x12"] {
            assert_eq!(
                dec.decode(encoded, u64::MAX),
                Ok(vec![Header::new(b"c", b"z")])
            );
        }

        // Only the last two entries fit; the first one was evicted.
        for encoded in [
            &b"\x04\x00\x82"[..], // Evicted entry by relative index.
            b"\x04\x82\x10",      // Evicted entry by post-base index.
            b"\x03\x01\x80",      // Present entry beyond RIC, relative.
            b"\x03\x81\x12",      // Present entry beyond RIC, post-base.
            b"\x00\x00\x80",      // Base zero cannot address a relative index.
            b"\x00\x00\x10",      // RIC zero cannot reference the table.
            b"\x04\x00\x83",      // Relative index beyond Base.
            b"\x04\x00\x42\x01v", // Evicted relative index.
            b"\x04\x82\x00\x01v", // Evicted post-base index.
            b"\x03\x01\x40\x01v", // Relative reference beyond RIC.
            b"\x03\x81\x02\x01v", // Post-base reference beyond RIC.
            b"\x04\x00\x43\x01v", // Relative index exceeds Base.
            b"\x00\x00\x00\x01v", // RIC zero cannot reference the table.
            b"\x00\x00\x40\x01a",
        ] {
            assert_eq!(
                dec.decode(encoded, u64::MAX),
                Err(Error::InvalidHeaderValue),
                "encoded={encoded:?}"
            );
        }

        for (prefix, mask, bits) in [
            ([0x04, 0x00], 0x80, 6),
            ([0x04, 0x80], 0x10, 4),
            ([0x04, 0x00], 0x40, 4),
            ([0x04, 0x80], 0x00, 3),
        ] {
            let mut encoded = [0; 16];
            let mut out = octets::OctetsMut::with_slice(&mut encoded);
            out.put_bytes(&prefix).unwrap();
            super::super::encode_int(u64::MAX, mask, bits, &mut out).unwrap();
            let len = out.off();

            assert_eq!(
                dec.decode(&encoded[..len], u64::MAX),
                Err(Error::InvalidHeaderValue)
            );
        }

        for encoded in [&b"\x04\x00\x40"[..], &b"\x04\x82\x02\x01"[..]] {
            assert_eq!(dec.decode(encoded, u64::MAX), Err(Error::BufferTooShort));
        }
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
