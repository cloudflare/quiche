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

use std::borrow::Cow;
use std::collections::VecDeque;

use super::encoder::encode_int;
use super::Error;
use super::Result;
use super::INSERT_WITH_LITERAL_NAME;
use super::INSERT_WITH_NAME_REF;
use super::SET_DYNAMIC_TABLE_CAPACITY;

use crate::h3::Header;
use crate::h3::NameValue;

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

#[derive(Clone, Copy, Debug, PartialEq)]
enum EncoderInstruction {
    SetDynamicTableCapacity,
    InsertWithNameRef,
    InsertWithLiteralName,
    Duplicate,
}

impl EncoderInstruction {
    pub fn from_byte(b: u8) -> EncoderInstruction {
        if b & INSERT_WITH_NAME_REF == INSERT_WITH_NAME_REF {
            return EncoderInstruction::InsertWithNameRef;
        }

        if b & INSERT_WITH_LITERAL_NAME == INSERT_WITH_LITERAL_NAME {
            return EncoderInstruction::InsertWithLiteralName;
        }

        if b & SET_DYNAMIC_TABLE_CAPACITY == SET_DYNAMIC_TABLE_CAPACITY {
            return EncoderInstruction::SetDynamicTableCapacity;
        }

        EncoderInstruction::Duplicate
    }
}

/// A QPACK decoder.
#[derive(Default)]
pub struct Decoder {
    dynamic_table: VecDeque<(Cow<'static, [u8]>, Vec<u8>)>,
    /// The number of insertions into the table
    insert_cnt: u64,
    /// The number of entries removed from the table
    base: u64,
    /// The computed size of the table as per rfc9204
    tbl_sz: u64,
    /// The current capacity requested by the peer
    capacity: u64,
    /// The capacity limit imposed by settings
    max_capacity: u64,

    /// The value of `insert_cnt` last time "Insert Count Increment" was emmited
    last_acked_insert: u64,
    /// A list of streams pending "Section Acknowledgment"
    unacked_sections: VecDeque<u64>,
    /// A list of streams pending "Stream Cancellation"
    unacked_cancellations: VecDeque<u64>,

    /// Internal buffer in case the decoder receives a partial buffer
    inner_buffer: Vec<u8>,
}

impl Decoder {
    /// Creates a new QPACK decoder.
    pub fn new(max_capacity: u64) -> Decoder {
        Decoder {
            max_capacity: max_capacity.min(u32::MAX as u64),
            ..Decoder::default()
        }
    }

    /// Check if the decoder wants to emit any instructions on the instruction
    /// stream
    pub fn has_instructions(&self) -> bool {
        self.last_acked_insert != self.insert_cnt ||
            !self.unacked_sections.is_empty() ||
            !self.unacked_cancellations.is_empty()
    }

    /// Emit any pending instructions on the instruction stream, once emitted
    /// the buffer must be fully sent to the peer, or else the encoder and
    /// decoder may get out of sync.
    pub fn emit_instructions(&mut self, buf: &mut [u8]) -> usize {
        const INSERT_CNT_INC: u8 = 0x00;
        const SECTION_ACK: u8 = 0x80;
        const STREAM_CANCEL: u8 = 0x40;

        let mut b = octets::OctetsMut::with_slice(buf);

        let inc_req_count = self.insert_cnt - self.last_acked_insert;

        if inc_req_count > 0 &&
            encode_int(inc_req_count, INSERT_CNT_INC, 6, &mut b).is_ok()
        {
            self.last_acked_insert = self.insert_cnt;
        }

        while let Some(section) = self.unacked_sections.front() {
            if encode_int(*section, SECTION_ACK, 7, &mut b).is_ok() {
                self.unacked_sections.pop_front();
            } else {
                break;
            }
        }

        if self.capacity > 0 {
            // Those notifications MAY be ommited if table size is 0, so omit them
            while let Some(section) = self.unacked_cancellations.front() {
                if encode_int(*section, STREAM_CANCEL, 6, &mut b).is_ok() {
                    self.unacked_cancellations.pop_front();
                } else {
                    break;
                }
            }
        } else {
            self.unacked_cancellations.clear();
        }

        b.off()
    }

    pub fn cancel_stream(&mut self, stream: u64) {
        self.unacked_cancellations.push_back(stream);
    }

    fn process_control(&mut self, b: &mut octets::Octets) -> Result<()> {
        let first = b.peek_u8()?;

        match EncoderInstruction::from_byte(first) {
            EncoderInstruction::SetDynamicTableCapacity => {
                let capacity = decode_int(b, 5)?;

                trace!("SetDynamicTableCapacity size={capacity}");

                self.resize_table(capacity)?;
            },

            EncoderInstruction::InsertWithNameRef => {
                let is_static = first & 0x40 == 0x40;
                let idx = decode_int(b, 6)?;

                let value = decode_str(b, 7)?;

                trace!("InsertWithNameRef index={idx} static={is_static} value={value:?}");

                if is_static {
                    let (name, _) = lookup_static(idx)?;
                    self.insert((Cow::Borrowed(name), value))?;
                } else {
                    let (name, _) = self.lookup_dynamic(
                        self.insert_cnt
                            .checked_sub(idx + 1)
                            .ok_or(Error::InvalidDynamicTableIndex)?,
                    )?;
                    self.insert((Cow::Owned(name.to_vec()), value))?;
                }
            },

            EncoderInstruction::InsertWithLiteralName => {
                let name = decode_str(b, 5)?;
                let value = decode_str(b, 7)?;

                trace!("InsertWithLiteralName name={name:?} value={value:?}");

                self.insert((Cow::Owned(name), value))?;
            },

            EncoderInstruction::Duplicate => {
                let idx = decode_int(b, 5)?;

                trace!("Duplicate index={idx}");

                let (name, value) = self.lookup_dynamic(
                    self.insert_cnt
                        .checked_sub(idx + 1)
                        .ok_or(Error::InvalidDynamicTableIndex)?,
                )?;

                self.insert((Cow::Owned(name.to_vec()), value.to_vec()))?;
            },
        }

        Ok(())
    }

    /// Processes control instructions from the encoder.
    pub fn control(&mut self, buf: &[u8]) -> Result<()> {
        let mut maybe_buf = Vec::new();

        let mut b = if !self.inner_buffer.is_empty() {
            // Have a buffered partial instruction, should concatenate the
            // provided buffer and try again
            std::mem::swap(&mut maybe_buf, &mut self.inner_buffer);
            maybe_buf.extend_from_slice(buf);
            octets::Octets::with_slice(maybe_buf.as_slice())
        } else {
            octets::Octets::with_slice(buf)
        };

        while b.cap() > 0 {
            let pos = b.off();
            match self.process_control(&mut b) {
                Ok(_) => {},
                Err(Error::BufferTooShort) => {
                    // Have partial instruction, have to buffer it now
                    self.inner_buffer.extend_from_slice(&b.buf()[pos..]);
                    return Ok(());
                },
                Err(err) => return Err(err),
            }
        }

        Ok(())
    }

    /// Evict the oldest entry in the table
    fn evict_one(&mut self) -> Result<()> {
        let entry = self
            .dynamic_table
            .pop_front()
            .ok_or(Error::DynamicTableTooBig)?;

        self.tbl_sz -= entry.qpack_cost();
        self.base += 1;
        Ok(())
    }

    fn insert(&mut self, entry: (Cow<'static, [u8]>, Vec<u8>)) -> Result<()> {
        self.tbl_sz += entry.qpack_cost();

        while self.tbl_sz > self.capacity {
            self.evict_one()?;
        }

        self.dynamic_table.push_back(entry);
        self.insert_cnt += 1;

        trace!("Insert insert_cnt={} size={}", self.insert_cnt, self.tbl_sz);

        Ok(())
    }

    fn resize_table(&mut self, new_capacity: u64) -> Result<()> {
        if new_capacity > self.max_capacity {
            return Err(Error::DynamicTableTooBig);
        }

        self.capacity = new_capacity;
        while self.tbl_sz > self.capacity {
            self.evict_one()?;
        }

        Ok(())
    }

    fn lookup_dynamic(&self, idx: u64) -> Result<(&[u8], &[u8])> {
        let idx = idx
            .checked_sub(self.base)
            .ok_or(Error::InvalidDynamicTableIndex)?;

        self.dynamic_table
            .get(idx as usize)
            .ok_or(Error::InvalidDynamicTableIndex)
            .map(|(n, v)| (&n[..], &v[..]))
    }

    fn decode_insert_cnt_and_base(
        &self, b: &mut octets::Octets,
    ) -> Result<(u64, u64)> {
        let mut req_insert_count = decode_int(b, 8)?;
        if req_insert_count != 0 {
            let max_entries = self.max_capacity / 32;
            let full_range = max_entries * 2;
            if req_insert_count > full_range {
                return Err(Error::InvalidDynamicTableIndex);
            }

            let max_value = self.insert_cnt + max_entries;

            let max_wrapped = (max_value / full_range) * full_range;

            req_insert_count = max_wrapped + req_insert_count - 1;

            // If req_insert_count exceeds max_value, the Encoder's value must
            // have wrapped one fewer time
            if req_insert_count > max_value {
                if req_insert_count <= full_range {
                    return Err(Error::InvalidDynamicTableIndex);
                }
                req_insert_count -= full_range;
            }

            // Value of 0 must be encoded as 0.
            if req_insert_count == 0 {
                return Err(Error::InvalidDynamicTableIndex);
            }
        }

        let delta_negative = b.peek_u8()? & 0x80 == 0x80;
        let delta = decode_int(b, 7)?;

        let base = if delta_negative {
            req_insert_count
                .checked_sub(delta + 1)
                .ok_or(Error::InvalidDynamicTableIndex)?
        } else {
            req_insert_count + delta
        };

        Ok((req_insert_count as u64, base as u64))
    }

    /// Decodes a QPACK header block into a list of headers.
    pub fn decode(
        &mut self, buf: &[u8], max_size: u64, stream_id: u64,
    ) -> Result<Vec<Header>> {
        let mut b = octets::Octets::with_slice(buf);

        let mut out = Vec::new();

        let mut left = max_size;

        let (req_insert_count, base) = self.decode_insert_cnt_and_base(&mut b)?;

        trace!("Header count={} base={}", req_insert_count, base);

        if req_insert_count > self.insert_cnt {
            return Err(Error::DynamicTableWouldBlock);
        }

        while b.cap() > 0 {
            let first = b.peek_u8()?;

            let hdr = match Representation::from_byte(first) {
                Representation::Indexed => {
                    const STATIC: u8 = 0x40;

                    let is_static = first & STATIC == STATIC;
                    let index = decode_int(&mut b, 6)?;

                    trace!("Indexed index={} static={}", index, is_static);

                    let (name, value) = if !is_static {
                        self.lookup_dynamic(
                            base.checked_sub(index + 1)
                                .ok_or(Error::InvalidDynamicTableIndex)?,
                        )?
                    } else {
                        lookup_static(index)?
                    };

                    Header::new(name, value)
                },

                Representation::IndexedWithPostBase => {
                    let index = decode_int(&mut b, 4)?;

                    trace!("Indexed With Post Base index={}", index);

                    let (name, value) = self.lookup_dynamic(base + index)?;

                    Header::new(name, value)
                },

                Representation::Literal => {
                    let name = decode_str(&mut b, 3)?;
                    let value = decode_str(&mut b, 7)?;

                    trace!("Literal Without Name Reference name={name:?} value={value:?}");

                    Header::new(name, value)
                },

                Representation::LiteralWithNameRef => {
                    const STATIC: u8 = 0x10;

                    let is_static = first & STATIC == STATIC;
                    let name_idx = decode_int(&mut b, 4)?;
                    let value = decode_str(&mut b, 7)?;

                    trace!("Literal name_idx={name_idx} static={is_static} value={value:?}");

                    let (name, _) = if !is_static {
                        self.lookup_dynamic(
                            base.checked_sub(name_idx + 1)
                                .ok_or(Error::InvalidDynamicTableIndex)?,
                        )?
                    } else {
                        lookup_static(name_idx)?
                    };

                    Header::new(name, value)
                },

                Representation::LiteralWithPostBase => {
                    let index = decode_int(&mut b, 3)?;
                    let value = decode_str(&mut b, 7)?;

                    trace!(
                        "Literal With Post Base index={index} value={value:?}"
                    );

                    let (name, _) = self.lookup_dynamic(base + index)?;

                    Header::new(name, value)
                },
            };

            left = left
                .checked_sub((hdr.0.len() + hdr.1.len()) as u64)
                .ok_or(Error::HeaderListTooLarge)?;

            out.push(hdr);
        }

        if req_insert_count > 0 {
            self.unacked_sections.push_back(stream_id);
        }

        Ok(out)
    }
}

fn lookup_static(idx: u64) -> Result<(&'static [u8], &'static [u8])> {
    if idx >= super::static_table::STATIC_DECODE_TABLE.len() as u64 {
        return Err(Error::InvalidStaticTableIndex);
    }

    Ok(super::static_table::STATIC_DECODE_TABLE[idx as usize])
}

fn decode_int(b: &mut octets::Octets, prefix: usize) -> Result<u64> {
    let mask = 2u64.pow(prefix as u32) - 1;

    let mut val = u64::from(b.get_u8()?);
    val &= mask;

    if val < mask {
        return Ok(val);
    }

    let mut shift = 0;

    while b.cap() > 0 {
        let byte = b.get_u8()?;

        let inc = u64::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or(Error::BufferTooShort)?;

        val = val.checked_add(inc).ok_or(Error::BufferTooShort)?;

        shift += 7;

        if byte & 0x80 == 0 {
            return Ok(val);
        }
    }

    Err(Error::BufferTooShort)
}

fn decode_str(b: &mut octets::Octets, prefix: usize) -> Result<Vec<u8>> {
    let first = b.peek_u8()?;

    let huff = first & (1 << prefix) != 0;

    let len = decode_int(b, prefix)? as usize;

    let mut val = b.get_bytes(len)?;

    let val = if huff {
        super::huffman::decode(&mut val)?
    } else {
        val.to_vec()
    };

    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_int1() {
        let encoded = [0b01010, 0x02];
        let mut b = octets::Octets::with_slice(&encoded);

        assert_eq!(decode_int(&mut b, 5), Ok(10));
    }

    #[test]
    fn decode_int2() {
        let encoded = [0b11111, 0b10011010, 0b00001010];
        let mut b = octets::Octets::with_slice(&encoded);

        assert_eq!(decode_int(&mut b, 5), Ok(1337));
    }

    #[test]
    fn decode_int3() {
        let encoded = [0b101010];
        let mut b = octets::Octets::with_slice(&encoded);

        assert_eq!(decode_int(&mut b, 8), Ok(42));
    }

    #[test]
    fn decode_dynamic1() {
        let mut decoder = Decoder::new(300);
        assert!(!decoder.has_instructions());

        // Stream: Encoder
        // 3fbd01              | Set Dynamic Table Capacity=220
        // c00f 7777 772e 6578 | Insert With Name Reference
        // 616d 706c 652e 636f | Static Table, Index=0
        // 6d                  |  (:authority=www.example.com)
        // c10c 2f73 616d 706c | Insert With Name Reference
        // 652f 7061 7468      |  Static Table, Index=1
        // |  (:path=/sample/path)
        //
        // Abs Ref Name        Value
        // ^-- acknowledged --^
        // 0   0  :authority  www.example.com
        // 1   0  :path       /sample/path
        // Size=106
        //
        // Stream: 4
        // 0381                | Required Insert Count = 2, Base = 0
        // 10                  | Indexed Field Line With Post-Base Index
        // |  Absolute Index = Base(0) + Index(0) = 0
        // |  (:authority=www.example.com)
        // 11                  | Indexed Field Line With Post-Base Index
        // |  Absolute Index = Base(0) + Index(1) = 1
        // |  (:path=/sample/path)
        //
        // Abs Ref Name        Value
        // ^-- acknowledged --^
        // 0   1  :authority  www.example.com
        // 1   1  :path       /sample/path
        // Size=106
        //
        // Stream: Decoder
        // 84                  | Section Acknowledgment (stream=4)
        //
        // Abs Ref Name        Value
        // 0   0  :authority  www.example.com
        // 1   0  :path       /sample/path
        // ^-- acknowledged --^
        // Size=106

        let mut decoder_stream = [0u8; 16];
        let encoder_stream = [
            0x3f, 0xbd, 0x01, 0xc0, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78,
            0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0xc1, 0x0c,
            0x2f, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x70, 0x61, 0x74,
            0x68,
        ];

        decoder.control(&encoder_stream).unwrap();

        assert_eq!(decoder.insert_cnt, 2);
        assert_eq!(decoder.tbl_sz, 106);

        let n = decoder.emit_instructions(&mut decoder_stream);

        assert_eq!(n, 1);
        assert_eq!(decoder_stream[0], 0x02);

        let enc_headers = [0x03, 0x81, 0x10, 0x11];
        let headers = decoder.decode(&enc_headers, u64::MAX, 4).unwrap();

        assert_eq!(headers[0], Header::new(":authority", "www.example.com"));
        assert_eq!(headers[1], Header::new(":path", "/sample/path"));
        assert!(decoder.has_instructions());

        let n = decoder.emit_instructions(&mut decoder_stream);

        assert_eq!(n, 1);
        assert_eq!(decoder_stream[0], 0x84);
    }

    #[test]
    fn decode_dynamic2() {
        let mut decoder = Decoder::new(300);
        let mut decoder_stream = [0u8; 16];

        let encoder_stream = [
            0x3f, 0xbd, 0x01, 0xc0, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78,
            0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0xc1, 0x0c,
            0x2f, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x70, 0x61, 0x74,
            0x68,
        ];

        assert!(!decoder.has_instructions());
        decoder.control(&encoder_stream).unwrap();
        decoder.emit_instructions(&mut decoder_stream);

        // Stream: Encoder
        // 4a63 7573 746f 6d2d | Insert With Literal Name
        // 6b65 790c 6375 7374 |  (custom-key=custom-value)
        // 6f6d 2d76 616c 7565 |
        //
        // Abs Ref Name        Value
        // 0   0  :authority  www.example.com
        // 1   0  :path       /sample/path
        // ^-- acknowledged --^
        // 2   0  custom-key  custom-value
        // Size=160
        //
        // Stream: Decoder
        // 01                  | Insert Count Increment (1)
        //
        // Abs Ref Name        Value
        // 0   0  :authority  www.example.com
        // 1   0  :path       /sample/path
        // 2   0  custom-key  custom-value
        // ^-- acknowledged --^
        // Size=160

        let encoder_stream = [
            0x4a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79,
            0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x76, 0x61, 0x6c,
            0x75, 0x65,
        ];
        decoder.control(&encoder_stream).unwrap();

        assert_eq!(decoder.insert_cnt, 3);
        assert_eq!(decoder.tbl_sz, 160);

        let n = decoder.emit_instructions(&mut decoder_stream);

        assert_eq!(n, 1);
        assert_eq!(decoder_stream[0], 0x01);

        let chk_hdr = |idx: u64, n: &str, v: &str| -> bool {
            let hdr = decoder.lookup_dynamic(idx).unwrap();
            hdr.0 == n.as_bytes() && hdr.1 == v.as_bytes()
        };

        assert!(chk_hdr(0, ":authority", "www.example.com"));
        assert!(chk_hdr(1, ":path", "/sample/path"));
        assert!(chk_hdr(2, "custom-key", "custom-value"));
    }

    #[test]
    fn decode_dynamic3() {
        let mut decoder = Decoder::new(300);
        let mut decoder_stream = [0u8; 16];

        let encoder_stream = [
            0x3f, 0xbd, 0x01, 0xc0, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78,
            0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0xc1, 0x0c,
            0x2f, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x70, 0x61, 0x74,
            0x68, 0x4a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65,
            0x79, 0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x76, 0x61,
            0x6c, 0x75, 0x65,
        ];

        assert!(!decoder.has_instructions());
        decoder.control(&encoder_stream).unwrap();
        decoder.emit_instructions(&mut decoder_stream);

        // Stream: Encoder
        // 02                  | Duplicate (Relative Index = 2)
        // |  Absolute Index =
        // |   Insert Count(3) - Index(2) - 1 = 0
        //
        // Abs Ref Name        Value
        // 0   0  :authority  www.example.com
        // 1   0  :path       /sample/path
        // 2   0  custom-key  custom-value
        // ^-- acknowledged --^
        // 3   0  :authority  www.example.com
        // Size=217
        //
        // Stream: 8
        // 0500                | Required Insert Count = 4, Base = 4
        // 80                  | Indexed Field Line, Dynamic Table
        // |  Absolute Index = Base(4) - Index(0) - 1 = 3
        // |  (:authority=www.example.com)
        // c1                  | Indexed Field Line, Static Table Index = 1
        // |  (:path=/)
        // 81                  | Indexed Field Line, Dynamic Table
        // |  Absolute Index = Base(4) - Index(1) - 1 = 2
        // |  (custom-key=custom-value)
        //
        // Abs Ref Name        Value
        // 0   0  :authority  www.example.com
        // 1   0  :path       /sample/path
        // 2   1  custom-key  custom-value
        // ^-- acknowledged --^
        // 3   1  :authority  www.example.com
        // Size=217
        //
        // Stream: Decoder
        // 48                  | Stream Cancellation (Stream=8)
        //
        // Abs Ref Name        Value
        // 0   0  :authority  www.example.com
        // 1   0  :path       /sample/path
        // 2   0  custom-key  custom-value
        // ^-- acknowledged --^
        // 3   0  :authority  www.example.com
        // Size=217

        let encoder_stream = [0x02];
        decoder.control(&encoder_stream).unwrap();
        decoder.emit_instructions(&mut decoder_stream);

        assert_eq!(decoder.insert_cnt, 4);
        assert_eq!(decoder.tbl_sz, 217);

        let chk_hdr = |idx: u64, n: &str, v: &str| -> bool {
            let hdr = decoder.lookup_dynamic(idx).unwrap();
            hdr.0 == n.as_bytes() && hdr.1 == v.as_bytes()
        };

        assert!(chk_hdr(3, ":authority", "www.example.com"));

        let enc_headers = [0x05, 0x00, 0x80, 0xc1, 0x81];
        let headers = decoder.decode(&enc_headers, u64::MAX, 8).unwrap();

        assert_eq!(headers[0], Header::new(":authority", "www.example.com"));
        assert_eq!(headers[1], Header::new(":path", "/"));
        assert_eq!(headers[2], Header::new("custom-key", "custom-value"));

        let n = decoder.emit_instructions(&mut decoder_stream);

        assert_eq!(n, 1);
        assert_eq!(decoder_stream[0], 0x88);

        assert!(!decoder.has_instructions());
        decoder.cancel_stream(8);
        assert!(decoder.has_instructions());

        let n = decoder.emit_instructions(&mut decoder_stream);

        assert_eq!(n, 1);
        assert_eq!(decoder_stream[0], 0x48);
    }

    #[test]
    /// Test partial instructions are properly buffered
    fn decode_dynamic4() {
        let mut decoder = Decoder::new(300);

        let encoder_stream = [
            0x3f, 0xbd, 0x01, 0xc0, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78,
            0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0xc1, 0x0c,
            0x2f, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x70, 0x61, 0x74,
            0x68, 0x4a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65,
            0x79, 0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x76, 0x61,
            0x6c, 0x75, 0x65, 0x02,
        ];

        assert!(!decoder.has_instructions());
        decoder.control(&encoder_stream[..7]).unwrap();
        decoder.control(&encoder_stream[7..31]).unwrap();
        decoder.control(&encoder_stream[31..]).unwrap();

        let chk_hdr = |idx: u64, n: &str, v: &str| -> bool {
            let hdr = decoder.lookup_dynamic(idx).unwrap();
            hdr.0 == n.as_bytes() && hdr.1 == v.as_bytes()
        };

        assert!(chk_hdr(0, ":authority", "www.example.com"));
        assert!(chk_hdr(1, ":path", "/sample/path"));
        assert!(chk_hdr(2, "custom-key", "custom-value"));
        assert!(chk_hdr(3, ":authority", "www.example.com"));
    }

    #[test]
    /// Test entries are evicted
    fn decode_dynamic5() {
        let mut decoder = Decoder::new(200);

        let encoder_stream = [
            0x3f, 0xa9, 0x01, 0xc0, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78,
            0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0xc1, 0x0c,
            0x2f, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x70, 0x61, 0x74,
            0x68, 0x4a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65,
            0x79, 0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x76, 0x61,
            0x6c, 0x75, 0x65, 0x02,
        ];

        assert!(!decoder.has_instructions());
        decoder.control(&encoder_stream).unwrap();
        let chk_hdr = |idx: u64, n: &str, v: &str| -> bool {
            let hdr = decoder.lookup_dynamic(idx).unwrap();
            hdr.0 == n.as_bytes() && hdr.1 == v.as_bytes()
        };

        assert_eq!(decoder.tbl_sz, 160);
        assert!(decoder.lookup_dynamic(0).is_err());
        assert!(chk_hdr(1, ":path", "/sample/path"));
        assert!(chk_hdr(2, "custom-key", "custom-value"));
        assert!(chk_hdr(3, ":authority", "www.example.com"));
    }
}
