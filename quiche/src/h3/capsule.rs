//! HTTP Capsule Protocol (RFC 9297).
//!
//! This module provides encoding and decoding of capsules as defined in
//! RFC 9297 Section 3.
//!
//! A capsule is a variable-length frame on an HTTP data stream, encoded as:
//!
//! ```text
//! Capsule {
//!   Capsule Type (i),
//!   Capsule Value Length (i),
//!   Capsule Value (..),
//! }
//! ```
//!
//! where `(i)` denotes a variable-length integer.

use super::Result;

/// RFC 9297 Section 3.2: DATAGRAM capsule type.
pub const DATAGRAM_CAPSULE: u64 = 0x00;

/// Encode a capsule header (type + value length) into `buf`.
///
/// Returns the number of bytes written.
pub fn encode_capsule_header(
    buf: &mut [u8], capsule_type: u64, value_len: u64,
) -> Result<usize> {
    let mut b = octets::OctetsMut::with_slice(buf);
    b.put_varint(capsule_type)?;
    b.put_varint(value_len)?;
    Ok(b.off())
}

/// Encode a complete capsule (header + value) into `buf`.
///
/// Returns the total number of bytes written (header + value).
pub fn encode_capsule(
    buf: &mut [u8], capsule_type: u64, value: &[u8],
) -> Result<usize> {
    let mut b = octets::OctetsMut::with_slice(buf);
    b.put_varint(capsule_type)?;
    b.put_varint(value.len() as u64)?;
    b.put_bytes(value)?;
    Ok(b.off())
}

/// Parser state for incremental capsule parsing from a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseState {
    /// Waiting for the capsule type varint.
    Type,

    /// Waiting for the capsule value length varint.
    Length,

    /// Reading capsule value bytes.
    Value,

    /// Capsule complete; next `parse()` call will emit `Done`.
    Finished,
}

/// Event returned by [`CapsuleParser::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapsuleEvent {
    /// Not enough data to make progress; feed more bytes.
    Pending,

    /// Capsule header has been fully parsed. The capsule type and value
    /// length are available via [`CapsuleParser::capsule_type`] and
    /// [`CapsuleParser::remaining`].
    Header {
        /// The capsule type identifier.
        capsule_type: u64,
        /// The length of the capsule value in bytes.
        value_len: u64,
    },

    /// A chunk of value data is available. The chunk occupies the last
    /// `len` bytes of the consumed region (i.e., `data[off - len..off]`
    /// where `off` is the caller's running offset after adding
    /// `consumed`).
    ValueChunk {
        /// Number of value bytes in this chunk.
        len: usize,
    },

    /// The capsule has been fully consumed and the parser has been reset
    /// to accept the next capsule.
    Done,
}

/// Incremental capsule parser.
///
/// This parser handles partial reads, buffering varint bytes internally
/// until a complete type or length field can be decoded.
///
/// Typical usage:
///
/// ```ignore
/// let mut parser = CapsuleParser::new();
/// loop {
///     let data = /* read from stream */;
///     let mut off = 0;
///     while off < data.len() {
///         let (event, consumed) = parser.parse(&data[off..])?;
///         off += consumed;
///         match event {
///             CapsuleEvent::Header { capsule_type, value_len } => { /* ... */ },
///             CapsuleEvent::ValueChunk { len } => { /* ... */ },
///             CapsuleEvent::Done => { /* capsule complete */ },
///             CapsuleEvent::Pending => break,
///         }
///     }
/// }
/// ```
#[derive(Debug)]
pub struct CapsuleParser {
    state: ParseState,

    // Buffer for accumulating varint bytes across partial reads.
    hdr_buf: Vec<u8>,

    capsule_type: u64,
    value_len: u64,
    value_read: u64,
}

impl CapsuleParser {
    /// Create a new parser ready to read the first capsule.
    pub fn new() -> Self {
        CapsuleParser {
            state: ParseState::Type,
            hdr_buf: Vec::new(),
            capsule_type: 0,
            value_len: 0,
            value_read: 0,
        }
    }

    /// Returns the capsule type of the capsule currently being parsed.
    ///
    /// Only meaningful after a [`CapsuleEvent::Header`] has been returned.
    pub fn capsule_type(&self) -> u64 {
        self.capsule_type
    }

    /// Returns the number of value bytes remaining to be read.
    ///
    /// Returns 0 when the parser is not in the `Value` state.
    pub fn remaining(&self) -> u64 {
        if self.state != ParseState::Value {
            return 0;
        }
        self.value_len.saturating_sub(self.value_read)
    }

    /// Returns the current parser state.
    pub fn state(&self) -> &ParseState {
        &self.state
    }

    /// Returns `true` if the parser is in the middle of parsing a capsule.
    ///
    /// RFC 9297 §3.3: if the receive side of a stream is terminated cleanly
    /// and this returns `true`, the last capsule was truncated and MUST be
    /// treated as a malformed message.
    pub fn is_in_progress(&self) -> bool {
        match self.state {
            ParseState::Type => !self.hdr_buf.is_empty(),
            ParseState::Length | ParseState::Value => true,
            ParseState::Finished => false,
        }
    }

    /// Feed data to the parser.
    ///
    /// Returns a `(CapsuleEvent, usize)` tuple where the `usize` is the
    /// number of bytes consumed from `data`. The caller should advance its
    /// read position by that amount and call `parse` again with the
    /// remaining data until [`CapsuleEvent::Pending`] is returned.
    pub fn parse(&mut self, data: &[u8]) -> Result<(CapsuleEvent, usize)> {
        // Finished state emits Done without consuming data.
        if self.state == ParseState::Finished {
            self.state = ParseState::Type;
            return Ok((CapsuleEvent::Done, 0));
        }

        if data.is_empty() {
            return Ok((CapsuleEvent::Pending, 0));
        }

        match self.state {
            ParseState::Type => self.parse_varint(data, true),

            ParseState::Length => self.parse_varint(data, false),

            ParseState::Value => self.parse_value(data),

            ParseState::Finished => unreachable!(),
        }
    }

    /// Try to parse a varint from accumulated + new data.
    ///
    /// When `is_type` is true we are parsing the capsule type field;
    /// otherwise we are parsing the value length field.
    fn parse_varint(
        &mut self, data: &[u8], is_type: bool,
    ) -> Result<(CapsuleEvent, usize)> {
        // If we have no accumulated bytes, try fast-path: parse directly
        // from the input.
        if self.hdr_buf.is_empty() {
            let mut b = octets::Octets::with_slice(data);
            match b.get_varint() {
                Ok(val) => {
                    let consumed = b.off();
                    return self.varint_complete(val, consumed, is_type);
                },

                Err(_) => {
                    // Not enough data; buffer what we have.
                    self.hdr_buf.extend_from_slice(data);
                    return Ok((CapsuleEvent::Pending, data.len()));
                },
            }
        }

        // Slow path: we have accumulated partial varint bytes. Append
        // one byte at a time until we can decode.
        let mut consumed = 0;
        while consumed < data.len() {
            self.hdr_buf.push(data[consumed]);
            consumed += 1;

            let mut b = octets::Octets::with_slice(&self.hdr_buf);
            match b.get_varint() {
                Ok(val) => {
                    self.hdr_buf.clear();
                    return self.varint_complete(val, consumed, is_type);
                },

                Err(_) => {
                    // Check if the buffer is unreasonably large (a varint
                    // is at most 8 bytes).
                    if self.hdr_buf.len() > 8 {
                        return Err(crate::h3::Error::FrameError);
                    }
                    continue;
                },
            }
        }

        // Consumed all input but still not enough for the varint.
        Ok((CapsuleEvent::Pending, consumed))
    }

    /// Handle a successfully decoded varint.
    fn varint_complete(
        &mut self, val: u64, consumed: usize, is_type: bool,
    ) -> Result<(CapsuleEvent, usize)> {
        if is_type {
            self.capsule_type = val;
            self.state = ParseState::Length;
            Ok((CapsuleEvent::Pending, consumed))
        } else {
            self.value_len = val;
            self.value_read = 0;

            if self.value_len == 0 {
                // Zero-length value: emit Header, then Done on next
                // parse() call via the Finished state.
                self.state = ParseState::Finished;
                Ok((
                    CapsuleEvent::Header {
                        capsule_type: self.capsule_type,
                        value_len: 0,
                    },
                    consumed,
                ))
            } else {
                self.state = ParseState::Value;
                Ok((
                    CapsuleEvent::Header {
                        capsule_type: self.capsule_type,
                        value_len: self.value_len,
                    },
                    consumed,
                ))
            }
        }
    }

    /// Consume value bytes from the input.
    fn parse_value(
        &mut self, data: &[u8],
    ) -> Result<(CapsuleEvent, usize)> {
        let remaining_u64 = self.value_len.saturating_sub(self.value_read);
        let remaining =
            std::cmp::min(remaining_u64, data.len() as u64) as usize;
        let chunk = std::cmp::min(data.len(), remaining);

        if chunk == 0 {
            return Ok((CapsuleEvent::Pending, 0));
        }

        self.value_read += chunk as u64;

        if self.value_read == self.value_len {
            // Value fully consumed; reset for next capsule.
            self.state = ParseState::Type;
            Ok((CapsuleEvent::Done, chunk))
        } else {
            Ok((
                CapsuleEvent::ValueChunk { len: chunk },
                chunk,
            ))
        }
    }

    /// Reset the parser to its initial state.
    pub fn reset(&mut self) {
        self.state = ParseState::Type;
        self.hdr_buf.clear();
        self.capsule_type = 0;
        self.value_len = 0;
        self.value_read = 0;
    }
}

impl Default for CapsuleParser {
    fn default() -> Self {
        CapsuleParser::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capsule_header_encode_decode() {
        let mut buf = [0u8; 64];

        let written =
            encode_capsule_header(&mut buf, DATAGRAM_CAPSULE, 10).unwrap();

        // Type 0x00 = 1 byte varint, length 10 = 1 byte varint.
        assert_eq!(written, 2);

        let mut b = octets::Octets::with_slice(&buf[..written]);
        let capsule_type = b.get_varint().unwrap();
        let value_len = b.get_varint().unwrap();
        assert_eq!(capsule_type, DATAGRAM_CAPSULE);
        assert_eq!(value_len, 10);
    }

    #[test]
    fn capsule_header_large_values() {
        let mut buf = [0u8; 64];

        // Use values that require multi-byte varints.
        let ctype = 0x1000;
        let vlen = 0x4000_0000;

        let written = encode_capsule_header(&mut buf, ctype, vlen).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..written]);
        assert_eq!(b.get_varint().unwrap(), ctype);
        assert_eq!(b.get_varint().unwrap(), vlen);
    }

    #[test]
    fn capsule_header_buffer_too_short() {
        let mut buf = [0u8; 1];

        // Type fits (1 byte) but length (10 = 1 byte) won't fit.
        let result = encode_capsule_header(&mut buf, 0x00, 10);
        assert!(result.is_err());
    }

    #[test]
    fn full_capsule_roundtrip() {
        let mut buf = [0u8; 128];
        let value = b"hello capsule";

        let written =
            encode_capsule(&mut buf, DATAGRAM_CAPSULE, value).unwrap();

        // Header: type(1) + length(1) + value(13) = 15.
        assert_eq!(written, 2 + value.len());

        let mut b = octets::Octets::with_slice(&buf[..written]);
        let capsule_type = b.get_varint().unwrap();
        let value_len = b.get_varint().unwrap();
        assert_eq!(capsule_type, DATAGRAM_CAPSULE);
        assert_eq!(value_len, value.len() as u64);

        let payload = b.get_bytes(value_len as usize).unwrap();
        assert_eq!(payload.as_ref(), value);
    }

    #[test]
    fn full_capsule_empty_value() {
        let mut buf = [0u8; 64];

        let written = encode_capsule(&mut buf, 0xFF, &[]).unwrap();

        let mut b = octets::Octets::with_slice(&buf[..written]);
        let capsule_type = b.get_varint().unwrap();
        let value_len = b.get_varint().unwrap();
        assert_eq!(capsule_type, 0xFF);
        assert_eq!(value_len, 0);
        assert_eq!(b.cap(), 0);
    }

    #[test]
    fn parser_complete_data() {
        let mut buf = [0u8; 128];
        let value = b"test data";
        let written =
            encode_capsule(&mut buf, DATAGRAM_CAPSULE, value).unwrap();

        let mut parser = CapsuleParser::new();
        let data = &buf[..written];

        // First parse should consume the type varint and return Pending
        // (type alone doesn't produce a header event).
        let (event, consumed1) = parser.parse(data).unwrap();
        assert_eq!(event, CapsuleEvent::Pending);
        assert!(consumed1 > 0);

        // Second parse should consume the length varint and return Header.
        let (event, consumed2) = parser.parse(&data[consumed1..]).unwrap();
        assert_eq!(
            event,
            CapsuleEvent::Header {
                capsule_type: DATAGRAM_CAPSULE,
                value_len: value.len() as u64,
            }
        );

        // Third parse should consume the value and return Done.
        let off = consumed1 + consumed2;
        let (event, consumed3) = parser.parse(&data[off..]).unwrap();
        assert_eq!(event, CapsuleEvent::Done);
        assert_eq!(consumed3, value.len());
        assert_eq!(off + consumed3, written);
    }

    #[test]
    fn parser_chunked_data() {
        let mut buf = [0u8; 128];
        let value = b"chunked";
        let written =
            encode_capsule(&mut buf, DATAGRAM_CAPSULE, value).unwrap();

        let mut parser = CapsuleParser::new();

        // Feed one byte at a time.
        let mut pos = 0;
        let mut saw_header = false;
        let mut saw_done = false;
        let mut value_bytes = 0;

        while pos < written {
            let (event, consumed) =
                parser.parse(&buf[pos..pos + 1]).unwrap();
            pos += consumed;

            match event {
                CapsuleEvent::Pending => {},

                CapsuleEvent::Header {
                    capsule_type,
                    value_len,
                } => {
                    assert_eq!(capsule_type, DATAGRAM_CAPSULE);
                    assert_eq!(value_len, value.len() as u64);
                    saw_header = true;
                },

                CapsuleEvent::ValueChunk { len } => {
                    value_bytes += len;
                },

                CapsuleEvent::Done => {
                    // Done also accounts for the last value byte consumed.
                    value_bytes += consumed;
                    saw_done = true;
                },
            }
        }

        assert_eq!(value_bytes, value.len());

        assert!(saw_header);
        assert!(saw_done);
    }

    #[test]
    fn parser_zero_length_capsule() {
        let mut buf = [0u8; 64];
        let written = encode_capsule(&mut buf, 0x00, &[]).unwrap();
        assert_eq!(written, 2); // type(1) + length(1)

        let mut parser = CapsuleParser::new();

        // Feed the type byte.
        let (event, c1) = parser.parse(&buf[..1]).unwrap();
        assert_eq!(event, CapsuleEvent::Pending);
        assert_eq!(c1, 1);

        // Feed the length byte (0). Zero-length value emits Header.
        let (event, c2) = parser.parse(&buf[c1..written]).unwrap();
        assert_eq!(
            event,
            CapsuleEvent::Header {
                capsule_type: 0x00,
                value_len: 0,
            }
        );
        assert_eq!(c1 + c2, written);

        // Next parse emits Done (Finished state, 0 consumed).
        let (event, c3) = parser.parse(&[]).unwrap();
        assert_eq!(event, CapsuleEvent::Done);
        assert_eq!(c3, 0);
    }

    #[test]
    fn parser_zero_length_capsule_multipart() {
        let mut buf = [0u8; 64];
        // Use a type that needs a 2-byte varint to exercise partial
        // buffering together with zero-length value.
        let written = encode_capsule(&mut buf, 0x42, &[]).unwrap();

        let mut parser = CapsuleParser::new();
        let mut pos = 0;
        let mut saw_header = false;

        // Feed one byte at a time.
        while pos < written {
            let (event, consumed) =
                parser.parse(&buf[pos..pos + 1]).unwrap();
            pos += consumed;
            if let CapsuleEvent::Header {
                capsule_type,
                value_len,
            } = event
            {
                assert_eq!(capsule_type, 0x42);
                assert_eq!(value_len, 0);
                saw_header = true;
            }
        }

        assert!(saw_header);
        assert_eq!(pos, written);

        // Finished state requires one more parse() call to emit Done.
        let (event, consumed) = parser.parse(&[]).unwrap();
        assert_eq!(event, CapsuleEvent::Done);
        assert_eq!(consumed, 0);
    }

    #[test]
    fn parser_multiple_capsules() {
        let mut buf = [0u8; 256];
        let v1 = b"first";
        let v2 = b"second";

        let w1 = encode_capsule(&mut buf, 0x01, v1).unwrap();
        let w2 = encode_capsule(&mut buf[w1..], 0x02, v2).unwrap();
        let total = w1 + w2;

        let mut parser = CapsuleParser::new();
        let mut pos = 0;
        let mut capsule_count = 0;

        while pos < total {
            let (event, consumed) =
                parser.parse(&buf[pos..total]).unwrap();
            pos += consumed;

            if event == CapsuleEvent::Done {
                capsule_count += 1;
            }
        }

        assert_eq!(capsule_count, 2);
    }

    #[test]
    fn parser_empty_input() {
        let mut parser = CapsuleParser::new();
        let (event, consumed) = parser.parse(&[]).unwrap();
        assert_eq!(event, CapsuleEvent::Pending);
        assert_eq!(consumed, 0);
    }

    #[test]
    fn parser_unknown_capsule_type() {
        let mut buf = [0u8; 128];
        let value = b"unknown";
        let written = encode_capsule(&mut buf, 0xFFFF, value).unwrap();

        let mut parser = CapsuleParser::new();
        let mut pos = 0;
        let mut saw_header = false;

        while pos < written {
            let (event, consumed) =
                parser.parse(&buf[pos..written]).unwrap();
            pos += consumed;

            if let CapsuleEvent::Header {
                capsule_type,
                value_len,
            } = event
            {
                assert_eq!(capsule_type, 0xFFFF);
                assert_eq!(value_len, value.len() as u64);
                saw_header = true;
            }
        }

        assert!(saw_header);
    }

    #[test]
    fn parser_reset() {
        let mut parser = CapsuleParser::new();

        // Partially feed data.
        let mut buf = [0u8; 64];
        let written = encode_capsule(&mut buf, 0x01, b"data").unwrap();

        let (_, consumed) = parser.parse(&buf[..1]).unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(*parser.state(), ParseState::Length);

        // Reset and verify clean state.
        parser.reset();
        assert_eq!(*parser.state(), ParseState::Type);
        assert_eq!(parser.capsule_type(), 0);
        assert_eq!(parser.remaining(), 0);

        // Should work normally after reset.
        let mut pos = 0;
        let mut saw_done = false;
        while pos < written {
            let (event, consumed) =
                parser.parse(&buf[pos..written]).unwrap();
            pos += consumed;
            if event == CapsuleEvent::Done {
                saw_done = true;
            }
        }
        assert!(saw_done);
    }

    #[test]
    fn parser_large_varint_chunked() {
        // Encode a capsule with a type that requires a 4-byte varint.
        let mut buf = [0u8; 128];
        let ctype = 0x3FFF_FFFF; // max 4-byte varint
        let value = b"lg";
        let written = encode_capsule(&mut buf, ctype, value).unwrap();

        let mut parser = CapsuleParser::new();
        let mut pos = 0;
        let mut saw_header = false;

        // Feed one byte at a time.
        while pos < written {
            let (event, consumed) =
                parser.parse(&buf[pos..pos + 1]).unwrap();
            pos += consumed;

            if let CapsuleEvent::Header {
                capsule_type,
                value_len,
            } = event
            {
                assert_eq!(capsule_type, ctype);
                assert_eq!(value_len, value.len() as u64);
                saw_header = true;
            }
        }

        assert!(saw_header);
    }

    #[test]
    fn encode_capsule_buffer_too_short() {
        let mut buf = [0u8; 2];
        let result = encode_capsule(&mut buf, 0x00, b"too long");
        assert!(result.is_err());
    }

    #[test]
    fn capsule_parser_is_in_progress_initial() {
        let parser = CapsuleParser::new();
        assert!(!parser.is_in_progress());
    }

    #[test]
    fn capsule_parser_is_in_progress_partial_type() {
        let mut parser = CapsuleParser::new();
        // Feed a partial varint (2-byte varint, only first byte)
        let data = [0x40]; // First byte of a 2-byte varint
        let (event, _) = parser.parse(&data).unwrap();
        assert_eq!(event, CapsuleEvent::Pending);
        assert!(parser.is_in_progress());
    }

    #[test]
    fn capsule_parser_is_in_progress_in_length() {
        let mut parser = CapsuleParser::new();
        // Feed complete type but no length
        let data = [0x00]; // type = 0 (1-byte varint)
        let (event, _) = parser.parse(&data).unwrap();
        assert_eq!(event, CapsuleEvent::Pending);
        assert!(parser.is_in_progress());
    }

    #[test]
    fn capsule_parser_is_in_progress_in_value() {
        let mut parser = CapsuleParser::new();
        // type = 0, length = 5
        let data = [0x00, 0x05, 0xAA];
        let mut off = 0;
        loop {
            let (event, consumed) =
                parser.parse(&data[off..]).unwrap();
            off += consumed;
            match event {
                CapsuleEvent::Pending => break,
                CapsuleEvent::Header { .. } => continue,
                CapsuleEvent::ValueChunk { .. } => break,
                CapsuleEvent::Done => unreachable!(),
            }
        }
        assert!(parser.is_in_progress());
    }

    #[test]
    fn capsule_parser_not_in_progress_after_done() {
        let mut parser = CapsuleParser::new();
        // type = 0, length = 0 (zero-length capsule)
        let data = [0x00, 0x00];
        let mut off = 0;
        loop {
            let (event, consumed) =
                parser.parse(&data[off..]).unwrap();
            off += consumed;
            if event == CapsuleEvent::Done {
                break;
            }
        }
        assert!(!parser.is_in_progress());
    }
}
