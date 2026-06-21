// Copyright (C) 2018-2019, Cloudflare, Inc.
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

/// Zero-copy abstraction for parsing and constructing network packets.
use std::mem;
use std::ptr;

/// Maximum value that can be encoded via varint.
pub const MAX_VAR_INT: u64 = 4_611_686_018_427_387_903;

/// A specialized [`Result`] type for [`OctetsMut`] operations.
///
/// [`Result`]: https://doc.rust-lang.org/std/result/enum.Result.html
/// [`OctetsMut`]: struct.OctetsMut.html
pub type Result<T> = std::result::Result<T, BufferTooShortError>;

/// An error indicating that the provided [`OctetsMut`] is not big enough.
///
/// [`OctetsMut`]: struct.OctetsMut.html
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferTooShortError;

impl std::fmt::Display for BufferTooShortError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "BufferTooShortError")
    }
}

impl std::error::Error for BufferTooShortError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// A byte sink for encoders in this crate.
///
/// This lets callers use octets encoders with output targets other than a
/// single contiguous [`OctetsMut`] buffer.
pub trait OctetsWriter {
    /// The error returned by the output sink.
    type Error;

    /// Writes `v` to the output sink.
    fn put_bytes(&mut self, v: &[u8]) -> std::result::Result<(), Self::Error>;

    /// Writes `v` to the output sink after HPACK Huffman-encoding it.
    ///
    /// The Huffman code implemented is the one defined for HPACK (RFC7541).
    #[cfg(feature = "huffman_hpack")]
    fn put_huffman_encoded<const LOWER_CASE: bool>(
        &mut self, v: &[u8],
    ) -> std::result::Result<(), Self::Error>
    where
        Self: Sized,
    {
        huffman_encode_with::<LOWER_CASE, _, _>(v, |chunk| self.put_bytes(chunk))
    }
}

/// Helper macro that asserts at compile time. It requires that
/// `cond` is a const expression.
macro_rules! static_assert {
    ($cond:expr) => {{
        const _: () = assert!($cond);
    }};
}

macro_rules! peek_u {
    ($b:expr, $ty:ty, $len:expr) => {{
        let len = $len;
        let src = &$b.buf[$b.off..];

        if src.len() < len {
            return Err(BufferTooShortError);
        }

        static_assert!($len <= mem::size_of::<$ty>());
        let mut out: $ty = 0;
        unsafe {
            let dst = &mut out as *mut $ty as *mut u8;
            let off = (mem::size_of::<$ty>() - len) as isize;

            ptr::copy_nonoverlapping(src.as_ptr(), dst.offset(off), len);
        };

        Ok(<$ty>::from_be(out))
    }};
}

macro_rules! get_u {
    ($b:expr, $ty:ty, $len:expr) => {{
        let out = peek_u!($b, $ty, $len);

        $b.off += $len;

        out
    }};
}

macro_rules! put_u {
    ($b:expr, $ty:ty, $v:expr, $len:expr) => {{
        let len = $len;

        if $b.buf.len() < $b.off + len {
            return Err(BufferTooShortError);
        }

        let v = $v;

        let dst = &mut $b.buf[$b.off..($b.off + len)];

        static_assert!($len <= mem::size_of::<$ty>());
        unsafe {
            let src = &<$ty>::to_be(v) as *const $ty as *const u8;
            let off = (mem::size_of::<$ty>() - len) as isize;

            ptr::copy_nonoverlapping(src.offset(off), dst.as_mut_ptr(), len);
        }

        $b.off += $len;

        Ok(dst)
    }};
}

/// A zero-copy immutable byte buffer.
///
/// `Octets` wraps an in-memory buffer of bytes and provides utility functions
/// for manipulating it. The underlying buffer is provided by the user and is
/// not copied when creating an `Octets`. Operations are panic-free and will
/// avoid indexing the buffer past its end.
///
/// Additionally, an offset (initially set to the start of the buffer) is
/// incremented as bytes are read from / written to the buffer, to allow for
/// sequential operations.
#[derive(Debug, PartialEq, Eq)]
pub struct Octets<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Octets<'a> {
    /// Creates an `Octets` from the given slice, without copying.
    ///
    /// Since the `Octets` is immutable, the input slice needs to be
    /// immutable.
    pub fn with_slice(buf: &'a [u8]) -> Self {
        Octets { buf, off: 0 }
    }

    /// Reads an unsigned 8-bit integer from the current offset and advances
    /// the buffer.
    pub fn get_u8(&mut self) -> Result<u8> {
        get_u!(self, u8, 1)
    }

    /// Reads an unsigned 8-bit integer from the current offset without
    /// advancing the buffer.
    pub fn peek_u8(&mut self) -> Result<u8> {
        peek_u!(self, u8, 1)
    }

    /// Reads an unsigned 16-bit integer in network byte-order from the current
    /// offset and advances the buffer.
    pub fn get_u16(&mut self) -> Result<u16> {
        get_u!(self, u16, 2)
    }

    /// Reads an unsigned 24-bit integer in network byte-order from the current
    /// offset and advances the buffer.
    pub fn get_u24(&mut self) -> Result<u32> {
        get_u!(self, u32, 3)
    }

    /// Reads an unsigned 32-bit integer in network byte-order from the current
    /// offset and advances the buffer.
    pub fn get_u32(&mut self) -> Result<u32> {
        get_u!(self, u32, 4)
    }

    /// Reads an unsigned 64-bit integer in network byte-order from the current
    /// offset and advances the buffer.
    pub fn get_u64(&mut self) -> Result<u64> {
        get_u!(self, u64, 8)
    }

    /// Reads an unsigned variable-length integer in network byte-order from
    /// the current offset and advances the buffer.
    pub fn get_varint(&mut self) -> Result<u64> {
        let first = self.peek_u8()?;

        let len = varint_parse_len(first);

        if len > self.cap() {
            return Err(BufferTooShortError);
        }

        let out = match len {
            1 => u64::from(self.get_u8()?),

            2 => u64::from(self.get_u16()? & 0x3fff),

            4 => u64::from(self.get_u32()? & 0x3fffffff),

            8 => self.get_u64()? & 0x3fffffffffffffff,

            _ => unreachable!(),
        };

        Ok(out)
    }

    /// Reads `len` bytes from the current offset without copying and advances
    /// the buffer.
    pub fn get_bytes(&mut self, len: usize) -> Result<Octets<'a>> {
        if self.cap() < len {
            return Err(BufferTooShortError);
        }

        let out = Octets {
            buf: &self.buf[self.off..self.off + len],
            off: 0,
        };

        self.off += len;

        Ok(out)
    }

    /// Reads `len` bytes from the current offset without copying and advances
    /// the buffer, where `len` is an unsigned 8-bit integer prefix.
    pub fn get_bytes_with_u8_length(&mut self) -> Result<Octets<'a>> {
        let len = self.get_u8()?;
        self.get_bytes(len as usize)
    }

    /// Reads `len` bytes from the current offset without copying and advances
    /// the buffer, where `len` is an unsigned 16-bit integer prefix in network
    /// byte-order.
    pub fn get_bytes_with_u16_length(&mut self) -> Result<Octets<'a>> {
        let len = self.get_u16()?;
        self.get_bytes(len as usize)
    }

    /// Reads `len` bytes from the current offset without copying and advances
    /// the buffer, where `len` is an unsigned variable-length integer prefix
    /// in network byte-order.
    pub fn get_bytes_with_varint_length(&mut self) -> Result<Octets<'a>> {
        let len = self.get_varint()?;
        self.get_bytes(len as usize)
    }

    /// Decodes a Huffman-encoded value from the current offset.
    ///
    /// The Huffman code implemented is the one defined for HPACK (RFC7541).
    #[cfg(feature = "huffman_hpack")]
    pub fn get_huffman_decoded(&mut self) -> Result<Vec<u8>> {
        use self::huffman_table::DECODE_TABLE;

        const FLAG_END: u8 = 1;
        const FLAG_SYM: u8 = 2;
        const FLAG_ERR: u8 = 4;

        // Max compression ratio is >= 0.5.
        let mut out = Vec::with_capacity(self.cap() << 1);

        let mut state = 0;
        let mut eos = false;

        while let Ok(byte) = self.get_u8() {
            for data in [byte >> 4, byte & 0xf] {
                let (next, sym, flags) = DECODE_TABLE[state][(data) as usize];

                if flags & FLAG_ERR == FLAG_ERR {
                    // Data followed the "end" marker.
                    return Err(BufferTooShortError);
                } else if flags & FLAG_SYM == FLAG_SYM {
                    out.push(sym);
                }

                state = next;

                // `eos` only correct when handling the byte & 0xf case; ignored
                // and overwritten in the byte >> 4 case.
                eos = flags & FLAG_END == FLAG_END;
            }
        }

        if state != 0 && !eos {
            return Err(BufferTooShortError);
        }

        Ok(out)
    }

    /// Reads `len` bytes from the current offset without copying and without
    /// advancing the buffer.
    pub fn peek_bytes(&self, len: usize) -> Result<Octets<'a>> {
        if self.cap() < len {
            return Err(BufferTooShortError);
        }

        let out = Octets {
            buf: &self.buf[self.off..self.off + len],
            off: 0,
        };

        Ok(out)
    }

    /// Rewinds the buffer offset by `len` elements.
    pub fn rewind(&mut self, len: usize) -> Result<()> {
        if self.off() < len {
            return Err(BufferTooShortError);
        }

        self.off -= len;

        Ok(())
    }

    /// Returns a slice of `len` elements from the current offset.
    pub fn slice(&self, len: usize) -> Result<&'a [u8]> {
        if len > self.cap() {
            return Err(BufferTooShortError);
        }

        Ok(&self.buf[self.off..self.off + len])
    }

    /// Returns a slice of `len` elements from the end of the buffer.
    pub fn slice_last(&self, len: usize) -> Result<&'a [u8]> {
        if len > self.cap() {
            return Err(BufferTooShortError);
        }

        let end = self.buf.len();
        Ok(&self.buf[end - len..end])
    }

    /// Advances the buffer's offset.
    pub fn skip(&mut self, skip: usize) -> Result<()> {
        if skip > self.cap() {
            return Err(BufferTooShortError);
        }

        self.off += skip;

        Ok(())
    }

    /// Returns the remaining capacity in the buffer.
    pub fn cap(&self) -> usize {
        self.buf.len() - self.off
    }

    /// Returns the total length of the buffer.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns `true` if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.len() == 0
    }

    /// Returns the current offset of the buffer.
    pub fn off(&self) -> usize {
        self.off
    }

    /// Returns a reference to the internal buffer.
    pub fn buf(&self) -> &'a [u8] {
        self.buf
    }

    /// Copies the buffer from the current offset into a new `Vec<u8>`.
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_ref().to_vec()
    }
}

impl AsRef<[u8]> for Octets<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.buf[self.off..]
    }
}

/// A zero-copy mutable byte buffer.
///
/// Like `Octets` but mutable.
#[derive(Debug, PartialEq, Eq)]
pub struct OctetsMut<'a> {
    buf: &'a mut [u8],
    off: usize,
}

impl<'a> OctetsMut<'a> {
    /// Creates an `OctetsMut` from the given slice, without copying.
    ///
    /// Since there's no copy, the input slice needs to be mutable to allow
    /// modifications.
    pub fn with_slice(buf: &'a mut [u8]) -> Self {
        OctetsMut { buf, off: 0 }
    }

    /// Reads an unsigned 8-bit integer from the current offset and advances
    /// the buffer.
    pub fn get_u8(&mut self) -> Result<u8> {
        get_u!(self, u8, 1)
    }

    /// Reads an unsigned 8-bit integer from the current offset without
    /// advancing the buffer.
    pub fn peek_u8(&mut self) -> Result<u8> {
        peek_u!(self, u8, 1)
    }

    /// Writes an unsigned 8-bit integer at the current offset and advances
    /// the buffer.
    pub fn put_u8(&mut self, v: u8) -> Result<&mut [u8]> {
        put_u!(self, u8, v, 1)
    }

    /// Reads an unsigned 16-bit integer in network byte-order from the current
    /// offset and advances the buffer.
    pub fn get_u16(&mut self) -> Result<u16> {
        get_u!(self, u16, 2)
    }

    /// Writes an unsigned 16-bit integer in network byte-order at the current
    /// offset and advances the buffer.
    pub fn put_u16(&mut self, v: u16) -> Result<&mut [u8]> {
        put_u!(self, u16, v, 2)
    }

    /// Reads an unsigned 24-bit integer in network byte-order from the current
    /// offset and advances the buffer.
    pub fn get_u24(&mut self) -> Result<u32> {
        get_u!(self, u32, 3)
    }

    /// Writes an unsigned 24-bit integer in network byte-order at the current
    /// offset and advances the buffer.
    pub fn put_u24(&mut self, v: u32) -> Result<&mut [u8]> {
        put_u!(self, u32, v, 3)
    }

    /// Reads an unsigned 32-bit integer in network byte-order from the current
    /// offset and advances the buffer.
    pub fn get_u32(&mut self) -> Result<u32> {
        get_u!(self, u32, 4)
    }

    /// Writes an unsigned 32-bit integer in network byte-order at the current
    /// offset and advances the buffer.
    pub fn put_u32(&mut self, v: u32) -> Result<&mut [u8]> {
        put_u!(self, u32, v, 4)
    }

    /// Reads an unsigned 64-bit integer in network byte-order from the current
    /// offset and advances the buffer.
    pub fn get_u64(&mut self) -> Result<u64> {
        get_u!(self, u64, 8)
    }

    /// Writes an unsigned 64-bit integer in network byte-order at the current
    /// offset and advances the buffer.
    pub fn put_u64(&mut self, v: u64) -> Result<&mut [u8]> {
        put_u!(self, u64, v, 8)
    }

    /// Reads an unsigned variable-length integer in network byte-order from
    /// the current offset and advances the buffer.
    pub fn get_varint(&mut self) -> Result<u64> {
        let first = self.peek_u8()?;

        let len = varint_parse_len(first);

        if len > self.cap() {
            return Err(BufferTooShortError);
        }

        let out = match len {
            1 => u64::from(self.get_u8()?),

            2 => u64::from(self.get_u16()? & 0x3fff),

            4 => u64::from(self.get_u32()? & 0x3fffffff),

            8 => self.get_u64()? & 0x3fffffffffffffff,

            _ => unreachable!(),
        };

        Ok(out)
    }

    /// Writes an unsigned variable-length integer in network byte-order at the
    /// current offset and advances the buffer.
    pub fn put_varint(&mut self, v: u64) -> Result<&mut [u8]> {
        self.put_varint_with_len(v, varint_len(v))
    }

    /// Writes an unsigned variable-length integer of the specified length, in
    /// network byte-order at the current offset and advances the buffer.
    pub fn put_varint_with_len(
        &mut self, v: u64, len: usize,
    ) -> Result<&mut [u8]> {
        if self.cap() < len {
            return Err(BufferTooShortError);
        }

        let buf = match len {
            1 => self.put_u8(v as u8)?,

            2 => {
                let buf = self.put_u16(v as u16)?;
                buf[0] |= 0x40;
                buf
            },

            4 => {
                let buf = self.put_u32(v as u32)?;
                buf[0] |= 0x80;
                buf
            },

            8 => {
                let buf = self.put_u64(v)?;
                buf[0] |= 0xc0;
                buf
            },

            _ => panic!("value is too large for varint"),
        };

        Ok(buf)
    }

    /// Reads `len` bytes from the current offset without copying and advances
    /// the buffer.
    pub fn get_bytes(&mut self, len: usize) -> Result<Octets<'_>> {
        if self.cap() < len {
            return Err(BufferTooShortError);
        }

        let out = Octets {
            buf: &self.buf[self.off..self.off + len],
            off: 0,
        };

        self.off += len;

        Ok(out)
    }

    /// Reads `len` bytes from the current offset without copying and advances
    /// the buffer.
    pub fn get_bytes_mut(&mut self, len: usize) -> Result<OctetsMut<'_>> {
        if self.cap() < len {
            return Err(BufferTooShortError);
        }

        let out = OctetsMut {
            buf: &mut self.buf[self.off..self.off + len],
            off: 0,
        };

        self.off += len;

        Ok(out)
    }

    /// Reads `len` bytes from the current offset without copying and advances
    /// the buffer, where `len` is an unsigned 8-bit integer prefix.
    pub fn get_bytes_with_u8_length(&mut self) -> Result<Octets<'_>> {
        let len = self.get_u8()?;
        self.get_bytes(len as usize)
    }

    /// Reads `len` bytes from the current offset without copying and advances
    /// the buffer, where `len` is an unsigned 16-bit integer prefix in network
    /// byte-order.
    pub fn get_bytes_with_u16_length(&mut self) -> Result<Octets<'_>> {
        let len = self.get_u16()?;
        self.get_bytes(len as usize)
    }

    /// Reads `len` bytes from the current offset without copying and advances
    /// the buffer, where `len` is an unsigned variable-length integer prefix
    /// in network byte-order.
    pub fn get_bytes_with_varint_length(&mut self) -> Result<Octets<'_>> {
        let len = self.get_varint()?;
        self.get_bytes(len as usize)
    }

    /// Reads `len` bytes from the current offset without copying and without
    /// advancing the buffer.
    pub fn peek_bytes(&mut self, len: usize) -> Result<Octets<'_>> {
        if self.cap() < len {
            return Err(BufferTooShortError);
        }

        let out = Octets {
            buf: &self.buf[self.off..self.off + len],
            off: 0,
        };

        Ok(out)
    }

    /// Reads `len` bytes from the current offset without copying and without
    /// advancing the buffer.
    pub fn peek_bytes_mut(&mut self, len: usize) -> Result<OctetsMut<'_>> {
        if self.cap() < len {
            return Err(BufferTooShortError);
        }

        let out = OctetsMut {
            buf: &mut self.buf[self.off..self.off + len],
            off: 0,
        };

        Ok(out)
    }

    /// Writes `v` to the current offset.
    pub fn put_bytes(&mut self, v: &[u8]) -> Result<()> {
        let len = v.len();

        if self.cap() < len {
            return Err(BufferTooShortError);
        }

        if len == 0 {
            return Ok(());
        }

        self.as_mut()[..len].copy_from_slice(v);

        self.off += len;

        Ok(())
    }

    /// Writes `v` to the current offset after Huffman-encoding it.
    ///
    /// The Huffman code implemented is the one defined for HPACK (RFC7541).
    #[cfg(feature = "huffman_hpack")]
    pub fn put_huffman_encoded<const LOWER_CASE: bool>(
        &mut self, v: &[u8],
    ) -> Result<()> {
        <Self as OctetsWriter>::put_huffman_encoded::<LOWER_CASE>(self, v)
    }

    /// Rewinds the buffer offset by `len` elements.
    pub fn rewind(&mut self, len: usize) -> Result<()> {
        if self.off() < len {
            return Err(BufferTooShortError);
        }

        self.off -= len;

        Ok(())
    }

    /// Splits the buffer in two at the given absolute offset.
    pub fn split_at(
        &mut self, off: usize,
    ) -> Result<(OctetsMut<'_>, OctetsMut<'_>)> {
        if self.len() < off {
            return Err(BufferTooShortError);
        }

        let (left, right) = self.buf.split_at_mut(off);

        let first = OctetsMut { buf: left, off: 0 };

        let last = OctetsMut { buf: right, off: 0 };

        Ok((first, last))
    }

    /// Returns a slice of `len` elements from the current offset.
    pub fn slice(&'a mut self, len: usize) -> Result<&'a mut [u8]> {
        if len > self.cap() {
            return Err(BufferTooShortError);
        }

        Ok(&mut self.buf[self.off..self.off + len])
    }

    /// Returns a slice of `len` elements from the end of the buffer.
    pub fn slice_last(&'a mut self, len: usize) -> Result<&'a mut [u8]> {
        if len > self.cap() {
            return Err(BufferTooShortError);
        }

        let end = self.buf.len();
        Ok(&mut self.buf[end - len..end])
    }

    /// Advances the buffer's offset.
    pub fn skip(&mut self, skip: usize) -> Result<()> {
        if skip > self.cap() {
            return Err(BufferTooShortError);
        }

        self.off += skip;

        Ok(())
    }

    /// Returns the remaining capacity in the buffer.
    pub fn cap(&self) -> usize {
        self.buf.len() - self.off
    }

    /// Returns the total length of the buffer.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns `true` if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.len() == 0
    }

    /// Returns the current offset of the buffer.
    pub fn off(&self) -> usize {
        self.off
    }

    /// Returns a reference to the internal buffer.
    pub fn buf(&self) -> &[u8] {
        self.buf
    }

    /// Copies the buffer from the current offset into a new `Vec<u8>`.
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_ref().to_vec()
    }
}

impl AsRef<[u8]> for OctetsMut<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.buf[self.off..]
    }
}

impl AsMut<[u8]> for OctetsMut<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.off..]
    }
}

impl OctetsWriter for OctetsMut<'_> {
    type Error = BufferTooShortError;

    fn put_bytes(&mut self, v: &[u8]) -> Result<()> {
        OctetsMut::put_bytes(self, v)
    }
}

/// Returns how many bytes it would take to encode `v` as a variable-length
/// integer.
pub const fn varint_len(v: u64) -> usize {
    if v <= 63 {
        1
    } else if v <= 16383 {
        2
    } else if v <= 1_073_741_823 {
        4
    } else if v <= MAX_VAR_INT {
        8
    } else {
        unreachable!()
    }
}

/// Returns how long the variable-length integer is, given its first byte.
pub const fn varint_parse_len(first: u8) -> usize {
    match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    }
}

/// Returns how long the Huffman encoding of the given buffer will be.
///
/// The Huffman code implemented is the one defined for HPACK (RFC7541).
#[cfg(feature = "huffman_hpack")]
pub fn huffman_encoding_len<const LOWER_CASE: bool>(src: &[u8]) -> Result<usize> {
    use self::huffman_table::ENCODE_TABLE;

    let mut bits: usize = 0;

    for &b in src {
        let b = if LOWER_CASE {
            b.to_ascii_lowercase()
        } else {
            b
        };

        let (nbits, _) = ENCODE_TABLE[b as usize];
        bits += nbits;
    }

    let mut len = bits / 8;

    if bits & 7 != 0 {
        len += 1;
    }

    if len > src.len() {
        return Err(BufferTooShortError);
    }

    Ok(len)
}

#[cfg(feature = "huffman_hpack")]
fn huffman_encode_with<const LOWER_CASE: bool, F, E>(
    src: &[u8], mut write: F,
) -> std::result::Result<(), E>
where
    F: FnMut(&[u8]) -> std::result::Result<(), E>,
{
    use self::huffman_table::ENCODE_TABLE;

    let mut bits: u64 = 0;
    let mut pending = 0;

    for &b in src {
        let b = if LOWER_CASE {
            b.to_ascii_lowercase()
        } else {
            b
        };
        let (nbits, code) = ENCODE_TABLE[b as usize];

        pending += nbits;

        if pending < 64 {
            // Have room for the new token.
            bits |= code << (64 - pending);
            continue;
        }

        pending -= 64;
        // Take only the bits that fit.
        bits |= code >> pending;
        write(&bits.to_be_bytes())?;

        bits = if pending == 0 {
            0
        } else {
            code << (64 - pending)
        };
    }

    if pending == 0 {
        return Ok(());
    }

    bits |= u64::MAX >> pending;
    // TODO: replace with `next_multiple_of(8)` when stable.
    pending = (pending + 7) & !7; // Round up to a byte.
    bits >>= 64 - pending;

    if pending >= 32 {
        pending -= 32;
        write(&((bits >> pending) as u32).to_be_bytes())?;
    }

    while pending > 0 {
        pending -= 8;
        write(&[(bits >> pending) as u8])?;
    }

    Ok(())
}

/// The functions in this mod test the compile time assertions in the
/// `put_u` and `peek_u` macros. If you compile this crate with
/// `--cfg test_invalid_len_compilation_fail`, e.g., by using
/// `cargo rustc  -- --cfg test_invalid_len_compilation_fail`
/// You will get two compiler errors
#[cfg(test_invalid_len_compilation_fail)]
pub mod fails_to_compile {
    use super::*;
    pub fn peek_invalid_fails_to_compile(b: &mut Octets) -> Result<u8> {
        peek_u!(b, u8, 2)
    }

    pub fn put_invalid_fails_to_compile<'a>(
        b: &'a mut OctetsMut, v: u8,
    ) -> Result<&'a mut [u8]> {
        put_u!(b, u8, v, 2)
    }
}

#[cfg(feature = "huffman_hpack")]
mod huffman_table;
