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

macro_rules! peek_u {
    ($b:expr, $ty:ty, $len:expr) => {{
        let len = $len;
        let src = &$b.buf[$b.off..];

        if src.len() < len {
            return Err(BufferTooShortError);
        }

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
    /// Since there's no copy, the input slice needs to be mutable to allow
    /// modifications.
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

    /// Returns a slice of `len` elements from the current offset.
    pub fn slice(&'a self, len: usize) -> Result<&'a [u8]> {
        if len > self.cap() {
            return Err(BufferTooShortError);
        }

        Ok(&self.buf[self.off..self.off + len])
    }

    /// Returns a slice of `len` elements from the end of the buffer.
    pub fn slice_last(&'a self, len: usize) -> Result<&'a [u8]> {
        if len > self.cap() {
            return Err(BufferTooShortError);
        }

        let cap = self.cap();
        Ok(&self.buf[cap - len..])
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

impl<'a> AsRef<[u8]> for Octets<'a> {
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
    pub fn get_bytes(&mut self, len: usize) -> Result<Octets> {
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
    pub fn get_bytes_mut(&mut self, len: usize) -> Result<OctetsMut> {
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
    pub fn get_bytes_with_u8_length(&mut self) -> Result<Octets> {
        let len = self.get_u8()?;
        self.get_bytes(len as usize)
    }

    /// Reads `len` bytes from the current offset without copying and advances
    /// the buffer, where `len` is an unsigned 16-bit integer prefix in network
    /// byte-order.
    pub fn get_bytes_with_u16_length(&mut self) -> Result<Octets> {
        let len = self.get_u16()?;
        self.get_bytes(len as usize)
    }

    /// Reads `len` bytes from the current offset without copying and advances
    /// the buffer, where `len` is an unsigned variable-length integer prefix
    /// in network byte-order.
    pub fn get_bytes_with_varint_length(&mut self) -> Result<Octets> {
        let len = self.get_varint()?;
        self.get_bytes(len as usize)
    }

    /// Reads `len` bytes from the current offset without copying and without
    /// advancing the buffer.
    pub fn peek_bytes(&mut self, len: usize) -> Result<Octets> {
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
    pub fn peek_bytes_mut(&mut self, len: usize) -> Result<OctetsMut> {
        if self.cap() < len {
            return Err(BufferTooShortError);
        }

        let out = OctetsMut {
            buf: &mut self.buf[self.off..self.off + len],
            off: 0,
        };

        Ok(out)
    }

    /// Writes `len` bytes from the current offset without copying and advances
    /// the buffer.
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

    /// Splits the buffer in two at the given absolute offset.
    pub fn split_at(&mut self, off: usize) -> Result<(OctetsMut, OctetsMut)> {
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

        let cap = self.cap();
        Ok(&mut self.buf[cap - len..])
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

impl<'a> AsRef<[u8]> for OctetsMut<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.buf[self.off..]
    }
}

impl<'a> AsMut<[u8]> for OctetsMut<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.off..]
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
    } else if v <= 4_611_686_018_427_387_903 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_u() {
        let d = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        ];

        let mut b = Octets::with_slice(&d);
        assert_eq!(b.cap(), 18);
        assert_eq!(b.off(), 0);

        assert_eq!(b.get_u8().unwrap(), 1);
        assert_eq!(b.cap(), 17);
        assert_eq!(b.off(), 1);

        assert_eq!(b.get_u16().unwrap(), 0x203);
        assert_eq!(b.cap(), 15);
        assert_eq!(b.off(), 3);

        assert_eq!(b.get_u24().unwrap(), 0x40506);
        assert_eq!(b.cap(), 12);
        assert_eq!(b.off(), 6);

        assert_eq!(b.get_u32().unwrap(), 0x0708090a);
        assert_eq!(b.cap(), 8);
        assert_eq!(b.off(), 10);

        assert_eq!(b.get_u64().unwrap(), 0x0b0c0d0e0f101112);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 18);

        assert!(b.get_u8().is_err());
        assert!(b.get_u16().is_err());
        assert!(b.get_u24().is_err());
        assert!(b.get_u32().is_err());
        assert!(b.get_u64().is_err());
    }

    #[test]
    fn get_u_mut() {
        let mut d = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        ];

        let mut b = OctetsMut::with_slice(&mut d);
        assert_eq!(b.cap(), 18);
        assert_eq!(b.off(), 0);

        assert_eq!(b.get_u8().unwrap(), 1);
        assert_eq!(b.cap(), 17);
        assert_eq!(b.off(), 1);

        assert_eq!(b.get_u16().unwrap(), 0x203);
        assert_eq!(b.cap(), 15);
        assert_eq!(b.off(), 3);

        assert_eq!(b.get_u24().unwrap(), 0x40506);
        assert_eq!(b.cap(), 12);
        assert_eq!(b.off(), 6);

        assert_eq!(b.get_u32().unwrap(), 0x0708090a);
        assert_eq!(b.cap(), 8);
        assert_eq!(b.off(), 10);

        assert_eq!(b.get_u64().unwrap(), 0x0b0c0d0e0f101112);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 18);

        assert!(b.get_u8().is_err());
        assert!(b.get_u16().is_err());
        assert!(b.get_u24().is_err());
        assert!(b.get_u32().is_err());
        assert!(b.get_u64().is_err());
    }

    #[test]
    fn peek_u() {
        let d = [1, 2];

        let mut b = Octets::with_slice(&d);
        assert_eq!(b.cap(), 2);
        assert_eq!(b.off(), 0);

        assert_eq!(b.peek_u8().unwrap(), 1);
        assert_eq!(b.cap(), 2);
        assert_eq!(b.off(), 0);

        assert_eq!(b.peek_u8().unwrap(), 1);
        assert_eq!(b.cap(), 2);
        assert_eq!(b.off(), 0);

        b.get_u16().unwrap();

        assert!(b.peek_u8().is_err());
    }

    #[test]
    fn peek_u_mut() {
        let mut d = [1, 2];

        let mut b = OctetsMut::with_slice(&mut d);
        assert_eq!(b.cap(), 2);
        assert_eq!(b.off(), 0);

        assert_eq!(b.peek_u8().unwrap(), 1);
        assert_eq!(b.cap(), 2);
        assert_eq!(b.off(), 0);

        assert_eq!(b.peek_u8().unwrap(), 1);
        assert_eq!(b.cap(), 2);
        assert_eq!(b.off(), 0);

        b.get_u16().unwrap();

        assert!(b.peek_u8().is_err());
    }

    #[test]
    fn get_bytes() {
        let d = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut b = Octets::with_slice(&d);
        assert_eq!(b.cap(), 10);
        assert_eq!(b.off(), 0);

        assert_eq!(b.get_bytes(5).unwrap().as_ref(), [1, 2, 3, 4, 5]);
        assert_eq!(b.cap(), 5);
        assert_eq!(b.off(), 5);

        assert_eq!(b.get_bytes(3).unwrap().as_ref(), [6, 7, 8]);
        assert_eq!(b.cap(), 2);
        assert_eq!(b.off(), 8);

        assert!(b.get_bytes(3).is_err());
        assert_eq!(b.cap(), 2);
        assert_eq!(b.off(), 8);

        assert_eq!(b.get_bytes(2).unwrap().as_ref(), [9, 10]);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 10);

        assert!(b.get_bytes(2).is_err());
    }

    #[test]
    fn get_bytes_mut() {
        let mut d = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut b = OctetsMut::with_slice(&mut d);
        assert_eq!(b.cap(), 10);
        assert_eq!(b.off(), 0);

        assert_eq!(b.get_bytes(5).unwrap().as_ref(), [1, 2, 3, 4, 5]);
        assert_eq!(b.cap(), 5);
        assert_eq!(b.off(), 5);

        assert_eq!(b.get_bytes(3).unwrap().as_ref(), [6, 7, 8]);
        assert_eq!(b.cap(), 2);
        assert_eq!(b.off(), 8);

        assert!(b.get_bytes(3).is_err());
        assert_eq!(b.cap(), 2);
        assert_eq!(b.off(), 8);

        assert_eq!(b.get_bytes(2).unwrap().as_ref(), [9, 10]);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 10);

        assert!(b.get_bytes(2).is_err());
    }

    #[test]
    fn peek_bytes() {
        let d = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut b = Octets::with_slice(&d);
        assert_eq!(b.cap(), 10);
        assert_eq!(b.off(), 0);

        assert_eq!(b.peek_bytes(5).unwrap().as_ref(), [1, 2, 3, 4, 5]);
        assert_eq!(b.cap(), 10);
        assert_eq!(b.off(), 0);

        assert_eq!(b.peek_bytes(5).unwrap().as_ref(), [1, 2, 3, 4, 5]);
        assert_eq!(b.cap(), 10);
        assert_eq!(b.off(), 0);

        b.get_bytes(5).unwrap();
    }

    #[test]
    fn peek_bytes_mut() {
        let mut d = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut b = OctetsMut::with_slice(&mut d);
        assert_eq!(b.cap(), 10);
        assert_eq!(b.off(), 0);

        assert_eq!(b.peek_bytes(5).unwrap().as_ref(), [1, 2, 3, 4, 5]);
        assert_eq!(b.cap(), 10);
        assert_eq!(b.off(), 0);

        assert_eq!(b.peek_bytes(5).unwrap().as_ref(), [1, 2, 3, 4, 5]);
        assert_eq!(b.cap(), 10);
        assert_eq!(b.off(), 0);

        b.get_bytes(5).unwrap();
    }

    #[test]
    fn get_varint() {
        let d = [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c];
        let mut b = Octets::with_slice(&d);
        assert_eq!(b.get_varint().unwrap(), 151288809941952652);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 8);

        let d = [0x9d, 0x7f, 0x3e, 0x7d];
        let mut b = Octets::with_slice(&d);
        assert_eq!(b.get_varint().unwrap(), 494878333);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 4);

        let d = [0x7b, 0xbd];
        let mut b = Octets::with_slice(&d);
        assert_eq!(b.get_varint().unwrap(), 15293);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 2);

        let d = [0x40, 0x25];
        let mut b = Octets::with_slice(&d);
        assert_eq!(b.get_varint().unwrap(), 37);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 2);

        let d = [0x25];
        let mut b = Octets::with_slice(&d);
        assert_eq!(b.get_varint().unwrap(), 37);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 1);
    }

    #[test]
    fn get_varint_mut() {
        let mut d = [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c];
        let mut b = OctetsMut::with_slice(&mut d);
        assert_eq!(b.get_varint().unwrap(), 151288809941952652);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 8);

        let mut d = [0x9d, 0x7f, 0x3e, 0x7d];
        let mut b = OctetsMut::with_slice(&mut d);
        assert_eq!(b.get_varint().unwrap(), 494878333);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 4);

        let mut d = [0x7b, 0xbd];
        let mut b = OctetsMut::with_slice(&mut d);
        assert_eq!(b.get_varint().unwrap(), 15293);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 2);

        let mut d = [0x40, 0x25];
        let mut b = OctetsMut::with_slice(&mut d);
        assert_eq!(b.get_varint().unwrap(), 37);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 2);

        let mut d = [0x25];
        let mut b = OctetsMut::with_slice(&mut d);
        assert_eq!(b.get_varint().unwrap(), 37);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 1);
    }

    #[test]
    fn put_varint() {
        let mut d = [0; 8];
        {
            let mut b = OctetsMut::with_slice(&mut d);
            assert!(b.put_varint(151288809941952652).is_ok());
            assert_eq!(b.cap(), 0);
            assert_eq!(b.off(), 8);
        }
        let exp = [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c];
        assert_eq!(&d, &exp);

        let mut d = [0; 4];
        {
            let mut b = OctetsMut::with_slice(&mut d);
            assert!(b.put_varint(494878333).is_ok());
            assert_eq!(b.cap(), 0);
            assert_eq!(b.off(), 4);
        }
        let exp = [0x9d, 0x7f, 0x3e, 0x7d];
        assert_eq!(&d, &exp);

        let mut d = [0; 2];
        {
            let mut b = OctetsMut::with_slice(&mut d);
            assert!(b.put_varint(15293).is_ok());
            assert_eq!(b.cap(), 0);
            assert_eq!(b.off(), 2);
        }
        let exp = [0x7b, 0xbd];
        assert_eq!(&d, &exp);

        let mut d = [0; 1];
        {
            let mut b = OctetsMut::with_slice(&mut d);
            assert!(b.put_varint(37).is_ok());
            assert_eq!(b.cap(), 0);
            assert_eq!(b.off(), 1);
        }
        let exp = [0x25];
        assert_eq!(&d, &exp);

        let mut d = [0; 3];
        {
            let mut b = OctetsMut::with_slice(&mut d);
            assert!(b.put_varint(151288809941952652).is_err());
            assert_eq!(b.cap(), 3);
            assert_eq!(b.off(), 0);
        }
        let exp = [0; 3];
        assert_eq!(&d, &exp);
    }

    #[test]
    #[should_panic]
    fn varint_too_large() {
        let mut d = [0; 3];
        let mut b = OctetsMut::with_slice(&mut d);
        assert!(b.put_varint(std::u64::MAX).is_err());
    }

    #[test]
    fn put_u() {
        let mut d = [0; 18];

        {
            let mut b = OctetsMut::with_slice(&mut d);
            assert_eq!(b.cap(), 18);
            assert_eq!(b.off(), 0);

            assert!(b.put_u8(1).is_ok());
            assert_eq!(b.cap(), 17);
            assert_eq!(b.off(), 1);

            assert!(b.put_u16(0x203).is_ok());
            assert_eq!(b.cap(), 15);
            assert_eq!(b.off(), 3);

            assert!(b.put_u24(0x40506).is_ok());
            assert_eq!(b.cap(), 12);
            assert_eq!(b.off(), 6);

            assert!(b.put_u32(0x0708090a).is_ok());
            assert_eq!(b.cap(), 8);
            assert_eq!(b.off(), 10);

            assert!(b.put_u64(0x0b0c0d0e0f101112).is_ok());
            assert_eq!(b.cap(), 0);
            assert_eq!(b.off(), 18);

            assert!(b.put_u8(1).is_err());
        }

        let exp = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        ];
        assert_eq!(&d, &exp);
    }

    #[test]
    fn put_bytes() {
        let mut d = [0; 5];

        {
            let mut b = OctetsMut::with_slice(&mut d);
            assert_eq!(b.cap(), 5);
            assert_eq!(b.off(), 0);

            let p = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e];
            assert!(b.put_bytes(&p).is_ok());
            assert_eq!(b.cap(), 0);
            assert_eq!(b.off(), 5);

            assert!(b.put_u8(1).is_err());
        }

        let exp = [0xa, 0xb, 0xc, 0xd, 0xe];
        assert_eq!(&d, &exp);
    }

    #[test]
    fn split() {
        let mut d = b"helloworld".to_vec();

        let mut b = OctetsMut::with_slice(&mut d);
        assert_eq!(b.cap(), 10);
        assert_eq!(b.off(), 0);
        assert_eq!(b.as_ref(), b"helloworld");

        assert!(b.get_bytes(5).is_ok());
        assert_eq!(b.cap(), 5);
        assert_eq!(b.off(), 5);
        assert_eq!(b.as_ref(), b"world");

        let off = b.off();

        let (first, last) = b.split_at(off).unwrap();
        assert_eq!(first.cap(), 5);
        assert_eq!(first.off(), 0);
        assert_eq!(first.as_ref(), b"hello");

        assert_eq!(last.cap(), 5);
        assert_eq!(last.off(), 0);
        assert_eq!(last.as_ref(), b"world");
    }

    #[test]
    fn split_at() {
        let mut d = b"helloworld".to_vec();

        {
            let mut b = OctetsMut::with_slice(&mut d);
            let (first, second) = b.split_at(5).unwrap();

            let mut exp1 = b"hello".to_vec();
            assert_eq!(first.as_ref(), &mut exp1[..]);

            let mut exp2 = b"world".to_vec();
            assert_eq!(second.as_ref(), &mut exp2[..]);
        }

        {
            let mut b = OctetsMut::with_slice(&mut d);
            let (first, second) = b.split_at(10).unwrap();

            let mut exp1 = b"helloworld".to_vec();
            assert_eq!(first.as_ref(), &mut exp1[..]);

            let mut exp2 = b"".to_vec();
            assert_eq!(second.as_ref(), &mut exp2[..]);
        }

        {
            let mut b = OctetsMut::with_slice(&mut d);
            let (first, second) = b.split_at(9).unwrap();

            let mut exp1 = b"helloworl".to_vec();
            assert_eq!(first.as_ref(), &mut exp1[..]);

            let mut exp2 = b"d".to_vec();
            assert_eq!(second.as_ref(), &mut exp2[..]);
        }

        {
            let mut b = OctetsMut::with_slice(&mut d);
            assert!(b.split_at(11).is_err());
        }
    }

    #[test]
    fn slice() {
        let d = b"helloworld".to_vec();

        {
            let b = Octets::with_slice(&d);
            let exp = b"hello".to_vec();
            assert_eq!(b.slice(5), Ok(&exp[..]));
        }

        {
            let b = Octets::with_slice(&d);
            let exp = b"".to_vec();
            assert_eq!(b.slice(0), Ok(&exp[..]));
        }

        {
            let mut b = Octets::with_slice(&d);
            b.get_bytes(5).unwrap();

            let exp = b"world".to_vec();
            assert_eq!(b.slice(5), Ok(&exp[..]));
        }

        {
            let b = Octets::with_slice(&d);
            assert!(b.slice(11).is_err());
        }
    }

    #[test]
    fn slice_mut() {
        let mut d = b"helloworld".to_vec();

        {
            let mut b = OctetsMut::with_slice(&mut d);
            let mut exp = b"hello".to_vec();
            assert_eq!(b.slice(5), Ok(&mut exp[..]));
        }

        {
            let mut b = OctetsMut::with_slice(&mut d);
            let mut exp = b"".to_vec();
            assert_eq!(b.slice(0), Ok(&mut exp[..]));
        }

        {
            let mut b = OctetsMut::with_slice(&mut d);
            b.get_bytes(5).unwrap();

            let mut exp = b"world".to_vec();
            assert_eq!(b.slice(5), Ok(&mut exp[..]));
        }

        {
            let mut b = OctetsMut::with_slice(&mut d);
            assert!(b.slice(11).is_err());
        }
    }

    #[test]
    fn slice_last() {
        let d = b"helloworld".to_vec();

        {
            let b = Octets::with_slice(&d);
            let exp = b"orld".to_vec();
            assert_eq!(b.slice_last(4), Ok(&exp[..]));
        }

        {
            let b = Octets::with_slice(&d);
            let exp = b"d".to_vec();
            assert_eq!(b.slice_last(1), Ok(&exp[..]));
        }

        {
            let b = Octets::with_slice(&d);
            let exp = b"".to_vec();
            assert_eq!(b.slice_last(0), Ok(&exp[..]));
        }

        {
            let b = Octets::with_slice(&d);
            let exp = b"helloworld".to_vec();
            assert_eq!(b.slice_last(10), Ok(&exp[..]));
        }

        {
            let b = Octets::with_slice(&d);
            assert!(b.slice_last(11).is_err());
        }
    }

    #[test]
    fn slice_last_mut() {
        let mut d = b"helloworld".to_vec();

        {
            let mut b = OctetsMut::with_slice(&mut d);
            let mut exp = b"orld".to_vec();
            assert_eq!(b.slice_last(4), Ok(&mut exp[..]));
        }

        {
            let mut b = OctetsMut::with_slice(&mut d);
            let mut exp = b"d".to_vec();
            assert_eq!(b.slice_last(1), Ok(&mut exp[..]));
        }

        {
            let mut b = OctetsMut::with_slice(&mut d);
            let mut exp = b"".to_vec();
            assert_eq!(b.slice_last(0), Ok(&mut exp[..]));
        }

        {
            let mut b = OctetsMut::with_slice(&mut d);
            let mut exp = b"helloworld".to_vec();
            assert_eq!(b.slice_last(10), Ok(&mut exp[..]));
        }

        {
            let mut b = OctetsMut::with_slice(&mut d);
            assert!(b.slice_last(11).is_err());
        }
    }
}
