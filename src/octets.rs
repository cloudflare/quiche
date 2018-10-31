// Copyright (c) 2018, Alessandro Ghedini
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
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

use std::mem;
use std::ptr;

use ::Result;
use ::Error;

macro_rules! peek_u {
    ($b:expr, $ty:ty) => ({
        let len = mem::size_of::<$ty>();

        let src = &$b.buf[$b.off..];

        if src.len() < len {
            return Err(Error::BufferTooShort);
        }

        let out = unsafe {
            ptr::read_unaligned(src.as_ptr() as *const $ty)
        };

        Ok(<$ty>::from_be(out))
    });
}

macro_rules! get_u {
    ($b:expr, $ty:ty) => ({
        let len = mem::size_of::<$ty>();
        let out = peek_u!($b, $ty);

        $b.off += len;

        out
    });
}

macro_rules! put_u {
    ($b:expr, $ty:ty, $v:expr) => ({
        let len = mem::size_of::<$ty>();

        let dst = &mut $b.buf[$b.off..];

        if dst.len() < len {
            return Err(Error::BufferTooShort)
        }

        unsafe {
            ptr::write_unaligned(dst.as_mut_ptr() as *mut $ty, <$ty>::to_be($v));
        }

        $b.off += len;

        Ok(dst)
    });
}

#[derive(Debug, PartialEq)]
pub struct Bytes<'a> {
    buf: &'a mut [u8],
    off: usize,
}

impl<'a> Bytes<'a> {
    pub fn new(buf: &'a mut [u8]) -> Bytes {
        Bytes {
            buf,
            off: 0,
        }
    }

    pub fn skip(&mut self, len: usize) -> Result<()> {
        if self.cap() < len {
            return Err(Error::BufferTooShort)
        }

        self.off += len;

        Ok(())
    }

    pub fn get_u8(&mut self) -> Result<u8> {
        get_u!(self, u8)
    }

    pub fn peek_u8(&mut self) -> Result<u8> {
        peek_u!(self, u8)
    }

    pub fn put_u8(&mut self, v: u8) -> Result<&mut [u8]> {
        put_u!(self, u8, v)
    }

    pub fn get_u16(&mut self) -> Result<u16> {
        get_u!(self, u16)
    }

    pub fn put_u16(&mut self, v: u16) -> Result<&mut [u8]> {
        put_u!(self, u16, v)
    }

    pub fn get_u32(&mut self) -> Result<u32> {
        get_u!(self, u32)
    }

    pub fn put_u32(&mut self, v: u32) -> Result<&mut [u8]> {
        put_u!(self, u32, v)
    }

    pub fn get_u64(&mut self) -> Result<u64> {
        get_u!(self, u64)
    }

    pub fn put_u64(&mut self, v: u64) -> Result<&mut [u8]> {
        put_u!(self, u64, v)
    }

    pub fn get_varint(&mut self) -> Result<u64> {
        let first = self.peek_u8()?;

        let len = match first >> 6 {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => 8,
            _ => return Err(Error::BufferTooShort),
        };

        let mut vec = self.get_bytes(len)?.to_vec();

        // Mask the 2 most significant bits to remove the encoded length.
        vec[0] &= 0x3f;

        let mut b = Bytes::new(&mut vec);

        let out = match len {
            1 => u64::from(b.get_u8()?),
            2 => u64::from(b.get_u16()?),
            4 => u64::from(b.get_u32()?),
            8 => b.get_u64()?,
            _ => return Err(Error::BufferTooShort),
        };

        Ok(out)
    }

    pub fn put_varint(&mut self, v: u64) -> Result<()> {
        if self.cap() == 0 {
            return Err(Error::BufferTooShort);
        }

        if v < 63 {
            self.put_u8(v as u8)?;
        } else if v < 16383 {
            let buf = self.put_u16(v as u16)?;
            buf[0] |= 0x40;
        } else if v < 1_073_741_823 {
            let buf = self.put_u32(v as u32)?;
            buf[0] |= 0x80;
        } else if v < 4_611_686_018_427_387_903 {
            let buf = self.put_u64(v)?;
            buf[0] |= 0xc0;
        } else {
            return Err(Error::BufferTooShort);
        };

        Ok(())
    }

    pub fn get_bytes(&mut self, len: usize) -> Result<Bytes> {
        if self.cap() < len {
            return Err(Error::BufferTooShort)
        }

        let out = Bytes {
            buf: &mut self.buf[self.off..self.off + len],
            off: 0,
        };

        self.off += len;

        Ok(out)
    }

    pub fn get_bytes_with_u8_length(&mut self) -> Result<Bytes> {
        let len = self.get_u8()?;
        self.get_bytes(len as usize)
    }

    pub fn get_bytes_with_u16_length(&mut self) -> Result<Bytes> {
        let len = self.get_u16()?;
        self.get_bytes(len as usize)
    }

    pub fn get_bytes_with_varint_length(&mut self) -> Result<Bytes> {
        let len = self.get_varint()?;
        self.get_bytes(len as usize)
    }

    pub fn peek_bytes(&mut self, len: usize) -> Result<Bytes> {
        if self.cap() < len {
            return Err(Error::BufferTooShort)
        }

        let out = Bytes {
            buf: &mut self.buf[self.off..self.off + len],
            off: 0,
        };

        Ok(out)
    }

    pub fn put_bytes(&mut self, v: &[u8]) -> Result<()> {
        let len = v.len();

        if self.cap() < len {
            return Err(Error::BufferTooShort)
        }

        if len == 0 {
            return Ok(());
        }

        unsafe {
            ptr::copy_nonoverlapping(v as *const [u8] as *const u8,
                                     self.as_mut().as_mut_ptr(),
                                     len);
        }

        self.off += len;

        Ok(())
    }

    pub fn split_at(&mut self, off: usize) -> Result<(Bytes, Bytes)> {
        if self.len() < off {
            return Err(Error::BufferTooShort);
        }

        let (left, right) = self.buf.split_at_mut(off);

        let first = Bytes {
            buf: left,
            off: 0,
        };

        let last = Bytes {
            buf: right,
            off: 0,
        };

        Ok((first, last))
    }

    pub fn slice(&'a mut self, len: usize) -> Result<&'a mut [u8]> {
        if len > self.cap() {
            return Err(Error::BufferTooShort);
        }

        Ok(&mut self.buf[self.off..self.off + len])
    }

    pub fn slice_last(&'a mut self, len: usize) -> Result<&'a mut [u8]> {
        if len > self.cap() {
            return Err(Error::BufferTooShort);
        }

        let cap = self.cap();
        Ok(&mut self.buf[cap - len..])
    }

    pub fn cap(&self) -> usize {
        self.buf.len() - self.off
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn off(&self) -> usize {
        self.off
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.as_ref().to_vec()
    }
}

impl<'a> AsRef<[u8]> for Bytes<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.buf[self.off..]
    }
}

impl<'a> AsMut<[u8]> for Bytes<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.off..]
    }
}

pub fn varint_len(v: u64) -> usize {
    if v < 63 {
        1
    } else if v < 16383 {
        2
    } else if v < 1_073_741_823 {
        4
    } else if v < 4_611_686_018_427_387_903 {
        8
    } else {
        0
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip() {
        let mut d: [u8; 15] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let mut b = Bytes::new(&mut d);
        assert_eq!(b.cap(), 15);
        assert_eq!(b.off(), 0);

        assert!(b.skip(5).is_ok());
        assert_eq!(b.cap(), 10);
        assert_eq!(b.off(), 5);

        assert!(b.skip(15).is_err());
        assert_eq!(b.cap(), 10);
        assert_eq!(b.off(), 5);

        assert!(b.skip(10).is_ok());
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 15);
    }

    #[test]
    fn get_u() {
        let mut d: [u8; 15] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let mut b = Bytes::new(&mut d);
        assert_eq!(b.cap(), 15);
        assert_eq!(b.off(), 0);

        assert_eq!(b.get_u8().unwrap(), 1);
        assert_eq!(b.cap(), 14);
        assert_eq!(b.off(), 1);

        assert_eq!(b.get_u16().unwrap(), 0x203);
        assert_eq!(b.cap(), 12);
        assert_eq!(b.off(), 3);

        assert_eq!(b.get_u32().unwrap(), 0x4050607);
        assert_eq!(b.cap(), 8);
        assert_eq!(b.off(), 7);

        assert_eq!(b.get_u64().unwrap(), 0x8090a0b0c0d0e0f);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 15);

        assert!(b.get_u8().is_err());
        assert!(b.get_u16().is_err());
        assert!(b.get_u32().is_err());
        assert!(b.get_u64().is_err());
    }

    #[test]
    fn peek_u() {
        let mut d: [u8; 2] = [1, 2];

        let mut b = Bytes::new(&mut d);
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
        let mut d: [u8; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut b = Bytes::new(&mut d);
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
        let mut d: [u8; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut b = Bytes::new(&mut d);
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
        let mut d: [u8; 8] = [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c];
        let mut b = Bytes::new(&mut d);
        assert_eq!(b.get_varint().unwrap(), 151288809941952652);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 8);

        let mut d: [u8; 4] = [0x9d, 0x7f, 0x3e, 0x7d];
        let mut b = Bytes::new(&mut d);
        assert_eq!(b.get_varint().unwrap(), 494878333);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 4);

        let mut d: [u8; 2] = [0x7b, 0xbd];
        let mut b = Bytes::new(&mut d);
        assert_eq!(b.get_varint().unwrap(), 15293);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 2);

        let mut d: [u8; 2] = [0x40, 0x25];
        let mut b = Bytes::new(&mut d);
        assert_eq!(b.get_varint().unwrap(), 37);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 2);

        let mut d: [u8; 1] = [0x25];
        let mut b = Bytes::new(&mut d);
        assert_eq!(b.get_varint().unwrap(), 37);
        assert_eq!(b.cap(), 0);
        assert_eq!(b.off(), 1);
    }

    #[test]
    fn put_varint() {
        let mut d: [u8; 8] = [0; 8];
        {
            let mut b = Bytes::new(&mut d);
            assert!(b.put_varint(151288809941952652).is_ok());
            assert_eq!(b.cap(), 0);
            assert_eq!(b.off(), 8);
        }
        let exp: [u8; 8] = [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c];
        assert_eq!(&d, &exp);

        let mut d: [u8; 4] = [0; 4];
        {
            let mut b = Bytes::new(&mut d);
            assert!(b.put_varint(494878333).is_ok());
            assert_eq!(b.cap(), 0);
            assert_eq!(b.off(), 4);
        }
        let exp: [u8; 4] = [0x9d, 0x7f, 0x3e, 0x7d];
        assert_eq!(&d, &exp);

        let mut d: [u8; 2] = [0; 2];
        {
            let mut b = Bytes::new(&mut d);
            assert!(b.put_varint(15293).is_ok());
            assert_eq!(b.cap(), 0);
            assert_eq!(b.off(), 2);
        }
        let exp: [u8; 2] = [0x7b, 0xbd];
        assert_eq!(&d, &exp);

        let mut d: [u8; 1] = [0; 1];
        {
            let mut b = Bytes::new(&mut d);
            assert!(b.put_varint(37).is_ok());
            assert_eq!(b.cap(), 0);
            assert_eq!(b.off(), 1);
        }
        let exp: [u8; 1] = [0x25];
        assert_eq!(&d, &exp);

        let mut d: [u8; 3] = [0; 3];
        {
            let mut b = Bytes::new(&mut d);
            assert!(b.put_varint(151288809941952652).is_err());
            assert_eq!(b.cap(), 3);
            assert_eq!(b.off(), 0);
        }
        let exp: [u8; 3] = [0; 3];
        assert_eq!(&d, &exp);
    }

    #[test]
    fn put_u() {
        let mut d: [u8; 15] = [0; 15];

        {
            let mut b = Bytes::new(&mut d);
            assert_eq!(b.cap(), 15);
            assert_eq!(b.off(), 0);

            assert!(b.put_u8(1).is_ok());
            assert_eq!(b.cap(), 14);
            assert_eq!(b.off(), 1);

            assert!(b.put_u16(0x203).is_ok());
            assert_eq!(b.cap(), 12);
            assert_eq!(b.off(), 3);

            assert!(b.put_u32(0x4050607).is_ok());
            assert_eq!(b.cap(), 8);
            assert_eq!(b.off(), 7);

            assert!(b.put_u64(0x8090a0b0c0d0e0f).is_ok());
            assert_eq!(b.cap(), 0);
            assert_eq!(b.off(), 15);

            assert!(b.put_u8(1).is_err());
        }

        let exp: [u8; 15] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        assert_eq!(&d, &exp);
    }

    #[test]
    fn put_bytes() {
        let mut d: [u8; 5] = [0; 5];

        {
            let mut b = Bytes::new(&mut d);
            assert_eq!(b.cap(), 5);
            assert_eq!(b.off(), 0);

            let p: [u8; 5] = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e];
            assert!(b.put_bytes(&p).is_ok());
            assert_eq!(b.cap(), 0);
            assert_eq!(b.off(), 5);

            assert!(b.put_u8(1).is_err());
        }

        let exp: [u8; 5] = [0xa, 0xb, 0xc, 0xd, 0xe];
        assert_eq!(&d, &exp);
    }

    #[test]
    fn split() {
        let mut d: [u8; 10] = *b"helloworld";

        let mut b = Bytes::new(&mut d);
        assert_eq!(b.cap(), 10);
        assert_eq!(b.off(), 0);
        assert_eq!(b.as_ref(), b"helloworld");

        assert!(b.skip(5).is_ok());
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
        let mut d: [u8; 10] = *b"helloworld";

        {
            let mut b = Bytes::new(&mut d);
            let (first, second) = b.split_at(5).unwrap();

            let mut exp1: [u8; 5] = *b"hello";
            assert_eq!(first.as_ref(), &mut exp1[..]);

            let mut exp2: [u8; 5] = *b"world";
            assert_eq!(second.as_ref(), &mut exp2[..]);
        }

        {
            let mut b = Bytes::new(&mut d);
            let (first, second) = b.split_at(10).unwrap();

            let mut exp1: [u8; 10] = *b"helloworld";
            assert_eq!(first.as_ref(), &mut exp1[..]);

            let mut exp2: [u8; 0] = *b"";
            assert_eq!(second.as_ref(), &mut exp2[..]);
        }

        {
            let mut b = Bytes::new(&mut d);
            let (first, second) = b.split_at(9).unwrap();

            let mut exp1: [u8; 9] = *b"helloworl";
            assert_eq!(first.as_ref(), &mut exp1[..]);

            let mut exp2: [u8; 1] = *b"d";
            assert_eq!(second.as_ref(), &mut exp2[..]);
        }

        {
            let mut b = Bytes::new(&mut d);
            assert!(b.split_at(11).is_err());
        }
    }

    #[test]
    fn slice() {
        let mut d: [u8; 10] = *b"helloworld";

        {
            let mut b = Bytes::new(&mut d);
            let mut exp: [u8; 5] = *b"hello";
            assert_eq!(b.slice(5), Ok(&mut exp[..]));
        }

        {
            let mut b = Bytes::new(&mut d);
            let mut exp: [u8; 0] = *b"";
            assert_eq!(b.slice(0), Ok(&mut exp[..]));
        }

        {
            let mut b = Bytes::new(&mut d);
            b.skip(5).unwrap();

            let mut exp: [u8; 5] = *b"world";
            assert_eq!(b.slice(5), Ok(&mut exp[..]));
        }

        {
            let mut b = Bytes::new(&mut d);
            assert!(b.slice(11).is_err());
        }
    }

    #[test]
    fn slice_last() {
        let mut d: [u8; 10] = *b"helloworld";

        {
            let mut b = Bytes::new(&mut d);
            let mut exp: [u8; 4] = *b"orld";
            assert_eq!(b.slice_last(4), Ok(&mut exp[..]));
        }

        {
            let mut b = Bytes::new(&mut d);
            let mut exp: [u8; 1] = *b"d";
            assert_eq!(b.slice_last(1), Ok(&mut exp[..]));
        }

        {
            let mut b = Bytes::new(&mut d);
            let mut exp: [u8; 0] = *b"";
            assert_eq!(b.slice_last(0), Ok(&mut exp[..]));
        }

        {
            let mut b = Bytes::new(&mut d);
            let mut exp: [u8; 10] = *b"helloworld";
            assert_eq!(b.slice_last(10), Ok(&mut exp[..]));
        }

        {
            let mut b = Bytes::new(&mut d);
            assert!(b.slice_last(11).is_err());
        }
    }
}
