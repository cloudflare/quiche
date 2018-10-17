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

use ::Result;

use std::cmp;
use std::collections::hash_map;
use std::collections::BinaryHeap;
use std::collections::VecDeque;

pub struct Stream {
    recv: RecvBuf,
    send: SendBuf,
}

impl Stream {
    pub fn new() -> Stream {
        Stream {
            recv: RecvBuf::new(),
            send: SendBuf::new(),
        }
    }

    pub fn push_recv(&mut self, data: &[u8], off: usize) -> Result<()> {
        self.recv.push(data, off)
    }

    pub fn pop_recv(&mut self, data: &mut [u8]) -> Result<usize> {
        self.recv.pop(data)
    }

    pub fn push_send(&mut self, data: &[u8]) -> Result<usize> {
        self.send.push(data)
    }

    pub fn can_read(&self) -> bool {
        self.recv.ready()
    }
}

pub struct StreamIterator<'a> {
    streams: hash_map::Iter<'a, u64, Stream>,
}

impl<'a> StreamIterator<'a> {
    pub fn new(streams: hash_map::Iter<'a, u64, Stream>) -> StreamIterator {
        StreamIterator {
            streams,
        }
    }
}

impl<'a> Iterator for StreamIterator<'a> {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.streams.next() {
                Some((k, s)) => {
                    if !s.can_read() {
                        continue;
                    }

                    return Some(*k);
                },

                None => return None,
            }
        }
    }
}

struct RecvBuf {
    data: BinaryHeap<RangeBuf>,
    off: usize,
    len: usize,
}

impl RecvBuf {
    fn new() -> RecvBuf {
        RecvBuf {
            data: BinaryHeap::new(),
            off: 0,
            len: 0,
        }
    }

    fn push(&mut self, data: &[u8], off: usize) -> Result<()> {
        let buf = RangeBuf {
            data: Vec::from(data),
            off: off,
        };

        self.len = cmp::max(self.len, buf.off + buf.len());

        self.data.push(buf);

        Ok(())
    }

    fn pop(&mut self, out: &mut [u8]) -> Result<usize> {
        let mut out_len = out.len();
        let mut out_off = 0;

        while out_len > 0 && self.ready() {
            let mut buf = match self.data.pop() {
                Some(v) => v,
                None => break,
            };

            if buf.len() > out_len {
                let new = RangeBuf {
                    data: buf.data.split_off(out_len),
                    off: buf.off + out_len,
                };

                self.data.push(new);
            }

            let out = &mut out[out_off .. out_off + buf.len()];
            out.copy_from_slice(&buf.data);

            out_len -= buf.len();
            out_off += buf.len();

            self.off += buf.len();
            self.len -= buf.len();
        }

        Ok(out_off)
    }

    fn ready(&self) -> bool {
        let buf = match self.data.peek() {
            Some(v) => v,
            None => return false,
        };

        buf.off == self.off
    }

    fn len(&self) -> usize {
        self.len
    }
}

struct SendBuf {
    data: VecDeque<RangeBuf>,
    off: usize,
}

impl SendBuf {
    fn new() -> SendBuf {
        SendBuf {
            data: VecDeque::new(),
            off: 0,
        }
    }

    fn push(&mut self, data: &[u8]) -> Result<usize> {
        let buf = RangeBuf {
            data: Vec::from(data),
            off: self.off,
        };

        self.data.push_back(buf);

        Ok(self.off)
    }

    // fn peek(&mut self, out: &mut [u8]) -> Result<usize> {

    // }

    // fn drop(&mut self, out: &mut [u8]) -> Result<usize> {

    // }
}

#[derive(Eq)]
struct RangeBuf {
    data: Vec<u8>,
    off: usize,
}

impl RangeBuf {
    pub fn len(&self) -> usize {
        self.data.len()
    }
}

impl Ord for RangeBuf {
    fn cmp(&self, other: &RangeBuf) -> cmp::Ordering {
        // Invert ordering to implement min-heap.
        match self.off.cmp(&other.off) {
            cmp::Ordering::Greater => cmp::Ordering::Less,
            cmp::Ordering::Less => cmp::Ordering::Greater,
            cmp::Ordering::Equal => cmp::Ordering::Equal,
        }
    }
}

impl PartialOrd for RangeBuf {
    fn partial_cmp(&self, other: &RangeBuf) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for RangeBuf {
    fn eq(&self, other: &RangeBuf) -> bool {
        self.off == other.off
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_read() {
        let mut buf = RecvBuf::new();
        assert_eq!(buf.len(), 0);

        let mut out: [u8; 10] = [0; 10];
        let read = buf.pop(&mut out);
        assert_eq!(read, Ok(0));
    }

    #[test]
    fn ordered_read() {
        let mut buf = RecvBuf::new();
        assert_eq!(buf.len(), 0);

        let first: [u8; 5] = *b"hello";
        let second: [u8; 5] = *b"world";
        let third: [u8; 9] = *b"something";

        assert!(buf.push(&second, 5).is_ok());
        assert_eq!(buf.len(), 10);

        let mut out: [u8; 10] = [0; 10];
        let read = buf.pop(&mut out);
        assert_eq!(read, Ok(0));

        assert!(buf.push(&third, 10).is_ok());
        assert_eq!(buf.len(), 19);

        assert!(buf.push(&first, 0).is_ok());
        assert_eq!(buf.len(), 19);

        let mut out: [u8; 20] = [0; 20];
        let read = buf.pop(&mut out);
        assert_eq!(read, Ok(19));
        assert_eq!(&out[..19], b"helloworldsomething");
        assert_eq!(buf.len(), 0);

        let read = buf.pop(&mut out);
        assert_eq!(read, Ok(0));
    }

    #[test]
    fn split_read() {
        let mut buf = RecvBuf::new();
        assert_eq!(buf.len(), 0);

        let first: [u8; 9] = *b"something";
        let second: [u8; 10] = *b"helloworld";

        assert!(buf.push(&second, 9).is_ok());
        assert_eq!(buf.len(), 19);

        assert!(buf.push(&first, 0).is_ok());
        assert_eq!(buf.len(), 19);

        let mut out: [u8; 14] = [0; 14];
        let read = buf.pop(&mut out);
        assert_eq!(read, Ok(14));
        assert_eq!(&out, b"somethinghello");
        assert_eq!(buf.len(), 5);

        let mut out: [u8; 10] = [0; 10];
        let read = buf.pop(&mut out);
        assert_eq!(read, Ok(5));
        assert_eq!(&out[0..5], b"world");
        assert_eq!(buf.len(), 0);
    }
}
