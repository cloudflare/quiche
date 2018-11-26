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
use std::collections::HashMap;
use std::collections::BinaryHeap;
use std::ops::Deref;

#[derive(Default)]
pub struct Stream {
    recv: RecvBuf,
    send: SendBuf,

    pub tx_data: usize,
    pub max_tx_data: usize,

    pub rx_data: usize,
    pub max_rx_data: usize,
    pub new_max_rx_data: usize,
}

impl Stream {
    pub fn new(max_rx_data: usize, max_tx_data: usize) -> Stream {
        Stream {
            recv: RecvBuf::default(),
            send: SendBuf::default(),

            rx_data: 0,
            max_rx_data,
            new_max_rx_data: max_rx_data,

            tx_data: 0,
            max_tx_data,
        }
    }

    pub fn recv_push(&mut self, buf: RangeBuf) -> Result<()> {
        self.recv.push(buf)
    }

    pub fn recv_pop(&mut self) -> Result<RangeBuf> {
        self.recv.pop()
    }

    pub fn send_push(&mut self, data: &[u8], fin: bool) -> Result<()> {
        self.send.push_slice(data, fin)
    }

    pub fn send_pop(&mut self, max_len: usize) -> Result<RangeBuf> {
        self.send.pop(max_len)
    }

    pub fn send_push_front(&mut self, buf: RangeBuf) -> Result<()> {
        self.send.push(buf)
    }

    pub fn readable(&self) -> bool {
        self.recv.ready()
    }

    pub fn writable(&self) -> bool {
        self.send.ready()
    }

    pub fn more_credit(&self) -> bool {
        // Send MAX_STREAM_DATA when the new limit is at least double the
        // amount of data that can be received before blocking.
        self.new_max_rx_data != self.max_rx_data &&
        self.new_max_rx_data / 2 > self.max_rx_data - self.rx_data
    }
}

pub fn is_local(id: u64, is_server: bool) -> bool {
    (id & 0x1) == (is_server as u64)
}

pub fn is_bidi(id: u64) -> bool {
    (id & 0x2) == 0
}

pub struct Readable<'a> {
    streams: hash_map::Iter<'a, u64, Stream>,
}

impl<'a> Readable<'a> {
    pub(crate) fn new(streams: &HashMap<u64, Stream>) -> Readable {
        Readable {
            streams: streams.iter(),
        }
    }
}

impl<'a> Iterator for Readable<'a> {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        for (id, s) in &mut self.streams {
            if s.readable() {
                return Some(*id);
            }
        }

        None
    }
}

#[derive(Default)]
struct RecvBuf {
    data: BinaryHeap<RangeBuf>,
    off: usize,
    len: usize,
}

impl RecvBuf {
    fn push(&mut self, buf: RangeBuf) -> Result<()> {
        // TODO: discard duplicated data (e.g. using RangeSet)
        if self.off >= buf.off() + buf.len() {
            // Data is fully duplicate.
            return Ok(());
        }

        self.len = cmp::max(self.len, buf.off + buf.len());

        self.data.push(buf);

        Ok(())
    }

    fn pop(&mut self) -> Result<RangeBuf> {
        let mut out = RangeBuf::default();

        while self.ready() {
            let mut buf = match self.data.pop() {
                Some(v) => v,
                None => break,
            };

            self.off += buf.len();
            self.len -= buf.len();

            out.fin = out.fin || buf.fin();

            out.data.append(&mut buf.data);
        }

        Ok(out)
    }

    fn ready(&self) -> bool {
        if self.len() == 0 {
            return false;
        }

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

#[derive(Default)]
struct SendBuf {
    data: BinaryHeap<RangeBuf>,
    off: usize,
    len: usize,
}

impl SendBuf {
    fn push_slice(&mut self, data: &[u8], fin: bool) -> Result<()> {
        let buf = RangeBuf::from(data, self.off, fin);
        self.push(buf)?;

        self.off += data.len();

        Ok(())
    }

    fn push(&mut self, buf: RangeBuf) -> Result<()> {
        self.off = cmp::min(self.off, buf.off());
        self.len += buf.len();

        self.data.push(buf);

        Ok(())
    }

    fn pop(&mut self, max_len: usize) -> Result<RangeBuf> {
        let mut out = RangeBuf::default();
        let mut out_len = max_len;

        while out_len > 0 && self.ready() {
            let mut buf = match self.data.pop() {
                Some(v) => v,
                None => break,
            };

            if buf.len() > out_len {
                let new_buf = RangeBuf {
                    data: buf.data.split_off(out_len),
                    off: buf.off + out_len,
                    fin: buf.fin,
                };

                buf.fin = false;

                self.data.push(new_buf);
            }

            if out.len() == 0 {
                out.off = buf.off;
            }

            self.len -= buf.len();

            out_len -= buf.len();

            out.fin = out.fin || buf.fin();

            out.data.append(&mut buf.data);
        }

        Ok(out)
    }

    fn ready(&self) -> bool {
        self.len() > 0
    }

    fn len(&self) -> usize {
        self.len
    }
}

#[derive(Debug, Default, Eq)]
pub struct RangeBuf {
    data: Vec<u8>,
    off: usize,
    fin: bool,
}

impl RangeBuf {
    pub fn from(buf: &[u8], off: usize, fin: bool) -> RangeBuf {
        RangeBuf {
            data: Vec::from(buf),
            off,
            fin,
        }
    }

    pub fn fin(&self) -> bool {
        self.fin
    }

    pub fn off(&self) -> usize {
        self.off
    }

    pub fn max_off(&self) -> usize {
        self.off() + self.len()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }
}

impl Deref for RangeBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.data
    }
}

impl Ord for RangeBuf {
    fn cmp(&self, other: &RangeBuf) -> cmp::Ordering {
        // Invert ordering to implement min-heap.
        self.off.cmp(&other.off).reverse()
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
        let mut buf = RecvBuf::default();
        assert_eq!(buf.len(), 0);

        let read = buf.pop().unwrap();
        assert_eq!(read.len(), 0);
    }

    #[test]
    fn ordered_read() {
        let mut buf = RecvBuf::default();
        assert_eq!(buf.len(), 0);

        let first = RangeBuf::from(b"hello", 0, false);
        let second = RangeBuf::from(b"world", 5, false);
        let third = RangeBuf::from(b"something", 10, false);

        assert!(buf.push(second).is_ok());
        assert_eq!(buf.len(), 10);

        let read = buf.pop().unwrap();
        assert_eq!(read.len(), 0);

        assert!(buf.push(third).is_ok());
        assert_eq!(buf.len(), 19);

        assert!(buf.push(first).is_ok());
        assert_eq!(buf.len(), 19);

        let read = buf.pop().unwrap();
        assert_eq!(read.len(), 19);
        assert_eq!(&read[..], b"helloworldsomething");
        assert_eq!(buf.len(), 0);

        let read = buf.pop().unwrap();
        assert_eq!(read.len(), 0);
    }

    #[test]
    fn incomplete_read() {
        let mut buf = RecvBuf::default();
        assert_eq!(buf.len(), 0);

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"helloworld", 9, false);

        assert!(buf.push(second).is_ok());
        assert_eq!(buf.len(), 19);

        let read = buf.pop().unwrap();
        assert_eq!(read.len(), 0);

        assert!(buf.push(first).is_ok());
        assert_eq!(buf.len(), 19);

        let read = buf.pop().unwrap();
        assert_eq!(read.len(), 19);
        assert_eq!(&read[..], b"somethinghelloworld");
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn empty_write() {
        let mut buf = RecvBuf::default();
        assert_eq!(buf.len(), 0);

        let write = buf.pop().unwrap();
        assert_eq!(write.len(), 0);
    }

    #[test]
    fn multi_write() {
        let mut buf = SendBuf::default();
        assert_eq!(buf.len(), 0);

        let first: [u8; 9] = *b"something";
        let second: [u8; 10] = *b"helloworld";

        assert!(buf.push_slice(&first, false).is_ok());
        assert_eq!(buf.len(), 9);

        assert!(buf.push_slice(&second, false).is_ok());
        assert_eq!(buf.len(), 19);

        let write = buf.pop(128).unwrap();
        assert_eq!(write.len(), 19);
        assert_eq!(&write[..], b"somethinghelloworld");
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn split_write() {
        let mut buf = SendBuf::default();
        assert_eq!(buf.len(), 0);

        let first: [u8; 9] = *b"something";
        let second: [u8; 10] = *b"helloworld";

        assert!(buf.push_slice(&first, false).is_ok());
        assert_eq!(buf.len(), 9);

        assert!(buf.push_slice(&second, true).is_ok());
        assert_eq!(buf.len(), 19);

        let write = buf.pop(10).unwrap();
        assert_eq!(write.off(), 0);
        assert_eq!(write.len(), 10);
        assert_eq!(&write[..], b"somethingh");
        assert_eq!(buf.len(), 9);

        let write = buf.pop(5).unwrap();
        assert_eq!(write.off(), 10);
        assert_eq!(write.len(), 5);
        assert_eq!(&write[..], b"ellow");
        assert_eq!(buf.len(), 4);

        let write = buf.pop(10).unwrap();
        assert_eq!(write.off(), 15);
        assert_eq!(write.len(), 4);
        assert_eq!(&write[..], b"orld");
        assert_eq!(buf.len(), 0);
    }
}
