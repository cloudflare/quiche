// Copyright (C) 2018, Cloudflare, Inc.
// Copyright (C) 2018, Alessandro Ghedini
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

use std::cmp;

use std::collections::hash_map;
use std::collections::HashMap;
use std::collections::BinaryHeap;

use crate::Result;
use crate::Error;

const MAX_WRITE_SIZE: usize = 1000;

#[derive(Default)]
pub struct Stream {
    recv: RecvBuf,
    send: SendBuf,

    max_tx_data: usize,

    rx_data: usize,
    max_rx_data: usize,
    new_max_rx_data: usize,
}

impl Stream {
    pub fn new(max_rx_data: usize, max_tx_data: usize) -> Stream {
        Stream {
            recv: RecvBuf::default(),
            send: SendBuf::default(),

            rx_data: 0,
            max_rx_data,
            new_max_rx_data: max_rx_data,

            max_tx_data,
        }
    }

    pub fn recv_push(&mut self, buf: RangeBuf) -> Result<()> {
        if buf.max_off() > self.max_rx_data {
            return Err(Error::FlowControl);
        }

        self.rx_data = cmp::max(self.rx_data, buf.max_off());

        self.recv.push(buf)
    }

    pub fn recv_pop(&mut self, out: &mut [u8]) -> Result<(usize, bool)> {
        let (len, fin) = self.recv.pop(out)?;

        self.new_max_rx_data = self.new_max_rx_data.checked_add(len)
                                                   .unwrap_or(std::usize::MAX);

        Ok((len, fin))
    }

    pub fn recv_update_max_data(&mut self) -> usize {
        self.max_rx_data = self.new_max_rx_data;

        self.new_max_rx_data
    }

    pub fn send_push(&mut self, data: &[u8], fin: bool) -> Result<()> {
        self.send.push_slice(data, fin)
    }

    pub fn send_pop(&mut self, max_len: usize) -> Result<RangeBuf> {
        self.send.pop(max_len, self.max_tx_data)
    }

    pub fn send_push_front(&mut self, buf: RangeBuf) -> Result<()> {
        self.send.push(buf)
    }

    pub fn send_max_data(&mut self, max_data: usize) {
        self.max_tx_data = cmp::max(self.max_tx_data, max_data);
    }

    pub fn readable(&self) -> bool {
        self.recv.ready()
    }

    pub fn writable(&self) -> bool {
        self.send.ready() && self.send.off() <= self.max_tx_data
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

/// An iterator over the streams that have outstanding data to read.
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

    fn pop(&mut self, out: &mut [u8]) -> Result<(usize, bool)> {
        let mut fin = false;
        let mut len = 0;
        let mut cap = out.len();

        if !self.ready() {
            return Err(Error::Done);
        }

        while cap > 0 && self.ready() {
            let mut buf = match self.data.pop() {
                Some(v) => v,
                None => break,
            };

            if buf.len() > cap {
                let new_buf = RangeBuf {
                    data: buf.data.split_off(cap),
                    off: buf.off + cap,
                    fin: buf.fin,
                };

                buf.fin = false;

                self.data.push(new_buf);
            }

            out[len..len + buf.len()].copy_from_slice(&buf.data);

            self.off += buf.len();
            self.len -= buf.len();

            len += buf.len();
            cap -= buf.len();

            fin = fin || buf.fin();
        }

        Ok((len, fin))
    }

    fn ready(&self) -> bool {
        let buf = match self.data.peek() {
            Some(v) => v,
            None => return false,
        };

        buf.off == self.off
    }

    #[allow(dead_code)]
    fn off(&self) -> usize {
        self.off
    }

    #[allow(dead_code)]
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
        let mut len = 0;

        if data.is_empty() {
            let buf = RangeBuf::from(&[], self.off, fin);
            return self.push(buf);
        }

        // Split the input buffer into multiple RangeBufs. Otherwise a big
        // buffer would need to be split later on when popping data, which
        // would cause a partial copy of the buffer.
        for chunk in data.chunks(MAX_WRITE_SIZE) {
            len += chunk.len();

            let fin = len == data.len() && fin;

            let buf = RangeBuf::from(chunk, self.off, fin);
            self.push(buf)?;

            self.off += chunk.len();
        }

        Ok(())
    }

    fn push(&mut self, buf: RangeBuf) -> Result<()> {
        self.len += buf.len();

        self.data.push(buf);

        Ok(())
    }

    fn pop(&mut self, max_len: usize, max_off: usize) -> Result<RangeBuf> {
        let mut out = RangeBuf::default();
        out.data = Vec::with_capacity(cmp::min(max_len, self.len()));

        let mut out_len = max_len;
        let mut out_off = self.data
                              .peek()
                              .map_or_else(|| 0, |d| d.off());

        while out_len > 0 && self.ready() && self.off() == out_off && self.off() < max_off {
            let mut buf = match self.data.pop() {
                Some(v) => v,
                None => break,
            };

            if buf.len() > out_len || buf.max_off() >= max_off {
                let new_len = cmp::min(out_len, max_off - buf.off());

                let new_buf = RangeBuf {
                    data: buf.data.split_off(new_len),
                    off: buf.off + new_len,
                    fin: buf.fin,
                };

                buf.fin = false;

                self.data.push(new_buf);
            }

            if out.is_empty() {
                out.off = buf.off;
            }

            self.len -= buf.len();

            out_len -= buf.len();
            out_off = buf.off() + buf.len();

            out.fin = out.fin || buf.fin();

            out.data.extend_from_slice(&buf.data);
        }

        Ok(out)
    }

    fn ready(&self) -> bool {
        !self.data.is_empty()
    }

    fn off(&self) -> usize {
        match self.data.peek() {
            Some(v) => v.off(),

            None => self.off,
        }
    }

    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.len
    }
}

/// Buffer holding data at a specific offset.
#[derive(Debug, Default, Eq)]
pub struct RangeBuf {
    data: Vec<u8>,
    off: usize,
    fin: bool,
}

impl RangeBuf {
    pub(crate) fn from(buf: &[u8], off: usize, fin: bool) -> RangeBuf {
        RangeBuf {
            data: Vec::from(buf),
            off,
            fin,
        }
    }

    /// Returns whether `self` holds the final offset in the stream.
    pub fn fin(&self) -> bool {
        self.fin
    }

    /// Returns the starting offset of `self`.
    pub fn off(&self) -> usize {
        self.off
    }

    /// Returns the final offset of `self`.
    pub fn max_off(&self) -> usize {
        self.off() + self.len()
    }

    /// Returns the length of `self`.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if `self` has a length of zero bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl std::ops::Deref for RangeBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.data
    }
}

impl std::ops::DerefMut for RangeBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.data
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
        let mut recv = RecvBuf::default();
        assert_eq!(recv.len(), 0);

        let mut buf = vec![0; 32];

        assert_eq!(recv.pop(buf.as_mut_slice()), Err(Error::Done));
    }

    #[test]
    fn ordered_read() {
        let mut recv = RecvBuf::default();
        assert_eq!(recv.len(), 0);

        let mut buf = vec![0; 32];

        let first = RangeBuf::from(b"hello", 0, false);
        let second = RangeBuf::from(b"world", 5, false);
        let third = RangeBuf::from(b"something", 10, true);

        assert!(recv.push(second).is_ok());
        assert_eq!(recv.len(), 10);
        assert_eq!(recv.off(), 0);

        assert_eq!(recv.pop(buf.as_mut_slice()), Err(Error::Done));

        assert!(recv.push(third).is_ok());
        assert_eq!(recv.len(), 19);
        assert_eq!(recv.off(), 0);

        assert_eq!(recv.pop(buf.as_mut_slice()), Err(Error::Done));

        assert!(recv.push(first).is_ok());
        assert_eq!(recv.len(), 19);
        assert_eq!(recv.off(), 0);

        let (len, fin) = recv.pop(buf.as_mut_slice()).unwrap();
        assert_eq!(len, 19);
        assert_eq!(fin, true);
        assert_eq!(&buf[..len], b"helloworldsomething");
        assert_eq!(recv.len(), 0);
        assert_eq!(recv.off(), 19);

        assert_eq!(recv.pop(buf.as_mut_slice()), Err(Error::Done));
    }

    #[test]
    fn split_read() {
        let mut recv = RecvBuf::default();
        assert_eq!(recv.len(), 0);

        let mut buf = vec![0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"helloworld", 9, true);

        assert!(recv.push(first).is_ok());
        assert_eq!(recv.len(), 9);
        assert_eq!(recv.off(), 0);

        assert!(recv.push(second).is_ok());
        assert_eq!(recv.len(), 19);
        assert_eq!(recv.off(), 0);

        let (len, fin) = recv.pop(&mut buf[..10]).unwrap();
        assert_eq!(len, 10);
        assert_eq!(fin, false);
        assert_eq!(&buf[..len], b"somethingh");
        assert_eq!(recv.len(), 9);
        assert_eq!(recv.off(), 10);

        let (len, fin) = recv.pop(&mut buf[..5]).unwrap();
        assert_eq!(len, 5);
        assert_eq!(fin, false);
        assert_eq!(&buf[..len], b"ellow");
        assert_eq!(recv.len(), 4);
        assert_eq!(recv.off(), 15);

        let (len, fin) = recv.pop(&mut buf[..10]).unwrap();
        assert_eq!(len, 4);
        assert_eq!(fin, true);
        assert_eq!(&buf[..len], b"orld");
        assert_eq!(recv.len(), 0);
        assert_eq!(recv.off(), 19);
    }

    #[test]
    fn incomplete_read() {
        let mut recv = RecvBuf::default();
        assert_eq!(recv.len(), 0);

        let mut buf = vec![0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"helloworld", 9, true);

        assert!(recv.push(second).is_ok());
        assert_eq!(recv.len(), 19);
        assert_eq!(recv.off(), 0);

        assert_eq!(recv.pop(buf.as_mut_slice()), Err(Error::Done));

        assert!(recv.push(first).is_ok());
        assert_eq!(recv.len(), 19);
        assert_eq!(recv.off(), 0);

        let (len, fin) = recv.pop(buf.as_mut_slice()).unwrap();
        assert_eq!(len, 19);
        assert_eq!(fin, true);
        assert_eq!(&buf[..len], b"somethinghelloworld");
        assert_eq!(recv.len(), 0);
        assert_eq!(recv.off(), 19);
    }

    #[test]
    fn zero_len_read() {
        let mut recv = RecvBuf::default();
        assert_eq!(recv.len(), 0);

        let mut buf = vec![0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"", 9, true);

        assert!(recv.push(first).is_ok());
        assert_eq!(recv.len(), 9);
        assert_eq!(recv.off(), 0);

        assert!(recv.push(second).is_ok());
        assert_eq!(recv.len(), 9);
        assert_eq!(recv.off(), 0);

        let (len, fin) = recv.pop(buf.as_mut_slice()).unwrap();
        assert_eq!(len, 9);
        assert_eq!(fin, true);
        assert_eq!(&buf[..len], b"something");
        assert_eq!(recv.len(), 0);
        assert_eq!(recv.off(), 9);
    }

    #[test]
    fn empty_write() {
        let mut send = SendBuf::default();
        assert_eq!(send.len(), 0);

        let write = send.pop(std::usize::MAX, std::usize::MAX).unwrap();
        assert_eq!(write.len(), 0);
        assert_eq!(write.fin(), false);
    }

    #[test]
    fn multi_write() {
        let mut send = SendBuf::default();
        assert_eq!(send.len(), 0);

        let first: [u8; 9] = *b"something";
        let second: [u8; 10] = *b"helloworld";

        assert!(send.push_slice(&first, false).is_ok());
        assert_eq!(send.len(), 9);

        assert!(send.push_slice(&second, true).is_ok());
        assert_eq!(send.len(), 19);

        let write = send.pop(128, std::usize::MAX).unwrap();
        assert_eq!(write.len(), 19);
        assert_eq!(write.fin(), true);
        assert_eq!(&write[..], b"somethinghelloworld");
        assert_eq!(send.len(), 0);
    }

    #[test]
    fn split_write() {
        let mut send = SendBuf::default();
        assert_eq!(send.len(), 0);

        let first: [u8; 9] = *b"something";
        let second: [u8; 10] = *b"helloworld";

        assert!(send.push_slice(&first, false).is_ok());
        assert_eq!(send.len(), 9);

        assert!(send.push_slice(&second, true).is_ok());
        assert_eq!(send.len(), 19);

        let write = send.pop(10, std::usize::MAX).unwrap();
        assert_eq!(write.off(), 0);
        assert_eq!(write.len(), 10);
        assert_eq!(write.fin(), false);
        assert_eq!(&write[..], b"somethingh");
        assert_eq!(send.len(), 9);

        let write = send.pop(5, std::usize::MAX).unwrap();
        assert_eq!(write.off(), 10);
        assert_eq!(write.len(), 5);
        assert_eq!(write.fin(), false);
        assert_eq!(&write[..], b"ellow");
        assert_eq!(send.len(), 4);

        let write = send.pop(10, std::usize::MAX).unwrap();
        assert_eq!(write.off(), 15);
        assert_eq!(write.len(), 4);
        assert_eq!(write.fin(), true);
        assert_eq!(&write[..], b"orld");
        assert_eq!(send.len(), 0);
    }

    #[test]
    fn resend() {
        let mut send = SendBuf::default();
        assert_eq!(send.len(), 0);
        assert_eq!(send.off(), 0);

        let first: [u8; 9] = *b"something";
        let second: [u8; 10] = *b"helloworld";

        assert!(send.push_slice(&first, false).is_ok());
        assert_eq!(send.off(), 0);

        assert!(send.push_slice(&second, true).is_ok());
        assert_eq!(send.off(), 0);

        let write1 = send.pop(4, std::usize::MAX).unwrap();
        assert_eq!(write1.off(), 0);
        assert_eq!(write1.len(), 4);
        assert_eq!(write1.fin(), false);
        assert_eq!(&write1[..], b"some");
        assert_eq!(send.len(), 15);
        assert_eq!(send.off(), 4);

        let write2 = send.pop(5, std::usize::MAX).unwrap();
        assert_eq!(write2.off(), 4);
        assert_eq!(write2.len(), 5);
        assert_eq!(write2.fin(), false);
        assert_eq!(&write2[..], b"thing");
        assert_eq!(send.len(), 10);
        assert_eq!(send.off(), 9);

        let write3 = send.pop(5, std::usize::MAX).unwrap();
        assert_eq!(write3.off(), 9);
        assert_eq!(write3.len(), 5);
        assert_eq!(write3.fin(), false);
        assert_eq!(&write3[..], b"hello");
        assert_eq!(send.len(), 5);
        assert_eq!(send.off(), 14);

        send.push(write2).unwrap();
        assert_eq!(send.len(), 10);
        assert_eq!(send.off(), 4);

        send.push(write1).unwrap();
        assert_eq!(send.len(), 14);
        assert_eq!(send.off(), 0);

        let write4 = send.pop(11, std::usize::MAX).unwrap();
        assert_eq!(write4.off(), 0);
        assert_eq!(write4.len(), 9);
        assert_eq!(write4.fin(), false);
        assert_eq!(&write4[..], b"something");
        assert_eq!(send.len(), 5);
        assert_eq!(send.off(), 14);

        let write5 = send.pop(11, std::usize::MAX).unwrap();
        assert_eq!(write5.off(), 14);
        assert_eq!(write5.len(), 5);
        assert_eq!(write5.fin(), true);
        assert_eq!(&write5[..], b"world");
        assert_eq!(send.len(), 0);
        assert_eq!(send.off(), 19);
    }

    #[test]
    fn write_blocked_by_off() {
        let mut send = SendBuf::default();
        assert_eq!(send.len(), 0);

        let first: [u8; 9] = *b"something";
        let second: [u8; 10] = *b"helloworld";

        assert!(send.push_slice(&first, false).is_ok());
        assert_eq!(send.len(), 9);

        assert!(send.push_slice(&second, true).is_ok());
        assert_eq!(send.len(), 19);

        let write = send.pop(10, 5).unwrap();
        assert_eq!(write.off(), 0);
        assert_eq!(write.len(), 5);
        assert_eq!(write.fin(), false);
        assert_eq!(&write[..], b"somet");
        assert_eq!(send.len(), 14);

        let write = send.pop(10, 5).unwrap();
        assert_eq!(write.off(), 0);
        assert_eq!(write.len(), 0);
        assert_eq!(write.fin(), false);
        assert_eq!(&write[..], b"");
        assert_eq!(send.len(), 14);

        let write = send.pop(10, 15).unwrap();
        assert_eq!(write.off(), 5);
        assert_eq!(write.len(), 10);
        assert_eq!(write.fin(), false);
        assert_eq!(&write[..], b"hinghellow");
        assert_eq!(send.len(), 4);

        let write = send.pop(10, 25).unwrap();
        assert_eq!(write.off(), 15);
        assert_eq!(write.len(), 4);
        assert_eq!(write.fin(), true);
        assert_eq!(&write[..], b"orld");
        assert_eq!(send.len(), 0);
    }

    #[test]
    fn zero_len_write() {
        let mut send = SendBuf::default();
        assert_eq!(send.len(), 0);

        let first: [u8; 9] = *b"something";

        assert!(send.push_slice(&first, false).is_ok());
        assert_eq!(send.len(), 9);

        assert!(send.push_slice(&[], true).is_ok());
        assert_eq!(send.len(), 9);

        let write = send.pop(10, std::usize::MAX).unwrap();
        assert_eq!(write.off(), 0);
        assert_eq!(write.len(), 9);
        assert_eq!(write.fin(), true);
        assert_eq!(&write[..], b"something");
        assert_eq!(send.len(), 0);
    }

    #[test]
    fn recv_flow_control() {
        let mut stream = Stream::new(15, 0);
        assert!(!stream.more_credit());

        let mut buf = vec![0; 32];

        let first = RangeBuf::from(b"hello", 0, false);
        let second = RangeBuf::from(b"world", 5, false);
        let third = RangeBuf::from(b"something", 10, false);

        assert_eq!(stream.recv_push(second), Ok(()));
        assert_eq!(stream.recv_push(first), Ok(()));
        assert!(!stream.more_credit());

        assert_eq!(stream.recv_push(third), Err(Error::FlowControl));

        let (len, fin) = stream.recv_pop(buf.as_mut_slice()).unwrap();
        assert_eq!(&buf[..len], b"helloworld");
        assert_eq!(fin, false);

        assert!(stream.more_credit());

        assert_eq!(stream.recv_update_max_data(), 25);
        assert!(!stream.more_credit());

        let third = RangeBuf::from(b"something", 10, false);
        assert_eq!(stream.recv_push(third), Ok(()));
    }

    #[test]
    fn send_flow_control() {
        let mut stream = Stream::new(0, 15);

        let first = b"hello";
        let second = b"world";
        let third = b"something";

        assert_eq!(stream.send_push(first, false), Ok(()));
        assert_eq!(stream.send_push(second, false), Ok(()));
        assert_eq!(stream.send_push(third, false), Ok(()));

        let write = stream.send_pop(25).unwrap();
        assert_eq!(write.off(), 0);
        assert_eq!(write.len(), 15);
        assert_eq!(write.fin(), false);
        assert_eq!(write.data, b"helloworldsomet");

        let write = stream.send_pop(25).unwrap();
        assert_eq!(write.off(), 0);
        assert_eq!(write.len(), 0);
        assert_eq!(write.fin(), false);
        assert_eq!(write.data, b"");

        let first = RangeBuf::from(b"helloworldsomet", 0, false);
        assert_eq!(stream.send_push_front(first), Ok(()));

        let write = stream.send_pop(10).unwrap();
        assert_eq!(write.off(), 0);
        assert_eq!(write.len(), 10);
        assert_eq!(write.fin(), false);
        assert_eq!(write.data, b"helloworld");

        let write = stream.send_pop(10).unwrap();
        assert_eq!(write.off(), 10);
        assert_eq!(write.len(), 5);
        assert_eq!(write.fin(), false);
        assert_eq!(write.data, b"somet");
    }
}
