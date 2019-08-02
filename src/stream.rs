// Copyright (C) 2018, Cloudflare, Inc.
// Copyright (C) 2018, Alessandro Ghedini
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

use std::cmp;

use std::collections::hash_map;
use std::collections::BinaryHeap;
use std::collections::HashMap;
use std::collections::VecDeque;

use crate::Error;
use crate::Result;

const MAX_WRITE_SIZE: usize = 1000;

/// Keeps track of QUIC streams and enforces stream limits.
#[derive(Default)]
pub struct StreamMap {
    /// Map of streams indexed by stream ID.
    streams: HashMap<u64, Stream>,

    /// Peer's maximum bidirectional stream count limit.
    peer_max_streams_bidi: usize,

    /// Peer's maximum unidirectional stream count limit.
    peer_max_streams_uni: usize,

    /// Local maximum bidirectional stream count limit.
    local_max_streams_bidi: usize,

    /// Local maximum unidirectional stream count limit.
    local_max_streams_uni: usize,

    /// Queue of stream IDs corresponding to streams that have outstanding
    /// data to send and enough flow control credits to send at least some of
    /// it.
    ///
    /// Streams are added to the back of the list, and removed from the front.
    writable: VecDeque<u64>,
}

impl StreamMap {
    /// Returns the stream with the given ID if it exists.
    pub fn get(&self, id: u64) -> Option<&Stream> {
        self.streams.get(&id)
    }

    /// Returns the mutable stream with the given ID if it exists.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut Stream> {
        self.streams.get_mut(&id)
    }

    /// Returns the mutable stream with the given ID if it exists, or creates
    /// a new one otherwise.
    ///
    /// The `local` parameter indicates whether the stream's creation was
    /// requested by the local application rather than the peer, and is
    /// used to validate the requested stream ID, and to select the initial
    /// flow control values from the local and remote transport parameters
    /// (also passed as arguments).
    ///
    /// This also takes care of enforcing both local and the peer's stream
    /// count limits. If one of these limits is violated, the `StreamLimit`
    /// error is returned.
    pub(crate) fn get_or_create(
        &mut self, id: u64, local_params: &crate::TransportParams,
        peer_params: &crate::TransportParams, local: bool, is_server: bool,
    ) -> Result<&mut Stream> {
        let stream = match self.streams.entry(id) {
            hash_map::Entry::Vacant(v) => {
                if local != is_local(id, is_server) {
                    return Err(Error::InvalidStreamState);
                }

                let (max_rx_data, max_tx_data) = match (local, is_bidi(id)) {
                    // Locally-initiated bidirectional stream.
                    (true, true) => (
                        local_params.initial_max_stream_data_bidi_local,
                        peer_params.initial_max_stream_data_bidi_remote,
                    ),

                    // Locally-initiated unidirectional stream.
                    (true, false) => (0, peer_params.initial_max_stream_data_uni),

                    // Remotely-initiated bidirectional stream.
                    (false, true) => (
                        local_params.initial_max_stream_data_bidi_remote,
                        peer_params.initial_max_stream_data_bidi_local,
                    ),

                    // Remotely-initiated unidirectional stream.
                    (false, false) =>
                        (local_params.initial_max_stream_data_uni, 0),
                };

                // Enforce stream count limits.
                match (is_local(id, is_server), is_bidi(id)) {
                    (true, true) =>
                        self.peer_max_streams_bidi = self
                            .peer_max_streams_bidi
                            .checked_sub(1)
                            .ok_or(Error::StreamLimit)?,

                    (true, false) =>
                        self.peer_max_streams_uni = self
                            .peer_max_streams_uni
                            .checked_sub(1)
                            .ok_or(Error::StreamLimit)?,

                    (false, true) =>
                        self.local_max_streams_bidi = self
                            .local_max_streams_bidi
                            .checked_sub(1)
                            .ok_or(Error::StreamLimit)?,

                    (false, false) =>
                        self.local_max_streams_uni = self
                            .local_max_streams_uni
                            .checked_sub(1)
                            .ok_or(Error::StreamLimit)?,
                };

                let s = Stream::new(max_rx_data as usize, max_tx_data as usize);
                v.insert(s)
            },

            hash_map::Entry::Occupied(v) => v.into_mut(),
        };

        Ok(stream)
    }

    /// Pushes the stream ID to the back of the writable streams queue.
    ///
    /// Note that the caller is responsible for checking that the specified
    /// stream ID was not in the queue already before calling this.
    ///
    /// Queueing a stream multiple times simultaneously means that it might be
    /// unfairly scheduled more often than other streams, and might also cause
    /// spurious cycles through the queue, so it should be avoided.
    pub fn push_writable(&mut self, stream_id: u64) {
        self.writable.push_back(stream_id);
    }

    /// Removes and returns the first stream ID from the writable streams queue.
    ///
    /// Note that if the stream is still writable after sending some of its
    /// outstanding data, it needs to be added back to the queu.
    pub fn pop_writable(&mut self) -> Option<u64> {
        self.writable.pop_front()
    }

    /// Updates the local maximum bidirectional stream count limit.
    pub fn update_local_max_streams_bidi(&mut self, v: usize) {
        self.local_max_streams_bidi = cmp::max(self.local_max_streams_bidi, v);
    }

    /// Updates the local maximum unidirectional stream count limit.
    pub fn update_local_max_streams_uni(&mut self, v: usize) {
        self.local_max_streams_uni = cmp::max(self.local_max_streams_uni, v);
    }

    /// Updates the peer's maximum bidirectional stream count limit.
    pub fn update_peer_max_streams_bidi(&mut self, v: usize) {
        self.peer_max_streams_bidi = cmp::max(self.peer_max_streams_bidi, v);
    }

    /// Updates the peer's maximum unidirectional stream count limit.
    pub fn update_peer_max_streams_uni(&mut self, v: usize) {
        self.peer_max_streams_uni = cmp::max(self.peer_max_streams_uni, v);
    }

    /// Creates an iterator over streams that have outstanding data to read.
    pub fn readable(&mut self) -> Readable {
        Readable::new(&self.streams)
    }

    /// Creates an iterator over all streams.
    pub fn iter_mut(&mut self) -> hash_map::IterMut<u64, Stream> {
        self.streams.iter_mut()
    }

    /// Returns true if there are any streams that have data to write.
    pub fn has_writable(&self) -> bool {
        !self.writable.is_empty()
    }

    /// Returns true if there are any streams that need to update the local
    /// flow control limit.
    pub fn has_out_of_credit(&self) -> bool {
        self.streams.values().any(|s| s.recv.more_credit())
    }
}

/// A QUIC stream.
#[derive(Default)]
pub struct Stream {
    /// Receive-side stream buffer.
    pub recv: RecvBuf,

    /// Send-side stream buffer.
    pub send: SendBuf,
}

impl Stream {
    /// Creates a new stream with the given flow control limits.
    pub fn new(max_rx_data: usize, max_tx_data: usize) -> Stream {
        Stream {
            recv: RecvBuf::new(max_rx_data),
            send: SendBuf::new(max_tx_data),
        }
    }

    /// Returns true if the stream has data to read.
    pub fn readable(&self) -> bool {
        self.recv.ready()
    }

    /// Returns true if the stream has data to send and is allowed to send at
    /// least some of it.
    pub fn writable(&self) -> bool {
        self.send.ready() && self.send.off() < self.send.max_data
    }
}

/// Returns true if the stream was created locally.
pub fn is_local(stream_id: u64, is_server: bool) -> bool {
    (stream_id & 0x1) == (is_server as u64)
}

/// Returns true if the stream is bidirectional.
pub fn is_bidi(stream_id: u64) -> bool {
    (stream_id & 0x2) == 0
}

/// An iterator over the streams that have outstanding data to read.
///
/// This can be obtained by calling a connection's [`readable()`] method.
///
/// [`readable()`]: struct.Connection.html#method.readable
pub struct Readable<'a> {
    streams: hash_map::Iter<'a, u64, Stream>,
}

impl<'a> Readable<'a> {
    fn new(streams: &HashMap<u64, Stream>) -> Readable {
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

/// Receive-side stream buffer.
///
/// Stream data received by the peer is buffered in a list of data chunks
/// ordered by offset in ascending order. Contiguous data can then be read
/// into a slice.
#[derive(Default)]
pub struct RecvBuf {
    /// Chunks of data received from the peer that have not yet been read by
    /// the application, ordered by offset.
    data: BinaryHeap<RangeBuf>,

    /// The lowest data offset that has yet to be read by the application.
    off: usize,

    /// The total length of data received on this stream.
    len: usize,

    /// The maximum offset the peer is allowed to send us.
    max_data: usize,

    /// The updated maximum offset the peer is allowed to send us.
    max_data_next: usize,

    /// The final stream offset received from the peer, if any.
    fin_off: Option<usize>,

    /// Whether incoming data is validated but not buffered.
    drain: bool,
}

impl RecvBuf {
    /// Creates a new receive buffer.
    fn new(max_data: usize) -> RecvBuf {
        RecvBuf {
            max_data,
            max_data_next: max_data,
            ..RecvBuf::default()
        }
    }

    /// Inserts the given chunk of data in the buffer.
    ///
    /// This also takes care of enforcing stream flow control limits, as well
    /// as handling incoming data that overlaps data that is already in the
    /// buffer.
    pub fn push(&mut self, buf: RangeBuf) -> Result<()> {
        if buf.max_off() > self.max_data {
            return Err(Error::FlowControl);
        }

        if let Some(fin_off) = self.fin_off {
            // Stream's size is known, forbid data beyond that point.
            if buf.max_off() > fin_off {
                return Err(Error::FinalSize);
            }

            // Stream's size is already known, forbid changing it.
            if buf.fin() && fin_off != buf.max_off() {
                return Err(Error::FinalSize);
            }
        }

        // Stream's known size is lower than data already received.
        if buf.fin() && buf.max_off() < self.len {
            return Err(Error::FinalSize);
        }

        // We already saved the final offset, so there's nothing else we
        // need to keep from the RangeBuf if it's empty.
        if self.fin_off.is_some() && buf.is_empty() {
            return Ok(());
        }

        if buf.fin() {
            self.fin_off = Some(buf.max_off());
        }

        // No need to store empty buffer that doesn't carry the fin flag.
        if !buf.fin() && buf.is_empty() {
            return Ok(());
        }

        // Check if data is fully duplicate, that is the buffer's max offset is
        // lower or equal to the offset already stored in the recv buffer.
        if self.off >= buf.max_off() {
            // An exception is applied to empty range buffers, because an empty
            // buffer's max offset matches the max offset of the recv buffer.
            //
            // By this point all spurious empty buffers should have already been
            // discarded, so allowing empty buffers here should be safe.
            if !buf.is_empty() {
                return Ok(());
            }
        }

        if self.drain {
            return Ok(());
        }

        let mut tmp_buf = Some(buf);

        while let Some(mut buf) = tmp_buf {
            tmp_buf = None;

            for b in &self.data {
                // New buffer is fully contained in existing buffer.
                if buf.off() >= b.off() && buf.max_off() <= b.max_off() {
                    return Ok(());
                }

                // New buffer's start overlaps existing buffer.
                if buf.off() >= b.off() && buf.off() < b.max_off() {
                    buf = buf.split_off(b.max_off() - buf.off());
                }

                // New buffer's end overlaps existing buffer.
                if buf.off() < b.off() && buf.max_off() > b.off() {
                    tmp_buf = Some(buf.split_off(b.off() - buf.off()));
                }
            }

            self.len = cmp::max(self.len, buf.max_off());

            self.data.push(buf);
        }

        Ok(())
    }

    /// Writes data from the receive buffer into the given output buffer.
    ///
    /// Only contiguous data is written to the output buffer, starting from
    /// offset 0. The offset is incremented as data is read out of the receive
    /// buffer into the application buffer. If there is no data at the expected
    /// read offset, the `Done` error is returned.
    ///
    /// On success the amount of data read, and a flag indicating if there is
    /// no more data in the buffer, are returned as a tuple.
    pub fn pop(&mut self, out: &mut [u8]) -> Result<(usize, bool)> {
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

            len += buf.len();
            cap -= buf.len();
        }

        self.max_data_next = self.max_data_next.saturating_add(len);

        Ok((len, self.is_fin()))
    }

    /// Resets the stream at the given offset.
    pub fn reset(&mut self, final_size: usize) -> Result<usize> {
        // Stream's size is already known, forbid changing it.
        if let Some(fin_off) = self.fin_off {
            if fin_off != final_size {
                return Err(Error::FinalSize);
            }
        }

        // Stream's known size is lower than data already received.
        if final_size < self.len {
            return Err(Error::FinalSize);
        }

        self.fin_off = Some(final_size);

        // Return how many bytes need to be removed from the connection flow
        // control.
        Ok(final_size - self.len)
    }

    /// Commits the new max_data limit and returns it.
    pub fn update_max_data(&mut self) -> usize {
        self.max_data = self.max_data_next;

        self.max_data
    }

    /// Shuts down receiving data.
    pub fn shutdown(&mut self) {
        self.drain = true;

        self.data.clear();
    }

    /// Returns true if we need to update the local flow control limit.
    pub fn more_credit(&self) -> bool {
        // Send MAX_STREAM_DATA when the new limit is at least double the
        // amount of data that can be received before blocking.
        self.fin_off.is_none() &&
            self.max_data_next != self.max_data &&
            self.max_data_next / 2 > self.max_data - self.len
    }

    /// Returns true if the receive-side of the stream is complete.
    pub fn is_fin(&self) -> bool {
        if self.fin_off == Some(self.off) {
            return true;
        }

        false
    }

    /// Returns true if the stream has data to be read.
    fn ready(&self) -> bool {
        let buf = match self.data.peek() {
            Some(v) => v,
            None => return false,
        };

        buf.off == self.off
    }
}

/// Send-side stream buffer.
///
/// Stream data scheduled to be sent to the peer is buffered in a list of data
/// chunks ordered by offset in ascending order. Contiguous data can then be
/// read into a slice.
///
/// By default, new data is appended at the end of the stream, but data can be
/// inserted at the start of the buffer (this is to allow data that needs to be
/// retransmitted to be re-buffered).
#[derive(Default)]
pub struct SendBuf {
    /// Chunks of data to be sent, ordered by offset.
    data: BinaryHeap<RangeBuf>,

    /// The maximum offset of data buffered in the stream.
    off: usize,

    /// The amount of data that was ever written to this stream.
    len: usize,

    /// The maximum offset we are allowed to send to the peer.
    max_data: usize,

    /// The highest contiguous ACK'd offset.
    off_ack: usize,

    /// Whether the stream's send-side has been shut down.
    shutdown: bool,
}

impl SendBuf {
    /// Creates a new send buffer.
    fn new(max_data: usize) -> SendBuf {
        SendBuf {
            max_data,
            ..SendBuf::default()
        }
    }

    /// Inserts the given slice of data at the end of the buffer.
    pub fn push_slice(&mut self, data: &[u8], fin: bool) -> Result<()> {
        let mut len = 0;

        if self.shutdown {
            return Ok(());
        }

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

    /// Inserts the given chunk of data in the buffer.
    pub fn push(&mut self, buf: RangeBuf) -> Result<()> {
        if self.shutdown {
            return Ok(());
        }

        // Don't queue data that was already fully ACK'd.
        if self.off_ack >= buf.max_off() {
            return Ok(());
        }

        self.len += buf.len();

        self.data.push(buf);

        Ok(())
    }

    /// Returns contiguous data from the send buffer as a single `RangeBuf`.
    pub fn pop(&mut self, max_data: usize) -> Result<RangeBuf> {
        let mut out = RangeBuf::default();
        out.data = Vec::with_capacity(cmp::min(max_data, self.len));

        let mut out_len = max_data;
        let mut out_off = self.data.peek().map_or_else(|| 0, RangeBuf::off);

        while out_len > 0 &&
            self.ready() &&
            self.off() == out_off &&
            self.off() < self.max_data
        {
            let mut buf = match self.data.pop() {
                Some(v) => v,
                None => break,
            };

            if buf.len() > out_len || buf.max_off() >= self.max_data {
                let new_len = cmp::min(out_len, self.max_data - buf.off());
                let new_buf = buf.split_off(new_len);

                self.data.push(new_buf);
            }

            if out.is_empty() {
                out.off = buf.off;
            }

            self.len -= buf.len();

            out_len -= buf.len();
            out_off = buf.max_off();

            out.fin = out.fin || buf.fin();

            out.data.extend_from_slice(&buf.data);
        }

        Ok(out)
    }

    /// Updates the max_data limit to the given value.
    pub fn update_max_data(&mut self, max_data: usize) {
        self.max_data = cmp::max(self.max_data, max_data);
    }

    /// Increments the ACK'd data offset.
    pub fn ack(&mut self, off: usize, len: usize) {
        // Keep track of the highest contiguously ACK'd offset. This can be
        // used to avoid spurious retransmissions of data that has already
        // been ACK'd.
        if self.off_ack == off {
            self.off_ack += len;
        }
    }

    /// Shuts down sending data.
    pub fn shutdown(&mut self) {
        self.shutdown = true;

        self.data.clear();
    }

    /// Returns true if there is data to be written.
    fn ready(&self) -> bool {
        !self.data.is_empty()
    }

    /// Returns the lowest offset of data buffered.
    fn off(&self) -> usize {
        match self.data.peek() {
            Some(v) => v.off(),

            None => self.off,
        }
    }
}

/// Buffer holding data at a specific offset.
#[derive(Clone, Debug, Default, Eq)]
pub struct RangeBuf {
    data: Vec<u8>,
    off: usize,
    fin: bool,
}

impl RangeBuf {
    /// Creates a new `RangeBuf` from the given slice.
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

    /// Splits the buffer into two at the given index.
    pub fn split_off(&mut self, at: usize) -> RangeBuf {
        let buf = RangeBuf {
            data: self.data.split_off(at),
            off: self.off + at,
            fin: self.fin,
        };

        self.fin = false;

        buf
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
        let mut recv = RecvBuf::new(std::usize::MAX);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        assert_eq!(recv.pop(&mut buf), Err(Error::Done));
    }

    #[test]
    fn empty_stream_frame() {
        let mut recv = RecvBuf::new(15);
        assert_eq!(recv.len, 0);

        let buf = RangeBuf::from(b"hello", 0, false);
        assert!(recv.push(buf).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        let mut buf = [0; 32];
        assert_eq!(recv.pop(&mut buf), Ok((5, false)));

        // Don't store non-fin empty buffer.
        let buf = RangeBuf::from(b"", 10, false);
        assert!(recv.push(buf).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 5);
        assert_eq!(recv.data.len(), 0);

        // Check flow control for empty buffer.
        let buf = RangeBuf::from(b"", 16, false);
        assert_eq!(recv.push(buf), Err(Error::FlowControl));

        // Store fin empty buffer.
        let buf = RangeBuf::from(b"", 5, true);
        assert!(recv.push(buf).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 5);
        assert_eq!(recv.data.len(), 1);

        // Don't store additional fin empty buffers.
        let buf = RangeBuf::from(b"", 5, true);
        assert!(recv.push(buf).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 5);
        assert_eq!(recv.data.len(), 1);

        // Don't store additional fin non-empty buffers.
        let buf = RangeBuf::from(b"aa", 3, true);
        assert!(recv.push(buf).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 5);
        assert_eq!(recv.data.len(), 1);

        // Validate final size with fin empty buffers.
        let buf = RangeBuf::from(b"", 6, true);
        assert_eq!(recv.push(buf), Err(Error::FinalSize));
        let buf = RangeBuf::from(b"", 4, true);
        assert_eq!(recv.push(buf), Err(Error::FinalSize));

        let mut buf = [0; 32];
        assert_eq!(recv.pop(&mut buf), Ok((0, true)));
    }

    #[test]
    fn ordered_read() {
        let mut recv = RecvBuf::new(std::usize::MAX);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"hello", 0, false);
        let second = RangeBuf::from(b"world", 5, false);
        let third = RangeBuf::from(b"something", 10, true);

        assert!(recv.push(second).is_ok());
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 0);

        assert_eq!(recv.pop(&mut buf), Err(Error::Done));

        assert!(recv.push(third).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        assert_eq!(recv.pop(&mut buf), Err(Error::Done));

        assert!(recv.push(first).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        let (len, fin) = recv.pop(&mut buf).unwrap();
        assert_eq!(len, 19);
        assert_eq!(fin, true);
        assert_eq!(&buf[..len], b"helloworldsomething");
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 19);

        assert_eq!(recv.pop(&mut buf), Err(Error::Done));
    }

    #[test]
    fn split_read() {
        let mut recv = RecvBuf::new(std::usize::MAX);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"helloworld", 9, true);

        assert!(recv.push(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);

        assert!(recv.push(second).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        let (len, fin) = recv.pop(&mut buf[..10]).unwrap();
        assert_eq!(len, 10);
        assert_eq!(fin, false);
        assert_eq!(&buf[..len], b"somethingh");
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 10);

        let (len, fin) = recv.pop(&mut buf[..5]).unwrap();
        assert_eq!(len, 5);
        assert_eq!(fin, false);
        assert_eq!(&buf[..len], b"ellow");
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 15);

        let (len, fin) = recv.pop(&mut buf[..10]).unwrap();
        assert_eq!(len, 4);
        assert_eq!(fin, true);
        assert_eq!(&buf[..len], b"orld");
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 19);
    }

    #[test]
    fn incomplete_read() {
        let mut recv = RecvBuf::new(std::usize::MAX);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"helloworld", 9, true);

        assert!(recv.push(second).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        assert_eq!(recv.pop(&mut buf), Err(Error::Done));

        assert!(recv.push(first).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        let (len, fin) = recv.pop(&mut buf).unwrap();
        assert_eq!(len, 19);
        assert_eq!(fin, true);
        assert_eq!(&buf[..len], b"somethinghelloworld");
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 19);
    }

    #[test]
    fn zero_len_read() {
        let mut recv = RecvBuf::new(std::usize::MAX);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"", 9, true);

        assert!(recv.push(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.push(second).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        let (len, fin) = recv.pop(&mut buf).unwrap();
        assert_eq!(len, 9);
        assert_eq!(fin, true);
        assert_eq!(&buf[..len], b"something");
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
    }

    #[test]
    fn past_read() {
        let mut recv = RecvBuf::new(std::usize::MAX);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 3, false);
        let third = RangeBuf::from(b"ello", 4, true);
        let fourth = RangeBuf::from(b"ello", 5, true);

        assert!(recv.push(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        let (len, fin) = recv.pop(&mut buf).unwrap();
        assert_eq!(len, 9);
        assert_eq!(fin, false);
        assert_eq!(&buf[..len], b"something");
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);

        assert!(recv.push(second).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.push(third), Err(Error::FinalSize));

        assert!(recv.push(fourth).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.pop(&mut buf), Err(Error::Done));
    }

    #[test]
    fn fully_overlapping_read() {
        let mut recv = RecvBuf::new(std::usize::MAX);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 4, false);

        assert!(recv.push(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.push(second).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        let (len, fin) = recv.pop(&mut buf).unwrap();
        assert_eq!(len, 9);
        assert_eq!(fin, false);
        assert_eq!(&buf[..len], b"something");
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.pop(&mut buf), Err(Error::Done));
    }

    #[test]
    fn fully_overlapping_read2() {
        let mut recv = RecvBuf::new(std::usize::MAX);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 4, false);

        assert!(recv.push(second).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.push(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        let (len, fin) = recv.pop(&mut buf).unwrap();
        assert_eq!(len, 9);
        assert_eq!(fin, false);
        assert_eq!(&buf[..len], b"somehello");
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.pop(&mut buf), Err(Error::Done));
    }

    #[test]
    fn fully_overlapping_read3() {
        let mut recv = RecvBuf::new(std::usize::MAX);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 3, false);

        assert!(recv.push(second).is_ok());
        assert_eq!(recv.len, 8);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.push(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 3);

        let (len, fin) = recv.pop(&mut buf).unwrap();
        assert_eq!(len, 9);
        assert_eq!(fin, false);
        assert_eq!(&buf[..len], b"somhellog");
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.pop(&mut buf), Err(Error::Done));
    }

    #[test]
    fn fully_overlapping_read_multi() {
        let mut recv = RecvBuf::new(std::usize::MAX);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"somethingsomething", 0, false);
        let second = RangeBuf::from(b"hello", 3, false);
        let third = RangeBuf::from(b"hello", 12, false);

        assert!(recv.push(second).is_ok());
        assert_eq!(recv.len, 8);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.push(third).is_ok());
        assert_eq!(recv.len, 17);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        assert!(recv.push(first).is_ok());
        assert_eq!(recv.len, 18);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 5);

        let (len, fin) = recv.pop(&mut buf).unwrap();
        assert_eq!(len, 18);
        assert_eq!(fin, false);
        assert_eq!(&buf[..len], b"somhellogsomhellog");
        assert_eq!(recv.len, 18);
        assert_eq!(recv.off, 18);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.pop(&mut buf), Err(Error::Done));
    }

    #[test]
    fn overlapping_start_read() {
        let mut recv = RecvBuf::new(std::usize::MAX);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 8, true);

        assert!(recv.push(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.push(second).is_ok());
        assert_eq!(recv.len, 13);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        let (len, fin) = recv.pop(&mut buf).unwrap();
        assert_eq!(len, 13);
        assert_eq!(fin, true);
        assert_eq!(&buf[..len], b"somethingello");
        assert_eq!(recv.len, 13);
        assert_eq!(recv.off, 13);

        assert_eq!(recv.pop(&mut buf), Err(Error::Done));
    }

    #[test]
    fn overlapping_end_read() {
        let mut recv = RecvBuf::new(std::usize::MAX);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"hello", 0, false);
        let second = RangeBuf::from(b"something", 3, true);

        assert!(recv.push(second).is_ok());
        assert_eq!(recv.len, 12);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.push(first).is_ok());
        assert_eq!(recv.len, 12);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        let (len, fin) = recv.pop(&mut buf).unwrap();
        assert_eq!(len, 12);
        assert_eq!(fin, true);
        assert_eq!(&buf[..len], b"helsomething");
        assert_eq!(recv.len, 12);
        assert_eq!(recv.off, 12);

        assert_eq!(recv.pop(&mut buf), Err(Error::Done));
    }

    #[test]
    fn partially_multi_overlapping_reordered_read() {
        let mut recv = RecvBuf::new(std::usize::MAX);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"hello", 8, false);
        let second = RangeBuf::from(b"something", 0, false);
        let third = RangeBuf::from(b"moar", 11, true);

        assert!(recv.push(first).is_ok());
        assert_eq!(recv.len, 13);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.push(second).is_ok());
        assert_eq!(recv.len, 13);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        assert!(recv.push(third).is_ok());
        assert_eq!(recv.len, 15);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 3);

        let (len, fin) = recv.pop(&mut buf).unwrap();
        assert_eq!(len, 15);
        assert_eq!(fin, true);
        assert_eq!(&buf[..len], b"somethinhelloar");
        assert_eq!(recv.len, 15);
        assert_eq!(recv.off, 15);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.pop(&mut buf), Err(Error::Done));
    }

    #[test]
    fn partially_multi_overlapping_reordered_read2() {
        let mut recv = RecvBuf::new(std::usize::MAX);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"aaa", 0, false);
        let second = RangeBuf::from(b"bbb", 2, false);
        let third = RangeBuf::from(b"ccc", 4, false);
        let fourth = RangeBuf::from(b"ddd", 6, false);
        let fifth = RangeBuf::from(b"eee", 9, false);
        let sixth = RangeBuf::from(b"fff", 11, false);

        assert!(recv.push(second).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.push(fourth).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        assert!(recv.push(third).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 3);

        assert!(recv.push(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 4);

        assert!(recv.push(sixth).is_ok());
        assert_eq!(recv.len, 14);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 5);

        assert!(recv.push(fifth).is_ok());
        assert_eq!(recv.len, 14);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 6);

        let (len, fin) = recv.pop(&mut buf).unwrap();
        assert_eq!(len, 14);
        assert_eq!(fin, false);
        assert_eq!(&buf[..len], b"aabbbcdddeefff");
        assert_eq!(recv.len, 14);
        assert_eq!(recv.off, 14);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.pop(&mut buf), Err(Error::Done));
    }

    #[test]
    fn empty_write() {
        let mut send = SendBuf::new(std::usize::MAX);
        assert_eq!(send.len, 0);

        let write = send.pop(std::usize::MAX).unwrap();
        assert_eq!(write.len(), 0);
        assert_eq!(write.fin(), false);
    }

    #[test]
    fn multi_write() {
        let mut send = SendBuf::new(std::usize::MAX);
        assert_eq!(send.len, 0);

        let first = *b"something";
        let second = *b"helloworld";

        assert!(send.push_slice(&first, false).is_ok());
        assert_eq!(send.len, 9);

        assert!(send.push_slice(&second, true).is_ok());
        assert_eq!(send.len, 19);

        let write = send.pop(128).unwrap();
        assert_eq!(write.len(), 19);
        assert_eq!(write.fin(), true);
        assert_eq!(&write[..], b"somethinghelloworld");
        assert_eq!(send.len, 0);
    }

    #[test]
    fn split_write() {
        let mut send = SendBuf::new(std::usize::MAX);
        assert_eq!(send.len, 0);

        let first = *b"something";
        let second = *b"helloworld";

        assert!(send.push_slice(&first, false).is_ok());
        assert_eq!(send.len, 9);

        assert!(send.push_slice(&second, true).is_ok());
        assert_eq!(send.len, 19);

        let write = send.pop(10).unwrap();
        assert_eq!(write.off(), 0);
        assert_eq!(write.len(), 10);
        assert_eq!(write.fin(), false);
        assert_eq!(&write[..], b"somethingh");
        assert_eq!(send.len, 9);

        let write = send.pop(5).unwrap();
        assert_eq!(write.off(), 10);
        assert_eq!(write.len(), 5);
        assert_eq!(write.fin(), false);
        assert_eq!(&write[..], b"ellow");
        assert_eq!(send.len, 4);

        let write = send.pop(10).unwrap();
        assert_eq!(write.off(), 15);
        assert_eq!(write.len(), 4);
        assert_eq!(write.fin(), true);
        assert_eq!(&write[..], b"orld");
        assert_eq!(send.len, 0);
    }

    #[test]
    fn resend() {
        let mut send = SendBuf::new(std::usize::MAX);
        assert_eq!(send.len, 0);
        assert_eq!(send.off(), 0);

        let first = *b"something";
        let second = *b"helloworld";

        assert!(send.push_slice(&first, false).is_ok());
        assert_eq!(send.off(), 0);

        assert!(send.push_slice(&second, true).is_ok());
        assert_eq!(send.off(), 0);

        let write1 = send.pop(4).unwrap();
        assert_eq!(write1.off(), 0);
        assert_eq!(write1.len(), 4);
        assert_eq!(write1.fin(), false);
        assert_eq!(&write1[..], b"some");
        assert_eq!(send.len, 15);
        assert_eq!(send.off(), 4);

        let write2 = send.pop(5).unwrap();
        assert_eq!(write2.off(), 4);
        assert_eq!(write2.len(), 5);
        assert_eq!(write2.fin(), false);
        assert_eq!(&write2[..], b"thing");
        assert_eq!(send.len, 10);
        assert_eq!(send.off(), 9);

        let write3 = send.pop(5).unwrap();
        assert_eq!(write3.off(), 9);
        assert_eq!(write3.len(), 5);
        assert_eq!(write3.fin(), false);
        assert_eq!(&write3[..], b"hello");
        assert_eq!(send.len, 5);
        assert_eq!(send.off(), 14);

        send.push(write2).unwrap();
        assert_eq!(send.len, 10);
        assert_eq!(send.off(), 4);

        send.push(write1).unwrap();
        assert_eq!(send.len, 14);
        assert_eq!(send.off(), 0);

        let write4 = send.pop(11).unwrap();
        assert_eq!(write4.off(), 0);
        assert_eq!(write4.len(), 9);
        assert_eq!(write4.fin(), false);
        assert_eq!(&write4[..], b"something");
        assert_eq!(send.len, 5);
        assert_eq!(send.off(), 14);

        let write5 = send.pop(11).unwrap();
        assert_eq!(write5.off(), 14);
        assert_eq!(write5.len(), 5);
        assert_eq!(write5.fin(), true);
        assert_eq!(&write5[..], b"world");
        assert_eq!(send.len, 0);
        assert_eq!(send.off(), 19);
    }

    #[test]
    fn write_blocked_by_off() {
        let mut send = SendBuf::default();
        assert_eq!(send.len, 0);

        let first = *b"something";
        let second = *b"helloworld";

        assert!(send.push_slice(&first, false).is_ok());
        assert_eq!(send.len, 9);

        assert!(send.push_slice(&second, true).is_ok());
        assert_eq!(send.len, 19);

        send.update_max_data(5);

        let write = send.pop(10).unwrap();
        assert_eq!(write.off(), 0);
        assert_eq!(write.len(), 5);
        assert_eq!(write.fin(), false);
        assert_eq!(&write[..], b"somet");
        assert_eq!(send.len, 14);

        let write = send.pop(10).unwrap();
        assert_eq!(write.off(), 0);
        assert_eq!(write.len(), 0);
        assert_eq!(write.fin(), false);
        assert_eq!(&write[..], b"");
        assert_eq!(send.len, 14);

        send.update_max_data(15);

        let write = send.pop(10).unwrap();
        assert_eq!(write.off(), 5);
        assert_eq!(write.len(), 10);
        assert_eq!(write.fin(), false);
        assert_eq!(&write[..], b"hinghellow");
        assert_eq!(send.len, 4);

        send.update_max_data(25);

        let write = send.pop(10).unwrap();
        assert_eq!(write.off(), 15);
        assert_eq!(write.len(), 4);
        assert_eq!(write.fin(), true);
        assert_eq!(&write[..], b"orld");
        assert_eq!(send.len, 0);
    }

    #[test]
    fn zero_len_write() {
        let mut send = SendBuf::new(std::usize::MAX);
        assert_eq!(send.len, 0);

        let first = *b"something";

        assert!(send.push_slice(&first, false).is_ok());
        assert_eq!(send.len, 9);

        assert!(send.push_slice(&[], true).is_ok());
        assert_eq!(send.len, 9);

        let write = send.pop(10).unwrap();
        assert_eq!(write.off(), 0);
        assert_eq!(write.len(), 9);
        assert_eq!(write.fin(), true);
        assert_eq!(&write[..], b"something");
        assert_eq!(send.len, 0);
    }

    #[test]
    fn recv_flow_control() {
        let mut stream = Stream::new(15, 0);
        assert!(!stream.recv.more_credit());

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"hello", 0, false);
        let second = RangeBuf::from(b"world", 5, false);
        let third = RangeBuf::from(b"something", 10, false);

        assert_eq!(stream.recv.push(second), Ok(()));
        assert_eq!(stream.recv.push(first), Ok(()));
        assert!(!stream.recv.more_credit());

        assert_eq!(stream.recv.push(third), Err(Error::FlowControl));

        let (len, fin) = stream.recv.pop(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"helloworld");
        assert_eq!(fin, false);

        assert!(stream.recv.more_credit());

        assert_eq!(stream.recv.update_max_data(), 25);
        assert!(!stream.recv.more_credit());

        let third = RangeBuf::from(b"something", 10, false);
        assert_eq!(stream.recv.push(third), Ok(()));
    }

    #[test]
    fn recv_past_fin() {
        let mut stream = Stream::new(15, 0);
        assert!(!stream.recv.more_credit());

        let first = RangeBuf::from(b"hello", 0, true);
        let second = RangeBuf::from(b"world", 5, false);

        assert_eq!(stream.recv.push(first), Ok(()));
        assert_eq!(stream.recv.push(second), Err(Error::FinalSize));
    }

    #[test]
    fn recv_fin_dup() {
        let mut stream = Stream::new(15, 0);
        assert!(!stream.recv.more_credit());

        let first = RangeBuf::from(b"hello", 0, true);
        let second = RangeBuf::from(b"hello", 0, true);

        assert_eq!(stream.recv.push(first), Ok(()));
        assert_eq!(stream.recv.push(second), Ok(()));

        let mut buf = [0; 32];

        let (len, fin) = stream.recv.pop(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"hello");
        assert_eq!(fin, true);
    }

    #[test]
    fn recv_fin_change() {
        let mut stream = Stream::new(15, 0);
        assert!(!stream.recv.more_credit());

        let first = RangeBuf::from(b"hello", 0, true);
        let second = RangeBuf::from(b"world", 5, true);

        assert_eq!(stream.recv.push(second), Ok(()));
        assert_eq!(stream.recv.push(first), Err(Error::FinalSize));
    }

    #[test]
    fn recv_fin_lower_than_received() {
        let mut stream = Stream::new(15, 0);
        assert!(!stream.recv.more_credit());

        let first = RangeBuf::from(b"hello", 0, true);
        let second = RangeBuf::from(b"world", 5, false);

        assert_eq!(stream.recv.push(second), Ok(()));
        assert_eq!(stream.recv.push(first), Err(Error::FinalSize));
    }

    #[test]
    fn recv_fin_flow_control() {
        let mut stream = Stream::new(15, 0);
        assert!(!stream.recv.more_credit());

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"hello", 0, false);
        let second = RangeBuf::from(b"world", 5, true);

        assert_eq!(stream.recv.push(first), Ok(()));
        assert_eq!(stream.recv.push(second), Ok(()));

        let (len, fin) = stream.recv.pop(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"helloworld");
        assert_eq!(fin, true);

        assert!(!stream.recv.more_credit());
    }

    #[test]
    fn recv_fin_reset_mismatch() {
        let mut stream = Stream::new(15, 0);
        assert!(!stream.recv.more_credit());

        let first = RangeBuf::from(b"hello", 0, true);

        assert_eq!(stream.recv.push(first), Ok(()));
        assert_eq!(stream.recv.reset(10), Err(Error::FinalSize));
    }

    #[test]
    fn recv_reset_dup() {
        let mut stream = Stream::new(15, 0);
        assert!(!stream.recv.more_credit());

        let first = RangeBuf::from(b"hello", 0, false);

        assert_eq!(stream.recv.push(first), Ok(()));
        assert_eq!(stream.recv.reset(5), Ok(0));
        assert_eq!(stream.recv.reset(5), Ok(0));
    }

    #[test]
    fn recv_reset_change() {
        let mut stream = Stream::new(15, 0);
        assert!(!stream.recv.more_credit());

        let first = RangeBuf::from(b"hello", 0, false);

        assert_eq!(stream.recv.push(first), Ok(()));
        assert_eq!(stream.recv.reset(5), Ok(0));
        assert_eq!(stream.recv.reset(10), Err(Error::FinalSize));
    }

    #[test]
    fn recv_reset_lower_than_received() {
        let mut stream = Stream::new(15, 0);
        assert!(!stream.recv.more_credit());

        let first = RangeBuf::from(b"hello", 0, false);

        assert_eq!(stream.recv.push(first), Ok(()));
        assert_eq!(stream.recv.reset(4), Err(Error::FinalSize));
    }

    #[test]
    fn send_flow_control() {
        let mut stream = Stream::new(0, 15);

        let first = b"hello";
        let second = b"world";
        let third = b"something";

        assert_eq!(stream.send.push_slice(first, false), Ok(()));
        assert_eq!(stream.send.push_slice(second, false), Ok(()));
        assert_eq!(stream.send.push_slice(third, false), Ok(()));

        let write = stream.send.pop(25).unwrap();
        assert_eq!(write.off(), 0);
        assert_eq!(write.len(), 15);
        assert_eq!(write.fin(), false);
        assert_eq!(write.data, b"helloworldsomet");

        let write = stream.send.pop(25).unwrap();
        assert_eq!(write.off(), 0);
        assert_eq!(write.len(), 0);
        assert_eq!(write.fin(), false);
        assert_eq!(write.data, b"");

        let first = RangeBuf::from(b"helloworldsomet", 0, false);
        assert_eq!(stream.send.push(first), Ok(()));

        let write = stream.send.pop(10).unwrap();
        assert_eq!(write.off(), 0);
        assert_eq!(write.len(), 10);
        assert_eq!(write.fin(), false);
        assert_eq!(write.data, b"helloworld");

        let write = stream.send.pop(10).unwrap();
        assert_eq!(write.off(), 10);
        assert_eq!(write.len(), 5);
        assert_eq!(write.fin(), false);
        assert_eq!(write.data, b"somet");
    }
}
