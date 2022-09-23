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

use std::cmp;

use std::sync::Arc;

use std::collections::hash_map;

use std::collections::BTreeMap;
use std::collections::BinaryHeap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;

use std::time;

use crate::Error;
use crate::Result;

use crate::flowcontrol;
use crate::ranges;

const DEFAULT_URGENCY: u8 = 127;

#[cfg(test)]
const SEND_BUFFER_SIZE: usize = 5;

#[cfg(not(test))]
const SEND_BUFFER_SIZE: usize = 4096;

// The default size of the receiver stream flow control window.
const DEFAULT_STREAM_WINDOW: u64 = 32 * 1024;

/// The maximum size of the receiver stream flow control window.
pub const MAX_STREAM_WINDOW: u64 = 16 * 1024 * 1024;

/// A simple no-op hasher for Stream IDs.
///
/// The QUIC protocol and quiche library guarantees stream ID uniqueness, so
/// we can save effort by avoiding using a more complicated algorithm.
#[derive(Default)]
pub struct StreamIdHasher {
    id: u64,
}

impl std::hash::Hasher for StreamIdHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.id
    }

    #[inline]
    fn write_u64(&mut self, id: u64) {
        self.id = id;
    }

    #[inline]
    fn write(&mut self, _: &[u8]) {
        // We need a default write() for the trait but stream IDs will always
        // be a u64 so we just delegate to write_u64.
        unimplemented!()
    }
}

type BuildStreamIdHasher = std::hash::BuildHasherDefault<StreamIdHasher>;

pub type StreamIdHashMap<V> = HashMap<u64, V, BuildStreamIdHasher>;
pub type StreamIdHashSet = HashSet<u64, BuildStreamIdHasher>;

/// Keeps track of QUIC streams and enforces stream limits.
#[derive(Default)]
pub struct StreamMap {
    /// Map of streams indexed by stream ID.
    streams: StreamIdHashMap<Stream>,

    /// Set of streams that were completed and garbage collected.
    ///
    /// Instead of keeping the full stream state forever, we collect completed
    /// streams to save memory, but we still need to keep track of previously
    /// created streams, to prevent peers from re-creating them.
    collected: StreamIdHashSet,

    /// Peer's maximum bidirectional stream count limit.
    peer_max_streams_bidi: u64,

    /// Peer's maximum unidirectional stream count limit.
    peer_max_streams_uni: u64,

    /// The total number of bidirectional streams opened by the peer.
    peer_opened_streams_bidi: u64,

    /// The total number of unidirectional streams opened by the peer.
    peer_opened_streams_uni: u64,

    /// Local maximum bidirectional stream count limit.
    local_max_streams_bidi: u64,
    local_max_streams_bidi_next: u64,

    /// Local maximum unidirectional stream count limit.
    local_max_streams_uni: u64,
    local_max_streams_uni_next: u64,

    /// The total number of bidirectional streams opened by the local endpoint.
    local_opened_streams_bidi: u64,

    /// The total number of unidirectional streams opened by the local endpoint.
    local_opened_streams_uni: u64,

    /// Queue of stream IDs corresponding to streams that have buffered data
    /// ready to be sent to the peer. This also implies that the stream has
    /// enough flow control credits to send at least some of that data.
    ///
    /// Streams are grouped by their priority, where each urgency level has two
    /// queues, one for non-incremental streams and one for incremental ones.
    ///
    /// Streams with lower urgency level are scheduled first, and within the
    /// same urgency level Non-incremental streams are scheduled first, in the
    /// order of their stream IDs, and incremental streams are scheduled in a
    /// round-robin fashion after all non-incremental streams have been flushed.
    flushable: BTreeMap<u8, (BinaryHeap<std::cmp::Reverse<u64>>, VecDeque<u64>)>,

    /// Set of stream IDs corresponding to streams that have outstanding data
    /// to read. This is used to generate a `StreamIter` of streams without
    /// having to iterate over the full list of streams.
    readable: StreamIdHashSet,

    /// Set of stream IDs corresponding to streams that have enough flow control
    /// capacity to be written to, and is not finished. This is used to generate
    /// a `StreamIter` of streams without having to iterate over the full list
    /// of streams.
    writable: StreamIdHashSet,

    /// Set of stream IDs corresponding to streams that are almost out of flow
    /// control credit and need to send MAX_STREAM_DATA. This is used to
    /// generate a `StreamIter` of streams without having to iterate over the
    /// full list of streams.
    almost_full: StreamIdHashSet,

    /// Set of stream IDs corresponding to streams that are blocked. The value
    /// of the map elements represents the offset of the stream at which the
    /// blocking occurred.
    blocked: StreamIdHashMap<u64>,

    /// Set of stream IDs corresponding to streams that are reset. The value
    /// of the map elements is a tuple of the error code and final size values
    /// to include in the RESET_STREAM frame.
    reset: StreamIdHashMap<(u64, u64)>,

    /// Set of stream IDs corresponding to streams that are shutdown on the
    /// receive side, and need to send a STOP_SENDING frame. The value of the
    /// map elements is the error code to include in the STOP_SENDING frame.
    stopped: StreamIdHashMap<u64>,

    /// The maximum size of a stream window.
    max_stream_window: u64,
}

impl StreamMap {
    pub fn new(
        max_streams_bidi: u64, max_streams_uni: u64, max_stream_window: u64,
    ) -> StreamMap {
        StreamMap {
            local_max_streams_bidi: max_streams_bidi,
            local_max_streams_bidi_next: max_streams_bidi,

            local_max_streams_uni: max_streams_uni,
            local_max_streams_uni_next: max_streams_uni,

            max_stream_window,

            ..StreamMap::default()
        }
    }

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
                // Stream has already been closed and garbage collected.
                if self.collected.contains(&id) {
                    return Err(Error::Done);
                }

                if local != is_local(id, is_server) {
                    return Err(Error::InvalidStreamState(id));
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

                // The two least significant bits from a stream id identify the
                // type of stream. Truncate those bits to get the sequence for
                // that stream type.
                let stream_sequence = id >> 2;

                // Enforce stream count limits.
                match (is_local(id, is_server), is_bidi(id)) {
                    (true, true) => {
                        let n = std::cmp::max(
                            self.local_opened_streams_bidi,
                            stream_sequence + 1,
                        );

                        if n > self.peer_max_streams_bidi {
                            return Err(Error::StreamLimit);
                        }

                        self.local_opened_streams_bidi = n;
                    },

                    (true, false) => {
                        let n = std::cmp::max(
                            self.local_opened_streams_uni,
                            stream_sequence + 1,
                        );

                        if n > self.peer_max_streams_uni {
                            return Err(Error::StreamLimit);
                        }

                        self.local_opened_streams_uni = n;
                    },

                    (false, true) => {
                        let n = std::cmp::max(
                            self.peer_opened_streams_bidi,
                            stream_sequence + 1,
                        );

                        if n > self.local_max_streams_bidi {
                            return Err(Error::StreamLimit);
                        }

                        self.peer_opened_streams_bidi = n;
                    },

                    (false, false) => {
                        let n = std::cmp::max(
                            self.peer_opened_streams_uni,
                            stream_sequence + 1,
                        );

                        if n > self.local_max_streams_uni {
                            return Err(Error::StreamLimit);
                        }

                        self.peer_opened_streams_uni = n;
                    },
                };

                let s = Stream::new(
                    max_rx_data,
                    max_tx_data,
                    is_bidi(id),
                    local,
                    self.max_stream_window,
                );
                v.insert(s)
            },

            hash_map::Entry::Occupied(v) => v.into_mut(),
        };

        // Stream might already be writable due to initial flow control limits.
        if stream.is_writable() {
            self.writable.insert(id);
        }

        Ok(stream)
    }

    /// Pushes the stream ID to the back of the flushable streams queue with
    /// the specified urgency.
    ///
    /// Note that the caller is responsible for checking that the specified
    /// stream ID was not in the queue already before calling this.
    ///
    /// Queueing a stream multiple times simultaneously means that it might be
    /// unfairly scheduled more often than other streams, and might also cause
    /// spurious cycles through the queue, so it should be avoided.
    pub fn push_flushable(&mut self, stream_id: u64, urgency: u8, incr: bool) {
        // Push the element to the back of the queue corresponding to the given
        // urgency. If the queue doesn't exist yet, create it first.
        let queues = self
            .flushable
            .entry(urgency)
            .or_insert_with(|| (BinaryHeap::new(), VecDeque::new()));

        if !incr {
            // Non-incremental streams are scheduled in order of their stream ID.
            queues.0.push(std::cmp::Reverse(stream_id))
        } else {
            // Incremental streams are scheduled in a round-robin fashion.
            queues.1.push_back(stream_id)
        };
    }

    /// Removes and returns the first stream ID from the flushable streams
    /// queue with the specified urgency.
    ///
    /// Note that if the stream is still flushable after sending some of its
    /// outstanding data, it needs to be added back to the queue.
    pub fn pop_flushable(&mut self) -> Option<u64> {
        // Remove the first element from the queue corresponding to the lowest
        // urgency that has elements.
        let (node, clear) =
            if let Some((urgency, queues)) = self.flushable.iter_mut().next() {
                let node = if !queues.0.is_empty() {
                    queues.0.pop().map(|x| x.0)
                } else {
                    queues.1.pop_front()
                };

                let clear = if queues.0.is_empty() && queues.1.is_empty() {
                    Some(*urgency)
                } else {
                    None
                };

                (node, clear)
            } else {
                (None, None)
            };

        // Remove the queue from the list of queues if it is now empty, so that
        // the next time `pop_flushable()` is called the next queue with elements
        // is used.
        if let Some(urgency) = &clear {
            self.flushable.remove(urgency);
        }

        node
    }

    /// Adds or removes the stream ID to/from the readable streams set.
    ///
    /// If the stream was already in the list, this does nothing.
    pub fn mark_readable(&mut self, stream_id: u64, readable: bool) {
        if readable {
            self.readable.insert(stream_id);
        } else {
            self.readable.remove(&stream_id);
        }
    }

    /// Adds or removes the stream ID to/from the writable streams set.
    ///
    /// This should also be called anytime a new stream is created, in addition
    /// to when an existing stream becomes writable (or stops being writable).
    ///
    /// If the stream was already in the list, this does nothing.
    pub fn mark_writable(&mut self, stream_id: u64, writable: bool) {
        if writable {
            self.writable.insert(stream_id);
        } else {
            self.writable.remove(&stream_id);
        }
    }

    /// Adds or removes the stream ID to/from the almost full streams set.
    ///
    /// If the stream was already in the list, this does nothing.
    pub fn mark_almost_full(&mut self, stream_id: u64, almost_full: bool) {
        if almost_full {
            self.almost_full.insert(stream_id);
        } else {
            self.almost_full.remove(&stream_id);
        }
    }

    /// Adds or removes the stream ID to/from the blocked streams set with the
    /// given offset value.
    ///
    /// If the stream was already in the list, this does nothing.
    pub fn mark_blocked(&mut self, stream_id: u64, blocked: bool, off: u64) {
        if blocked {
            self.blocked.insert(stream_id, off);
        } else {
            self.blocked.remove(&stream_id);
        }
    }

    /// Adds or removes the stream ID to/from the reset streams set with the
    /// given error code and final size values.
    ///
    /// If the stream was already in the list, this does nothing.
    pub fn mark_reset(
        &mut self, stream_id: u64, reset: bool, error_code: u64, final_size: u64,
    ) {
        if reset {
            self.reset.insert(stream_id, (error_code, final_size));
        } else {
            self.reset.remove(&stream_id);
        }
    }

    /// Adds or removes the stream ID to/from the stopped streams set with the
    /// given error code.
    ///
    /// If the stream was already in the list, this does nothing.
    pub fn mark_stopped(
        &mut self, stream_id: u64, stopped: bool, error_code: u64,
    ) {
        if stopped {
            self.stopped.insert(stream_id, error_code);
        } else {
            self.stopped.remove(&stream_id);
        }
    }

    /// Updates the peer's maximum bidirectional stream count limit.
    pub fn update_peer_max_streams_bidi(&mut self, v: u64) {
        self.peer_max_streams_bidi = cmp::max(self.peer_max_streams_bidi, v);
    }

    /// Updates the peer's maximum unidirectional stream count limit.
    pub fn update_peer_max_streams_uni(&mut self, v: u64) {
        self.peer_max_streams_uni = cmp::max(self.peer_max_streams_uni, v);
    }

    /// Commits the new max_streams_bidi limit.
    pub fn update_max_streams_bidi(&mut self) {
        self.local_max_streams_bidi = self.local_max_streams_bidi_next;
    }

    /// Returns the current max_streams_bidi limit.
    pub fn max_streams_bidi(&self) -> u64 {
        self.local_max_streams_bidi
    }

    /// Returns the new max_streams_bidi limit.
    pub fn max_streams_bidi_next(&mut self) -> u64 {
        self.local_max_streams_bidi_next
    }

    /// Commits the new max_streams_uni limit.
    pub fn update_max_streams_uni(&mut self) {
        self.local_max_streams_uni = self.local_max_streams_uni_next;
    }

    /// Returns the new max_streams_uni limit.
    pub fn max_streams_uni_next(&mut self) -> u64 {
        self.local_max_streams_uni_next
    }

    /// Returns the number of bidirectional streams that can be created
    /// before the peer's stream count limit is reached.
    pub fn peer_streams_left_bidi(&self) -> u64 {
        self.peer_max_streams_bidi - self.local_opened_streams_bidi
    }

    /// Returns the number of unidirectional streams that can be created
    /// before the peer's stream count limit is reached.
    pub fn peer_streams_left_uni(&self) -> u64 {
        self.peer_max_streams_uni - self.local_opened_streams_uni
    }

    /// Drops completed stream.
    ///
    /// This should only be called when Stream::is_complete() returns true for
    /// the given stream.
    pub fn collect(&mut self, stream_id: u64, local: bool) {
        if !local {
            // If the stream was created by the peer, give back a max streams
            // credit.
            if is_bidi(stream_id) {
                self.local_max_streams_bidi_next =
                    self.local_max_streams_bidi_next.saturating_add(1);
            } else {
                self.local_max_streams_uni_next =
                    self.local_max_streams_uni_next.saturating_add(1);
            }
        }

        self.streams.remove(&stream_id);
        self.collected.insert(stream_id);
    }

    /// Creates an iterator over streams that have outstanding data to read.
    pub fn readable(&self) -> StreamIter {
        StreamIter::from(&self.readable)
    }

    /// Creates an iterator over streams that can be written to.
    pub fn writable(&self) -> StreamIter {
        StreamIter::from(&self.writable)
    }

    /// Creates an iterator over streams that need to send MAX_STREAM_DATA.
    pub fn almost_full(&self) -> StreamIter {
        StreamIter::from(&self.almost_full)
    }

    /// Creates an iterator over streams that need to send STREAM_DATA_BLOCKED.
    pub fn blocked(&self) -> hash_map::Iter<u64, u64> {
        self.blocked.iter()
    }

    /// Creates an iterator over streams that need to send RESET_STREAM.
    pub fn reset(&self) -> hash_map::Iter<u64, (u64, u64)> {
        self.reset.iter()
    }

    /// Creates an iterator over streams that need to send STOP_SENDING.
    pub fn stopped(&self) -> hash_map::Iter<u64, u64> {
        self.stopped.iter()
    }

    /// Returns true if the stream has been collected.
    pub fn is_collected(&self, stream_id: u64) -> bool {
        self.collected.contains(&stream_id)
    }

    /// Returns true if there are any streams that have data to write.
    pub fn has_flushable(&self) -> bool {
        !self.flushable.is_empty()
    }

    /// Returns true if there are any streams that have data to read.
    pub fn has_readable(&self) -> bool {
        !self.readable.is_empty()
    }

    /// Returns true if there are any streams that need to update the local
    /// flow control limit.
    pub fn has_almost_full(&self) -> bool {
        !self.almost_full.is_empty()
    }

    /// Returns true if there are any streams that are blocked.
    pub fn has_blocked(&self) -> bool {
        !self.blocked.is_empty()
    }

    /// Returns true if there are any streams that are reset.
    pub fn has_reset(&self) -> bool {
        !self.reset.is_empty()
    }

    /// Returns true if there are any streams that need to send STOP_SENDING.
    pub fn has_stopped(&self) -> bool {
        !self.stopped.is_empty()
    }

    /// Returns true if the max bidirectional streams count needs to be updated
    /// by sending a MAX_STREAMS frame to the peer.
    pub fn should_update_max_streams_bidi(&self) -> bool {
        self.local_max_streams_bidi_next != self.local_max_streams_bidi &&
            self.local_max_streams_bidi_next / 2 >
                self.local_max_streams_bidi - self.peer_opened_streams_bidi
    }

    /// Returns true if the max unidirectional streams count needs to be updated
    /// by sending a MAX_STREAMS frame to the peer.
    pub fn should_update_max_streams_uni(&self) -> bool {
        self.local_max_streams_uni_next != self.local_max_streams_uni &&
            self.local_max_streams_uni_next / 2 >
                self.local_max_streams_uni - self.peer_opened_streams_uni
    }

    /// Returns the number of active streams in the map.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.streams.len()
    }
}

/// A QUIC stream.
#[derive(Default)]
pub struct Stream {
    /// Receive-side stream buffer.
    pub recv: RecvBuf,

    /// Send-side stream buffer.
    pub send: SendBuf,

    /// Whether the stream is bidirectional.
    pub bidi: bool,

    /// Whether the stream was created by the local endpoint.
    pub local: bool,

    /// Application data.
    pub data: Option<Box<dyn std::any::Any + Send + Sync>>,

    /// The stream's urgency (lower is better). Default is `DEFAULT_URGENCY`.
    pub urgency: u8,

    /// Whether the stream can be flushed incrementally. Default is `true`.
    pub incremental: bool,
}

impl Stream {
    /// Creates a new stream with the given flow control limits.
    pub fn new(
        max_rx_data: u64, max_tx_data: u64, bidi: bool, local: bool,
        max_window: u64,
    ) -> Stream {
        Stream {
            recv: RecvBuf::new(max_rx_data, max_window),
            send: SendBuf::new(max_tx_data),
            bidi,
            local,
            data: None,
            urgency: DEFAULT_URGENCY,
            incremental: true,
        }
    }

    /// Returns true if the stream has data to read.
    pub fn is_readable(&self) -> bool {
        self.recv.ready()
    }

    /// Returns true if the stream has enough flow control capacity to be
    /// written to, and is not finished.
    pub fn is_writable(&self) -> bool {
        !self.send.shutdown &&
            !self.send.is_fin() &&
            self.send.off < self.send.max_data
    }

    /// Returns true if the stream has data to send and is allowed to send at
    /// least some of it.
    pub fn is_flushable(&self) -> bool {
        self.send.ready() && self.send.off_front() < self.send.max_data
    }

    /// Returns true if the stream is complete.
    ///
    /// For bidirectional streams this happens when both the receive and send
    /// sides are complete. That is when all incoming data has been read by the
    /// application, and when all outgoing data has been acked by the peer.
    ///
    /// For unidirectional streams this happens when either the receive or send
    /// side is complete, depending on whether the stream was created locally
    /// or not.
    pub fn is_complete(&self) -> bool {
        match (self.bidi, self.local) {
            // For bidirectional streams we need to check both receive and send
            // sides for completion.
            (true, _) => self.recv.is_fin() && self.send.is_complete(),

            // For unidirectional streams generated locally, we only need to
            // check the send side for completion.
            (false, true) => self.send.is_complete(),

            // For unidirectional streams generated by the peer, we only need
            // to check the receive side for completion.
            (false, false) => self.recv.is_fin(),
        }
    }

    /// Returns true if the stream is not storing incoming data.
    pub fn is_draining(&self) -> bool {
        self.recv.drain
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

/// An iterator over QUIC streams.
#[derive(Default)]
pub struct StreamIter {
    streams: VecDeque<u64>,
}

impl StreamIter {
    #[inline]
    fn from(streams: &StreamIdHashSet) -> Self {
        StreamIter {
            streams: streams.iter().copied().collect(),
        }
    }
}

impl Iterator for StreamIter {
    type Item = u64;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.streams.pop_front()
    }
}

impl ExactSizeIterator for StreamIter {
    #[inline]
    fn len(&self) -> usize {
        self.streams.len()
    }
}

/// Receive-side stream buffer.
///
/// Stream data received by the peer is buffered in a list of data chunks
/// ordered by offset in ascending order. Contiguous data can then be read
/// into a slice.
#[derive(Debug, Default)]
pub struct RecvBuf {
    /// Chunks of data received from the peer that have not yet been read by
    /// the application, ordered by offset.
    data: BinaryHeap<RangeBuf>,

    /// The lowest data offset that has yet to be read by the application.
    off: u64,

    /// The total length of data received on this stream.
    len: u64,

    /// Receiver flow controller.
    flow_control: flowcontrol::FlowControl,

    /// The final stream offset received from the peer, if any.
    fin_off: Option<u64>,

    /// The error code received via RESET_STREAM.
    error: Option<u64>,

    /// Whether incoming data is validated but not buffered.
    drain: bool,
}

impl RecvBuf {
    /// Creates a new receive buffer.
    fn new(max_data: u64, max_window: u64) -> RecvBuf {
        RecvBuf {
            flow_control: flowcontrol::FlowControl::new(
                max_data,
                cmp::min(max_data, DEFAULT_STREAM_WINDOW),
                max_window,
            ),
            ..RecvBuf::default()
        }
    }

    /// Inserts the given chunk of data in the buffer.
    ///
    /// This also takes care of enforcing stream flow control limits, as well
    /// as handling incoming data that overlaps data that is already in the
    /// buffer.
    pub fn write(&mut self, buf: RangeBuf) -> Result<()> {
        if buf.max_off() > self.max_data() {
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

        // No need to process an empty buffer with the fin flag, if we already
        // know the final size.
        if buf.fin() && buf.is_empty() && self.fin_off.is_some() {
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

        let mut tmp_bufs = VecDeque::with_capacity(2);
        tmp_bufs.push_back(buf);

        'tmp: while let Some(mut buf) = tmp_bufs.pop_front() {
            // Discard incoming data below current stream offset. Bytes up to
            // `self.off` have already been received so we should not buffer
            // them again. This is also important to make sure `ready()` doesn't
            // get stuck when a buffer with lower offset than the stream's is
            // buffered.
            if self.off_front() > buf.off() {
                buf = buf.split_off((self.off_front() - buf.off()) as usize);
            }

            // Handle overlapping data. If the incoming data's starting offset
            // is above the previous maximum received offset, there is clearly
            // no overlap so this logic can be skipped. However do still try to
            // merge an empty final buffer (i.e. an empty buffer with the fin
            // flag set, which is the only kind of empty buffer that should
            // reach this point).
            if buf.off() < self.max_off() || buf.is_empty() {
                for b in &self.data {
                    // New buffer is fully contained in existing buffer.
                    if buf.off() >= b.off() && buf.max_off() <= b.max_off() {
                        continue 'tmp;
                    }

                    // New buffer's start overlaps existing buffer.
                    if buf.off() >= b.off() && buf.off() < b.max_off() {
                        buf = buf.split_off((b.max_off() - buf.off()) as usize);
                    }

                    // New buffer's end overlaps existing buffer.
                    if buf.off() < b.off() && buf.max_off() > b.off() {
                        tmp_bufs.push_back(
                            buf.split_off((b.off() - buf.off()) as usize),
                        );
                    }
                }
            }

            self.len = cmp::max(self.len, buf.max_off());

            if !self.drain {
                self.data.push(buf);
            }
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
    pub fn emit(&mut self, out: &mut [u8]) -> Result<(usize, bool)> {
        let mut len = 0;
        let mut cap = out.len();

        if !self.ready() {
            return Err(Error::Done);
        }

        // The stream was reset, so return the error code instead.
        if let Some(e) = self.error {
            return Err(Error::StreamReset(e));
        }

        while cap > 0 && self.ready() {
            let mut buf = match self.data.peek_mut() {
                Some(v) => v,

                None => break,
            };

            let buf_len = cmp::min(buf.len(), cap);

            out[len..len + buf_len].copy_from_slice(&buf[..buf_len]);

            self.off += buf_len as u64;

            len += buf_len;
            cap -= buf_len;

            if buf_len < buf.len() {
                buf.consume(buf_len);

                // We reached the maximum capacity, so end here.
                break;
            }

            std::collections::binary_heap::PeekMut::pop(buf);
        }

        // Update consumed bytes for flow control.
        self.flow_control.add_consumed(len as u64);

        Ok((len, self.is_fin()))
    }

    /// Resets the stream at the given offset.
    pub fn reset(&mut self, error_code: u64, final_size: u64) -> Result<usize> {
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

        // Calculate how many bytes need to be removed from the connection flow
        // control.
        let max_data_delta = final_size - self.len;

        if self.error.is_some() {
            return Ok(max_data_delta as usize);
        }

        self.error = Some(error_code);

        // Clear all data already buffered.
        self.off = final_size;

        self.data.clear();

        // In order to ensure the application is notified when the stream is
        // reset, enqueue a zero-length buffer at the final size offset.
        let buf = RangeBuf::from(b"", final_size, true);
        self.write(buf)?;

        Ok(max_data_delta as usize)
    }

    /// Commits the new max_data limit.
    pub fn update_max_data(&mut self, now: time::Instant) {
        self.flow_control.update_max_data(now);
    }

    /// Return the new max_data limit.
    pub fn max_data_next(&mut self) -> u64 {
        self.flow_control.max_data_next()
    }

    /// Return the current flow control limit.
    fn max_data(&self) -> u64 {
        self.flow_control.max_data()
    }

    /// Return the current window.
    pub fn window(&self) -> u64 {
        self.flow_control.window()
    }

    /// Autotune the window size.
    pub fn autotune_window(&mut self, now: time::Instant, rtt: time::Duration) {
        self.flow_control.autotune_window(now, rtt);
    }

    /// Shuts down receiving data.
    pub fn shutdown(&mut self) -> Result<()> {
        if self.drain {
            return Err(Error::Done);
        }

        self.drain = true;

        self.data.clear();

        self.off = self.max_off();

        Ok(())
    }

    /// Returns the lowest offset of data buffered.
    pub fn off_front(&self) -> u64 {
        self.off
    }

    /// Returns true if we need to update the local flow control limit.
    pub fn almost_full(&self) -> bool {
        self.fin_off.is_none() && self.flow_control.should_update_max_data()
    }

    /// Returns the largest offset ever received.
    pub fn max_off(&self) -> u64 {
        self.len
    }

    /// Returns true if the receive-side of the stream is complete.
    ///
    /// This happens when the stream's receive final size is known, and the
    /// application has read all data from the stream.
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

        buf.off() == self.off
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
#[derive(Debug, Default)]
pub struct SendBuf {
    /// Chunks of data to be sent, ordered by offset.
    data: VecDeque<RangeBuf>,

    /// The index of the buffer that needs to be sent next.
    pos: usize,

    /// The maximum offset of data buffered in the stream.
    off: u64,

    /// The amount of data currently buffered.
    len: u64,

    /// The maximum offset we are allowed to send to the peer.
    max_data: u64,

    /// The last offset the stream was blocked at, if any.
    blocked_at: Option<u64>,

    /// The final stream offset written to the stream, if any.
    fin_off: Option<u64>,

    /// Whether the stream's send-side has been shut down.
    shutdown: bool,

    /// Ranges of data offsets that have been acked.
    acked: ranges::RangeSet,

    /// The error code received via STOP_SENDING.
    error: Option<u64>,
}

impl SendBuf {
    /// Creates a new send buffer.
    fn new(max_data: u64) -> SendBuf {
        SendBuf {
            max_data,
            ..SendBuf::default()
        }
    }

    /// Inserts the given slice of data at the end of the buffer.
    ///
    /// The number of bytes that were actually stored in the buffer is returned
    /// (this may be lower than the size of the input buffer, in case of partial
    /// writes).
    pub fn write(&mut self, mut data: &[u8], mut fin: bool) -> Result<usize> {
        let max_off = self.off + data.len() as u64;

        // Get the stream send capacity. This will return an error if the stream
        // was stopped.
        let capacity = self.cap()?;

        if data.len() > capacity {
            // Truncate the input buffer according to the stream's capacity.
            let len = capacity;
            data = &data[..len];

            // We are not buffering the full input, so clear the fin flag.
            fin = false;
        }

        if let Some(fin_off) = self.fin_off {
            // Can't write past final offset.
            if max_off > fin_off {
                return Err(Error::FinalSize);
            }

            // Can't "undo" final offset.
            if max_off == fin_off && !fin {
                return Err(Error::FinalSize);
            }
        }

        if fin {
            self.fin_off = Some(max_off);
        }

        // Don't queue data that was already fully acked.
        if self.ack_off() >= max_off {
            return Ok(data.len());
        }

        // We already recorded the final offset, so we can just discard the
        // empty buffer now.
        if data.is_empty() {
            return Ok(data.len());
        }

        let mut len = 0;

        // Split the remaining input data into consistently-sized buffers to
        // avoid fragmentation.
        for chunk in data.chunks(SEND_BUFFER_SIZE) {
            len += chunk.len();

            let fin = len == data.len() && fin;

            let buf = RangeBuf::from(chunk, self.off, fin);

            // The new data can simply be appended at the end of the send buffer.
            self.data.push_back(buf);

            self.off += chunk.len() as u64;
            self.len += chunk.len() as u64;
        }

        Ok(len)
    }

    /// Writes data from the send buffer into the given output buffer.
    pub fn emit(&mut self, out: &mut [u8]) -> Result<(usize, bool)> {
        let mut out_len = out.len();
        let out_off = self.off_front();

        let mut next_off = out_off;

        while out_len > 0 &&
            self.ready() &&
            self.off_front() == next_off &&
            self.off_front() < self.max_data
        {
            let buf = match self.data.get_mut(self.pos) {
                Some(v) => v,

                None => break,
            };

            if buf.is_empty() {
                self.pos += 1;
                continue;
            }

            let buf_len = cmp::min(buf.len(), out_len);
            let partial = buf_len < buf.len();

            // Copy data to the output buffer.
            let out_pos = (next_off - out_off) as usize;
            out[out_pos..out_pos + buf_len].copy_from_slice(&buf[..buf_len]);

            self.len -= buf_len as u64;

            out_len -= buf_len;

            next_off = buf.off() + buf_len as u64;

            buf.consume(buf_len);

            if partial {
                // We reached the maximum capacity, so end here.
                break;
            }

            self.pos += 1;
        }

        // Override the `fin` flag set for the output buffer by matching the
        // buffer's maximum offset against the stream's final offset (if known).
        //
        // This is more efficient than tracking `fin` using the range buffers
        // themselves, and lets us avoid queueing empty buffers just so we can
        // propagate the final size.
        let fin = self.fin_off == Some(next_off);

        Ok((out.len() - out_len, fin))
    }

    /// Updates the max_data limit to the given value.
    pub fn update_max_data(&mut self, max_data: u64) {
        self.max_data = cmp::max(self.max_data, max_data);
    }

    /// Updates the last offset the stream was blocked at, if any.
    pub fn update_blocked_at(&mut self, blocked_at: Option<u64>) {
        self.blocked_at = blocked_at;
    }

    /// The last offset the stream was blocked at, if any.
    pub fn blocked_at(&self) -> Option<u64> {
        self.blocked_at
    }

    /// Increments the acked data offset.
    pub fn ack(&mut self, off: u64, len: usize) {
        self.acked.insert(off..off + len as u64);
    }

    pub fn ack_and_drop(&mut self, off: u64, len: usize) {
        self.ack(off, len);

        let ack_off = self.ack_off();

        if self.data.is_empty() {
            return;
        }

        if off > ack_off {
            return;
        }

        let mut drop_until = None;

        // Drop contiguously acked data from the front of the buffer.
        for (i, buf) in self.data.iter_mut().enumerate() {
            // Newly acked range is past highest contiguous acked range, so we
            // can't drop it.
            if buf.off >= ack_off {
                break;
            }

            // Highest contiguous acked range falls within newly acked range,
            // so we can't drop it.
            if buf.off < ack_off && ack_off < buf.max_off() {
                break;
            }

            // Newly acked range can be dropped.
            drop_until = Some(i);
        }

        if let Some(drop) = drop_until {
            self.data.drain(..=drop);

            // When a buffer is marked for retransmission, but then acked before
            // it could be retransmitted, we might end up decreasing the SendBuf
            // position too much, so make sure that doesn't happen.
            self.pos = self.pos.saturating_sub(drop + 1);
        }
    }

    pub fn retransmit(&mut self, off: u64, len: usize) {
        let max_off = off + len as u64;
        let ack_off = self.ack_off();

        if self.data.is_empty() {
            return;
        }

        if max_off <= ack_off {
            return;
        }

        for i in 0..self.data.len() {
            let buf = &mut self.data[i];

            if buf.off >= max_off {
                break;
            }

            if off > buf.max_off() {
                continue;
            }

            // Split the buffer into 2 if the retransmit range ends before the
            // buffer's final offset.
            let new_buf = if buf.off < max_off && max_off < buf.max_off() {
                Some(buf.split_off((max_off - buf.off as u64) as usize))
            } else {
                None
            };

            let prev_pos = buf.pos;

            // Reduce the buffer's position (expand the buffer) if the retransmit
            // range is past the buffer's starting offset.
            buf.pos = if off > buf.off && off <= buf.max_off() {
                cmp::min(buf.pos, buf.start + (off - buf.off) as usize)
            } else {
                buf.start
            };

            self.pos = cmp::min(self.pos, i);

            self.len += (prev_pos - buf.pos) as u64;

            if let Some(b) = new_buf {
                self.data.insert(i + 1, b);
            }
        }
    }

    /// Resets the stream at the current offset and clears all buffered data.
    pub fn reset(&mut self) -> Result<(u64, u64)> {
        let unsent_off = self.off_front();
        let unsent_len = self.off_back() - unsent_off;

        self.fin_off = Some(unsent_off);

        // Drop all buffered data.
        self.data.clear();

        // Mark all data as acked.
        self.ack(0, self.off as usize);

        self.pos = 0;
        self.len = 0;
        self.off = unsent_off;

        Ok((self.fin_off.unwrap(), unsent_len))
    }

    /// Resets the streams and records the received error code.
    ///
    /// Calling this again after the first time has no effect.
    pub fn stop(&mut self, error_code: u64) -> Result<(u64, u64)> {
        if self.error.is_some() {
            return Err(Error::Done);
        }

        let (fin_off, unsent) = self.reset()?;

        self.error = Some(error_code);

        Ok((fin_off, unsent))
    }

    /// Shuts down sending data.
    pub fn shutdown(&mut self) -> Result<(u64, u64)> {
        if self.shutdown {
            return Err(Error::Done);
        }

        self.shutdown = true;

        self.reset()
    }

    /// Returns the largest offset of data buffered.
    pub fn off_back(&self) -> u64 {
        self.off
    }

    /// Returns the lowest offset of data buffered.
    pub fn off_front(&self) -> u64 {
        let mut pos = self.pos;

        // Skip empty buffers from the start of the queue.
        while let Some(b) = self.data.get(pos) {
            if !b.is_empty() {
                return b.off();
            }

            pos += 1;
        }

        self.off
    }

    /// The maximum offset we are allowed to send to the peer.
    pub fn max_off(&self) -> u64 {
        self.max_data
    }

    /// Returns true if all data in the stream has been sent.
    ///
    /// This happens when the stream's send final size is known, and the
    /// application has already written data up to that point.
    pub fn is_fin(&self) -> bool {
        if self.fin_off == Some(self.off) {
            return true;
        }

        false
    }

    /// Returns true if the send-side of the stream is complete.
    ///
    /// This happens when the stream's send final size is known, and the peer
    /// has already acked all stream data up to that point.
    pub fn is_complete(&self) -> bool {
        if let Some(fin_off) = self.fin_off {
            if self.acked == (0..fin_off) {
                return true;
            }
        }

        false
    }

    /// Returns true if the stream was stopped before completion.
    pub fn is_stopped(&self) -> bool {
        self.error.is_some()
    }

    /// Returns true if there is data to be written.
    fn ready(&self) -> bool {
        !self.data.is_empty() && self.off_front() < self.off
    }

    /// Returns the highest contiguously acked offset.
    fn ack_off(&self) -> u64 {
        match self.acked.iter().next() {
            // Only consider the initial range if it contiguously covers the
            // start of the stream (i.e. from offset 0).
            Some(std::ops::Range { start: 0, end }) => end,

            Some(_) | None => 0,
        }
    }

    /// Returns the outgoing flow control capacity.
    pub fn cap(&self) -> Result<usize> {
        // The stream was stopped, so return the error code instead.
        if let Some(e) = self.error {
            return Err(Error::StreamStopped(e));
        }

        Ok((self.max_data - self.off) as usize)
    }
}

/// Buffer holding data at a specific offset.
///
/// The data is stored in a `Vec<u8>` in such a way that it can be shared
/// between multiple `RangeBuf` objects.
///
/// Each `RangeBuf` will have its own view of that buffer, where the `start`
/// value indicates the initial offset within the `Vec`, and `len` indicates the
/// number of bytes, starting from `start` that are included.
///
/// In addition, `pos` indicates the current offset within the `Vec`, starting
/// from the very beginning of the `Vec`.
///
/// Finally, `off` is the starting offset for the specific `RangeBuf` within the
/// stream the buffer belongs to.
#[derive(Clone, Debug, Default, Eq)]
pub struct RangeBuf {
    /// The internal buffer holding the data.
    ///
    /// To avoid needless allocations when a RangeBuf is split, this field is
    /// reference-counted and can be shared between multiple RangeBuf objects,
    /// and sliced using the `start` and `len` values.
    data: Arc<Vec<u8>>,

    /// The initial offset within the internal buffer.
    start: usize,

    /// The current offset within the internal buffer.
    pos: usize,

    /// The number of bytes in the buffer, from the initial offset.
    len: usize,

    /// The offset of the buffer within a stream.
    off: u64,

    /// Whether this contains the final byte in the stream.
    fin: bool,
}

impl RangeBuf {
    /// Creates a new `RangeBuf` from the given slice.
    pub fn from(buf: &[u8], off: u64, fin: bool) -> RangeBuf {
        RangeBuf {
            data: Arc::new(Vec::from(buf)),
            start: 0,
            pos: 0,
            len: buf.len(),
            off,
            fin,
        }
    }

    /// Returns whether `self` holds the final offset in the stream.
    pub fn fin(&self) -> bool {
        self.fin
    }

    /// Returns the starting offset of `self`.
    pub fn off(&self) -> u64 {
        (self.off - self.start as u64) + self.pos as u64
    }

    /// Returns the final offset of `self`.
    pub fn max_off(&self) -> u64 {
        self.off() + self.len() as u64
    }

    /// Returns the length of `self`.
    pub fn len(&self) -> usize {
        self.len - (self.pos - self.start)
    }

    /// Returns true if `self` has a length of zero bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Consumes the starting `count` bytes of `self`.
    pub fn consume(&mut self, count: usize) {
        self.pos += count;
    }

    /// Splits the buffer into two at the given index.
    pub fn split_off(&mut self, at: usize) -> RangeBuf {
        assert!(
            at <= self.len,
            "`at` split index (is {}) should be <= len (is {})",
            at,
            self.len
        );

        let buf = RangeBuf {
            data: self.data.clone(),
            start: self.start + at,
            pos: cmp::max(self.pos, self.start + at),
            len: self.len - at,
            off: self.off + at as u64,
            fin: self.fin,
        };

        self.pos = cmp::min(self.pos, self.start + at);
        self.len = at;
        self.fin = false;

        buf
    }
}

impl std::ops::Deref for RangeBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.data[self.pos..self.start + self.len]
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
        let mut recv = RecvBuf::new(std::u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn empty_stream_frame() {
        let mut recv = RecvBuf::new(15, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let buf = RangeBuf::from(b"hello", 0, false);
        assert!(recv.write(buf).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        let mut buf = [0; 32];
        assert_eq!(recv.emit(&mut buf), Ok((5, false)));

        // Don't store non-fin empty buffer.
        let buf = RangeBuf::from(b"", 10, false);
        assert!(recv.write(buf).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 5);
        assert_eq!(recv.data.len(), 0);

        // Check flow control for empty buffer.
        let buf = RangeBuf::from(b"", 16, false);
        assert_eq!(recv.write(buf), Err(Error::FlowControl));

        // Store fin empty buffer.
        let buf = RangeBuf::from(b"", 5, true);
        assert!(recv.write(buf).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 5);
        assert_eq!(recv.data.len(), 1);

        // Don't store additional fin empty buffers.
        let buf = RangeBuf::from(b"", 5, true);
        assert!(recv.write(buf).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 5);
        assert_eq!(recv.data.len(), 1);

        // Don't store additional fin non-empty buffers.
        let buf = RangeBuf::from(b"aa", 3, true);
        assert!(recv.write(buf).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 5);
        assert_eq!(recv.data.len(), 1);

        // Validate final size with fin empty buffers.
        let buf = RangeBuf::from(b"", 6, true);
        assert_eq!(recv.write(buf), Err(Error::FinalSize));
        let buf = RangeBuf::from(b"", 4, true);
        assert_eq!(recv.write(buf), Err(Error::FinalSize));

        let mut buf = [0; 32];
        assert_eq!(recv.emit(&mut buf), Ok((0, true)));
    }

    #[test]
    fn ordered_read() {
        let mut recv = RecvBuf::new(std::u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"hello", 0, false);
        let second = RangeBuf::from(b"world", 5, false);
        let third = RangeBuf::from(b"something", 10, true);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 0);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));

        assert!(recv.write(third).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 19);
        assert_eq!(fin, true);
        assert_eq!(&buf[..len], b"helloworldsomething");
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 19);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn split_read() {
        let mut recv = RecvBuf::new(std::u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"helloworld", 9, true);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        let (len, fin) = recv.emit(&mut buf[..10]).unwrap();
        assert_eq!(len, 10);
        assert_eq!(fin, false);
        assert_eq!(&buf[..len], b"somethingh");
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 10);

        let (len, fin) = recv.emit(&mut buf[..5]).unwrap();
        assert_eq!(len, 5);
        assert_eq!(fin, false);
        assert_eq!(&buf[..len], b"ellow");
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 15);

        let (len, fin) = recv.emit(&mut buf[..10]).unwrap();
        assert_eq!(len, 4);
        assert_eq!(fin, true);
        assert_eq!(&buf[..len], b"orld");
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 19);
    }

    #[test]
    fn incomplete_read() {
        let mut recv = RecvBuf::new(std::u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"helloworld", 9, true);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 19);
        assert_eq!(fin, true);
        assert_eq!(&buf[..len], b"somethinghelloworld");
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 19);
    }

    #[test]
    fn zero_len_read() {
        let mut recv = RecvBuf::new(std::u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"", 9, true);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 9);
        assert_eq!(fin, true);
        assert_eq!(&buf[..len], b"something");
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
    }

    #[test]
    fn past_read() {
        let mut recv = RecvBuf::new(std::u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 3, false);
        let third = RangeBuf::from(b"ello", 4, true);
        let fourth = RangeBuf::from(b"ello", 5, true);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 9);
        assert_eq!(fin, false);
        assert_eq!(&buf[..len], b"something");
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.write(third), Err(Error::FinalSize));

        assert!(recv.write(fourth).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn fully_overlapping_read() {
        let mut recv = RecvBuf::new(std::u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 4, false);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 9);
        assert_eq!(fin, false);
        assert_eq!(&buf[..len], b"something");
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn fully_overlapping_read2() {
        let mut recv = RecvBuf::new(std::u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 4, false);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 9);
        assert_eq!(fin, false);
        assert_eq!(&buf[..len], b"somehello");
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn fully_overlapping_read3() {
        let mut recv = RecvBuf::new(std::u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 3, false);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 8);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 3);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 9);
        assert_eq!(fin, false);
        assert_eq!(&buf[..len], b"somhellog");
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn fully_overlapping_read_multi() {
        let mut recv = RecvBuf::new(std::u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"somethingsomething", 0, false);
        let second = RangeBuf::from(b"hello", 3, false);
        let third = RangeBuf::from(b"hello", 12, false);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 8);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(third).is_ok());
        assert_eq!(recv.len, 17);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 18);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 5);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 18);
        assert_eq!(fin, false);
        assert_eq!(&buf[..len], b"somhellogsomhellog");
        assert_eq!(recv.len, 18);
        assert_eq!(recv.off, 18);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn overlapping_start_read() {
        let mut recv = RecvBuf::new(std::u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 8, true);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 13);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 13);
        assert_eq!(fin, true);
        assert_eq!(&buf[..len], b"somethingello");
        assert_eq!(recv.len, 13);
        assert_eq!(recv.off, 13);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn overlapping_end_read() {
        let mut recv = RecvBuf::new(std::u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"hello", 0, false);
        let second = RangeBuf::from(b"something", 3, true);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 12);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 12);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 12);
        assert_eq!(fin, true);
        assert_eq!(&buf[..len], b"helsomething");
        assert_eq!(recv.len, 12);
        assert_eq!(recv.off, 12);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn overlapping_end_twice_read() {
        let mut recv = RecvBuf::new(std::u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"he", 0, false);
        let second = RangeBuf::from(b"ow", 4, false);
        let third = RangeBuf::from(b"rl", 7, false);
        let fourth = RangeBuf::from(b"helloworld", 0, true);

        assert!(recv.write(third).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 3);

        assert!(recv.write(fourth).is_ok());
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 6);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 10);
        assert_eq!(fin, true);
        assert_eq!(&buf[..len], b"helloworld");
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 10);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn overlapping_end_twice_and_contained_read() {
        let mut recv = RecvBuf::new(std::u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"hellow", 0, false);
        let second = RangeBuf::from(b"barfoo", 10, true);
        let third = RangeBuf::from(b"rl", 7, false);
        let fourth = RangeBuf::from(b"elloworldbarfoo", 1, true);

        assert!(recv.write(third).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 16);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 16);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 3);

        assert!(recv.write(fourth).is_ok());
        assert_eq!(recv.len, 16);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 5);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 16);
        assert_eq!(fin, true);
        assert_eq!(&buf[..len], b"helloworldbarfoo");
        assert_eq!(recv.len, 16);
        assert_eq!(recv.off, 16);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn partially_multi_overlapping_reordered_read() {
        let mut recv = RecvBuf::new(std::u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"hello", 8, false);
        let second = RangeBuf::from(b"something", 0, false);
        let third = RangeBuf::from(b"moar", 11, true);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 13);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 13);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        assert!(recv.write(third).is_ok());
        assert_eq!(recv.len, 15);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 3);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 15);
        assert_eq!(fin, true);
        assert_eq!(&buf[..len], b"somethinhelloar");
        assert_eq!(recv.len, 15);
        assert_eq!(recv.off, 15);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn partially_multi_overlapping_reordered_read2() {
        let mut recv = RecvBuf::new(std::u64::MAX, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"aaa", 0, false);
        let second = RangeBuf::from(b"bbb", 2, false);
        let third = RangeBuf::from(b"ccc", 4, false);
        let fourth = RangeBuf::from(b"ddd", 6, false);
        let fifth = RangeBuf::from(b"eee", 9, false);
        let sixth = RangeBuf::from(b"fff", 11, false);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(fourth).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 2);

        assert!(recv.write(third).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 3);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 4);

        assert!(recv.write(sixth).is_ok());
        assert_eq!(recv.len, 14);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 5);

        assert!(recv.write(fifth).is_ok());
        assert_eq!(recv.len, 14);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 6);

        let (len, fin) = recv.emit(&mut buf).unwrap();
        assert_eq!(len, 14);
        assert_eq!(fin, false);
        assert_eq!(&buf[..len], b"aabbbcdddeefff");
        assert_eq!(recv.len, 14);
        assert_eq!(recv.off, 14);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.emit(&mut buf), Err(Error::Done));
    }

    #[test]
    fn empty_write() {
        let mut buf = [0; 5];

        let mut send = SendBuf::new(std::u64::MAX);
        assert_eq!(send.len, 0);

        let (written, fin) = send.emit(&mut buf).unwrap();
        assert_eq!(written, 0);
        assert_eq!(fin, false);
    }

    #[test]
    fn multi_write() {
        let mut buf = [0; 128];

        let mut send = SendBuf::new(std::u64::MAX);
        assert_eq!(send.len, 0);

        let first = b"something";
        let second = b"helloworld";

        assert!(send.write(first, false).is_ok());
        assert_eq!(send.len, 9);

        assert!(send.write(second, true).is_ok());
        assert_eq!(send.len, 19);

        let (written, fin) = send.emit(&mut buf[..128]).unwrap();
        assert_eq!(written, 19);
        assert_eq!(fin, true);
        assert_eq!(&buf[..written], b"somethinghelloworld");
        assert_eq!(send.len, 0);
    }

    #[test]
    fn split_write() {
        let mut buf = [0; 10];

        let mut send = SendBuf::new(std::u64::MAX);
        assert_eq!(send.len, 0);

        let first = b"something";
        let second = b"helloworld";

        assert!(send.write(first, false).is_ok());
        assert_eq!(send.len, 9);

        assert!(send.write(second, true).is_ok());
        assert_eq!(send.len, 19);

        assert_eq!(send.off_front(), 0);

        let (written, fin) = send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 10);
        assert_eq!(fin, false);
        assert_eq!(&buf[..written], b"somethingh");
        assert_eq!(send.len, 9);

        assert_eq!(send.off_front(), 10);

        let (written, fin) = send.emit(&mut buf[..5]).unwrap();
        assert_eq!(written, 5);
        assert_eq!(fin, false);
        assert_eq!(&buf[..written], b"ellow");
        assert_eq!(send.len, 4);

        assert_eq!(send.off_front(), 15);

        let (written, fin) = send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 4);
        assert_eq!(fin, true);
        assert_eq!(&buf[..written], b"orld");
        assert_eq!(send.len, 0);

        assert_eq!(send.off_front(), 19);
    }

    #[test]
    fn resend() {
        let mut buf = [0; 15];

        let mut send = SendBuf::new(std::u64::MAX);
        assert_eq!(send.len, 0);
        assert_eq!(send.off_front(), 0);

        let first = b"something";
        let second = b"helloworld";

        assert!(send.write(first, false).is_ok());
        assert_eq!(send.off_front(), 0);

        assert!(send.write(second, true).is_ok());
        assert_eq!(send.off_front(), 0);

        assert_eq!(send.len, 19);

        let (written, fin) = send.emit(&mut buf[..4]).unwrap();
        assert_eq!(written, 4);
        assert_eq!(fin, false);
        assert_eq!(&buf[..written], b"some");
        assert_eq!(send.len, 15);
        assert_eq!(send.off_front(), 4);

        let (written, fin) = send.emit(&mut buf[..5]).unwrap();
        assert_eq!(written, 5);
        assert_eq!(fin, false);
        assert_eq!(&buf[..written], b"thing");
        assert_eq!(send.len, 10);
        assert_eq!(send.off_front(), 9);

        let (written, fin) = send.emit(&mut buf[..5]).unwrap();
        assert_eq!(written, 5);
        assert_eq!(fin, false);
        assert_eq!(&buf[..written], b"hello");
        assert_eq!(send.len, 5);
        assert_eq!(send.off_front(), 14);

        send.retransmit(4, 5);
        assert_eq!(send.len, 10);
        assert_eq!(send.off_front(), 4);

        send.retransmit(0, 4);
        assert_eq!(send.len, 14);
        assert_eq!(send.off_front(), 0);

        let (written, fin) = send.emit(&mut buf[..11]).unwrap();
        assert_eq!(written, 9);
        assert_eq!(fin, false);
        assert_eq!(&buf[..written], b"something");
        assert_eq!(send.len, 5);
        assert_eq!(send.off_front(), 14);

        let (written, fin) = send.emit(&mut buf[..11]).unwrap();
        assert_eq!(written, 5);
        assert_eq!(fin, true);
        assert_eq!(&buf[..written], b"world");
        assert_eq!(send.len, 0);
        assert_eq!(send.off_front(), 19);
    }

    #[test]
    fn write_blocked_by_off() {
        let mut buf = [0; 10];

        let mut send = SendBuf::default();
        assert_eq!(send.len, 0);

        let first = b"something";
        let second = b"helloworld";

        assert_eq!(send.write(first, false), Ok(0));
        assert_eq!(send.len, 0);

        assert_eq!(send.write(second, true), Ok(0));
        assert_eq!(send.len, 0);

        send.update_max_data(5);

        assert_eq!(send.write(first, false), Ok(5));
        assert_eq!(send.len, 5);

        assert_eq!(send.write(second, true), Ok(0));
        assert_eq!(send.len, 5);

        assert_eq!(send.off_front(), 0);

        let (written, fin) = send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 5);
        assert_eq!(fin, false);
        assert_eq!(&buf[..written], b"somet");
        assert_eq!(send.len, 0);

        assert_eq!(send.off_front(), 5);

        let (written, fin) = send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 0);
        assert_eq!(fin, false);
        assert_eq!(&buf[..written], b"");
        assert_eq!(send.len, 0);

        send.update_max_data(15);

        assert_eq!(send.write(&first[5..], false), Ok(4));
        assert_eq!(send.len, 4);

        assert_eq!(send.write(second, true), Ok(6));
        assert_eq!(send.len, 10);

        assert_eq!(send.off_front(), 5);

        let (written, fin) = send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 10);
        assert_eq!(fin, false);
        assert_eq!(&buf[..10], b"hinghellow");
        assert_eq!(send.len, 0);

        send.update_max_data(25);

        assert_eq!(send.write(&second[6..], true), Ok(4));
        assert_eq!(send.len, 4);

        assert_eq!(send.off_front(), 15);

        let (written, fin) = send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 4);
        assert_eq!(fin, true);
        assert_eq!(&buf[..written], b"orld");
        assert_eq!(send.len, 0);
    }

    #[test]
    fn zero_len_write() {
        let mut buf = [0; 10];

        let mut send = SendBuf::new(std::u64::MAX);
        assert_eq!(send.len, 0);

        let first = b"something";

        assert!(send.write(first, false).is_ok());
        assert_eq!(send.len, 9);

        assert!(send.write(&[], true).is_ok());
        assert_eq!(send.len, 9);

        assert_eq!(send.off_front(), 0);

        let (written, fin) = send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 9);
        assert_eq!(fin, true);
        assert_eq!(&buf[..written], b"something");
        assert_eq!(send.len, 0);
    }

    #[test]
    fn recv_flow_control() {
        let mut stream = Stream::new(15, 0, true, true, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"hello", 0, false);
        let second = RangeBuf::from(b"world", 5, false);
        let third = RangeBuf::from(b"something", 10, false);

        assert_eq!(stream.recv.write(second), Ok(()));
        assert_eq!(stream.recv.write(first), Ok(()));
        assert!(!stream.recv.almost_full());

        assert_eq!(stream.recv.write(third), Err(Error::FlowControl));

        let (len, fin) = stream.recv.emit(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"helloworld");
        assert_eq!(fin, false);

        assert!(stream.recv.almost_full());

        stream.recv.update_max_data(time::Instant::now());
        assert_eq!(stream.recv.max_data_next(), 25);
        assert!(!stream.recv.almost_full());

        let third = RangeBuf::from(b"something", 10, false);
        assert_eq!(stream.recv.write(third), Ok(()));
    }

    #[test]
    fn recv_past_fin() {
        let mut stream = Stream::new(15, 0, true, true, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let first = RangeBuf::from(b"hello", 0, true);
        let second = RangeBuf::from(b"world", 5, false);

        assert_eq!(stream.recv.write(first), Ok(()));
        assert_eq!(stream.recv.write(second), Err(Error::FinalSize));
    }

    #[test]
    fn recv_fin_dup() {
        let mut stream = Stream::new(15, 0, true, true, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let first = RangeBuf::from(b"hello", 0, true);
        let second = RangeBuf::from(b"hello", 0, true);

        assert_eq!(stream.recv.write(first), Ok(()));
        assert_eq!(stream.recv.write(second), Ok(()));

        let mut buf = [0; 32];

        let (len, fin) = stream.recv.emit(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"hello");
        assert_eq!(fin, true);
    }

    #[test]
    fn recv_fin_change() {
        let mut stream = Stream::new(15, 0, true, true, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let first = RangeBuf::from(b"hello", 0, true);
        let second = RangeBuf::from(b"world", 5, true);

        assert_eq!(stream.recv.write(second), Ok(()));
        assert_eq!(stream.recv.write(first), Err(Error::FinalSize));
    }

    #[test]
    fn recv_fin_lower_than_received() {
        let mut stream = Stream::new(15, 0, true, true, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let first = RangeBuf::from(b"hello", 0, true);
        let second = RangeBuf::from(b"world", 5, false);

        assert_eq!(stream.recv.write(second), Ok(()));
        assert_eq!(stream.recv.write(first), Err(Error::FinalSize));
    }

    #[test]
    fn recv_fin_flow_control() {
        let mut stream = Stream::new(15, 0, true, true, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"hello", 0, false);
        let second = RangeBuf::from(b"world", 5, true);

        assert_eq!(stream.recv.write(first), Ok(()));
        assert_eq!(stream.recv.write(second), Ok(()));

        let (len, fin) = stream.recv.emit(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"helloworld");
        assert_eq!(fin, true);

        assert!(!stream.recv.almost_full());
    }

    #[test]
    fn recv_fin_reset_mismatch() {
        let mut stream = Stream::new(15, 0, true, true, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let first = RangeBuf::from(b"hello", 0, true);

        assert_eq!(stream.recv.write(first), Ok(()));
        assert_eq!(stream.recv.reset(0, 10), Err(Error::FinalSize));
    }

    #[test]
    fn recv_reset_dup() {
        let mut stream = Stream::new(15, 0, true, true, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let first = RangeBuf::from(b"hello", 0, false);

        assert_eq!(stream.recv.write(first), Ok(()));
        assert_eq!(stream.recv.reset(0, 5), Ok(0));
        assert_eq!(stream.recv.reset(0, 5), Ok(0));
    }

    #[test]
    fn recv_reset_change() {
        let mut stream = Stream::new(15, 0, true, true, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let first = RangeBuf::from(b"hello", 0, false);

        assert_eq!(stream.recv.write(first), Ok(()));
        assert_eq!(stream.recv.reset(0, 5), Ok(0));
        assert_eq!(stream.recv.reset(0, 10), Err(Error::FinalSize));
    }

    #[test]
    fn recv_reset_lower_than_received() {
        let mut stream = Stream::new(15, 0, true, true, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let first = RangeBuf::from(b"hello", 0, false);

        assert_eq!(stream.recv.write(first), Ok(()));
        assert_eq!(stream.recv.reset(0, 4), Err(Error::FinalSize));
    }

    #[test]
    fn send_flow_control() {
        let mut buf = [0; 25];

        let mut stream = Stream::new(0, 15, true, true, DEFAULT_STREAM_WINDOW);

        let first = b"hello";
        let second = b"world";
        let third = b"something";

        assert!(stream.send.write(first, false).is_ok());
        assert!(stream.send.write(second, false).is_ok());
        assert!(stream.send.write(third, false).is_ok());

        assert_eq!(stream.send.off_front(), 0);

        let (written, fin) = stream.send.emit(&mut buf[..25]).unwrap();
        assert_eq!(written, 15);
        assert_eq!(fin, false);
        assert_eq!(&buf[..written], b"helloworldsomet");

        assert_eq!(stream.send.off_front(), 15);

        let (written, fin) = stream.send.emit(&mut buf[..25]).unwrap();
        assert_eq!(written, 0);
        assert_eq!(fin, false);
        assert_eq!(&buf[..written], b"");

        stream.send.retransmit(0, 15);

        assert_eq!(stream.send.off_front(), 0);

        let (written, fin) = stream.send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 10);
        assert_eq!(fin, false);
        assert_eq!(&buf[..written], b"helloworld");

        assert_eq!(stream.send.off_front(), 10);

        let (written, fin) = stream.send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 5);
        assert_eq!(fin, false);
        assert_eq!(&buf[..written], b"somet");
    }

    #[test]
    fn send_past_fin() {
        let mut stream = Stream::new(0, 15, true, true, DEFAULT_STREAM_WINDOW);

        let first = b"hello";
        let second = b"world";
        let third = b"third";

        assert_eq!(stream.send.write(first, false), Ok(5));

        assert_eq!(stream.send.write(second, true), Ok(5));
        assert!(stream.send.is_fin());

        assert_eq!(stream.send.write(third, false), Err(Error::FinalSize));
    }

    #[test]
    fn send_fin_dup() {
        let mut stream = Stream::new(0, 15, true, true, DEFAULT_STREAM_WINDOW);

        assert_eq!(stream.send.write(b"hello", true), Ok(5));
        assert!(stream.send.is_fin());

        assert_eq!(stream.send.write(b"", true), Ok(0));
        assert!(stream.send.is_fin());
    }

    #[test]
    fn send_undo_fin() {
        let mut stream = Stream::new(0, 15, true, true, DEFAULT_STREAM_WINDOW);

        assert_eq!(stream.send.write(b"hello", true), Ok(5));
        assert!(stream.send.is_fin());

        assert_eq!(
            stream.send.write(b"helloworld", true),
            Err(Error::FinalSize)
        );
    }

    #[test]
    fn send_fin_max_data_match() {
        let mut buf = [0; 15];

        let mut stream = Stream::new(0, 15, true, true, DEFAULT_STREAM_WINDOW);

        let slice = b"hellohellohello";

        assert!(stream.send.write(slice, true).is_ok());

        let (written, fin) = stream.send.emit(&mut buf[..15]).unwrap();
        assert_eq!(written, 15);
        assert_eq!(fin, true);
        assert_eq!(&buf[..written], slice);
    }

    #[test]
    fn send_fin_zero_length() {
        let mut buf = [0; 5];

        let mut stream = Stream::new(0, 15, true, true, DEFAULT_STREAM_WINDOW);

        assert_eq!(stream.send.write(b"hello", false), Ok(5));
        assert_eq!(stream.send.write(b"", true), Ok(0));
        assert!(stream.send.is_fin());

        let (written, fin) = stream.send.emit(&mut buf[..5]).unwrap();
        assert_eq!(written, 5);
        assert_eq!(fin, true);
        assert_eq!(&buf[..written], b"hello");
    }

    #[test]
    fn send_ack() {
        let mut buf = [0; 5];

        let mut stream = Stream::new(0, 15, true, true, DEFAULT_STREAM_WINDOW);

        assert_eq!(stream.send.write(b"hello", false), Ok(5));
        assert_eq!(stream.send.write(b"world", false), Ok(5));
        assert_eq!(stream.send.write(b"", true), Ok(0));
        assert!(stream.send.is_fin());

        assert_eq!(stream.send.off_front(), 0);

        let (written, fin) = stream.send.emit(&mut buf[..5]).unwrap();
        assert_eq!(written, 5);
        assert_eq!(fin, false);
        assert_eq!(&buf[..written], b"hello");

        stream.send.ack_and_drop(0, 5);

        stream.send.retransmit(0, 5);

        assert_eq!(stream.send.off_front(), 5);

        let (written, fin) = stream.send.emit(&mut buf[..5]).unwrap();
        assert_eq!(written, 5);
        assert_eq!(fin, true);
        assert_eq!(&buf[..written], b"world");
    }

    #[test]
    fn send_ack_reordering() {
        let mut buf = [0; 5];

        let mut stream = Stream::new(0, 15, true, true, DEFAULT_STREAM_WINDOW);

        assert_eq!(stream.send.write(b"hello", false), Ok(5));
        assert_eq!(stream.send.write(b"world", false), Ok(5));
        assert_eq!(stream.send.write(b"", true), Ok(0));
        assert!(stream.send.is_fin());

        assert_eq!(stream.send.off_front(), 0);

        let (written, fin) = stream.send.emit(&mut buf[..5]).unwrap();
        assert_eq!(written, 5);
        assert_eq!(fin, false);
        assert_eq!(&buf[..written], b"hello");

        assert_eq!(stream.send.off_front(), 5);

        let (written, fin) = stream.send.emit(&mut buf[..1]).unwrap();
        assert_eq!(written, 1);
        assert_eq!(fin, false);
        assert_eq!(&buf[..written], b"w");

        stream.send.ack_and_drop(5, 1);
        stream.send.ack_and_drop(0, 5);

        stream.send.retransmit(0, 5);
        stream.send.retransmit(5, 1);

        assert_eq!(stream.send.off_front(), 6);

        let (written, fin) = stream.send.emit(&mut buf[..5]).unwrap();
        assert_eq!(written, 4);
        assert_eq!(fin, true);
        assert_eq!(&buf[..written], b"orld");
    }

    #[test]
    fn recv_data_below_off() {
        let mut stream = Stream::new(15, 0, true, true, DEFAULT_STREAM_WINDOW);

        let first = RangeBuf::from(b"hello", 0, false);

        assert_eq!(stream.recv.write(first), Ok(()));

        let mut buf = [0; 10];

        let (len, fin) = stream.recv.emit(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"hello");
        assert_eq!(fin, false);

        let first = RangeBuf::from(b"elloworld", 1, true);
        assert_eq!(stream.recv.write(first), Ok(()));

        let (len, fin) = stream.recv.emit(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"world");
        assert_eq!(fin, true);
    }

    #[test]
    fn stream_complete() {
        let mut stream = Stream::new(30, 30, true, true, DEFAULT_STREAM_WINDOW);

        assert_eq!(stream.send.write(b"hello", false), Ok(5));
        assert_eq!(stream.send.write(b"world", false), Ok(5));

        assert!(!stream.send.is_complete());
        assert!(!stream.send.is_fin());

        assert_eq!(stream.send.write(b"", true), Ok(0));

        assert!(!stream.send.is_complete());
        assert!(stream.send.is_fin());

        let buf = RangeBuf::from(b"hello", 0, true);
        assert!(stream.recv.write(buf).is_ok());
        assert!(!stream.recv.is_fin());

        stream.send.ack(6, 4);
        assert!(!stream.send.is_complete());

        let mut buf = [0; 2];
        assert_eq!(stream.recv.emit(&mut buf), Ok((2, false)));
        assert!(!stream.recv.is_fin());

        stream.send.ack(1, 5);
        assert!(!stream.send.is_complete());

        stream.send.ack(0, 1);
        assert!(stream.send.is_complete());

        assert!(!stream.is_complete());

        let mut buf = [0; 3];
        assert_eq!(stream.recv.emit(&mut buf), Ok((3, true)));
        assert!(stream.recv.is_fin());

        assert!(stream.is_complete());
    }

    #[test]
    fn send_fin_zero_length_output() {
        let mut buf = [0; 5];

        let mut stream = Stream::new(0, 15, true, true, DEFAULT_STREAM_WINDOW);

        assert_eq!(stream.send.write(b"hello", false), Ok(5));
        assert_eq!(stream.send.off_front(), 0);
        assert!(!stream.send.is_fin());

        let (written, fin) = stream.send.emit(&mut buf).unwrap();
        assert_eq!(written, 5);
        assert_eq!(fin, false);
        assert_eq!(&buf[..written], b"hello");

        assert_eq!(stream.send.write(b"", true), Ok(0));
        assert!(stream.send.is_fin());
        assert_eq!(stream.send.off_front(), 5);

        let (written, fin) = stream.send.emit(&mut buf).unwrap();
        assert_eq!(written, 0);
        assert_eq!(fin, true);
        assert_eq!(&buf[..written], b"");
    }

    #[test]
    fn send_emit() {
        let mut buf = [0; 5];

        let mut stream = Stream::new(0, 20, true, true, DEFAULT_STREAM_WINDOW);

        assert_eq!(stream.send.write(b"hello", false), Ok(5));
        assert_eq!(stream.send.write(b"world", false), Ok(5));
        assert_eq!(stream.send.write(b"olleh", false), Ok(5));
        assert_eq!(stream.send.write(b"dlrow", true), Ok(5));
        assert_eq!(stream.send.off_front(), 0);
        assert_eq!(stream.send.data.len(), 4);

        assert!(stream.is_flushable());

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..4]), Ok((4, false)));
        assert_eq!(stream.send.off_front(), 4);
        assert_eq!(&buf[..4], b"hell");

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..4]), Ok((4, false)));
        assert_eq!(stream.send.off_front(), 8);
        assert_eq!(&buf[..4], b"owor");

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..2]), Ok((2, false)));
        assert_eq!(stream.send.off_front(), 10);
        assert_eq!(&buf[..2], b"ld");

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..1]), Ok((1, false)));
        assert_eq!(stream.send.off_front(), 11);
        assert_eq!(&buf[..1], b"o");

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((5, false)));
        assert_eq!(stream.send.off_front(), 16);
        assert_eq!(&buf[..5], b"llehd");

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((4, true)));
        assert_eq!(stream.send.off_front(), 20);
        assert_eq!(&buf[..4], b"lrow");

        assert!(!stream.is_flushable());

        assert!(!stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((0, true)));
        assert_eq!(stream.send.off_front(), 20);
    }

    #[test]
    fn send_emit_ack() {
        let mut buf = [0; 5];

        let mut stream = Stream::new(0, 20, true, true, DEFAULT_STREAM_WINDOW);

        assert_eq!(stream.send.write(b"hello", false), Ok(5));
        assert_eq!(stream.send.write(b"world", false), Ok(5));
        assert_eq!(stream.send.write(b"olleh", false), Ok(5));
        assert_eq!(stream.send.write(b"dlrow", true), Ok(5));
        assert_eq!(stream.send.off_front(), 0);
        assert_eq!(stream.send.data.len(), 4);

        assert!(stream.is_flushable());

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..4]), Ok((4, false)));
        assert_eq!(stream.send.off_front(), 4);
        assert_eq!(&buf[..4], b"hell");

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..4]), Ok((4, false)));
        assert_eq!(stream.send.off_front(), 8);
        assert_eq!(&buf[..4], b"owor");

        stream.send.ack_and_drop(0, 5);
        assert_eq!(stream.send.data.len(), 3);

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..2]), Ok((2, false)));
        assert_eq!(stream.send.off_front(), 10);
        assert_eq!(&buf[..2], b"ld");

        stream.send.ack_and_drop(7, 5);
        assert_eq!(stream.send.data.len(), 3);

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..1]), Ok((1, false)));
        assert_eq!(stream.send.off_front(), 11);
        assert_eq!(&buf[..1], b"o");

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((5, false)));
        assert_eq!(stream.send.off_front(), 16);
        assert_eq!(&buf[..5], b"llehd");

        stream.send.ack_and_drop(5, 7);
        assert_eq!(stream.send.data.len(), 2);

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((4, true)));
        assert_eq!(stream.send.off_front(), 20);
        assert_eq!(&buf[..4], b"lrow");

        assert!(!stream.is_flushable());

        assert!(!stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((0, true)));
        assert_eq!(stream.send.off_front(), 20);

        stream.send.ack_and_drop(22, 4);
        assert_eq!(stream.send.data.len(), 2);

        stream.send.ack_and_drop(20, 1);
        assert_eq!(stream.send.data.len(), 2);
    }

    #[test]
    fn send_emit_retransmit() {
        let mut buf = [0; 5];

        let mut stream = Stream::new(0, 20, true, true, DEFAULT_STREAM_WINDOW);

        assert_eq!(stream.send.write(b"hello", false), Ok(5));
        assert_eq!(stream.send.write(b"world", false), Ok(5));
        assert_eq!(stream.send.write(b"olleh", false), Ok(5));
        assert_eq!(stream.send.write(b"dlrow", true), Ok(5));
        assert_eq!(stream.send.off_front(), 0);
        assert_eq!(stream.send.data.len(), 4);

        assert!(stream.is_flushable());

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..4]), Ok((4, false)));
        assert_eq!(stream.send.off_front(), 4);
        assert_eq!(&buf[..4], b"hell");

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..4]), Ok((4, false)));
        assert_eq!(stream.send.off_front(), 8);
        assert_eq!(&buf[..4], b"owor");

        stream.send.retransmit(3, 3);
        assert_eq!(stream.send.off_front(), 3);

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..3]), Ok((3, false)));
        assert_eq!(stream.send.off_front(), 8);
        assert_eq!(&buf[..3], b"low");

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..2]), Ok((2, false)));
        assert_eq!(stream.send.off_front(), 10);
        assert_eq!(&buf[..2], b"ld");

        stream.send.ack_and_drop(7, 2);

        stream.send.retransmit(8, 2);

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..2]), Ok((2, false)));
        assert_eq!(stream.send.off_front(), 10);
        assert_eq!(&buf[..2], b"ld");

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..1]), Ok((1, false)));
        assert_eq!(stream.send.off_front(), 11);
        assert_eq!(&buf[..1], b"o");

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((5, false)));
        assert_eq!(stream.send.off_front(), 16);
        assert_eq!(&buf[..5], b"llehd");

        stream.send.retransmit(12, 2);

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..2]), Ok((2, false)));
        assert_eq!(stream.send.off_front(), 16);
        assert_eq!(&buf[..2], b"le");

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((4, true)));
        assert_eq!(stream.send.off_front(), 20);
        assert_eq!(&buf[..4], b"lrow");

        assert!(!stream.is_flushable());

        assert!(!stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((0, true)));
        assert_eq!(stream.send.off_front(), 20);

        stream.send.retransmit(7, 12);

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((5, false)));
        assert_eq!(stream.send.off_front(), 12);
        assert_eq!(&buf[..5], b"rldol");

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((5, false)));
        assert_eq!(stream.send.off_front(), 17);
        assert_eq!(&buf[..5], b"lehdl");

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((2, false)));
        assert_eq!(stream.send.off_front(), 20);
        assert_eq!(&buf[..2], b"ro");

        stream.send.ack_and_drop(12, 7);

        stream.send.retransmit(7, 12);

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((5, false)));
        assert_eq!(stream.send.off_front(), 12);
        assert_eq!(&buf[..5], b"rldol");

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((5, false)));
        assert_eq!(stream.send.off_front(), 17);
        assert_eq!(&buf[..5], b"lehdl");

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((2, false)));
        assert_eq!(stream.send.off_front(), 20);
        assert_eq!(&buf[..2], b"ro");
    }

    #[test]
    fn rangebuf_split_off() {
        let mut buf = RangeBuf::from(b"helloworld", 5, true);
        assert_eq!(buf.start, 0);
        assert_eq!(buf.pos, 0);
        assert_eq!(buf.len, 10);
        assert_eq!(buf.off, 5);
        assert_eq!(buf.fin, true);

        assert_eq!(buf.len(), 10);
        assert_eq!(buf.off(), 5);
        assert_eq!(buf.fin(), true);

        assert_eq!(&buf[..], b"helloworld");

        // Advance buffer.
        buf.consume(5);

        assert_eq!(buf.start, 0);
        assert_eq!(buf.pos, 5);
        assert_eq!(buf.len, 10);
        assert_eq!(buf.off, 5);
        assert_eq!(buf.fin, true);

        assert_eq!(buf.len(), 5);
        assert_eq!(buf.off(), 10);
        assert_eq!(buf.fin(), true);

        assert_eq!(&buf[..], b"world");

        // Split buffer before position.
        let mut new_buf = buf.split_off(3);

        assert_eq!(buf.start, 0);
        assert_eq!(buf.pos, 3);
        assert_eq!(buf.len, 3);
        assert_eq!(buf.off, 5);
        assert_eq!(buf.fin, false);

        assert_eq!(buf.len(), 0);
        assert_eq!(buf.off(), 8);
        assert_eq!(buf.fin(), false);

        assert_eq!(&buf[..], b"");

        assert_eq!(new_buf.start, 3);
        assert_eq!(new_buf.pos, 5);
        assert_eq!(new_buf.len, 7);
        assert_eq!(new_buf.off, 8);
        assert_eq!(new_buf.fin, true);

        assert_eq!(new_buf.len(), 5);
        assert_eq!(new_buf.off(), 10);
        assert_eq!(new_buf.fin(), true);

        assert_eq!(&new_buf[..], b"world");

        // Advance buffer.
        new_buf.consume(2);

        assert_eq!(new_buf.start, 3);
        assert_eq!(new_buf.pos, 7);
        assert_eq!(new_buf.len, 7);
        assert_eq!(new_buf.off, 8);
        assert_eq!(new_buf.fin, true);

        assert_eq!(new_buf.len(), 3);
        assert_eq!(new_buf.off(), 12);
        assert_eq!(new_buf.fin(), true);

        assert_eq!(&new_buf[..], b"rld");

        // Split buffer after position.
        let mut new_new_buf = new_buf.split_off(5);

        assert_eq!(new_buf.start, 3);
        assert_eq!(new_buf.pos, 7);
        assert_eq!(new_buf.len, 5);
        assert_eq!(new_buf.off, 8);
        assert_eq!(new_buf.fin, false);

        assert_eq!(new_buf.len(), 1);
        assert_eq!(new_buf.off(), 12);
        assert_eq!(new_buf.fin(), false);

        assert_eq!(&new_buf[..], b"r");

        assert_eq!(new_new_buf.start, 8);
        assert_eq!(new_new_buf.pos, 8);
        assert_eq!(new_new_buf.len, 2);
        assert_eq!(new_new_buf.off, 13);
        assert_eq!(new_new_buf.fin, true);

        assert_eq!(new_new_buf.len(), 2);
        assert_eq!(new_new_buf.off(), 13);
        assert_eq!(new_new_buf.fin(), true);

        assert_eq!(&new_new_buf[..], b"ld");

        // Advance buffer.
        new_new_buf.consume(2);

        assert_eq!(new_new_buf.start, 8);
        assert_eq!(new_new_buf.pos, 10);
        assert_eq!(new_new_buf.len, 2);
        assert_eq!(new_new_buf.off, 13);
        assert_eq!(new_new_buf.fin, true);

        assert_eq!(new_new_buf.len(), 0);
        assert_eq!(new_new_buf.off(), 15);
        assert_eq!(new_new_buf.fin(), true);

        assert_eq!(&new_new_buf[..], b"");
    }

    /// RFC9000 2.1: A stream ID that is used out of order results in all
    /// streams of that type with lower-numbered stream IDs also being opened.
    #[test]
    fn stream_limit_auto_open() {
        let local_tp = crate::TransportParams::default();
        let peer_tp = crate::TransportParams::default();

        let mut streams = StreamMap::new(5, 5, 5);

        let stream_id = 500;
        assert!(!is_local(stream_id, true), "stream id is peer initiated");
        assert!(is_bidi(stream_id), "stream id is bidirectional");
        assert_eq!(
            streams
                .get_or_create(stream_id, &local_tp, &peer_tp, false, true)
                .err(),
            Some(Error::StreamLimit),
            "stream limit should be exceeded"
        );
    }

    /// Stream limit should be satisfied regardless of what order we open
    /// streams
    #[test]
    fn stream_create_out_of_order() {
        let local_tp = crate::TransportParams::default();
        let peer_tp = crate::TransportParams::default();

        let mut streams = StreamMap::new(5, 5, 5);

        for stream_id in [8, 12, 4] {
            assert!(is_local(stream_id, false), "stream id is client initiated");
            assert!(is_bidi(stream_id), "stream id is bidirectional");
            assert!(streams
                .get_or_create(stream_id, &local_tp, &peer_tp, false, true)
                .is_ok());
        }
    }

    /// Check stream limit boundary cases
    #[test]
    fn stream_limit_edge() {
        let local_tp = crate::TransportParams::default();
        let peer_tp = crate::TransportParams::default();

        let mut streams = StreamMap::new(3, 3, 3);

        // Highest permitted
        let stream_id = 8;
        assert!(streams
            .get_or_create(stream_id, &local_tp, &peer_tp, false, true)
            .is_ok());

        // One more than highest permitted
        let stream_id = 12;
        assert_eq!(
            streams
                .get_or_create(stream_id, &local_tp, &peer_tp, false, true)
                .err(),
            Some(Error::StreamLimit)
        );
    }

    /// Check SendBuf::len calculation on a retransmit case
    #[test]
    fn send_buf_len_on_retransmit() {
        let mut buf = [0; 15];

        let mut send = SendBuf::new(std::u64::MAX);
        assert_eq!(send.len, 0);
        assert_eq!(send.off_front(), 0);

        let first = b"something";

        assert!(send.write(first, false).is_ok());
        assert_eq!(send.off_front(), 0);

        assert_eq!(send.len, 9);

        let (written, fin) = send.emit(&mut buf[..4]).unwrap();
        assert_eq!(written, 4);
        assert_eq!(fin, false);
        assert_eq!(&buf[..written], b"some");
        assert_eq!(send.len, 5);
        assert_eq!(send.off_front(), 4);

        send.retransmit(3, 5);
        assert_eq!(send.len, 6);
        assert_eq!(send.off_front(), 3);
    }
}
