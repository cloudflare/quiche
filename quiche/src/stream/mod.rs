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
use std::collections::HashMap;
use std::collections::HashSet;

use intrusive_collections::intrusive_adapter;
use intrusive_collections::KeyAdapter;
use intrusive_collections::RBTree;
use intrusive_collections::RBTreeAtomicLink;

use smallvec::SmallVec;

use crate::Error;
use crate::Result;

const DEFAULT_URGENCY: u8 = 127;

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
    flushable: RBTree<StreamFlushablePriorityAdapter>,

    /// Set of stream IDs corresponding to streams that have outstanding data
    /// to read. This is used to generate a `StreamIter` of streams without
    /// having to iterate over the full list of streams.
    pub readable: RBTree<StreamReadablePriorityAdapter>,

    /// Set of stream IDs corresponding to streams that have enough flow control
    /// capacity to be written to, and is not finished. This is used to generate
    /// a `StreamIter` of streams without having to iterate over the full list
    /// of streams.
    pub writable: RBTree<StreamWritablePriorityAdapter>,

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
        let (stream, is_new_and_writable) = match self.streams.entry(id) {
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
                    id,
                    max_rx_data,
                    max_tx_data,
                    is_bidi(id),
                    local,
                    self.max_stream_window,
                );

                let is_writable = s.is_writable();

                (v.insert(s), is_writable)
            },

            hash_map::Entry::Occupied(v) => (v.into_mut(), false),
        };

        // Newly created stream might already be writable due to initial flow
        // control limits.
        if is_new_and_writable {
            self.writable.insert(Arc::clone(&stream.priority_key));
        }

        Ok(stream)
    }

    /// Adds the stream ID to the readable streams set.
    ///
    /// If the stream was already in the list, this does nothing.
    pub fn insert_readable(&mut self, priority_key: &Arc<StreamPriorityKey>) {
        if !priority_key.readable.is_linked() {
            self.readable.insert(Arc::clone(priority_key));
        }
    }

    /// Removes the stream ID from the readable streams set.
    pub fn remove_readable(&mut self, priority_key: &Arc<StreamPriorityKey>) {
        if !priority_key.readable.is_linked() {
            return;
        }

        let mut c = {
            let ptr = Arc::as_ptr(priority_key);
            unsafe { self.readable.cursor_mut_from_ptr(ptr) }
        };

        c.remove();
    }

    /// Adds the stream ID to the writable streams set.
    ///
    /// This should also be called anytime a new stream is created, in addition
    /// to when an existing stream becomes writable.
    ///
    /// If the stream was already in the list, this does nothing.
    pub fn insert_writable(&mut self, priority_key: &Arc<StreamPriorityKey>) {
        if !priority_key.writable.is_linked() {
            self.writable.insert(Arc::clone(priority_key));
        }
    }

    /// Removes the stream ID from the writable streams set.
    ///
    /// This should also be called anytime an existing stream stops being
    /// writable.
    pub fn remove_writable(&mut self, priority_key: &Arc<StreamPriorityKey>) {
        if !priority_key.writable.is_linked() {
            return;
        }

        let mut c = {
            let ptr = Arc::as_ptr(priority_key);
            unsafe { self.writable.cursor_mut_from_ptr(ptr) }
        };

        c.remove();
    }

    /// Adds the stream ID to the flushable streams set.
    ///
    /// If the stream was already in the list, this does nothing.
    pub fn insert_flushable(&mut self, priority_key: &Arc<StreamPriorityKey>) {
        if !priority_key.flushable.is_linked() {
            self.flushable.insert(Arc::clone(priority_key));
        }
    }

    /// Removes the stream ID from the flushable streams set.
    pub fn remove_flushable(&mut self, priority_key: &Arc<StreamPriorityKey>) {
        if !priority_key.flushable.is_linked() {
            return;
        }

        let mut c = {
            let ptr = Arc::as_ptr(priority_key);
            unsafe { self.flushable.cursor_mut_from_ptr(ptr) }
        };

        c.remove();
    }

    pub fn peek_flushable(&self) -> Option<Arc<StreamPriorityKey>> {
        self.flushable.front().clone_pointer()
    }

    /// Updates the priorities of a stream.
    pub fn update_priority(
        &mut self, old: &Arc<StreamPriorityKey>, new: &Arc<StreamPriorityKey>,
    ) {
        if old.readable.is_linked() {
            self.remove_readable(old);
            self.readable.insert(Arc::clone(new));
        }

        if old.writable.is_linked() {
            self.remove_writable(old);
            self.writable.insert(Arc::clone(new));
        }

        if old.flushable.is_linked() {
            self.remove_flushable(old);
            self.flushable.insert(Arc::clone(new));
        }
    }

    /// Adds the stream ID to the almost full streams set.
    ///
    /// If the stream was already in the list, this does nothing.
    pub fn insert_almost_full(&mut self, stream_id: u64) {
        self.almost_full.insert(stream_id);
    }

    /// Removes the stream ID from the almost full streams set.
    pub fn remove_almost_full(&mut self, stream_id: u64) {
        self.almost_full.remove(&stream_id);
    }

    /// Adds the stream ID to the blocked streams set with the
    /// given offset value.
    ///
    /// If the stream was already in the list, this does nothing.
    pub fn insert_blocked(&mut self, stream_id: u64, off: u64) {
        self.blocked.insert(stream_id, off);
    }

    /// Removes the stream ID from the blocked streams set.
    pub fn remove_blocked(&mut self, stream_id: u64) {
        self.blocked.remove(&stream_id);
    }

    /// Adds the stream ID to the reset streams set with the
    /// given error code and final size values.
    ///
    /// If the stream was already in the list, this does nothing.
    pub fn insert_reset(
        &mut self, stream_id: u64, error_code: u64, final_size: u64,
    ) {
        self.reset.insert(stream_id, (error_code, final_size));
    }

    /// Removes the stream ID from the reset streams set.
    pub fn remove_reset(&mut self, stream_id: u64) {
        self.reset.remove(&stream_id);
    }

    /// Adds the stream ID to the stopped streams set with the
    /// given error code.
    ///
    /// If the stream was already in the list, this does nothing.
    pub fn insert_stopped(&mut self, stream_id: u64, error_code: u64) {
        self.stopped.insert(stream_id, error_code);
    }

    /// Removes the stream ID from the stopped streams set.
    pub fn remove_stopped(&mut self, stream_id: u64) {
        self.stopped.remove(&stream_id);
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

        let s = self.streams.remove(&stream_id).unwrap();

        self.remove_readable(&s.priority_key);

        self.remove_writable(&s.priority_key);

        self.remove_flushable(&s.priority_key);

        self.collected.insert(stream_id);
    }

    /// Creates an iterator over streams that have outstanding data to read.
    pub fn readable(&self) -> StreamIter {
        StreamIter {
            streams: self.readable.iter().map(|s| s.id).collect(),
            index: 0,
        }
    }

    /// Creates an iterator over streams that can be written to.
    pub fn writable(&self) -> StreamIter {
        StreamIter {
            streams: self.writable.iter().map(|s| s.id).collect(),
            index: 0,
        }
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
pub struct Stream {
    /// Receive-side stream buffer.
    pub recv: recv_buf::RecvBuf,

    /// Send-side stream buffer.
    pub send: send_buf::SendBuf,

    pub send_lowat: usize,

    /// Whether the stream is bidirectional.
    pub bidi: bool,

    /// Whether the stream was created by the local endpoint.
    pub local: bool,

    /// The stream's urgency (lower is better). Default is `DEFAULT_URGENCY`.
    pub urgency: u8,

    /// Whether the stream can be flushed incrementally. Default is `true`.
    pub incremental: bool,

    pub priority_key: Arc<StreamPriorityKey>,
}

impl Stream {
    /// Creates a new stream with the given flow control limits.
    pub fn new(
        id: u64, max_rx_data: u64, max_tx_data: u64, bidi: bool, local: bool,
        max_window: u64,
    ) -> Stream {
        let priority_key = Arc::new(StreamPriorityKey {
            id,
            ..Default::default()
        });

        Stream {
            recv: recv_buf::RecvBuf::new(max_rx_data, max_window),
            send: send_buf::SendBuf::new(max_tx_data),
            send_lowat: 1,
            bidi,
            local,
            urgency: priority_key.urgency,
            incremental: priority_key.incremental,
            priority_key,
        }
    }

    /// Returns true if the stream has data to read.
    pub fn is_readable(&self) -> bool {
        self.recv.ready()
    }

    /// Returns true if the stream has enough flow control capacity to be
    /// written to, and is not finished.
    pub fn is_writable(&self) -> bool {
        !self.send.is_shutdown() &&
            !self.send.is_fin() &&
            (self.send.off_back() + self.send_lowat as u64) <
                self.send.max_off()
    }

    /// Returns true if the stream has data to send and is allowed to send at
    /// least some of it.
    pub fn is_flushable(&self) -> bool {
        self.send.ready() && self.send.off_front() < self.send.max_off()
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
}

/// Returns true if the stream was created locally.
pub fn is_local(stream_id: u64, is_server: bool) -> bool {
    (stream_id & 0x1) == (is_server as u64)
}

/// Returns true if the stream is bidirectional.
pub fn is_bidi(stream_id: u64) -> bool {
    (stream_id & 0x2) == 0
}

#[derive(Clone, Debug)]
pub struct StreamPriorityKey {
    pub urgency: u8,
    pub incremental: bool,
    pub id: u64,

    pub readable: RBTreeAtomicLink,
    pub writable: RBTreeAtomicLink,
    pub flushable: RBTreeAtomicLink,
}

impl Default for StreamPriorityKey {
    fn default() -> Self {
        Self {
            urgency: DEFAULT_URGENCY,
            incremental: true,
            id: Default::default(),
            readable: Default::default(),
            writable: Default::default(),
            flushable: Default::default(),
        }
    }
}

impl PartialEq for StreamPriorityKey {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for StreamPriorityKey {}

impl PartialOrd for StreamPriorityKey {
    // Priority ordering is complex, disable Clippy warning.
    #[allow(clippy::incorrect_partial_ord_impl_on_ord_type)]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // Ignore priority if ID matches.
        if self.id == other.id {
            return Some(std::cmp::Ordering::Equal);
        }

        // First, order by urgency...
        if self.urgency != other.urgency {
            return self.urgency.partial_cmp(&other.urgency);
        }

        // ...when the urgency is the same, and both are not incremental, order
        // by stream ID...
        if !self.incremental && !other.incremental {
            return self.id.partial_cmp(&other.id);
        }

        // ...non-incremental takes priority over incremental...
        if self.incremental && !other.incremental {
            return Some(std::cmp::Ordering::Greater);
        }
        if !self.incremental && other.incremental {
            return Some(std::cmp::Ordering::Less);
        }

        // ...finally, when both are incremental, `other` takes precedence (so
        // `self` is always sorted after other same-urgency incremental
        // entries).
        Some(std::cmp::Ordering::Greater)
    }
}

impl Ord for StreamPriorityKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // `partial_cmp()` never returns `None`, so this should be safe.
        self.partial_cmp(other).unwrap()
    }
}

intrusive_adapter!(pub StreamWritablePriorityAdapter = Arc<StreamPriorityKey>: StreamPriorityKey { writable: RBTreeAtomicLink });

impl<'a> KeyAdapter<'a> for StreamWritablePriorityAdapter {
    type Key = StreamPriorityKey;

    fn get_key(&self, s: &StreamPriorityKey) -> Self::Key {
        s.clone()
    }
}

intrusive_adapter!(pub StreamReadablePriorityAdapter = Arc<StreamPriorityKey>: StreamPriorityKey { readable: RBTreeAtomicLink });

impl<'a> KeyAdapter<'a> for StreamReadablePriorityAdapter {
    type Key = StreamPriorityKey;

    fn get_key(&self, s: &StreamPriorityKey) -> Self::Key {
        s.clone()
    }
}

intrusive_adapter!(pub StreamFlushablePriorityAdapter = Arc<StreamPriorityKey>: StreamPriorityKey { flushable: RBTreeAtomicLink });

impl<'a> KeyAdapter<'a> for StreamFlushablePriorityAdapter {
    type Key = StreamPriorityKey;

    fn get_key(&self, s: &StreamPriorityKey) -> Self::Key {
        s.clone()
    }
}

/// An iterator over QUIC streams.
#[derive(Default)]
pub struct StreamIter {
    streams: SmallVec<[u64; 8]>,
    index: usize,
}

impl StreamIter {
    #[inline]
    fn from(streams: &StreamIdHashSet) -> Self {
        StreamIter {
            streams: streams.iter().copied().collect(),
            index: 0,
        }
    }
}

impl Iterator for StreamIter {
    type Item = u64;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let v = self.streams.get(self.index)?;
        self.index += 1;
        Some(*v)
    }
}

impl ExactSizeIterator for StreamIter {
    #[inline]
    fn len(&self) -> usize {
        self.streams.len() - self.index
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
    fn recv_flow_control() {
        let mut stream = Stream::new(0, 15, 0, true, true, DEFAULT_STREAM_WINDOW);
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
        assert!(!fin);

        assert!(stream.recv.almost_full());

        stream.recv.update_max_data(std::time::Instant::now());
        assert_eq!(stream.recv.max_data_next(), 25);
        assert!(!stream.recv.almost_full());

        let third = RangeBuf::from(b"something", 10, false);
        assert_eq!(stream.recv.write(third), Ok(()));
    }

    #[test]
    fn recv_past_fin() {
        let mut stream = Stream::new(0, 15, 0, true, true, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let first = RangeBuf::from(b"hello", 0, true);
        let second = RangeBuf::from(b"world", 5, false);

        assert_eq!(stream.recv.write(first), Ok(()));
        assert_eq!(stream.recv.write(second), Err(Error::FinalSize));
    }

    #[test]
    fn recv_fin_dup() {
        let mut stream = Stream::new(0, 15, 0, true, true, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let first = RangeBuf::from(b"hello", 0, true);
        let second = RangeBuf::from(b"hello", 0, true);

        assert_eq!(stream.recv.write(first), Ok(()));
        assert_eq!(stream.recv.write(second), Ok(()));

        let mut buf = [0; 32];

        let (len, fin) = stream.recv.emit(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"hello");
        assert!(fin);
    }

    #[test]
    fn recv_fin_change() {
        let mut stream = Stream::new(0, 15, 0, true, true, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let first = RangeBuf::from(b"hello", 0, true);
        let second = RangeBuf::from(b"world", 5, true);

        assert_eq!(stream.recv.write(second), Ok(()));
        assert_eq!(stream.recv.write(first), Err(Error::FinalSize));
    }

    #[test]
    fn recv_fin_lower_than_received() {
        let mut stream = Stream::new(0, 15, 0, true, true, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let first = RangeBuf::from(b"hello", 0, true);
        let second = RangeBuf::from(b"world", 5, false);

        assert_eq!(stream.recv.write(second), Ok(()));
        assert_eq!(stream.recv.write(first), Err(Error::FinalSize));
    }

    #[test]
    fn recv_fin_flow_control() {
        let mut stream = Stream::new(0, 15, 0, true, true, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let mut buf = [0; 32];

        let first = RangeBuf::from(b"hello", 0, false);
        let second = RangeBuf::from(b"world", 5, true);

        assert_eq!(stream.recv.write(first), Ok(()));
        assert_eq!(stream.recv.write(second), Ok(()));

        let (len, fin) = stream.recv.emit(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"helloworld");
        assert!(fin);

        assert!(!stream.recv.almost_full());
    }

    #[test]
    fn recv_fin_reset_mismatch() {
        let mut stream = Stream::new(0, 15, 0, true, true, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let first = RangeBuf::from(b"hello", 0, true);

        assert_eq!(stream.recv.write(first), Ok(()));
        assert_eq!(stream.recv.reset(0, 10), Err(Error::FinalSize));
    }

    #[test]
    fn recv_reset_dup() {
        let mut stream = Stream::new(0, 15, 0, true, true, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let first = RangeBuf::from(b"hello", 0, false);

        assert_eq!(stream.recv.write(first), Ok(()));
        assert_eq!(stream.recv.reset(0, 5), Ok(0));
        assert_eq!(stream.recv.reset(0, 5), Ok(0));
    }

    #[test]
    fn recv_reset_change() {
        let mut stream = Stream::new(0, 15, 0, true, true, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let first = RangeBuf::from(b"hello", 0, false);

        assert_eq!(stream.recv.write(first), Ok(()));
        assert_eq!(stream.recv.reset(0, 5), Ok(0));
        assert_eq!(stream.recv.reset(0, 10), Err(Error::FinalSize));
    }

    #[test]
    fn recv_reset_lower_than_received() {
        let mut stream = Stream::new(0, 15, 0, true, true, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let first = RangeBuf::from(b"hello", 0, false);

        assert_eq!(stream.recv.write(first), Ok(()));
        assert_eq!(stream.recv.reset(0, 4), Err(Error::FinalSize));
    }

    #[test]
    fn send_flow_control() {
        let mut buf = [0; 25];

        let mut stream = Stream::new(0, 0, 15, true, true, DEFAULT_STREAM_WINDOW);

        let first = b"hello";
        let second = b"world";
        let third = b"something";

        assert!(stream.send.write(first, false).is_ok());
        assert!(stream.send.write(second, false).is_ok());
        assert!(stream.send.write(third, false).is_ok());

        assert_eq!(stream.send.off_front(), 0);

        let (written, fin) = stream.send.emit(&mut buf[..25]).unwrap();
        assert_eq!(written, 15);
        assert!(!fin);
        assert_eq!(&buf[..written], b"helloworldsomet");

        assert_eq!(stream.send.off_front(), 15);

        let (written, fin) = stream.send.emit(&mut buf[..25]).unwrap();
        assert_eq!(written, 0);
        assert!(!fin);
        assert_eq!(&buf[..written], b"");

        stream.send.retransmit(0, 15);

        assert_eq!(stream.send.off_front(), 0);

        let (written, fin) = stream.send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 10);
        assert!(!fin);
        assert_eq!(&buf[..written], b"helloworld");

        assert_eq!(stream.send.off_front(), 10);

        let (written, fin) = stream.send.emit(&mut buf[..10]).unwrap();
        assert_eq!(written, 5);
        assert!(!fin);
        assert_eq!(&buf[..written], b"somet");
    }

    #[test]
    fn send_past_fin() {
        let mut stream = Stream::new(0, 0, 15, true, true, DEFAULT_STREAM_WINDOW);

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
        let mut stream = Stream::new(0, 0, 15, true, true, DEFAULT_STREAM_WINDOW);

        assert_eq!(stream.send.write(b"hello", true), Ok(5));
        assert!(stream.send.is_fin());

        assert_eq!(stream.send.write(b"", true), Ok(0));
        assert!(stream.send.is_fin());
    }

    #[test]
    fn send_undo_fin() {
        let mut stream = Stream::new(0, 0, 15, true, true, DEFAULT_STREAM_WINDOW);

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

        let mut stream = Stream::new(0, 0, 15, true, true, DEFAULT_STREAM_WINDOW);

        let slice = b"hellohellohello";

        assert!(stream.send.write(slice, true).is_ok());

        let (written, fin) = stream.send.emit(&mut buf[..15]).unwrap();
        assert_eq!(written, 15);
        assert!(fin);
        assert_eq!(&buf[..written], slice);
    }

    #[test]
    fn send_fin_zero_length() {
        let mut buf = [0; 5];

        let mut stream = Stream::new(0, 0, 15, true, true, DEFAULT_STREAM_WINDOW);

        assert_eq!(stream.send.write(b"hello", false), Ok(5));
        assert_eq!(stream.send.write(b"", true), Ok(0));
        assert!(stream.send.is_fin());

        let (written, fin) = stream.send.emit(&mut buf[..5]).unwrap();
        assert_eq!(written, 5);
        assert!(fin);
        assert_eq!(&buf[..written], b"hello");
    }

    #[test]
    fn send_ack() {
        let mut buf = [0; 5];

        let mut stream = Stream::new(0, 0, 15, true, true, DEFAULT_STREAM_WINDOW);

        assert_eq!(stream.send.write(b"hello", false), Ok(5));
        assert_eq!(stream.send.write(b"world", false), Ok(5));
        assert_eq!(stream.send.write(b"", true), Ok(0));
        assert!(stream.send.is_fin());

        assert_eq!(stream.send.off_front(), 0);

        let (written, fin) = stream.send.emit(&mut buf[..5]).unwrap();
        assert_eq!(written, 5);
        assert!(!fin);
        assert_eq!(&buf[..written], b"hello");

        stream.send.ack_and_drop(0, 5);

        stream.send.retransmit(0, 5);

        assert_eq!(stream.send.off_front(), 5);

        let (written, fin) = stream.send.emit(&mut buf[..5]).unwrap();
        assert_eq!(written, 5);
        assert!(fin);
        assert_eq!(&buf[..written], b"world");
    }

    #[test]
    fn send_ack_reordering() {
        let mut buf = [0; 5];

        let mut stream = Stream::new(0, 0, 15, true, true, DEFAULT_STREAM_WINDOW);

        assert_eq!(stream.send.write(b"hello", false), Ok(5));
        assert_eq!(stream.send.write(b"world", false), Ok(5));
        assert_eq!(stream.send.write(b"", true), Ok(0));
        assert!(stream.send.is_fin());

        assert_eq!(stream.send.off_front(), 0);

        let (written, fin) = stream.send.emit(&mut buf[..5]).unwrap();
        assert_eq!(written, 5);
        assert!(!fin);
        assert_eq!(&buf[..written], b"hello");

        assert_eq!(stream.send.off_front(), 5);

        let (written, fin) = stream.send.emit(&mut buf[..1]).unwrap();
        assert_eq!(written, 1);
        assert!(!fin);
        assert_eq!(&buf[..written], b"w");

        stream.send.ack_and_drop(5, 1);
        stream.send.ack_and_drop(0, 5);

        stream.send.retransmit(0, 5);
        stream.send.retransmit(5, 1);

        assert_eq!(stream.send.off_front(), 6);

        let (written, fin) = stream.send.emit(&mut buf[..5]).unwrap();
        assert_eq!(written, 4);
        assert!(fin);
        assert_eq!(&buf[..written], b"orld");
    }

    #[test]
    fn recv_data_below_off() {
        let mut stream = Stream::new(0, 15, 0, true, true, DEFAULT_STREAM_WINDOW);

        let first = RangeBuf::from(b"hello", 0, false);

        assert_eq!(stream.recv.write(first), Ok(()));

        let mut buf = [0; 10];

        let (len, fin) = stream.recv.emit(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"hello");
        assert!(!fin);

        let first = RangeBuf::from(b"elloworld", 1, true);
        assert_eq!(stream.recv.write(first), Ok(()));

        let (len, fin) = stream.recv.emit(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"world");
        assert!(fin);
    }

    #[test]
    fn stream_complete() {
        let mut stream =
            Stream::new(0, 30, 30, true, true, DEFAULT_STREAM_WINDOW);

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

        let mut stream = Stream::new(0, 0, 15, true, true, DEFAULT_STREAM_WINDOW);

        assert_eq!(stream.send.write(b"hello", false), Ok(5));
        assert_eq!(stream.send.off_front(), 0);
        assert!(!stream.send.is_fin());

        let (written, fin) = stream.send.emit(&mut buf).unwrap();
        assert_eq!(written, 5);
        assert!(!fin);
        assert_eq!(&buf[..written], b"hello");

        assert_eq!(stream.send.write(b"", true), Ok(0));
        assert!(stream.send.is_fin());
        assert_eq!(stream.send.off_front(), 5);

        let (written, fin) = stream.send.emit(&mut buf).unwrap();
        assert_eq!(written, 0);
        assert!(fin);
        assert_eq!(&buf[..written], b"");
    }

    #[test]
    fn send_emit() {
        let mut buf = [0; 5];

        let mut stream = Stream::new(0, 0, 20, true, true, DEFAULT_STREAM_WINDOW);

        assert_eq!(stream.send.write(b"hello", false), Ok(5));
        assert_eq!(stream.send.write(b"world", false), Ok(5));
        assert_eq!(stream.send.write(b"olleh", false), Ok(5));
        assert_eq!(stream.send.write(b"dlrow", true), Ok(5));
        assert_eq!(stream.send.off_front(), 0);
        assert_eq!(stream.send.bufs_count(), 4);

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

        let mut stream = Stream::new(0, 0, 20, true, true, DEFAULT_STREAM_WINDOW);

        assert_eq!(stream.send.write(b"hello", false), Ok(5));
        assert_eq!(stream.send.write(b"world", false), Ok(5));
        assert_eq!(stream.send.write(b"olleh", false), Ok(5));
        assert_eq!(stream.send.write(b"dlrow", true), Ok(5));
        assert_eq!(stream.send.off_front(), 0);
        assert_eq!(stream.send.bufs_count(), 4);

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
        assert_eq!(stream.send.bufs_count(), 3);

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..2]), Ok((2, false)));
        assert_eq!(stream.send.off_front(), 10);
        assert_eq!(&buf[..2], b"ld");

        stream.send.ack_and_drop(7, 5);
        assert_eq!(stream.send.bufs_count(), 3);

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..1]), Ok((1, false)));
        assert_eq!(stream.send.off_front(), 11);
        assert_eq!(&buf[..1], b"o");

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((5, false)));
        assert_eq!(stream.send.off_front(), 16);
        assert_eq!(&buf[..5], b"llehd");

        stream.send.ack_and_drop(5, 7);
        assert_eq!(stream.send.bufs_count(), 2);

        assert!(stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((4, true)));
        assert_eq!(stream.send.off_front(), 20);
        assert_eq!(&buf[..4], b"lrow");

        assert!(!stream.is_flushable());

        assert!(!stream.send.ready());
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((0, true)));
        assert_eq!(stream.send.off_front(), 20);

        stream.send.ack_and_drop(22, 4);
        assert_eq!(stream.send.bufs_count(), 2);

        stream.send.ack_and_drop(20, 1);
        assert_eq!(stream.send.bufs_count(), 2);
    }

    #[test]
    fn send_emit_retransmit() {
        let mut buf = [0; 5];

        let mut stream = Stream::new(0, 0, 20, true, true, DEFAULT_STREAM_WINDOW);

        assert_eq!(stream.send.write(b"hello", false), Ok(5));
        assert_eq!(stream.send.write(b"world", false), Ok(5));
        assert_eq!(stream.send.write(b"olleh", false), Ok(5));
        assert_eq!(stream.send.write(b"dlrow", true), Ok(5));
        assert_eq!(stream.send.off_front(), 0);
        assert_eq!(stream.send.bufs_count(), 4);

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
        assert!(buf.fin);

        assert_eq!(buf.len(), 10);
        assert_eq!(buf.off(), 5);
        assert!(buf.fin());

        assert_eq!(&buf[..], b"helloworld");

        // Advance buffer.
        buf.consume(5);

        assert_eq!(buf.start, 0);
        assert_eq!(buf.pos, 5);
        assert_eq!(buf.len, 10);
        assert_eq!(buf.off, 5);
        assert!(buf.fin);

        assert_eq!(buf.len(), 5);
        assert_eq!(buf.off(), 10);
        assert!(buf.fin());

        assert_eq!(&buf[..], b"world");

        // Split buffer before position.
        let mut new_buf = buf.split_off(3);

        assert_eq!(buf.start, 0);
        assert_eq!(buf.pos, 3);
        assert_eq!(buf.len, 3);
        assert_eq!(buf.off, 5);
        assert!(!buf.fin);

        assert_eq!(buf.len(), 0);
        assert_eq!(buf.off(), 8);
        assert!(!buf.fin());

        assert_eq!(&buf[..], b"");

        assert_eq!(new_buf.start, 3);
        assert_eq!(new_buf.pos, 5);
        assert_eq!(new_buf.len, 7);
        assert_eq!(new_buf.off, 8);
        assert!(new_buf.fin);

        assert_eq!(new_buf.len(), 5);
        assert_eq!(new_buf.off(), 10);
        assert!(new_buf.fin());

        assert_eq!(&new_buf[..], b"world");

        // Advance buffer.
        new_buf.consume(2);

        assert_eq!(new_buf.start, 3);
        assert_eq!(new_buf.pos, 7);
        assert_eq!(new_buf.len, 7);
        assert_eq!(new_buf.off, 8);
        assert!(new_buf.fin);

        assert_eq!(new_buf.len(), 3);
        assert_eq!(new_buf.off(), 12);
        assert!(new_buf.fin());

        assert_eq!(&new_buf[..], b"rld");

        // Split buffer after position.
        let mut new_new_buf = new_buf.split_off(5);

        assert_eq!(new_buf.start, 3);
        assert_eq!(new_buf.pos, 7);
        assert_eq!(new_buf.len, 5);
        assert_eq!(new_buf.off, 8);
        assert!(!new_buf.fin);

        assert_eq!(new_buf.len(), 1);
        assert_eq!(new_buf.off(), 12);
        assert!(!new_buf.fin());

        assert_eq!(&new_buf[..], b"r");

        assert_eq!(new_new_buf.start, 8);
        assert_eq!(new_new_buf.pos, 8);
        assert_eq!(new_new_buf.len, 2);
        assert_eq!(new_new_buf.off, 13);
        assert!(new_new_buf.fin);

        assert_eq!(new_new_buf.len(), 2);
        assert_eq!(new_new_buf.off(), 13);
        assert!(new_new_buf.fin());

        assert_eq!(&new_new_buf[..], b"ld");

        // Advance buffer.
        new_new_buf.consume(2);

        assert_eq!(new_new_buf.start, 8);
        assert_eq!(new_new_buf.pos, 10);
        assert_eq!(new_new_buf.len, 2);
        assert_eq!(new_new_buf.off, 13);
        assert!(new_new_buf.fin);

        assert_eq!(new_new_buf.len(), 0);
        assert_eq!(new_new_buf.off(), 15);
        assert!(new_new_buf.fin());

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

    fn cycle_stream_priority(stream_id: u64, streams: &mut StreamMap) {
        let key = streams.get(stream_id).unwrap().priority_key.clone();
        streams.update_priority(&key.clone(), &key);
    }

    #[test]
    fn writable_prioritized_default_priority() {
        let local_tp = crate::TransportParams::default();
        let peer_tp = crate::TransportParams {
            initial_max_stream_data_bidi_local: 100,
            initial_max_stream_data_uni: 100,
            ..Default::default()
        };

        let mut streams = StreamMap::new(100, 100, 100);

        for id in [0, 4, 8, 12] {
            assert!(streams
                .get_or_create(id, &local_tp, &peer_tp, false, true)
                .is_ok());
        }

        let walk_1: Vec<u64> = streams.writable().collect();
        cycle_stream_priority(*walk_1.first().unwrap(), &mut streams);
        let walk_2: Vec<u64> = streams.writable().collect();
        cycle_stream_priority(*walk_2.first().unwrap(), &mut streams);
        let walk_3: Vec<u64> = streams.writable().collect();
        cycle_stream_priority(*walk_3.first().unwrap(), &mut streams);
        let walk_4: Vec<u64> = streams.writable().collect();
        cycle_stream_priority(*walk_4.first().unwrap(), &mut streams);
        let walk_5: Vec<u64> = streams.writable().collect();

        // All streams are non-incremental and same urgency by default. Multiple
        // visits shuffle their order.
        assert_eq!(walk_1, vec![0, 4, 8, 12]);
        assert_eq!(walk_2, vec![4, 8, 12, 0]);
        assert_eq!(walk_3, vec![8, 12, 0, 4]);
        assert_eq!(walk_4, vec![12, 0, 4, 8,]);
        assert_eq!(walk_5, vec![0, 4, 8, 12]);
    }

    #[test]
    fn writable_prioritized_insert_order() {
        let local_tp = crate::TransportParams::default();
        let peer_tp = crate::TransportParams {
            initial_max_stream_data_bidi_local: 100,
            initial_max_stream_data_uni: 100,
            ..Default::default()
        };

        let mut streams = StreamMap::new(100, 100, 100);

        // Inserting same-urgency incremental streams in a "random" order yields
        // same order to start with.
        for id in [12, 4, 8, 0] {
            assert!(streams
                .get_or_create(id, &local_tp, &peer_tp, false, true)
                .is_ok());
        }

        let walk_1: Vec<u64> = streams.writable().collect();
        cycle_stream_priority(*walk_1.first().unwrap(), &mut streams);
        let walk_2: Vec<u64> = streams.writable().collect();
        cycle_stream_priority(*walk_2.first().unwrap(), &mut streams);
        let walk_3: Vec<u64> = streams.writable().collect();
        cycle_stream_priority(*walk_3.first().unwrap(), &mut streams);
        let walk_4: Vec<u64> = streams.writable().collect();
        cycle_stream_priority(*walk_4.first().unwrap(), &mut streams);
        let walk_5: Vec<u64> = streams.writable().collect();
        assert_eq!(walk_1, vec![12, 4, 8, 0]);
        assert_eq!(walk_2, vec![4, 8, 0, 12]);
        assert_eq!(walk_3, vec![8, 0, 12, 4,]);
        assert_eq!(walk_4, vec![0, 12, 4, 8]);
        assert_eq!(walk_5, vec![12, 4, 8, 0]);
    }

    #[test]
    fn writable_prioritized_mixed_urgency() {
        let local_tp = crate::TransportParams::default();
        let peer_tp = crate::TransportParams {
            initial_max_stream_data_bidi_local: 100,
            initial_max_stream_data_uni: 100,
            ..Default::default()
        };

        let mut streams = StreamMap::new(100, 100, 100);

        // Streams where the urgency descends (becomes more important). No stream
        // shares an urgency.
        let input = vec![
            (0, 100),
            (4, 90),
            (8, 80),
            (12, 70),
            (16, 60),
            (20, 50),
            (24, 40),
            (28, 30),
            (32, 20),
            (36, 10),
            (40, 0),
        ];

        for (id, urgency) in input.clone() {
            // this duplicates some code from stream_priority in order to access
            // streams and the collection they're in
            let stream = streams
                .get_or_create(id, &local_tp, &peer_tp, false, true)
                .unwrap();

            stream.urgency = urgency;

            let new_priority_key = Arc::new(StreamPriorityKey {
                urgency: stream.urgency,
                incremental: stream.incremental,
                id,
                ..Default::default()
            });

            let old_priority_key = std::mem::replace(
                &mut stream.priority_key,
                new_priority_key.clone(),
            );

            streams.update_priority(&old_priority_key, &new_priority_key);
        }

        let walk_1: Vec<u64> = streams.writable().collect();
        assert_eq!(walk_1, vec![40, 36, 32, 28, 24, 20, 16, 12, 8, 4, 0]);

        // Re-applying priority to a stream does not cause duplication.
        for (id, urgency) in input {
            // this duplicates some code from stream_priority in order to access
            // streams and the collection they're in
            let stream = streams
                .get_or_create(id, &local_tp, &peer_tp, false, true)
                .unwrap();

            stream.urgency = urgency;

            let new_priority_key = Arc::new(StreamPriorityKey {
                urgency: stream.urgency,
                incremental: stream.incremental,
                id,
                ..Default::default()
            });

            let old_priority_key = std::mem::replace(
                &mut stream.priority_key,
                new_priority_key.clone(),
            );

            streams.update_priority(&old_priority_key, &new_priority_key);
        }

        let walk_2: Vec<u64> = streams.writable().collect();
        assert_eq!(walk_2, vec![40, 36, 32, 28, 24, 20, 16, 12, 8, 4, 0]);

        // Removing streams doesn't break expected ordering.
        streams.collect(24, true);

        let walk_3: Vec<u64> = streams.writable().collect();
        assert_eq!(walk_3, vec![40, 36, 32, 28, 20, 16, 12, 8, 4, 0]);

        streams.collect(40, true);
        streams.collect(0, true);

        let walk_4: Vec<u64> = streams.writable().collect();
        assert_eq!(walk_4, vec![36, 32, 28, 20, 16, 12, 8, 4]);

        // Adding streams doesn't break expected ordering.
        streams
            .get_or_create(44, &local_tp, &peer_tp, false, true)
            .unwrap();

        let walk_5: Vec<u64> = streams.writable().collect();
        assert_eq!(walk_5, vec![36, 32, 28, 20, 16, 12, 8, 4, 44]);
    }

    #[test]
    fn writable_prioritized_mixed_urgencies_incrementals() {
        let local_tp = crate::TransportParams::default();
        let peer_tp = crate::TransportParams {
            initial_max_stream_data_bidi_local: 100,
            initial_max_stream_data_uni: 100,
            ..Default::default()
        };

        let mut streams = StreamMap::new(100, 100, 100);

        // Streams that share some urgency level
        let input = vec![
            (0, 100),
            (4, 20),
            (8, 100),
            (12, 20),
            (16, 90),
            (20, 25),
            (24, 90),
            (28, 30),
            (32, 80),
            (36, 20),
            (40, 0),
        ];

        for (id, urgency) in input.clone() {
            // this duplicates some code from stream_priority in order to access
            // streams and the collection they're in
            let stream = streams
                .get_or_create(id, &local_tp, &peer_tp, false, true)
                .unwrap();

            stream.urgency = urgency;

            let new_priority_key = Arc::new(StreamPriorityKey {
                urgency: stream.urgency,
                incremental: stream.incremental,
                id,
                ..Default::default()
            });

            let old_priority_key = std::mem::replace(
                &mut stream.priority_key,
                new_priority_key.clone(),
            );

            streams.update_priority(&old_priority_key, &new_priority_key);
        }

        let walk_1: Vec<u64> = streams.writable().collect();
        cycle_stream_priority(4, &mut streams);
        cycle_stream_priority(16, &mut streams);
        cycle_stream_priority(0, &mut streams);
        let walk_2: Vec<u64> = streams.writable().collect();
        cycle_stream_priority(12, &mut streams);
        cycle_stream_priority(24, &mut streams);
        cycle_stream_priority(8, &mut streams);
        let walk_3: Vec<u64> = streams.writable().collect();
        cycle_stream_priority(36, &mut streams);
        cycle_stream_priority(16, &mut streams);
        cycle_stream_priority(0, &mut streams);
        let walk_4: Vec<u64> = streams.writable().collect();
        cycle_stream_priority(4, &mut streams);
        cycle_stream_priority(24, &mut streams);
        cycle_stream_priority(8, &mut streams);
        let walk_5: Vec<u64> = streams.writable().collect();
        cycle_stream_priority(12, &mut streams);
        cycle_stream_priority(16, &mut streams);
        cycle_stream_priority(0, &mut streams);
        let walk_6: Vec<u64> = streams.writable().collect();
        cycle_stream_priority(36, &mut streams);
        cycle_stream_priority(24, &mut streams);
        cycle_stream_priority(8, &mut streams);
        let walk_7: Vec<u64> = streams.writable().collect();
        cycle_stream_priority(4, &mut streams);
        cycle_stream_priority(16, &mut streams);
        cycle_stream_priority(0, &mut streams);
        let walk_8: Vec<u64> = streams.writable().collect();
        cycle_stream_priority(12, &mut streams);
        cycle_stream_priority(24, &mut streams);
        cycle_stream_priority(8, &mut streams);
        let walk_9: Vec<u64> = streams.writable().collect();
        cycle_stream_priority(36, &mut streams);
        cycle_stream_priority(16, &mut streams);
        cycle_stream_priority(0, &mut streams);

        assert_eq!(walk_1, vec![40, 4, 12, 36, 20, 28, 32, 16, 24, 0, 8]);
        assert_eq!(walk_2, vec![40, 12, 36, 4, 20, 28, 32, 24, 16, 8, 0]);
        assert_eq!(walk_3, vec![40, 36, 4, 12, 20, 28, 32, 16, 24, 0, 8]);
        assert_eq!(walk_4, vec![40, 4, 12, 36, 20, 28, 32, 24, 16, 8, 0]);
        assert_eq!(walk_5, vec![40, 12, 36, 4, 20, 28, 32, 16, 24, 0, 8]);
        assert_eq!(walk_6, vec![40, 36, 4, 12, 20, 28, 32, 24, 16, 8, 0]);
        assert_eq!(walk_7, vec![40, 4, 12, 36, 20, 28, 32, 16, 24, 0, 8]);
        assert_eq!(walk_8, vec![40, 12, 36, 4, 20, 28, 32, 24, 16, 8, 0]);
        assert_eq!(walk_9, vec![40, 36, 4, 12, 20, 28, 32, 16, 24, 0, 8]);

        // Removing streams doesn't break expected ordering.
        streams.collect(20, true);

        let walk_10: Vec<u64> = streams.writable().collect();
        assert_eq!(walk_10, vec![40, 4, 12, 36, 28, 32, 24, 16, 8, 0]);

        // Adding streams doesn't break expected ordering.
        let stream = streams
            .get_or_create(44, &local_tp, &peer_tp, false, true)
            .unwrap();

        stream.urgency = 20;
        stream.incremental = true;

        let new_priority_key = Arc::new(StreamPriorityKey {
            urgency: stream.urgency,
            incremental: stream.incremental,
            id: 44,
            ..Default::default()
        });

        let old_priority_key =
            std::mem::replace(&mut stream.priority_key, new_priority_key.clone());

        streams.update_priority(&old_priority_key, &new_priority_key);

        let walk_11: Vec<u64> = streams.writable().collect();
        assert_eq!(walk_11, vec![40, 4, 12, 36, 44, 28, 32, 24, 16, 8, 0]);
    }

    #[test]
    fn priority_tree_dupes() {
        let mut prioritized_writable: RBTree<StreamWritablePriorityAdapter> =
            Default::default();

        for id in [0, 4, 8, 12] {
            let s = Arc::new(StreamPriorityKey {
                urgency: 0,
                incremental: false,
                id,
                ..Default::default()
            });

            prioritized_writable.insert(s);
        }

        let walk_1: Vec<u64> =
            prioritized_writable.iter().map(|s| s.id).collect();
        assert_eq!(walk_1, vec![0, 4, 8, 12]);

        // Default keys could cause duplicate entries, this is normally protected
        // against via StreamMap.
        for id in [0, 4, 8, 12] {
            let s = Arc::new(StreamPriorityKey {
                urgency: 0,
                incremental: false,
                id,
                ..Default::default()
            });

            prioritized_writable.insert(s);
        }

        let walk_2: Vec<u64> =
            prioritized_writable.iter().map(|s| s.id).collect();
        assert_eq!(walk_2, vec![0, 0, 4, 4, 8, 8, 12, 12]);
    }
}

mod recv_buf;
mod send_buf;
