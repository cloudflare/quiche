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

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use std::collections::hash_map;
use std::collections::HashMap;
use std::collections::HashSet;

use intrusive_collections::intrusive_adapter;
use intrusive_collections::KeyAdapter;
use intrusive_collections::RBTree;
use intrusive_collections::RBTreeAtomicLink;

use smallvec::SmallVec;

use crate::buffers::DefaultBufFactory;
use crate::BufFactory;
use crate::Error;
use crate::Result;

const DEFAULT_URGENCY: u8 = 127;

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

/// Return value type of `RecvBuf::reset()`
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct RecvBufResetReturn {
    /// Returns the difference between the previous max_data offset
    /// received and the final size reported by the reset
    pub max_data_delta: u64,

    /// The amount of flow control credit that should be returned to the
    /// connection level flow control.
    pub consumed_flowcontrol: u64,
}

impl RecvBufResetReturn {
    pub fn zero() -> Self {
        Self {
            max_data_delta: 0,
            consumed_flowcontrol: 0,
        }
    }
}

/// Action to perform when reading from a stream's receive buffer.
pub enum RecvAction<T: bytes::BufMut> {
    /// Emit data by copying it into the provided buffer.
    Emit { out: T },
    /// Discard up to the specified number of bytes without copying.
    Discard { len: usize },
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

/// One of the priority queues a stream can be scheduled in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PriorityQueue {
    Readable,
    Writable,
    Flushable,
}

/// Keeps track of QUIC streams and enforces stream limits.
#[derive(Default)]
pub struct StreamMap<F: BufFactory = DefaultBufFactory> {
    /// Map of streams indexed by stream ID.
    streams: StreamIdHashMap<Stream<F>>,

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

    /// Initial maximum bidirectional stream count.
    initial_max_streams_bidi: u64,

    /// Local maximum unidirectional stream count limit.
    local_max_streams_uni: u64,
    local_max_streams_uni_next: u64,

    /// Initial maximum unidirectional stream count.
    initial_max_streams_uni: u64,

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

    /// Total number of bytes in send buffers across all streams.
    tx_buffered: usize,

    /// Source of round-robin positions. A stream takes the next value when it
    /// is created, and again each time it is cycled, which places it behind
    /// the other streams in its priority group.
    ///
    /// Must not wrap: a stream ahead of the wrap would sit at the back of
    /// every group, never picked and so never cycled back into rotation.
    sequence_counter: SequenceCounter,
}

/// A distinct type so that taking a position borrows only the counter, leaving
/// the stream map borrowable at the same time.
#[derive(Default)]
struct SequenceCounter(u64);

impl SequenceCounter {
    fn advance(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(1);
        self.0
    }
}

impl<F: BufFactory> StreamMap<F> {
    pub fn new(
        max_streams_bidi: u64, max_streams_uni: u64, max_stream_window: u64,
    ) -> Self {
        StreamMap {
            local_max_streams_bidi: max_streams_bidi,
            local_max_streams_bidi_next: max_streams_bidi,
            initial_max_streams_bidi: max_streams_bidi,

            local_max_streams_uni: max_streams_uni,
            local_max_streams_uni_next: max_streams_uni,
            initial_max_streams_uni: max_streams_uni,

            max_stream_window,

            ..StreamMap::default()
        }
    }

    /// Returns the stream with the given ID if it exists.
    pub fn get(&self, id: u64) -> Option<&Stream<F>> {
        self.streams.get(&id)
    }

    /// Returns the mutable stream with the given ID if it exists.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut Stream<F>> {
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
    ) -> Result<&mut Stream<F>> {
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
                        let n = cmp::max(
                            self.local_opened_streams_bidi,
                            stream_sequence + 1,
                        );

                        if n > self.peer_max_streams_bidi {
                            return Err(Error::StreamLimit);
                        }

                        self.local_opened_streams_bidi = n;
                    },

                    (true, false) => {
                        let n = cmp::max(
                            self.local_opened_streams_uni,
                            stream_sequence + 1,
                        );

                        if n > self.peer_max_streams_uni {
                            return Err(Error::StreamLimit);
                        }

                        self.local_opened_streams_uni = n;
                    },

                    (false, true) => {
                        let n = cmp::max(
                            self.peer_opened_streams_bidi,
                            stream_sequence + 1,
                        );

                        if n > self.local_max_streams_bidi {
                            return Err(Error::StreamLimit);
                        }

                        self.peer_opened_streams_bidi = n;
                    },

                    (false, false) => {
                        let n = cmp::max(
                            self.peer_opened_streams_uni,
                            stream_sequence + 1,
                        );

                        if n > self.local_max_streams_uni {
                            return Err(Error::StreamLimit);
                        }

                        self.peer_opened_streams_uni = n;
                    },
                };

                let initial_window = max_rx_data;

                let sequence = self.sequence_counter.advance();

                let s = Stream::new(
                    id,
                    max_rx_data,
                    max_tx_data,
                    local,
                    initial_window,
                    self.max_stream_window,
                );

                s.priority_key.set_sequences(sequence);

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
            // SAFETY: `priority_key` is the `Arc` this tree holds; see
            // `StreamPriorityKey`.
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
            // SAFETY: `priority_key` is the `Arc` this tree holds; see
            // `StreamPriorityKey`.
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
            // SAFETY: `priority_key` is the `Arc` this tree holds; see
            // `StreamPriorityKey`.
            unsafe { self.flushable.cursor_mut_from_ptr(ptr) }
        };

        c.remove();
    }

    pub fn peek_flushable(&self) -> Option<Arc<StreamPriorityKey>> {
        self.flushable.front().clone_pointer()
    }

    /// Updates the priorities of a stream.
    fn update_priority(
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

    /// Records that a stream was serviced in one queue, moving it to the back
    /// of its priority group there.
    ///
    /// Call this from every point that services a stream. Whether the service
    /// left the stream in the queue, whether the stream still exists, and
    /// whether it is incremental are all decided here, so a service point
    /// needs no condition of its own. The stream's position in the other
    /// queues is left alone.
    ///
    /// The new position is recorded even when the stream is not currently in
    /// the queue, so that it re-enters at the back rather than where it left
    /// off.
    pub fn cycle_priority(&mut self, stream_id: u64, queue: PriorityQueue) {
        let Some(stream) = self.streams.get(&stream_id) else {
            return;
        };

        // A non-incremental stream has no round-robin position to move:
        // `position` masks the sequence out for it.
        if !stream.priority_key.incremental {
            return;
        }

        let key = Arc::clone(&stream.priority_key);
        let sequence = self.sequence_counter.advance();

        // The queue is sorted by the value being changed, so unlink first.
        let linked = self.remove_from(queue, &key);
        key.set_sequence(queue, sequence);

        if linked {
            self.insert_into(queue, &key);
        }
    }

    /// Removes the stream from `queue`, returning whether it was linked there.
    fn remove_from(
        &mut self, queue: PriorityQueue, key: &Arc<StreamPriorityKey>,
    ) -> bool {
        let linked = match queue {
            PriorityQueue::Readable => key.readable.is_linked(),
            PriorityQueue::Writable => key.writable.is_linked(),
            PriorityQueue::Flushable => key.flushable.is_linked(),
        };

        match queue {
            PriorityQueue::Readable => self.remove_readable(key),
            PriorityQueue::Writable => self.remove_writable(key),
            PriorityQueue::Flushable => self.remove_flushable(key),
        }

        linked
    }

    fn insert_into(
        &mut self, queue: PriorityQueue, key: &Arc<StreamPriorityKey>,
    ) {
        match queue {
            PriorityQueue::Readable => self.insert_readable(key),
            PriorityQueue::Writable => self.insert_writable(key),
            PriorityQueue::Flushable => self.insert_flushable(key),
        }
    }

    /// Sets a stream's urgency and incremental flag.
    ///
    /// Urgency and the incremental flag apply to every queue, so the stream
    /// moves to the back of its new priority group in all of them. The key is
    /// replaced rather than edited in place because the queues order
    /// themselves by its contents.
    pub fn set_priority(
        &mut self, stream_id: u64, urgency: u8, incremental: bool,
    ) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };

        if stream.urgency == urgency && stream.incremental == incremental {
            return;
        }

        stream.urgency = urgency;
        stream.incremental = incremental;

        let sequence = self.sequence_counter.advance();

        let new = Arc::new(StreamPriorityKey::new(
            stream_id,
            urgency,
            incremental,
            sequence,
        ));
        let old = std::mem::replace(&mut stream.priority_key, Arc::clone(&new));

        self.update_priority(&old, &new);
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

    /// Sets the max_streams_bidi limit to the given value.
    pub fn set_max_streams_bidi(&mut self, max: u64) {
        self.local_max_streams_bidi = max;
        self.local_max_streams_bidi_next = max;
        self.initial_max_streams_bidi = max;
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

    /// Returns the peer's current maximum bidirectional stream count limit.
    pub fn peer_max_streams_bidi(&self) -> u64 {
        self.peer_max_streams_bidi
    }

    /// Returns the number of bidirectional streams that can be created
    /// before the peer's stream count limit is reached.
    pub fn peer_streams_left_bidi(&self) -> u64 {
        self.peer_max_streams_bidi - self.local_opened_streams_bidi
    }

    /// Returns the peer's current maximum unidirectional stream count limit.
    pub fn peer_max_streams_uni(&self) -> u64 {
        self.peer_max_streams_uni
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
    pub fn blocked(&self) -> hash_map::Iter<'_, u64, u64> {
        self.blocked.iter()
    }

    /// Creates an iterator over streams that need to send RESET_STREAM.
    pub fn reset(&self) -> hash_map::Iter<'_, u64, (u64, u64)> {
        self.reset.iter()
    }

    /// Creates an iterator over streams that need to send STOP_SENDING.
    pub fn stopped(&self) -> hash_map::Iter<'_, u64, u64> {
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
    ///
    /// This only sends MAX_STREAMS when available capacity is at or below 50%
    /// of the initial maximum streams target.
    pub fn should_update_max_streams_bidi(&self) -> bool {
        let available = self
            .local_max_streams_bidi
            .saturating_sub(self.peer_opened_streams_bidi);
        self.local_max_streams_bidi_next != self.local_max_streams_bidi &&
            available <= self.initial_max_streams_bidi / 2
    }

    /// Returns true if the max unidirectional streams count needs to be updated
    /// by sending a MAX_STREAMS frame to the peer.
    ///
    /// This only send MAX_STREAMS when available capacity is at or below 50% of
    /// the initial maximum streams target.
    pub fn should_update_max_streams_uni(&self) -> bool {
        let available = self
            .local_max_streams_uni
            .saturating_sub(self.peer_opened_streams_uni);
        self.local_max_streams_uni_next != self.local_max_streams_uni &&
            available <= self.initial_max_streams_uni / 2
    }

    /// Returns the number of active streams in the map.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// Returns the total number of bytes buffered across all streams.
    pub(crate) fn tx_buffered(&self) -> usize {
        self.tx_buffered
    }

    /// Computes the actual number of bytes in send buffers by summing across
    /// all streams. This is used for debugging to verify that tx_buffered
    /// is accurate.
    fn tx_buffered_actual(&self) -> usize {
        self.streams
            .values()
            .map(|s| s.send.buffered_bytes() as usize)
            .sum()
    }

    /// Checks if the stored tx_buffered matches the actual value.
    /// Returns true if they match, false otherwise.
    pub(crate) fn tx_buffered_is_consistent(&self) -> bool {
        self.tx_buffered == self.tx_buffered_actual()
    }

    /// Updates the tx_buffered value by adding the delta.
    pub(crate) fn add_tx_buffered(&mut self, delta: usize) {
        self.tx_buffered += delta;

        #[cfg(debug_assertions)]
        self.debug_check_tx_buffered_consistency();
    }

    /// Updates the tx_buffered value by subtracting the delta.
    pub(crate) fn sub_tx_buffered(&mut self, delta: usize) {
        debug_assert!(self.tx_buffered >= delta);
        self.tx_buffered = self.tx_buffered.saturating_sub(delta);

        #[cfg(debug_assertions)]
        self.debug_check_tx_buffered_consistency();
    }

    /// Verifies that the stored tx_buffered value matches the actual bytes in
    /// send buffers across all streams. Enabled in debug builds to catch
    /// inconsistencies early.
    #[cfg(debug_assertions)]
    pub(crate) fn debug_check_tx_buffered_consistency(&self) {
        if !self.tx_buffered_is_consistent() {
            let buffered_per_stream = self
                .streams
                .iter()
                .map(|(id, s)| (*id, s.send.buffered_bytes()))
                .collect::<Vec<_>>();

            let actual = self.tx_buffered_actual();
            let stored = self.tx_buffered;
            panic!(
                "tx_buffered mismatch: stored={}, actual={}, diff={}, buffered_per_stream={:?}",
                stored,
                actual,
                stored as i64 - actual as i64,
                buffered_per_stream
            );
        }
    }
}

/// A QUIC stream.
pub struct Stream<F: BufFactory = DefaultBufFactory> {
    /// Receive-side stream buffer.
    pub recv: recv_buf::RecvBuf,

    /// Send-side stream buffer.
    pub send: send_buf::SendBuf<F>,

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

impl<F: BufFactory> Stream<F> {
    /// Creates a new stream with the given flow control limits.
    pub fn new(
        id: u64, max_rx_data: u64, max_tx_data: u64, local: bool,
        initial_window: u64, max_window: u64,
    ) -> Self {
        let priority_key = Arc::new(StreamPriorityKey {
            id,
            ..Default::default()
        });

        Stream {
            recv: recv_buf::RecvBuf::new(max_rx_data, initial_window, max_window),
            send: send_buf::SendBuf::new(max_tx_data),
            send_lowat: 1,
            bidi: is_bidi(id),
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
        let off_front = self.send.off_front();

        !self.send.is_empty() &&
            off_front < self.send.off_back() &&
            off_front < self.send.max_off()
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

/// A stream's entry in the three priority queues.
///
/// Each queue links this key rather than the stream, and removal is by raw
/// pointer, so the `Arc` a queue holds must stay the one `Stream::priority_key`
/// holds. Cycling reuses the key, and the only code that replaces it
/// (`StreamMap::set_priority`) hands the old `Arc` to `update_priority` to
/// relink every queue.
#[derive(Debug)]
pub struct StreamPriorityKey {
    pub urgency: u8,
    pub incremental: bool,
    pub id: u64,

    /// Round-robin position within a priority group, one per queue. Each
    /// queue reads only its own field, so servicing a stream in one queue does
    /// not reorder it in the others.
    ///
    /// Atomic for interior mutability, not for concurrency: the key is shared
    /// through an `Arc` with the queues, and it has to stay `Sync` to keep
    /// `Connection` `Send`. Every access is made through `&StreamMap` or
    /// `&mut StreamMap` from one thread, so `Relaxed` orders nothing that needs
    /// ordering.
    readable_sequence: AtomicU64,
    writable_sequence: AtomicU64,
    flushable_sequence: AtomicU64,

    pub readable: RBTreeAtomicLink,
    pub writable: RBTreeAtomicLink,
    pub flushable: RBTreeAtomicLink,
}

impl StreamPriorityKey {
    /// A key for a stream at the given priority, starting at `sequence` in
    /// every queue and linked in none of them.
    fn new(id: u64, urgency: u8, incremental: bool, sequence: u64) -> Self {
        Self {
            id,
            urgency,
            incremental,
            readable_sequence: AtomicU64::new(sequence),
            writable_sequence: AtomicU64::new(sequence),
            flushable_sequence: AtomicU64::new(sequence),
            readable: Default::default(),
            writable: Default::default(),
            flushable: Default::default(),
        }
    }
}

impl Default for StreamPriorityKey {
    fn default() -> Self {
        Self::new(0, DEFAULT_URGENCY, true, 0)
    }
}

/// A stream's position in one priority queue.
///
/// The derived ordering compares the fields in declaration order: urgency,
/// then non-incremental ahead of incremental, then the queue's round-robin
/// sequence, then stream ID. `sequence` is only meaningful for incremental
/// streams, so it is masked out otherwise to keep non-incremental streams
/// ordered by ID.
///
/// See [RFC 9218 Section 4] for urgency and incremental semantics.
///
/// [RFC 9218 Section 4]: https://www.rfc-editor.org/rfc/rfc9218.html#section-4
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct StreamPriorityPosition {
    urgency: u8,
    incremental: bool,
    sequence: u64,
    id: u64,
}

impl StreamPriorityKey {
    fn position(&self, sequence: u64) -> StreamPriorityPosition {
        StreamPriorityPosition {
            urgency: self.urgency,
            incremental: self.incremental,
            sequence: if self.incremental { sequence } else { 0 },
            id: self.id,
        }
    }

    fn readable_sequence(&self) -> u64 {
        self.readable_sequence.load(Ordering::Relaxed)
    }

    fn writable_sequence(&self) -> u64 {
        self.writable_sequence.load(Ordering::Relaxed)
    }

    fn flushable_sequence(&self) -> u64 {
        self.flushable_sequence.load(Ordering::Relaxed)
    }

    /// Sets this stream's position in `queue`.
    ///
    /// Only sound while the stream is unlinked from `queue`: the queue orders
    /// itself by this value, so changing it under a linked node would leave
    /// the queue sorted by a stale key. The other queues read their own
    /// fields and are unaffected.
    fn set_sequence(&self, queue: PriorityQueue, sequence: u64) {
        let (field, linked) = match queue {
            PriorityQueue::Readable =>
                (&self.readable_sequence, self.readable.is_linked()),
            PriorityQueue::Writable =>
                (&self.writable_sequence, self.writable.is_linked()),
            PriorityQueue::Flushable =>
                (&self.flushable_sequence, self.flushable.is_linked()),
        };

        debug_assert!(!linked, "stream {} is still linked in {queue:?}", self.id);

        field.store(sequence, Ordering::Relaxed);
    }

    /// Sets this stream's position in every queue.
    fn set_sequences(&self, sequence: u64) {
        self.set_sequence(PriorityQueue::Readable, sequence);
        self.set_sequence(PriorityQueue::Writable, sequence);
        self.set_sequence(PriorityQueue::Flushable, sequence);
    }
}

intrusive_adapter!(pub StreamWritablePriorityAdapter = Arc<StreamPriorityKey>: StreamPriorityKey { writable: RBTreeAtomicLink });

impl KeyAdapter<'_> for StreamWritablePriorityAdapter {
    type Key = StreamPriorityPosition;

    fn get_key(&self, s: &StreamPriorityKey) -> Self::Key {
        s.position(s.writable_sequence())
    }
}

intrusive_adapter!(pub StreamReadablePriorityAdapter = Arc<StreamPriorityKey>: StreamPriorityKey { readable: RBTreeAtomicLink });

impl KeyAdapter<'_> for StreamReadablePriorityAdapter {
    type Key = StreamPriorityPosition;

    fn get_key(&self, s: &StreamPriorityKey) -> Self::Key {
        s.position(s.readable_sequence())
    }
}

intrusive_adapter!(pub StreamFlushablePriorityAdapter = Arc<StreamPriorityKey>: StreamPriorityKey { flushable: RBTreeAtomicLink });

impl KeyAdapter<'_> for StreamFlushablePriorityAdapter {
    type Key = StreamPriorityPosition;

    fn get_key(&self, s: &StreamPriorityKey) -> Self::Key {
        s.position(s.flushable_sequence())
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

#[cfg(test)]
mod tests {
    use crate::range_buf::RangeBuf;

    use super::*;

    /// The default size of the receiver stream flow control window.
    const DEFAULT_STREAM_WINDOW: u64 = 32 * 1024;

    #[test]
    fn recv_flow_control() {
        let mut stream = <Stream>::new(0, 15, 0, true, 15, DEFAULT_STREAM_WINDOW);
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
        let mut stream = <Stream>::new(0, 15, 0, true, 15, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let first = RangeBuf::from(b"hello", 0, true);
        let second = RangeBuf::from(b"world", 5, false);

        assert_eq!(stream.recv.write(first), Ok(()));
        assert_eq!(stream.recv.write(second), Err(Error::FinalSize));
    }

    #[test]
    fn recv_fin_dup() {
        let mut stream = <Stream>::new(0, 15, 0, true, 15, DEFAULT_STREAM_WINDOW);
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
        let mut stream = <Stream>::new(0, 15, 0, true, 15, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let first = RangeBuf::from(b"hello", 0, true);
        let second = RangeBuf::from(b"world", 5, true);

        assert_eq!(stream.recv.write(second), Ok(()));
        assert_eq!(stream.recv.write(first), Err(Error::FinalSize));
    }

    #[test]
    fn recv_fin_lower_than_received() {
        let mut stream = <Stream>::new(0, 15, 0, true, 15, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let first = RangeBuf::from(b"hello", 0, true);
        let second = RangeBuf::from(b"world", 5, false);

        assert_eq!(stream.recv.write(second), Ok(()));
        assert_eq!(stream.recv.write(first), Err(Error::FinalSize));
    }

    #[test]
    fn recv_fin_flow_control() {
        let mut stream = <Stream>::new(0, 15, 0, true, 15, DEFAULT_STREAM_WINDOW);
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
        let mut stream = <Stream>::new(0, 15, 0, true, 15, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let first = RangeBuf::from(b"hello", 0, true);

        assert_eq!(stream.recv.write(first), Ok(()));
        assert_eq!(stream.recv.reset(0, 10), Err(Error::FinalSize));
    }

    #[test]
    fn recv_reset_with_gap() {
        let mut stream = <Stream>::new(0, 15, 0, true, 15, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let first = RangeBuf::from(b"hello", 0, false);

        assert_eq!(stream.recv.write(first), Ok(()));
        // Read one byte.
        assert_eq!(stream.recv.emit(&mut [0; 1]), Ok((1, false)));
        // Reset with a final size > than max previously received
        assert_eq!(
            stream.recv.reset(0, 10),
            Ok(RecvBufResetReturn {
                max_data_delta: 5,
                // consumed_flowcontrol is 9, since we already read 1 byte
                consumed_flowcontrol: 9
            })
        );
        assert_eq!(stream.recv.reset(0, 10), Ok(RecvBufResetReturn::zero()));
    }

    #[test]
    fn recv_reset_dup() {
        let mut stream = <Stream>::new(0, 15, 0, true, 15, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let first = RangeBuf::from(b"hello", 0, false);

        assert_eq!(stream.recv.write(first), Ok(()));
        assert_eq!(
            stream.recv.reset(0, 5),
            Ok(RecvBufResetReturn {
                max_data_delta: 0,
                consumed_flowcontrol: 5
            })
        );
        assert_eq!(stream.recv.reset(0, 5), Ok(RecvBufResetReturn::zero()));
    }

    #[test]
    fn recv_reset_change() {
        let mut stream = <Stream>::new(0, 15, 0, true, 15, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let first = RangeBuf::from(b"hello", 0, false);

        assert_eq!(stream.recv.write(first), Ok(()));
        assert_eq!(
            stream.recv.reset(0, 5),
            Ok(RecvBufResetReturn {
                max_data_delta: 0,
                consumed_flowcontrol: 5
            })
        );
        assert_eq!(stream.recv.reset(0, 10), Err(Error::FinalSize));
    }

    #[test]
    fn recv_reset_lower_than_received() {
        let mut stream = <Stream>::new(0, 15, 0, true, 15, DEFAULT_STREAM_WINDOW);
        assert!(!stream.recv.almost_full());

        let first = RangeBuf::from(b"hello", 0, false);

        assert_eq!(stream.recv.write(first), Ok(()));
        assert_eq!(stream.recv.reset(0, 4), Err(Error::FinalSize));
    }

    #[test]
    fn send_flow_control() {
        let mut buf = [0; 25];

        let mut stream = <Stream>::new(0, 0, 15, true, 0, DEFAULT_STREAM_WINDOW);

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
        let mut stream = <Stream>::new(0, 0, 15, true, 0, DEFAULT_STREAM_WINDOW);

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
        let mut stream = <Stream>::new(0, 0, 15, true, 0, DEFAULT_STREAM_WINDOW);

        assert_eq!(stream.send.write(b"hello", true), Ok(5));
        assert!(stream.send.is_fin());

        assert_eq!(stream.send.write(b"", true), Ok(0));
        assert!(stream.send.is_fin());
    }

    #[test]
    fn send_undo_fin() {
        let mut stream = <Stream>::new(0, 0, 15, true, 0, DEFAULT_STREAM_WINDOW);

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

        let mut stream = <Stream>::new(0, 0, 15, true, 0, DEFAULT_STREAM_WINDOW);

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

        let mut stream = <Stream>::new(0, 0, 15, true, 0, DEFAULT_STREAM_WINDOW);

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

        let mut stream = <Stream>::new(0, 0, 15, true, 0, DEFAULT_STREAM_WINDOW);

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

        let mut stream = <Stream>::new(0, 0, 15, true, 0, DEFAULT_STREAM_WINDOW);

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
        let mut stream = <Stream>::new(0, 15, 0, true, 15, DEFAULT_STREAM_WINDOW);

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
            <Stream>::new(0, 30, 30, true, 30, DEFAULT_STREAM_WINDOW);

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

        let mut stream = <Stream>::new(0, 0, 15, true, 0, DEFAULT_STREAM_WINDOW);

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

    fn stream_send_ready(stream: &Stream) -> bool {
        !stream.send.is_empty() &&
            stream.send.off_front() < stream.send.off_back()
    }

    #[test]
    fn send_emit() {
        let mut buf = [0; 5];

        let mut stream = <Stream>::new(0, 0, 20, true, 0, DEFAULT_STREAM_WINDOW);

        assert_eq!(stream.send.write(b"hello", false), Ok(5));
        assert_eq!(stream.send.write(b"world", false), Ok(5));
        assert_eq!(stream.send.write(b"olleh", false), Ok(5));
        assert_eq!(stream.send.write(b"dlrow", true), Ok(5));
        assert_eq!(stream.send.off_front(), 0);
        assert_eq!(stream.send.bufs_count(), 4);

        assert!(stream.is_flushable());

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..4]), Ok((4, false)));
        assert_eq!(stream.send.off_front(), 4);
        assert_eq!(&buf[..4], b"hell");

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..4]), Ok((4, false)));
        assert_eq!(stream.send.off_front(), 8);
        assert_eq!(&buf[..4], b"owor");

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..2]), Ok((2, false)));
        assert_eq!(stream.send.off_front(), 10);
        assert_eq!(&buf[..2], b"ld");

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..1]), Ok((1, false)));
        assert_eq!(stream.send.off_front(), 11);
        assert_eq!(&buf[..1], b"o");

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((5, false)));
        assert_eq!(stream.send.off_front(), 16);
        assert_eq!(&buf[..5], b"llehd");

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((4, true)));
        assert_eq!(stream.send.off_front(), 20);
        assert_eq!(&buf[..4], b"lrow");

        assert!(!stream.is_flushable());

        assert!(!stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((0, true)));
        assert_eq!(stream.send.off_front(), 20);
    }

    #[test]
    fn send_emit_ack() {
        let mut buf = [0; 5];

        let mut stream = <Stream>::new(0, 0, 20, true, 0, DEFAULT_STREAM_WINDOW);

        assert_eq!(stream.send.write(b"hello", false), Ok(5));
        assert_eq!(stream.send.write(b"world", false), Ok(5));
        assert_eq!(stream.send.write(b"olleh", false), Ok(5));
        assert_eq!(stream.send.write(b"dlrow", true), Ok(5));
        assert_eq!(stream.send.off_front(), 0);
        assert_eq!(stream.send.bufs_count(), 4);

        assert!(stream.is_flushable());

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..4]), Ok((4, false)));
        assert_eq!(stream.send.off_front(), 4);
        assert_eq!(&buf[..4], b"hell");

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..4]), Ok((4, false)));
        assert_eq!(stream.send.off_front(), 8);
        assert_eq!(&buf[..4], b"owor");

        stream.send.ack_and_drop(0, 5);
        assert_eq!(stream.send.bufs_count(), 3);

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..2]), Ok((2, false)));
        assert_eq!(stream.send.off_front(), 10);
        assert_eq!(&buf[..2], b"ld");

        stream.send.ack_and_drop(7, 5);
        assert_eq!(stream.send.bufs_count(), 3);

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..1]), Ok((1, false)));
        assert_eq!(stream.send.off_front(), 11);
        assert_eq!(&buf[..1], b"o");

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((5, false)));
        assert_eq!(stream.send.off_front(), 16);
        assert_eq!(&buf[..5], b"llehd");

        stream.send.ack_and_drop(5, 7);
        assert_eq!(stream.send.bufs_count(), 2);

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((4, true)));
        assert_eq!(stream.send.off_front(), 20);
        assert_eq!(&buf[..4], b"lrow");

        assert!(!stream.is_flushable());

        assert!(!stream_send_ready(&stream));
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

        let mut stream = <Stream>::new(
            0,
            0,
            20,
            true,
            DEFAULT_STREAM_WINDOW,
            DEFAULT_STREAM_WINDOW,
        );

        assert_eq!(stream.send.write(b"hello", false), Ok(5));
        assert_eq!(stream.send.write(b"world", false), Ok(5));
        assert_eq!(stream.send.write(b"olleh", false), Ok(5));
        assert_eq!(stream.send.write(b"dlrow", true), Ok(5));
        assert_eq!(stream.send.off_front(), 0);
        assert_eq!(stream.send.bufs_count(), 4);

        assert!(stream.is_flushable());

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..4]), Ok((4, false)));
        assert_eq!(stream.send.off_front(), 4);
        assert_eq!(&buf[..4], b"hell");

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..4]), Ok((4, false)));
        assert_eq!(stream.send.off_front(), 8);
        assert_eq!(&buf[..4], b"owor");

        stream.send.retransmit(3, 3);
        assert_eq!(stream.send.off_front(), 3);

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..3]), Ok((3, false)));
        assert_eq!(stream.send.off_front(), 8);
        assert_eq!(&buf[..3], b"low");

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..2]), Ok((2, false)));
        assert_eq!(stream.send.off_front(), 10);
        assert_eq!(&buf[..2], b"ld");

        stream.send.ack_and_drop(7, 2);

        stream.send.retransmit(8, 2);

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..2]), Ok((2, false)));
        assert_eq!(stream.send.off_front(), 10);
        assert_eq!(&buf[..2], b"ld");

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..1]), Ok((1, false)));
        assert_eq!(stream.send.off_front(), 11);
        assert_eq!(&buf[..1], b"o");

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((5, false)));
        assert_eq!(stream.send.off_front(), 16);
        assert_eq!(&buf[..5], b"llehd");

        stream.send.retransmit(12, 2);

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..2]), Ok((2, false)));
        assert_eq!(stream.send.off_front(), 16);
        assert_eq!(&buf[..2], b"le");

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((4, true)));
        assert_eq!(stream.send.off_front(), 20);
        assert_eq!(&buf[..4], b"lrow");

        assert!(!stream.is_flushable());

        assert!(!stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((0, true)));
        assert_eq!(stream.send.off_front(), 20);

        stream.send.retransmit(7, 12);

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((5, false)));
        assert_eq!(stream.send.off_front(), 12);
        assert_eq!(&buf[..5], b"rldol");

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((5, false)));
        assert_eq!(stream.send.off_front(), 17);
        assert_eq!(&buf[..5], b"lehdl");

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((2, false)));
        assert_eq!(stream.send.off_front(), 20);
        assert_eq!(&buf[..2], b"ro");

        stream.send.ack_and_drop(12, 7);

        stream.send.retransmit(7, 12);

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((5, false)));
        assert_eq!(stream.send.off_front(), 12);
        assert_eq!(&buf[..5], b"rldol");

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((5, false)));
        assert_eq!(stream.send.off_front(), 17);
        assert_eq!(&buf[..5], b"lehdl");

        assert!(stream_send_ready(&stream));
        assert_eq!(stream.send.emit(&mut buf[..5]), Ok((2, false)));
        assert_eq!(stream.send.off_front(), 20);
        assert_eq!(&buf[..2], b"ro");
    }

    #[test]
    fn rangebuf_split_off() {
        let mut buf = <RangeBuf>::from(b"helloworld", 5, true);
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

        let mut streams = <StreamMap>::new(5, 5, 5);

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

        let mut streams = <StreamMap>::new(5, 5, 5);

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

        let mut streams = <StreamMap>::new(3, 3, 3);

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
        streams.cycle_priority(stream_id, PriorityQueue::Writable);
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

        let mut streams = <StreamMap>::new(100, 100, 100);

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
            streams
                .get_or_create(id, &local_tp, &peer_tp, false, true)
                .unwrap();
            streams.set_priority(id, urgency, true);
        }

        let walk_1: Vec<u64> = streams.writable().collect();
        assert_eq!(walk_1, vec![40, 36, 32, 28, 24, 20, 16, 12, 8, 4, 0]);

        // Re-applying priority to a stream does not cause duplication. Set a
        // different urgency and back, since setting the urgency a stream
        // already has does nothing.
        for (id, urgency) in input {
            streams.set_priority(id, urgency + 1, true);
            streams.set_priority(id, urgency, true);
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
            streams
                .get_or_create(id, &local_tp, &peer_tp, false, true)
                .unwrap();
            streams.set_priority(id, urgency, true);
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
        streams
            .get_or_create(44, &local_tp, &peer_tp, false, true)
            .unwrap();
        streams.set_priority(44, 20, true);

        let walk_11: Vec<u64> = streams.writable().collect();
        assert_eq!(walk_11, vec![40, 4, 12, 36, 44, 28, 32, 24, 16, 8, 0]);

        // Re-applying the priority a stream already has must not move it. An
        // application that reasserts unchanged priorities would otherwise
        // reset the round-robin position of every stream it names.
        for (id, urgency) in input {
            streams.set_priority(id, urgency, true);
        }

        let walk_12: Vec<u64> = streams.writable().collect();
        assert_eq!(walk_12, walk_11);
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

    #[test]
    fn retransmit_returns_zero_when_already_acked() {
        let mut stream = <Stream>::new(0, 15, 15, true, 0, 15);

        // Write and emit some data.
        assert_eq!(stream.send.write(b"hello", false), Ok(5));
        assert_eq!(stream.send.buffered_bytes(), 5);

        let mut buf = [0; 10];
        let (written, _) = stream.send.emit(&mut buf).unwrap();
        assert_eq!(written, 5);
        assert_eq!(stream.send.buffered_bytes(), 0);

        // Mark data for retransmission.
        let retransmitted = stream.send.retransmit(0, 5);
        assert_eq!(retransmitted, 5);
        assert_eq!(stream.send.buffered_bytes(), 5);

        // Ack the data.
        stream.send.ack_and_drop(0, 5);
        assert_eq!(stream.send.buffered_bytes(), 0);

        // Try to retransmit again - should return 0 since data is acked.
        let retransmitted = stream.send.retransmit(0, 5);
        assert_eq!(retransmitted, 0);
        assert_eq!(stream.send.buffered_bytes(), 0);
    }

    #[test]
    fn retransmit_returns_partial_when_some_acked() {
        let mut stream = <Stream>::new(0, 15, 15, true, 0, 15);

        // Write and emit 10 bytes.
        assert_eq!(stream.send.write(b"helloworld", false), Ok(10));
        assert_eq!(stream.send.buffered_bytes(), 10);

        let mut buf = [0; 10];
        let (written, _) = stream.send.emit(&mut buf).unwrap();
        assert_eq!(written, 10);
        assert_eq!(stream.send.buffered_bytes(), 0);

        // Mark all data for retransmission.
        let retransmitted = stream.send.retransmit(0, 10);
        assert_eq!(retransmitted, 10);
        assert_eq!(stream.send.buffered_bytes(), 10);

        // Ack first 5 bytes and drop them.
        let dropped = stream.send.ack_and_drop(0, 5);
        assert_eq!(dropped, 5);
        assert_eq!(stream.send.buffered_bytes(), 5);

        // Try to retransmit all 10 bytes - should return 5 since first 5 are
        // acked.
        let retransmitted = stream.send.retransmit(0, 10);
        assert_eq!(retransmitted, 0); // Already marked, so no change
        assert_eq!(stream.send.buffered_bytes(), 5);
    }

    #[test]
    fn ack_and_drop_decrements_len_and_returns_dropped() {
        let mut stream = <Stream>::new(0, 15, 15, true, 0, 15);

        // Write some data.
        assert_eq!(stream.send.write(b"hello", false), Ok(5));
        assert_eq!(stream.send.buffered_bytes(), 5);

        // Emit it.
        let mut buf = [0; 10];
        let (written, _) = stream.send.emit(&mut buf).unwrap();
        assert_eq!(written, 5);
        assert_eq!(stream.send.buffered_bytes(), 0);

        // Mark for retransmission.
        let retransmitted = stream.send.retransmit(0, 5);
        assert_eq!(retransmitted, 5);
        assert_eq!(stream.send.buffered_bytes(), 5);

        // Ack and drop - should decrement len and return dropped amount.
        let dropped = stream.send.ack_and_drop(0, 5);
        assert_eq!(dropped, 5);
        assert_eq!(stream.send.buffered_bytes(), 0);
    }

    #[test]
    fn ack_and_drop_partial_buffer() {
        let mut stream = <Stream>::new(0, 30, 30, true, 0, 30);

        // Write and emit two chunks.
        assert_eq!(stream.send.write(b"hello", false), Ok(5));
        assert_eq!(stream.send.write(b"world", false), Ok(5));
        assert_eq!(stream.send.buffered_bytes(), 10);

        let mut buf = [0; 10];
        let (written, _) = stream.send.emit(&mut buf).unwrap();
        assert_eq!(written, 10);
        assert_eq!(stream.send.buffered_bytes(), 0);

        // Mark both chunks for retransmission.
        let retransmitted = stream.send.retransmit(0, 10);
        assert_eq!(retransmitted, 10);
        assert_eq!(stream.send.buffered_bytes(), 10);

        // Ack and drop only first chunk.
        let dropped = stream.send.ack_and_drop(0, 5);
        assert_eq!(dropped, 5);
        assert_eq!(stream.send.buffered_bytes(), 5);

        // Ack and drop second chunk.
        let dropped = stream.send.ack_and_drop(5, 5);
        assert_eq!(dropped, 5);
        assert_eq!(stream.send.buffered_bytes(), 0);
    }

    #[test]
    fn ack_and_drop_returns_zero_when_nothing_dropped() {
        let mut stream = <Stream>::new(0, 15, 15, true, 0, 15);

        // Write and emit data.
        assert_eq!(stream.send.write(b"hello", false), Ok(5));
        let mut buf = [0; 10];
        let (written, _) = stream.send.emit(&mut buf).unwrap();
        assert_eq!(written, 5);

        // Ack data that's already been fully emitted and not retransmitted.
        // Nothing should be dropped since there's no buffered data.
        let dropped = stream.send.ack_and_drop(0, 5);
        assert_eq!(dropped, 0);
        assert_eq!(stream.send.buffered_bytes(), 0);
    }

    #[test]
    fn cache_consistency_through_full_lifecycle() {
        // This test verifies that StreamMap.tx_buffered stays in sync with
        // actual buffered data through a full lifecycle: write → emit →
        // retransmit → ack.
        let mut streams = <StreamMap>::new(5, 5, 15);

        // Create a stream using low-level StreamMap interface.
        let local_params = crate::TransportParams {
            initial_max_data: 30,
            initial_max_stream_data_bidi_local: 15,
            initial_max_stream_data_bidi_remote: 15,
            initial_max_stream_data_uni: 10,
            initial_max_streams_bidi: 5,
            initial_max_streams_uni: 5,
            ..Default::default()
        };
        let peer_params = local_params.clone();

        // Update peer stream limits to allow locally-initiated streams.
        streams.update_peer_max_streams_bidi(5);
        streams.update_peer_max_streams_uni(5);

        let stream_id = 0u64;

        // Write data: both stream.send.buffered_bytes() and tx_buffered increase.
        {
            let stream = streams
                .get_or_create(
                    stream_id,
                    &local_params,
                    &peer_params,
                    true,
                    false,
                )
                .unwrap();
            assert_eq!(stream.send.write(b"hello", false), Ok(5));
        }
        streams.add_tx_buffered(5);
        assert_eq!(streams.get(stream_id).unwrap().send.buffered_bytes(), 5);
        assert_eq!(streams.tx_buffered(), 5);
        assert!(streams.tx_buffered_is_consistent());

        // Emit data: both stream.send.buffered_bytes() and tx_buffered decrease.
        let mut buf = [0; 10];
        let written = {
            let stream = streams.get_mut(stream_id).unwrap();
            let (written, _) = stream.send.emit(&mut buf).unwrap();
            written
        };
        assert_eq!(written, 5);
        streams.sub_tx_buffered(5);
        assert_eq!(streams.get(stream_id).unwrap().send.buffered_bytes(), 0);
        assert_eq!(streams.tx_buffered(), 0);
        assert!(streams.tx_buffered_is_consistent());

        // Retransmit: both stream.send.buffered_bytes() and tx_buffered increase
        // by actual amount retransmitted.
        let retransmitted = {
            let stream = streams.get_mut(stream_id).unwrap();
            stream.send.retransmit(0, 5)
        };
        assert_eq!(retransmitted, 5);
        streams.add_tx_buffered(retransmitted);
        assert_eq!(streams.get(stream_id).unwrap().send.buffered_bytes(), 5);
        assert_eq!(streams.tx_buffered(), 5);
        assert!(streams.tx_buffered_is_consistent());

        // Ack and drop: both stream.send.buffered_bytes() and tx_buffered
        // decrease by actual amount dropped.
        let dropped = {
            let stream = streams.get_mut(stream_id).unwrap();
            stream.send.ack_and_drop(0, 5)
        };
        assert_eq!(dropped, 5);
        streams.sub_tx_buffered(dropped);
        assert_eq!(streams.get(stream_id).unwrap().send.buffered_bytes(), 0);
        assert_eq!(streams.tx_buffered(), 0);
        assert!(streams.tx_buffered_is_consistent());
    }

    #[test]
    fn send_buf_len_reflects_buffered_data() {
        let mut stream = <Stream>::new(0, 15, 15, true, 0, 15);

        // Initially empty.
        assert_eq!(stream.send.buffered_bytes(), 0);

        // After write.
        assert_eq!(stream.send.write(b"hello", false), Ok(5));
        assert_eq!(stream.send.buffered_bytes(), 5);

        // After emit.
        let mut buf = [0; 10];
        let (written, _) = stream.send.emit(&mut buf).unwrap();
        assert_eq!(written, 5);
        assert_eq!(stream.send.buffered_bytes(), 0);

        // After retransmit.
        let retransmitted = stream.send.retransmit(0, 5);
        assert_eq!(retransmitted, 5);
        assert_eq!(stream.send.buffered_bytes(), 5);

        // After ack_and_drop.
        let dropped = stream.send.ack_and_drop(0, 5);
        assert_eq!(dropped, 5);
        assert_eq!(stream.send.buffered_bytes(), 0);
    }

    /// At equal urgency, non-incremental streams are served ahead of
    /// incremental ones, and among themselves in stream ID order regardless of
    /// when they were created or last serviced (RFC 9218 Section 4).
    ///
    /// A non-incremental stream has no round-robin position, so cycling must
    /// not move it. This is what masking the sequence in `position` provides,
    /// and what the field order of `StreamPriorityPosition` encodes.
    #[test]
    fn non_incremental_ahead_of_incremental() {
        let local_tp = crate::TransportParams::default();
        let peer_tp = crate::TransportParams {
            initial_max_stream_data_bidi_local: 100,
            initial_max_stream_data_uni: 100,
            ..Default::default()
        };

        let mut streams: StreamMap = StreamMap::new(100, 100, 100);

        // Created out of ID order, and the non-incremental ones last.
        for (id, incremental) in [(8, true), (0, true), (12, false), (4, false)] {
            streams
                .get_or_create(id, &local_tp, &peer_tp, false, true)
                .unwrap();
            streams.set_priority(id, DEFAULT_URGENCY, incremental);
        }

        assert_eq!(streams.writable().collect::<Vec<u64>>(), vec![4, 12, 8, 0]);

        // Cycling cannot move a non-incremental stream.
        streams.cycle_priority(4, PriorityQueue::Writable);
        assert_eq!(streams.writable().collect::<Vec<u64>>(), vec![4, 12, 8, 0]);

        // An incremental stream cycles behind its incremental peers only.
        streams.cycle_priority(8, PriorityQueue::Writable);
        assert_eq!(streams.writable().collect::<Vec<u64>>(), vec![4, 12, 0, 8]);
    }

    /// Cycling a stream in one queue must not move it in the others, while
    /// setting its priority must move it in all of them.
    ///
    /// A stream can sit in the flushable, readable and writable queues at
    /// once. Reading from it reschedules only what is read next; it must not
    /// reorder what is sent, which is scheduled from the client's priority
    /// signals rather than from local read behaviour. Urgency and the
    /// incremental flag, in contrast, select the priority group in every
    /// queue.
    #[test]
    fn cycle_priority_is_per_queue() {
        let local_tp = crate::TransportParams::default();
        let peer_tp = crate::TransportParams {
            initial_max_stream_data_bidi_local: 100,
            initial_max_stream_data_uni: 100,
            ..Default::default()
        };

        let mut streams: StreamMap = StreamMap::new(100, 100, 100);

        for id in [4, 8, 12] {
            streams
                .get_or_create(id, &local_tp, &peer_tp, false, true)
                .unwrap();
            streams
                .get_mut(id)
                .unwrap()
                .send
                .write(b"data", false)
                .unwrap();
            let priority_key = Arc::clone(&streams.get(id).unwrap().priority_key);
            streams.insert_flushable(&priority_key);
            streams.insert_readable(&priority_key);
            streams.insert_writable(&priority_key);
        }

        macro_rules! order {
            ($tree:expr) => {{
                let mut v = Vec::new();
                let mut c = $tree.front();
                while let Some(k) = c.get() {
                    v.push(k.id);
                    c.move_next();
                }
                v
            }};
        }

        assert_eq!(order!(streams.flushable), vec![4, 8, 12]);
        assert_eq!(order!(streams.readable), vec![4, 8, 12]);
        assert_eq!(order!(streams.writable), vec![4, 8, 12]);

        // A read moves the stream in the readable queue only.
        streams.cycle_priority(4, PriorityQueue::Readable);
        assert_eq!(order!(streams.readable), vec![8, 12, 4]);
        assert_eq!(order!(streams.flushable), vec![4, 8, 12]);
        assert_eq!(order!(streams.writable), vec![4, 8, 12]);

        // A send moves it in the flushable queue only.
        streams.cycle_priority(4, PriorityQueue::Flushable);
        assert_eq!(order!(streams.flushable), vec![8, 12, 4]);
        assert_eq!(order!(streams.readable), vec![8, 12, 4]);
        assert_eq!(order!(streams.writable), vec![4, 8, 12]);

        // And a write moves it in the writable queue only.
        streams.cycle_priority(4, PriorityQueue::Writable);
        assert_eq!(order!(streams.writable), vec![8, 12, 4]);
        assert_eq!(order!(streams.flushable), vec![8, 12, 4]);
        assert_eq!(order!(streams.readable), vec![8, 12, 4]);

        // Setting a priority moves the stream in every queue. Set a different
        // urgency and back, since setting the urgency a stream already has
        // does nothing.
        streams.set_priority(8, DEFAULT_URGENCY + 1, true);
        streams.set_priority(8, DEFAULT_URGENCY, true);
        assert_eq!(order!(streams.readable), vec![12, 4, 8]);
        assert_eq!(order!(streams.writable), vec![12, 4, 8]);
        assert_eq!(order!(streams.flushable), vec![12, 4, 8]);
    }

    /// A stream created after another has been serviced starts behind it.
    ///
    /// A new stream takes the current round-robin position in each queue. With
    /// the default position it would sort ahead of every stream that has ever
    /// been serviced, and so preempt streams that have been waiting since
    /// before it existed.
    #[test]
    fn new_stream_starts_at_the_back() {
        let local_tp = crate::TransportParams::default();
        let peer_tp = crate::TransportParams {
            initial_max_stream_data_bidi_local: 100,
            initial_max_stream_data_uni: 100,
            ..Default::default()
        };

        let mut streams: StreamMap = StreamMap::new(100, 100, 100);

        let link = |streams: &mut StreamMap, id| {
            streams
                .get_or_create(id, &local_tp, &peer_tp, false, true)
                .unwrap();
            streams
                .get_mut(id)
                .unwrap()
                .send
                .write(b"data", false)
                .unwrap();
            let key = Arc::clone(&streams.get(id).unwrap().priority_key);
            streams.insert_readable(&key);
            streams.insert_flushable(&key);
        };

        link(&mut streams, 4);
        link(&mut streams, 8);

        // Service stream 4 in every queue, so it sits behind stream 8.
        for queue in [
            PriorityQueue::Readable,
            PriorityQueue::Writable,
            PriorityQueue::Flushable,
        ] {
            streams.cycle_priority(4, queue);
        }

        link(&mut streams, 12);

        assert_eq!(streams.readable().collect::<Vec<u64>>(), vec![8, 4, 12]);
        assert_eq!(streams.writable().collect::<Vec<u64>>(), vec![8, 4, 12]);
        assert_eq!(
            streams.flushable.iter().map(|k| k.id).collect::<Vec<u64>>(),
            vec![8, 4, 12]
        );
    }

    /// Cycling a queue the stream is not linked in must not add it there.
    ///
    /// Callers cycle a stream whenever they service it, including when that
    /// service removed it from the queue, so `cycle_priority` is routinely
    /// asked to cycle a queue the stream is absent from.
    #[test]
    fn cycle_priority_no_phantom_entries() {
        let local_tp = crate::TransportParams::default();
        let peer_tp = crate::TransportParams {
            initial_max_stream_data_bidi_local: 100,
            initial_max_stream_data_uni: 100,
            ..Default::default()
        };

        let mut streams: StreamMap = StreamMap::new(100, 100, 100);

        // get_or_create leaves the stream writable, so take it back out to
        // leave it linked in the flushable queue alone.
        streams
            .get_or_create(4, &local_tp, &peer_tp, false, true)
            .unwrap();
        streams
            .get_mut(4)
            .unwrap()
            .send
            .write(b"data", false)
            .unwrap();
        let priority_key = Arc::clone(&streams.get(4).unwrap().priority_key);
        streams.remove_writable(&priority_key);
        streams.insert_flushable(&priority_key);

        assert!(streams.readable().next().is_none());
        assert!(streams.writable().next().is_none());
        assert_eq!(streams.peek_flushable().unwrap().id, 4);

        streams.cycle_priority(4, PriorityQueue::Readable);
        streams.cycle_priority(4, PriorityQueue::Writable);

        assert!(streams.readable().next().is_none());
        assert!(streams.writable().next().is_none());

        let before = streams.get(4).unwrap().priority_key.flushable_sequence();

        streams.cycle_priority(4, PriorityQueue::Flushable);

        // The stream moved rather than being left where it was.
        assert_ne!(
            streams.get(4).unwrap().priority_key.flushable_sequence(),
            before
        );

        assert_eq!(streams.peek_flushable().unwrap().id, 4);
    }
}

mod recv_buf;
mod send_buf;
