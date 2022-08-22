// Copyright (C) 2022, Cloudflare, Inc.
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

use crate::Error;
use crate::Result;

use crate::frame;
use crate::packet::ConnectionId;

use std::collections::VecDeque;

/// A structure holding a `ConnectionId` and all its related metadata.
#[derive(Debug, Default)]
pub struct ConnectionIdEntry {
    /// The Connection ID.
    pub cid: ConnectionId<'static>,

    /// Its associated sequence number.
    pub seq: u64,

    /// Its associated reset token. Initial CIDs may not have any reset token.
    pub reset_token: Option<u128>,

    /// The path identifier using this CID, if any.
    pub path_id: Option<usize>,
}

#[derive(Default)]
struct BoundedNonEmptyConnectionIdVecDeque {
    /// The inner `VecDeque`.
    inner: VecDeque<ConnectionIdEntry>,

    /// The maximum number of elements that the `VecDeque` can have.
    capacity: usize,
}

impl BoundedNonEmptyConnectionIdVecDeque {
    /// Creates a `VecDeque` bounded by `capacity` and inserts
    /// `initial_entry` in it.
    fn new(capacity: usize, initial_entry: ConnectionIdEntry) -> Self {
        let mut inner = VecDeque::with_capacity(1);
        inner.push_back(initial_entry);
        Self { inner, capacity }
    }

    /// Updates the maximum capacity of the inner `VecDeque` to `new_capacity`.
    /// Does nothing if `new_capacity` is lower or equal to the current
    /// `capacity`.
    fn resize(&mut self, new_capacity: usize) {
        if new_capacity > self.capacity {
            self.capacity = new_capacity;
        }
    }

    /// Returns the oldest inserted entry still present in the `VecDeque`.
    fn get_oldest(&self) -> &ConnectionIdEntry {
        self.inner.front().expect("vecdeque is empty")
    }

    /// Gets a immutable reference to the entry having the provided `seq`.
    fn get(&self, seq: u64) -> Option<&ConnectionIdEntry> {
        // We need to iterate over the whole map to find the key.
        self.inner.iter().find(|e| e.seq == seq)
    }

    /// Gets a mutable reference to the entry having the provided `seq`.
    fn get_mut(&mut self, seq: u64) -> Option<&mut ConnectionIdEntry> {
        // We need to iterate over the whole map to find the key.
        self.inner.iter_mut().find(|e| e.seq == seq)
    }

    /// Returns an iterator over the entries in the `VecDeque`.
    fn iter(&self) -> impl Iterator<Item = &ConnectionIdEntry> {
        self.inner.iter()
    }

    /// Returns the number of elements in the `VecDeque`.
    fn len(&self) -> usize {
        self.inner.len()
    }

    /// Inserts the provided entry in the `VecDeque`.
    ///
    /// This method ensures the unicity of the `seq` associated to an entry. If
    /// an entry has the same `seq` than `e`, this method updates the entry in
    /// the `VecDeque` and the number of stored elements remains unchanged.
    ///
    /// If inserting a new element would exceed the collection's capacity, this
    /// method raises an [`IdLimit`].
    ///
    /// [`IdLimit`]: enum.Error.html#IdLimit
    fn insert(&mut self, e: ConnectionIdEntry) -> Result<()> {
        // Ensure we don't have duplicates.
        match self.get_mut(e.seq) {
            Some(oe) => *oe = e,
            None => {
                if self.inner.len() == self.capacity {
                    return Err(Error::IdLimit);
                }
                self.inner.push_back(e);
            },
        };
        Ok(())
    }

    /// Removes all the elements in the collection and inserts the provided one.
    fn clear_and_insert(&mut self, e: ConnectionIdEntry) {
        self.inner.clear();
        self.inner.push_back(e);
    }

    /// Removes the element in the collection having the provided `seq`.
    ///
    /// If this method is called when there remains a single element in the
    /// collection, this method raises an [`OutOfIdentifiers`].
    ///
    /// Returns `Some` if the element was in the collection and removed, or
    /// `None` if it was not and nothing was modified.
    ///
    /// [`OutOfIdentifiers`]: enum.Error.html#OutOfIdentifiers
    fn remove(&mut self, seq: u64) -> Result<Option<ConnectionIdEntry>> {
        if self.inner.len() <= 1 {
            return Err(Error::OutOfIdentifiers);
        }

        Ok(self
            .inner
            .iter()
            .position(|e| e.seq == seq)
            .and_then(|index| self.inner.remove(index)))
    }

    /// Removes all the elements in the collection whose `seq` is lower than the
    /// provided one, and inserts `e` in the collection.
    ///
    /// For each removed element `re`, `f(re)` is called.
    ///
    /// If the inserted element has a `seq` lower than the one used to remove
    /// elements, it raises an [`OutOfIdentifiers`].
    ///
    /// [`OutOfIdentifiers`]: enum.Error.html#OutOfIdentifiers
    fn remove_lower_than_and_insert<F>(
        &mut self, seq: u64, e: ConnectionIdEntry, mut f: F,
    ) -> Result<()>
    where
        F: FnMut(&ConnectionIdEntry),
    {
        // The insert entry MUST have a sequence higher or equal to the ones
        // being retired.
        if e.seq < seq {
            return Err(Error::OutOfIdentifiers);
        }

        // To avoid exceeding the capacity of the inner `VecDeque`, we first
        // remove the elements and then insert the new one.
        self.inner.retain(|e| {
            if e.seq < seq {
                f(e);
                false
            } else {
                true
            }
        });

        // Note that if no element has been retired and the `VecDeque` reaches
        // its capacity limit, this will raise an `IdLimit`.
        self.insert(e)
    }
}

/// An iterator over QUIC Connection IDs.
pub struct ConnectionIdIter {
    cids: VecDeque<ConnectionId<'static>>,
}

impl Iterator for ConnectionIdIter {
    type Item = ConnectionId<'static>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.cids.pop_front()
    }
}

impl ExactSizeIterator for ConnectionIdIter {
    #[inline]
    fn len(&self) -> usize {
        self.cids.len()
    }
}

#[derive(Default)]
pub struct ConnectionIdentifiers {
    /// All the Destination Connection IDs provided by our peer.
    dcids: BoundedNonEmptyConnectionIdVecDeque,

    /// All the Source Connection IDs we provide to our peer.
    scids: BoundedNonEmptyConnectionIdVecDeque,

    /// Source Connection IDs that should be announced to the peer.
    advertise_new_scid_seqs: VecDeque<u64>,

    /// Retired Destination Connection IDs that should be announced to the peer.
    retire_dcid_seqs: VecDeque<u64>,

    /// Retired Source Connection IDs that should be notified to the
    /// application.
    retired_scids: VecDeque<ConnectionId<'static>>,

    /// Largest "Retire Prior To" we received from the peer.
    largest_peer_retire_prior_to: u64,

    /// Largest sequence number we received from the peer.
    largest_destination_seq: u64,

    /// Next sequence number to use.
    next_scid_seq: u64,

    /// "Retire Prior To" value to advertise to the peer.
    retire_prior_to: u64,

    /// The maximum number of source Connection IDs our peer allows us.
    source_conn_id_limit: usize,

    /// Does the host use zero-length source Connection ID.
    zero_length_scid: bool,

    /// Does the host use zero-length destination Connection ID.
    zero_length_dcid: bool,
}

impl ConnectionIdentifiers {
    /// Creates a new `ConnectionIdentifiers` with the specified destination
    /// connection ID limit and initial source Connection ID. The destination
    /// Connection ID is set to the empty one.
    pub fn new(
        mut destination_conn_id_limit: usize, initial_scid: &ConnectionId,
        initial_path_id: usize, reset_token: Option<u128>,
    ) -> ConnectionIdentifiers {
        // It must be at least 2.
        if destination_conn_id_limit < 2 {
            destination_conn_id_limit = 2;
        }

        // Initially, the limit of active source connection IDs is 2.
        let source_conn_id_limit = 2;

        // Record the zero-length SCID status.
        let zero_length_scid = initial_scid.is_empty();

        let initial_scid =
            ConnectionId::from_ref(initial_scid.as_ref()).into_owned();

        // We need to track up to (2 * source_conn_id_limit - 1) source
        // Connection IDs when the host wants to force their renewal.
        let scids = BoundedNonEmptyConnectionIdVecDeque::new(
            2 * source_conn_id_limit - 1,
            ConnectionIdEntry {
                cid: initial_scid,
                seq: 0,
                reset_token,
                path_id: Some(initial_path_id),
            },
        );

        let dcids = BoundedNonEmptyConnectionIdVecDeque::new(
            destination_conn_id_limit,
            ConnectionIdEntry {
                cid: ConnectionId::default(),
                seq: 0,
                reset_token: None,
                path_id: Some(initial_path_id),
            },
        );

        // Because we already inserted the initial SCID.
        let next_scid_seq = 1;
        ConnectionIdentifiers {
            scids,
            dcids,
            retired_scids: VecDeque::new(),
            next_scid_seq,
            source_conn_id_limit,
            zero_length_scid,
            ..Default::default()
        }
    }

    /// Sets the maximum number of source connection IDs our peer allows us.
    pub fn set_source_conn_id_limit(&mut self, v: u64) {
        // Bound conn id limit so our scids queue sizing is valid.
        let v = std::cmp::min(v, (usize::MAX / 2) as u64) as usize;

        // It must be at least 2.
        if v >= 2 {
            self.source_conn_id_limit = v;
            // We need to track up to (2 * source_conn_id_limit - 1) source
            // Connection IDs when the host wants to force their renewal.
            self.scids.resize(2 * v - 1);
        }
    }

    /// Gets the destination Connection ID associated with the provided sequence
    /// number.
    #[inline]
    pub fn get_dcid(&self, seq_num: u64) -> Result<&ConnectionIdEntry> {
        self.dcids.get(seq_num).ok_or(Error::InvalidState)
    }

    /// Gets the source Connection ID associated with the provided sequence
    /// number.
    #[inline]
    pub fn get_scid(&self, seq_num: u64) -> Result<&ConnectionIdEntry> {
        self.scids.get(seq_num).ok_or(Error::InvalidState)
    }

    /// Adds a new source identifier, and indicates whether it should be
    /// advertised through a `NEW_CONNECTION_ID` frame or not.
    ///
    /// At any time, the peer cannot have more Destination Connection IDs than
    /// the maximum number of active Connection IDs it negotiated. In such case
    /// (i.e., when [`active_source_cids()`] - `peer_active_conn_id_limit` = 0,
    /// if the caller agrees to request the removal of previous connection IDs,
    /// it sets the `retire_if_needed` parameter. Otherwise, an [`IdLimit`] is
    /// returned.
    ///
    /// Note that setting `retire_if_needed` does not prevent this function from
    /// returning an [`IdLimit`] in the case the caller wants to retire still
    /// unannounced Connection IDs.
    ///
    /// When setting the initial Source Connection ID, the `reset_token` may be
    /// `None`. However, other Source CIDs must have an associated
    /// `reset_token`. Providing `None` as the `reset_token` for non-initial
    /// SCIDs raises an [`InvalidState`].
    ///
    /// In the case the provided `cid` is already present, it does not add it.
    /// If the provided `reset_token` differs from the one already registered,
    /// returns an `InvalidState`.
    ///
    /// Returns the sequence number associated to that new source identifier.
    ///
    /// [`active_source_cids()`]:  struct.ConnectionIdentifiers.html#method.active_source_cids
    /// [`InvalidState`]: enum.Error.html#InvalidState
    /// [`IdLimit`]: enum.Error.html#IdLimit
    pub fn new_scid(
        &mut self, cid: ConnectionId<'static>, reset_token: Option<u128>,
        advertise: bool, path_id: Option<usize>, retire_if_needed: bool,
    ) -> Result<u64> {
        if self.zero_length_scid {
            return Err(Error::InvalidState);
        }

        // Check whether the number of source Connection IDs does not exceed the
        // limit. If the host agrees to retire old CIDs, it can store up to
        // (2 * source_active_conn_id - 1) source CIDs. This limit is enforced
        // when calling `self.scids.insert()`.
        if self.scids.len() >= self.source_conn_id_limit {
            if !retire_if_needed {
                return Err(Error::IdLimit);
            }

            // We need to retire the lowest one.
            self.retire_prior_to = self.lowest_usable_scid_seq()? + 1;
        }

        let seq = self.next_scid_seq;

        if reset_token.is_none() && seq != 0 {
            return Err(Error::InvalidState);
        }

        // Check first that the SCID has not been inserted before.
        if let Some(e) = self.scids.iter().find(|e| e.cid == cid) {
            if e.reset_token != reset_token {
                return Err(Error::InvalidState);
            }
            return Ok(e.seq);
        }

        self.scids.insert(ConnectionIdEntry {
            cid,
            seq,
            reset_token,
            path_id,
        })?;
        self.next_scid_seq += 1;

        self.mark_advertise_new_scid_seq(seq, advertise);

        Ok(seq)
    }

    /// Sets the initial destination identifier.
    pub fn set_initial_dcid(
        &mut self, cid: ConnectionId<'static>, reset_token: Option<u128>,
        path_id: Option<usize>,
    ) {
        // Record the zero-length DCID status.
        self.zero_length_dcid = cid.is_empty();
        self.dcids.clear_and_insert(ConnectionIdEntry {
            cid,
            seq: 0,
            reset_token,
            path_id,
        });
    }

    /// Adds a new Destination Connection ID (originating from a
    /// NEW_CONNECTION_ID frame) and process all its related metadata.
    ///
    /// Returns an error if the provided Connection ID or its metadata are
    /// invalid.
    ///
    /// Returns a list of tuples (DCID sequence number, Path ID), containing the
    /// sequence number of retired DCIDs that were linked to their respective
    /// Path ID.
    pub fn new_dcid(
        &mut self, cid: ConnectionId<'static>, seq: u64, reset_token: u128,
        retire_prior_to: u64,
    ) -> Result<Vec<(u64, usize)>> {
        if self.zero_length_dcid {
            return Err(Error::InvalidState);
        }

        let mut retired_path_ids = Vec::new();
        // If an endpoint receives a NEW_CONNECTION_ID frame that repeats a
        // previously issued connection ID with a different Stateless Reset
        // Token field value or a different Sequence Number field value, or if a
        // sequence number is used for different connection IDs, the endpoint
        // MAY treat that receipt as a connection error of type
        // PROTOCOL_VIOLATION.
        if let Some(e) = self.dcids.iter().find(|e| e.cid == cid || e.seq == seq)
        {
            if e.cid != cid || e.seq != seq || e.reset_token != Some(reset_token)
            {
                return Err(Error::InvalidFrame);
            }
            // The identifier is already there, nothing to do.
            return Ok(retired_path_ids);
        }

        // The value in the Retire Prior To field MUST be less than or equal to
        // the value in the Sequence Number field. Receiving a value in the
        // Retire Prior To field that is greater than that in the Sequence
        // Number field MUST be treated as a connection error of type
        // FRAME_ENCODING_ERROR.
        if retire_prior_to > seq {
            return Err(Error::InvalidFrame);
        }

        // An endpoint that receives a NEW_CONNECTION_ID frame with a sequence
        // number smaller than the Retire Prior To field of a previously
        // received NEW_CONNECTION_ID frame MUST send a corresponding
        // RETIRE_CONNECTION_ID frame that retires the newly received connection
        // ID, unless it has already done so for that sequence number.
        if seq < self.largest_peer_retire_prior_to &&
            !self.retire_dcid_seqs.contains(&seq)
        {
            self.retire_dcid_seqs.push_back(seq);
            return Ok(retired_path_ids);
        }

        if seq > self.largest_destination_seq {
            self.largest_destination_seq = seq;
        }

        let new_entry = ConnectionIdEntry {
            cid: cid.clone(),
            seq,
            reset_token: Some(reset_token),
            path_id: None,
        };

        // A receiver MUST ignore any Retire Prior To fields that do not
        // increase the largest received Retire Prior To value.
        //
        // After processing a NEW_CONNECTION_ID frame and adding and retiring
        // active connection IDs, if the number of active connection IDs exceeds
        // the value advertised in its active_connection_id_limit transport
        // parameter, an endpoint MUST close the connection with an error of type
        // CONNECTION_ID_LIMIT_ERROR.
        if retire_prior_to > self.largest_peer_retire_prior_to {
            let retired = &mut self.retire_dcid_seqs;
            self.dcids.remove_lower_than_and_insert(
                retire_prior_to,
                new_entry,
                |e| {
                    retired.push_back(e.seq);

                    if let Some(pid) = e.path_id {
                        retired_path_ids.push((e.seq, pid));
                    }
                },
            )?;
            self.largest_peer_retire_prior_to = retire_prior_to;
        } else {
            self.dcids.insert(new_entry)?;
        }

        Ok(retired_path_ids)
    }

    /// Retires the Source Connection ID having the provided sequence number.
    ///
    /// In case the retired Connection ID is the same as the one used by the
    /// packet requesting the retiring, or if the retired sequence number is
    /// greater than any previously advertised sequence numbers, it returns an
    /// [`InvalidState`].
    ///
    /// Returns the path ID that was associated to the retired CID, if any.
    ///
    /// [`InvalidState`]: enum.Error.html#InvalidState
    pub fn retire_scid(
        &mut self, seq: u64, pkt_dcid: &ConnectionId,
    ) -> Result<Option<usize>> {
        if seq >= self.next_scid_seq {
            return Err(Error::InvalidState);
        }

        let pid = if let Some(e) = self.scids.remove(seq)? {
            if e.cid == *pkt_dcid {
                return Err(Error::InvalidState);
            }

            // Notifies the application.
            self.retired_scids.push_back(e.cid);

            // Retiring this SCID may increase the retire prior to.
            let lowest_scid_seq = self.lowest_usable_scid_seq()?;
            self.retire_prior_to = lowest_scid_seq;

            e.path_id
        } else {
            None
        };

        Ok(pid)
    }

    /// Retires the Destination Connection ID having the provided sequence
    /// number.
    ///
    /// If the caller tries to retire the last destination Connection ID, this
    /// method triggers an [`OutOfIdentifiers`].
    ///
    /// If the caller tries to retire a non-existing Destination Connection
    /// ID sequence number, this method returns an [`InvalidState`].
    ///
    /// Returns the path ID that was associated to the retired CID, if any.
    ///
    /// [`OutOfIdentifiers`]: enum.Error.html#OutOfIdentifiers
    /// [`InvalidState`]: enum.Error.html#InvalidState
    pub fn retire_dcid(&mut self, seq: u64) -> Result<Option<usize>> {
        if self.zero_length_dcid {
            return Err(Error::InvalidState);
        }

        let e = self.dcids.remove(seq)?.ok_or(Error::InvalidState)?;

        self.retire_dcid_seqs.push_back(seq);

        Ok(e.path_id)
    }

    /// Updates the Source Connection ID entry with the provided sequence number
    /// to indicate that it is now linked to the provided path ID.
    pub fn link_scid_to_path_id(
        &mut self, dcid_seq: u64, path_id: usize,
    ) -> Result<()> {
        let e = self.scids.get_mut(dcid_seq).ok_or(Error::InvalidState)?;
        e.path_id = Some(path_id);
        Ok(())
    }

    /// Updates the Destination Connection ID entry with the provided sequence
    /// number to indicate that it is now linked to the provided path ID.
    pub fn link_dcid_to_path_id(
        &mut self, dcid_seq: u64, path_id: usize,
    ) -> Result<()> {
        let e = self.dcids.get_mut(dcid_seq).ok_or(Error::InvalidState)?;
        e.path_id = Some(path_id);
        Ok(())
    }

    /// Gets the minimum Source Connection ID sequence number whose removal has
    /// not been requested yet.
    #[inline]
    pub fn lowest_usable_scid_seq(&self) -> Result<u64> {
        self.scids
            .iter()
            .filter_map(|e| {
                if e.seq >= self.retire_prior_to {
                    Some(e.seq)
                } else {
                    None
                }
            })
            .min()
            .ok_or(Error::InvalidState)
    }

    /// Gets the lowest Destination Connection ID sequence number that is not
    /// associated to a path.
    #[inline]
    pub fn lowest_available_dcid_seq(&self) -> Option<u64> {
        self.dcids
            .iter()
            .filter_map(|e| {
                if e.path_id.is_none() {
                    Some(e.seq)
                } else {
                    None
                }
            })
            .min()
    }

    /// Finds the sequence number of the Source Connection ID having the
    /// provided value and the identifier of the path using it, if any.
    #[inline]
    pub fn find_scid_seq(
        &self, scid: &ConnectionId,
    ) -> Option<(u64, Option<usize>)> {
        self.scids.iter().find_map(|e| {
            if e.cid == *scid {
                Some((e.seq, e.path_id))
            } else {
                None
            }
        })
    }

    /// Returns the number of Source Connection IDs that have not been
    /// assigned to a path yet.
    ///
    /// Note that this function is only meaningful if the host uses non-zero
    /// length Source Connection IDs.
    #[inline]
    pub fn available_scids(&self) -> usize {
        self.scids.iter().filter(|e| e.path_id.is_none()).count()
    }

    /// Returns the number of Destination Connection IDs that have not been
    /// assigned to a path yet.
    ///
    /// Note that this function returns 0 if the host uses zero length
    /// Destination Connection IDs.
    #[inline]
    pub fn available_dcids(&self) -> usize {
        if self.zero_length_dcid() {
            return 0;
        }
        self.dcids.iter().filter(|e| e.path_id.is_none()).count()
    }

    /// Returns the oldest active source Connection ID of this connection.
    #[inline]
    pub fn oldest_scid(&self) -> &ConnectionIdEntry {
        self.scids.get_oldest()
    }

    /// Returns the oldest known active destination Connection ID of this
    /// connection.
    ///
    /// Note that due to e.g., reordering at reception side, the oldest known
    /// active destination Connection ID is not necessarily the one having the
    /// lowest sequence.
    #[inline]
    pub fn oldest_dcid(&self) -> &ConnectionIdEntry {
        self.dcids.get_oldest()
    }

    /// Adds or remove the source Connection ID sequence number from the
    /// source Connection ID set that need to be advertised to the peer through
    /// NEW_CONNECTION_ID frames.
    #[inline]
    pub fn mark_advertise_new_scid_seq(
        &mut self, scid_seq: u64, advertise: bool,
    ) {
        if advertise {
            self.advertise_new_scid_seqs.push_back(scid_seq);
        } else if let Some(index) = self
            .advertise_new_scid_seqs
            .iter()
            .position(|s| *s == scid_seq)
        {
            self.advertise_new_scid_seqs.remove(index);
        }
    }

    /// Adds or remove the destination Connection ID sequence number from the
    /// retired destination Connection ID set that need to be advertised to the
    /// peer through RETIRE_CONNECTION_ID frames.
    #[inline]
    pub fn mark_retire_dcid_seq(&mut self, dcid_seq: u64, retire: bool) {
        if retire {
            self.retire_dcid_seqs.push_back(dcid_seq);
        } else if let Some(index) =
            self.retire_dcid_seqs.iter().position(|s| *s == dcid_seq)
        {
            self.retire_dcid_seqs.remove(index);
        }
    }

    /// Gets a source Connection ID's sequence number requiring advertising it
    /// to the peer through NEW_CONNECTION_ID frame, if any.
    ///
    /// If `Some`, it always returns the same value until it has been removed
    /// using `mark_advertise_new_scid_seq`.
    #[inline]
    pub fn next_advertise_new_scid_seq(&self) -> Option<u64> {
        self.advertise_new_scid_seqs.front().copied()
    }

    /// Gets a destination Connection IDs's sequence number that need to send
    /// RETIRE_CONNECTION_ID frames.
    ///
    /// If `Some`, it always returns the same value until it has been removed
    /// using `mark_retire_dcid_seq`.
    #[inline]
    pub fn next_retire_dcid_seq(&self) -> Option<u64> {
        self.retire_dcid_seqs.front().copied()
    }

    /// Returns true if there are new source Connection IDs to advertise.
    #[inline]
    pub fn has_new_scids(&self) -> bool {
        !self.advertise_new_scid_seqs.is_empty()
    }

    /// Returns true if there are retired destination Connection IDs to\
    /// advertise.
    #[inline]
    pub fn has_retire_dcids(&self) -> bool {
        !self.retire_dcid_seqs.is_empty()
    }

    /// Returns whether zero-length source CIDs are used.
    #[inline]
    pub fn zero_length_scid(&self) -> bool {
        self.zero_length_scid
    }

    /// Returns whether zero-length destination CIDs are used.
    #[inline]
    pub fn zero_length_dcid(&self) -> bool {
        self.zero_length_dcid
    }

    /// Gets the NEW_CONNECTION_ID frame related to the source connection ID
    /// with sequence `seq_num`.
    pub fn get_new_connection_id_frame_for(
        &self, seq_num: u64,
    ) -> Result<frame::Frame> {
        let e = self.scids.get(seq_num).ok_or(Error::InvalidState)?;
        Ok(frame::Frame::NewConnectionId {
            seq_num,
            retire_prior_to: self.retire_prior_to,
            conn_id: e.cid.to_vec(),
            reset_token: e.reset_token.ok_or(Error::InvalidState)?.to_be_bytes(),
        })
    }

    /// Returns the number of source Connection IDs that are active. This is
    /// only meaningful if the host uses non-zero length Source Connection IDs.
    #[inline]
    pub fn active_source_cids(&self) -> usize {
        self.scids.len()
    }

    pub fn pop_retired_scid(&mut self) -> Option<ConnectionId<'static>> {
        self.retired_scids.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::create_cid_and_reset_token;

    #[test]
    fn ids_new_scids() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_source_conn_id_limit(3);
        ids.set_initial_dcid(dcid, None, Some(0));

        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.available_scids(), 0);
        assert_eq!(ids.has_new_scids(), false);
        assert_eq!(ids.next_advertise_new_scid_seq(), None);

        let (scid2, rt2) = create_cid_and_reset_token(16);

        assert_eq!(ids.new_scid(scid2, Some(rt2), true, None, false), Ok(1));
        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.available_scids(), 1);
        assert_eq!(ids.has_new_scids(), true);
        assert_eq!(ids.next_advertise_new_scid_seq(), Some(1));

        let (scid3, rt3) = create_cid_and_reset_token(16);

        assert_eq!(ids.new_scid(scid3, Some(rt3), true, None, false), Ok(2));
        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.available_scids(), 2);
        assert_eq!(ids.has_new_scids(), true);
        assert_eq!(ids.next_advertise_new_scid_seq(), Some(1));

        // If now we give another CID, it reports an error since it exceeds the
        // limit of active CIDs.
        let (scid4, rt4) = create_cid_and_reset_token(16);

        assert_eq!(
            ids.new_scid(scid4, Some(rt4), true, None, false),
            Err(Error::IdLimit),
        );
        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.available_scids(), 2);
        assert_eq!(ids.has_new_scids(), true);
        assert_eq!(ids.next_advertise_new_scid_seq(), Some(1));

        // Assume we sent one of them.
        ids.mark_advertise_new_scid_seq(1, false);
        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.available_scids(), 2);
        assert_eq!(ids.has_new_scids(), true);
        assert_eq!(ids.next_advertise_new_scid_seq(), Some(2));

        // Send the other.
        ids.mark_advertise_new_scid_seq(2, false);

        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.available_scids(), 2);
        assert_eq!(ids.has_new_scids(), false);
        assert_eq!(ids.next_advertise_new_scid_seq(), None);
    }

    #[test]
    fn new_dcid_event() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut ids = ConnectionIdentifiers::new(2, &scid, 0, None);
        ids.set_initial_dcid(dcid, None, Some(0));

        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.dcids.len(), 1);

        let (dcid2, rt2) = create_cid_and_reset_token(16);

        assert_eq!(
            ids.new_dcid(dcid2.clone(), 1, rt2, 0),
            Ok(Vec::<(u64, usize)>::new()),
        );
        assert_eq!(ids.available_dcids(), 1);
        assert_eq!(ids.dcids.len(), 2);

        // Now we assume that the client wants to advertise more source
        // Connection IDs than the advertised limit. This is valid if it
        // requests its peer to retire enough Connection IDs to fit within the
        // limits.
        let (dcid3, rt3) = create_cid_and_reset_token(16);
        assert_eq!(ids.new_dcid(dcid3.clone(), 2, rt3, 1), Ok(vec![(0, 0)]));
        // The CID module does not handle path replacing. Fake it now.
        ids.link_dcid_to_path_id(1, 0).unwrap();
        assert_eq!(ids.available_dcids(), 1);
        assert_eq!(ids.dcids.len(), 2);
        assert_eq!(ids.has_retire_dcids(), true);
        assert_eq!(ids.next_retire_dcid_seq(), Some(0));

        // Fake RETIRE_CONNECTION_ID sending.
        ids.mark_retire_dcid_seq(0, false);
        assert_eq!(ids.has_retire_dcids(), false);
        assert_eq!(ids.next_retire_dcid_seq(), None);

        // Now tries to experience CID retirement. If the server tries to remove
        // non-existing DCIDs, it fails.
        assert_eq!(ids.retire_dcid(0), Err(Error::InvalidState));
        assert_eq!(ids.retire_dcid(3), Err(Error::InvalidState));
        assert_eq!(ids.has_retire_dcids(), false);
        assert_eq!(ids.dcids.len(), 2);

        // Now it removes DCID with sequence 1.
        assert_eq!(ids.retire_dcid(1), Ok(Some(0)));
        // The CID module does not handle path replacing. Fake it now.
        ids.link_dcid_to_path_id(2, 0).unwrap();
        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.has_retire_dcids(), true);
        assert_eq!(ids.next_retire_dcid_seq(), Some(1));
        assert_eq!(ids.dcids.len(), 1);

        // Fake RETIRE_CONNECTION_ID sending.
        ids.mark_retire_dcid_seq(1, false);
        assert_eq!(ids.has_retire_dcids(), false);
        assert_eq!(ids.next_retire_dcid_seq(), None);

        // Trying to remove the last DCID triggers an error.
        assert_eq!(ids.retire_dcid(2), Err(Error::OutOfIdentifiers));
        assert_eq!(ids.available_dcids(), 0);
        assert_eq!(ids.has_retire_dcids(), false);
        assert_eq!(ids.dcids.len(), 1);
    }

    #[test]
    fn retire_scids() {
        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        let mut ids = ConnectionIdentifiers::new(3, &scid, 0, None);
        ids.set_initial_dcid(dcid, None, Some(0));
        ids.set_source_conn_id_limit(3);

        let (scid2, rt2) = create_cid_and_reset_token(16);
        let (scid3, rt3) = create_cid_and_reset_token(16);

        assert_eq!(
            ids.new_scid(scid2.clone(), Some(rt2), true, None, false),
            Ok(1),
        );
        assert_eq!(ids.scids.len(), 2);
        assert_eq!(
            ids.new_scid(scid3.clone(), Some(rt3), true, None, false),
            Ok(2),
        );
        assert_eq!(ids.scids.len(), 3);

        assert_eq!(ids.pop_retired_scid(), None);

        assert_eq!(ids.retire_scid(0, &scid2), Ok(Some(0)));

        assert_eq!(ids.pop_retired_scid(), Some(scid));
        assert_eq!(ids.pop_retired_scid(), None);

        assert_eq!(ids.retire_scid(1, &scid3), Ok(None));

        assert_eq!(ids.pop_retired_scid(), Some(scid2));
        assert_eq!(ids.pop_retired_scid(), None);
    }
}
