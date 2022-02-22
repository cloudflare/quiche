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

use std::collections::HashMap;
use std::collections::VecDeque;

/// A Connection Id-specific event.
#[derive(Clone, Debug, PartialEq)]
pub enum ConnectionIdEvent {
    /// The related `ConnectionId`, with the associated sequence number as
    /// `u64` and stateless reset token as `u128`, can now be used to reach the
    /// peer.
    NewDestination(u64, ConnectionId<'static>, u128),
    /// The related Connection ID with the associated sequence number as
    /// `u64`, must be retired because the peer required us to do so.
    RetiredDestination(u64),
    /// The related Source `ConnectionId` has been retired by the peer.
    RetiredSource(ConnectionId<'static>),
}

/// A structure holding a `ConnectionId` and all its related metadata.
#[derive(Debug)]
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

/// A simple no-op hasher for Connection ID sequence numbers.
///
/// The QUIC protocol and quiche library guarantees Connection ID sequence
/// number uniqueness, so we can save effort by avoiding using a more
/// complicated algorithm.
#[derive(Default)]
pub struct ConnectionIdSeqHasher {
    id: u64,
}

impl std::hash::Hasher for ConnectionIdSeqHasher {
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
        // We need a default write() for the trait but Connection ID sequence
        // number will always be a u64 so we just delegate to write_u64.
        unimplemented!()
    }
}

type BuildConnectionIdSeqHasher =
    std::hash::BuildHasherDefault<ConnectionIdSeqHasher>;

type ConnectionIdSeqHashMap<V> = HashMap<u64, V, BuildConnectionIdSeqHasher>;

#[derive(Default)]
pub struct ConnectionIdentifiers {
    /// All the Destination Connection IDs provided by our peer.
    dcids: ConnectionIdSeqHashMap<ConnectionIdEntry>,
    /// All the Source Connection IDs we provide to our peer.
    scids: ConnectionIdSeqHashMap<ConnectionIdEntry>,

    /// Source Connection IDs that should be announced to the peer.
    new_scids: VecDeque<u64>,
    /// Retired Destination Connection IDs that should be announced to the peer.
    retire_dcids: VecDeque<u64>,

    /// All Connection ID related events that should be notified to the
    /// application.
    events: Option<VecDeque<ConnectionIdEvent>>,

    /// Largest "Retire Prior To" we received from the peer.
    largest_peer_retire_prior_to: u64,
    /// Largest sequence number we received from the peer.
    largest_destination_seq: u64,
    /// Next sequence number to use.
    next_scid_seq: u64,
    /// "Retire Prior To" value to advertise to the peer.
    retire_prior_to: u64,

    /// The maximum number of destination Connection IDs we allow.
    destination_conn_id_limit: usize,
    /// The maximum number of source Connection IDs our peer allows us.
    source_conn_id_limit: usize,

    /// Does the host use zero-length source Connection ID.
    zero_length_scid: bool,
    /// Does the host use zero-length destination Connection ID.
    zero_length_dcid: bool,
}

impl ConnectionIdentifiers {
    /// Creates a new `ConnectionIdentifiers` with the specified destination
    /// connection ID limit.
    pub fn new(
        mut destination_conn_id_limit: usize, enable_events: bool,
    ) -> ConnectionIdentifiers {
        // It must be at least 2.
        if destination_conn_id_limit < 2 {
            destination_conn_id_limit = 2;
        }
        let events = if enable_events {
            Some(VecDeque::new())
        } else {
            None
        };
        ConnectionIdentifiers {
            destination_conn_id_limit,
            source_conn_id_limit: 2,
            events,
            ..Default::default()
        }
    }

    /// Sets the maximum number of source connection IDs our peer allows us.
    pub fn set_source_conn_id_limit(&mut self, v: u64) {
        // It must be at least 2.
        if v >= 2 {
            self.source_conn_id_limit = v as usize;
        }
    }

    /// Gets the source Connection ID associated with the provided sequence
    /// number.
    #[inline]
    pub fn get_scid(&self, seq_num: u64) -> Result<&ConnectionIdEntry> {
        self.scids.get(&seq_num).ok_or(Error::InvalidState)
    }

    /// Adds a new source identifier, and indicates whether it should be
    /// advertised through a `NEW_CONNECTION_ID` frame or not.
    ///
    /// At any time, the peer cannot have more Destination Connection IDs than
    /// the maximum number of active Connection IDs it negotiated. In such case
    /// (i.e., when [`active_source_cids()`] - `peer_active_conn_id_limit` = 0,
    /// if the caller agrees to request the removal of previous connection IDs,
    /// it sets the `retire_if_needed` parameter. Otherwhise, an [`IdLimit`] is
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

        if self.scids.len() >= self.source_conn_id_limit {
            if !retire_if_needed {
                return Err(Error::IdLimit);
            }

            // Avoid buggy applications from driving the stack crazy.
            let wrap_around_limit = 2 * self.source_conn_id_limit;
            if self.scids.len() >= wrap_around_limit {
                return Err(Error::IdLimit);
            }

            // We need to retire the lowest one.
            self.retire_prior_to = self.lowest_usable_scid_seq()? + 1;
        }

        let seq = self.next_scid_seq;

        if reset_token.is_none() && seq != 0 {
            return Err(Error::InvalidState);
        }

        if seq == 0 {
            // Record the zero-length SCID status.
            self.zero_length_scid = cid.is_empty();
        }

        // Check first that the SCID has not been inserted before.
        if let Some((s, e)) = self.scids.iter().find(|(_, e)| e.cid == cid) {
            if e.reset_token != reset_token {
                return Err(Error::InvalidState);
            }
            return Ok(*s);
        }

        self.scids.insert(seq, ConnectionIdEntry {
            cid,
            seq,
            reset_token,
            path_id,
        });
        self.next_scid_seq += 1;

        self.mark_new_scids(seq, advertise);

        Ok(seq)
    }

    /// Sets the initial destination identifier.
    pub fn set_initial_dcid(
        &mut self, cid: ConnectionId<'static>, reset_token: Option<u128>,
        path_id: Option<usize>,
    ) {
        self.dcids.clear();
        // Record the zero-length DCID status.
        self.zero_length_dcid = cid.is_empty();
        self.dcids.insert(0, ConnectionIdEntry {
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
        if let Some(e) =
            self.dcids.values().find(|e| e.cid == cid || e.seq == seq)
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
        if seq < self.largest_peer_retire_prior_to {
            if !self.retire_dcids.contains(&seq) {
                self.retire_dcids.push_back(seq);
                return Ok(retired_path_ids);
            }
        }

        // A receiver MUST ignore any Retire Prior To fields that do not
        // increase the largest received Retire Prior To value.
        if retire_prior_to > self.largest_peer_retire_prior_to {
            let retired = &mut self.retire_dcids;
            let events = &mut self.events;
            self.dcids.retain(|seq, e| {
                if *seq < retire_prior_to {
                    retired.push_back(*seq);
                    // We also need to notify the application.
                    if let Some(evs) = events {
                        evs.push_back(ConnectionIdEvent::RetiredDestination(
                            *seq,
                        ));
                    }

                    if let Some(pid) = e.path_id {
                        retired_path_ids.push((*seq, pid));
                    }

                    return false;
                }
                true
            });
            self.largest_peer_retire_prior_to = retire_prior_to;
        }

        if seq > self.largest_destination_seq {
            self.largest_destination_seq = seq;
        }

        self.dcids.insert(seq, ConnectionIdEntry {
            cid: cid.clone(),
            seq,
            reset_token: Some(reset_token),
            path_id: None,
        });

        // After processing a NEW_CONNECTION_ID frame and adding and retiring
        // active connection IDs, if the number of active connection IDs exceeds
        // the value advertised in its active_connection_id_limit transport
        // parameter, an endpoint MUST close the connection with an error of type
        // CONNECTION_ID_LIMIT_ERROR.
        if self.dcids.len() > self.destination_conn_id_limit {
            return Err(Error::IdLimit);
        }

        // Notifies the application.
        if let Some(evs) = &mut self.events {
            evs.push_back(ConnectionIdEvent::NewDestination(
                seq,
                cid,
                reset_token,
            ));
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

        let pid = if let Some(e) = self.scids.remove(&seq) {
            if e.cid == *pkt_dcid {
                return Err(Error::InvalidState);
            }
            // Notifies the application.
            if let Some(evs) = &mut self.events {
                evs.push_back(ConnectionIdEvent::RetiredSource(e.cid));
            }

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

        if self.dcids.len() == 1 {
            return Err(Error::OutOfIdentifiers);
        }

        let e = self.dcids.remove(&seq).ok_or(Error::InvalidState)?;

        self.retire_dcids.push_back(seq);

        Ok(e.path_id)
    }

    /// Updates the Destination Connection ID entry with the provided sequence
    /// number to indicate that it is now linked to the provided path ID.
    pub fn link_dcid_to_path_id(
        &mut self, dcid_seq: u64, path_id: usize,
    ) -> Result<()> {
        let e = self.dcids.get_mut(&dcid_seq).ok_or(Error::InvalidState)?;
        e.path_id = Some(path_id);
        Ok(())
    }

    /// Gets the minimum Source Connection ID sequence number whose removal has
    /// not been requested yet.
    #[inline]
    pub fn lowest_usable_scid_seq(&self) -> Result<u64> {
        self.scids
            .keys()
            .filter_map(|x| {
                if *x >= self.retire_prior_to {
                    Some(*x)
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
            .filter_map(
                |(s, e)| if e.path_id.is_none() { Some(*s) } else { None },
            )
            .min()
    }

    /// Returns the oldest active source Connection ID on this connection.
    #[inline]
    pub fn oldest_scid(&self) -> Result<&ConnectionIdEntry> {
        self.scids.values().next().ok_or(Error::InvalidState)
    }

    /// Returns the oldest active destinatino Connection ID on this connection.
    #[inline]
    pub fn oldest_dcid(&self) -> Result<&ConnectionIdEntry> {
        self.dcids.values().next().ok_or(Error::InvalidState)
    }

    /// Adds or remove the destination Connection ID sequence number from the
    /// retire destination Connection ID set.
    #[inline]
    pub fn mark_new_scids(&mut self, scid_seq: u64, new: bool) {
        if new {
            self.new_scids.push_back(scid_seq);
        } else {
            self.new_scids.retain(|s| *s != scid_seq);
        }
    }

    /// Adds or remove the destination Connection ID sequence number from the
    /// retire destination Connection ID set.
    #[inline]
    pub fn mark_retire_dcids(&mut self, dcid_seq: u64, retire: bool) {
        if retire {
            self.retire_dcids.push_back(dcid_seq);
        } else {
            self.retire_dcids.retain(|s| *s != dcid_seq);
        }
    }

    /// Creates an iterator over source Connection IDs that need to send
    /// NEW_CONNECTION_ID frames.
    #[inline]
    pub fn new_scids(&self) -> std::collections::vec_deque::Iter<u64> {
        self.new_scids.iter()
    }

    /// Creates an iterator over destination Connection IDs that need to send
    /// RETIRE_CONNECTION_ID frames.
    #[inline]
    pub fn retire_dcids(&self) -> std::collections::vec_deque::Iter<u64> {
        self.retire_dcids.iter()
    }

    /// Returns true if there are new source Connection IDs to advertise.
    #[inline]
    pub fn has_new_scids(&self) -> bool {
        !self.new_scids.is_empty()
    }

    /// Returns true if there are retired destination Connection IDs to\
    /// advertise.
    #[inline]
    pub fn has_retire_dcids(&self) -> bool {
        !self.retire_dcids.is_empty()
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

    /// Gets the first CID-related event to be notified to the application.
    #[inline]
    pub fn pop_event(&mut self) -> Option<ConnectionIdEvent> {
        self.events.as_mut().and_then(|evs| evs.pop_front())
    }

    /// Gets the NEW_CONNECTION_ID frame related to the source connection ID
    /// with sequence `seq_num`.
    pub fn get_new_connection_id_frame_for(
        &self, seq_num: u64,
    ) -> Result<frame::Frame> {
        let e = self.scids.get(&seq_num).ok_or(Error::InvalidState)?;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::create_cid_and_reset_token;

    impl ConnectionIdentifiers {
        /// Returns the number of Source Connection IDs that have not been
        /// assigned to a path yet.
        ///
        /// Note that this function is only meaningful if the host uses non-zero
        /// length Source Connection IDs.
        #[inline]
        fn available_scids(&self) -> usize {
            self.scids.values().filter(|e| e.path_id.is_none()).count()
        }
    }

    #[test]
    fn ids_new_scids() {
        let mut ids = ConnectionIdentifiers::new(2, true);
        ids.set_source_conn_id_limit(3);

        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        ids.set_initial_dcid(dcid, None, None);
        ids.new_scid(scid, None, false, None, false).unwrap();

        assert_eq!(ids.pop_event(), None);
        assert_eq!(ids.available_scids(), 1);
        assert_eq!(ids.has_new_scids(), false);
        assert_eq!(ids.new_scids().collect::<Vec<&u64>>(), Vec::<&u64>::new());

        let (scid2, rt2) = create_cid_and_reset_token(16);

        assert_eq!(ids.new_scid(scid2, Some(rt2), true, None, false), Ok(1));
        assert_eq!(ids.available_scids(), 2);
        assert_eq!(ids.has_new_scids(), true);
        assert_eq!(ids.new_scids().collect::<Vec<&u64>>(), vec![&1]);

        let (scid3, rt3) = create_cid_and_reset_token(16);

        assert_eq!(ids.new_scid(scid3, Some(rt3), true, None, false), Ok(2));
        assert_eq!(ids.available_scids(), 3);
        assert_eq!(ids.has_new_scids(), true);
        assert_eq!(ids.new_scids().collect::<Vec<&u64>>(), vec![&1, &2]);

        // If now we give another CID, it reports an error since it exceeds the
        // limit of active CIDs.
        let (scid4, rt4) = create_cid_and_reset_token(16);

        assert_eq!(
            ids.new_scid(scid4, Some(rt4), true, None, false),
            Err(Error::IdLimit),
        );
        assert_eq!(ids.available_scids(), 3);
        assert_eq!(ids.has_new_scids(), true);
        assert_eq!(ids.new_scids().collect::<Vec<&u64>>(), vec![&1, &2]);
        assert_eq!(ids.pop_event(), None);

        // Assume we sent them.
        ids.mark_new_scids(1, false);
        ids.mark_new_scids(2, false);

        assert_eq!(ids.available_scids(), 3);
        assert_eq!(ids.has_new_scids(), false);
        assert_eq!(ids.new_scids().collect::<Vec<&u64>>(), Vec::<&u64>::new());
        assert_eq!(ids.pop_event(), None);
    }

    #[test]
    fn new_dcid_event() {
        let mut ids = ConnectionIdentifiers::new(2, true);

        let (scid, _) = create_cid_and_reset_token(16);
        let (dcid, _) = create_cid_and_reset_token(16);

        ids.set_initial_dcid(dcid, None, None);
        ids.new_scid(scid, None, false, None, false).unwrap();

        assert_eq!(ids.pop_event(), None);

        assert_eq!(ids.dcids.len(), 1);

        let (dcid2, rt2) = create_cid_and_reset_token(16);

        assert_eq!(
            ids.new_dcid(dcid2.clone(), 1, rt2, 0),
            Ok(Vec::<(u64, usize)>::new()),
        );
        assert_eq!(
            ids.pop_event(),
            Some(ConnectionIdEvent::NewDestination(1, dcid2, rt2))
        );
        assert_eq!(ids.pop_event(), None);
        assert_eq!(ids.dcids.len(), 2);

        // Now we assume that the client wants to advertise more source
        // Connection IDs than the advertised limit. This is valid if it
        // requests its peer to retire enough Connection IDs to fit within the
        // limits.
        let (dcid3, rt3) = create_cid_and_reset_token(16);
        assert_eq!(
            ids.new_dcid(dcid3.clone(), 2, rt3, 1),
            Ok(Vec::<(u64, usize)>::new()),
        );
        assert_eq!(
            ids.pop_event(),
            Some(ConnectionIdEvent::RetiredDestination(0))
        );
        assert_eq!(
            ids.pop_event(),
            Some(ConnectionIdEvent::NewDestination(2, dcid3, rt3))
        );
        assert_eq!(ids.pop_event(), None);
        assert_eq!(ids.dcids.len(), 2);
        assert_eq!(ids.has_retire_dcids(), true);
        assert_eq!(ids.retire_dcids().collect::<Vec::<&u64>>(), vec![&0]);

        // Fake RETIRE_CONNECTION_ID sending.
        ids.mark_retire_dcids(0, false);
        assert_eq!(ids.has_retire_dcids(), false);
        assert_eq!(
            ids.retire_dcids().collect::<Vec::<&u64>>(),
            Vec::<&u64>::new()
        );

        // Now tries to experience CID retirement. If the server tries to remove
        // non-existing DCIDs, it fails.
        assert_eq!(ids.retire_dcid(0), Err(Error::InvalidState));
        assert_eq!(ids.retire_dcid(3), Err(Error::InvalidState));
        assert_eq!(ids.has_retire_dcids(), false);
        assert_eq!(ids.dcids.len(), 2);

        // Now it removes DCID with sequence 1.
        assert_eq!(ids.retire_dcid(1), Ok(None));
        assert_eq!(ids.has_retire_dcids(), true);
        assert_eq!(ids.retire_dcids().collect::<Vec::<&u64>>(), vec![&1]);
        assert_eq!(ids.dcids.len(), 1);

        // Fake RETIRE_CONNECTION_ID sending.
        ids.mark_retire_dcids(1, false);
        assert_eq!(ids.has_retire_dcids(), false);
        assert_eq!(
            ids.retire_dcids().collect::<Vec::<&u64>>(),
            Vec::<&u64>::new()
        );

        // Trying to remove the last DCID triggers an error.
        assert_eq!(ids.retire_dcid(2), Err(Error::OutOfIdentifiers));
        assert_eq!(ids.has_retire_dcids(), false);
        assert_eq!(ids.dcids.len(), 1);
    }
}
